#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/pte.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill(struct intr_frame *);
void page_fault(struct intr_frame *);

bool is_stack_access(void *fault_addr, void *esp) {
	return (fault_addr < PHYS_BASE) && (fault_addr > STACK_BOTTOM)
			&& (fault_addr + 32 >= esp);
}

/* Registers handlers for interrupts that can be caused by user
 programs.

 In a real Unix-like OS, most of these interrupts would be
 passed along to the user process in the form of signals, as
 described in [SV-386] 3-24 and 3-25, but we don't implement
 signals.  Instead, we'll make them simply kill the user
 process.

 Page faults are an exception.  Here they are treated the same
 way as other exceptions, but this will need to change to
 implement virtual memory.

 Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
 Reference" for a description of each of these exceptions. */
void exception_init(void) {
	/* These exceptions can be raised explicitly by a user program,
	 e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
	 we set DPL==3, meaning that user programs are allowed to
	 invoke them via these instructions. */
	intr_register_int(3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
	intr_register_int(4, 3, INTR_ON, kill, "#OF Overflow Exception");
	intr_register_int(5, 3, INTR_ON, kill,
			"#BR BOUND Range Exceeded Exception");

	/* These exceptions have DPL==0, preventing user processes from
	 invoking them via the INT instruction.  They can still be
	 caused indirectly, e.g. #DE can be caused by dividing by
	 0.  */
	intr_register_int(0, 0, INTR_ON, kill, "#DE Divide Error");
	intr_register_int(1, 0, INTR_ON, kill, "#DB Debug Exception");
	intr_register_int(6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
	intr_register_int(7, 0, INTR_ON, kill,
			"#NM Device Not Available Exception");
	intr_register_int(11, 0, INTR_ON, kill, "#NP Segment Not Present");
	intr_register_int(12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
	intr_register_int(13, 0, INTR_ON, kill, "#GP General Protection Exception");
	intr_register_int(16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
	intr_register_int(19, 0, INTR_ON, kill,
			"#XF SIMD Floating-Point Exception");

	/* Most exceptions can be handled with interrupts turned on.
	 We need to disable interrupts for page faults because the
	 fault address is stored in CR2 and needs to be preserved. */
	intr_register_int(14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void exception_print_stats(void) {
	printf("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void kill(struct intr_frame *f) {
	/* This interrupt is one (probably) caused by a user process.
	 For example, the process might have tried to access unmapped
	 virtual memory (a page fault).  For now, we simply kill the
	 user process.  Later, we'll want to handle page faults in
	 the kernel.  Real Unix-like operating systems pass most
	 exceptions back to the process via signals, but we don't
	 implement them. */

	/* The interrupt frame's code segment value tells us where the
	 exception originated. */
	switch (f->cs) {
	case SEL_UCSEG:
		/* User's code segment, so it's a user exception, as we
		 expected.  Kill the user process.  */
		printf("%s: dying due to interrupt %#04x (%s).\n", thread_name(),
				f->vec_no, intr_name(f->vec_no));
		intr_dump_frame(f);
		thread_exit();

	case SEL_KCSEG:
		/* Kernel's code segment, which indicates a kernel bug.
		 Kernel code shouldn't throw exceptions.  (Page faults
		 may cause kernel exceptions--but they shouldn't arrive
		 here.)  Panic the kernel to make the point.  */
		intr_dump_frame(f);
		PANIC("Kernel bug - unexpected interrupt in kernel");

	default:
		/* Some other code segment?  Shouldn't happen.  Panic the
		 kernel. */
		printf("Interrupt %#04x (%s) in unknown segment %04x\n", f->vec_no,
				intr_name(f->vec_no), f->cs);
		thread_exit();
	}
}

/* Page fault handler.  This is a skeleton that must be filled in
 to implement virtual memory.  Some solutions to task 2 may
 also require modifying this code.

 At entry, the address that faulted is in CR2 (Control Register
 2) and information about the fault, formatted as described in
 the PF_* macros in exception.h, is in F's error_code member.  The
 example code here shows how to parse that information.  You
 can find more information about both of these in the
 description of "Interrupt 14--Page Fault Exception (#PF)" in
 [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
void page_fault(struct intr_frame *f) {
	bool not_present; /* True: not-present page, false: writing r/o page. */
	bool write; /* True: access was write, false: access was read. */
	bool user; /* True: access by user, false: access by kernel. */
	void *fault_addr; /* Fault address. */

	/* Obtain faulting address, the virtual address that was
	 accessed to cause the fault.  It may point to code or to
	 data.  It is not necessarily the address of the instruction
	 that caused the fault (that's f->eip).
	 See [IA32-v2a] "MOV--Move to/from Control Registers" and
	 [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
	 (#PF)". */
	asm ("movl %%cr2, %0" : "=r" (fault_addr));

	/* Turn interrupts back on (they were only off so that we could
	 be assured of reading CR2 before it changed). */
	intr_enable();

	/* Count page faults. */
	page_fault_cnt++;

	void * fault_page = (void *) (PTE_ADDR & (uint32_t) fault_addr);
	struct thread *t = thread_current();

	/* Determine cause. */
	not_present = (f->error_code & PF_P) == 0;
	write = (f->error_code & PF_W) != 0;
	user = (f->error_code & PF_U) != 0;

	//printf("page fault occured %p!\n", fault_page);
	if (!not_present) {
		//printf("present\n");
	} else {
		//printf("not present\n");
	}
	if (write) {
		//printf("access to write\n");
	} else {
		//printf("access to read\n");
	}
	if (user) {
		//printf("accessing user page\n");
	} else {
		//printf("accessing kernel page\n");
	}
	//ADDED

	if (fault_addr == NULL) {
		//printf("page fault! 0 exit null\n");
		exit(-1);
	}

	if (is_kernel_vaddr(fault_addr)) {
		//printf("page fault! 0 exit kernel\n");
		exit(-1);
	} // if trying to access kernel memory

	if (not_present) {
		//printf("page fault!\n");
		bool syslock = false;
		if (lock_held_by_current_thread(&filesys_lock)) {
			lock_release(&filesys_lock);
			syslock = true;
		}
		struct suppl_page *lpage = (struct suppl_page*) malloc(
				sizeof(struct suppl_page));
		lpage->upage = fault_page;
//
		struct hash_iterator i;

		hash_first(&i, &thread_current()->page_table);
		//printf("fault at address%p\n",fault_addr);
		while (hash_next(&i)) {
			struct suppl_page *f = hash_entry(hash_cur(&i), struct suppl_page,
					hash_elem);
			 //printf("%p, ",f->upage);
			if (f->frame_sourcefile != NULL) {
				//printf("is file page\n");
				//printf("%d, %d",f->frame_sourcefile->content_length,f->frame_sourcefile->file_offset);

			}
			//printf("\n");
		}
		//
		struct hash_elem *elem = hash_find(&thread_current()->page_table,
				&lpage->hash_elem);
		free(lpage);
		if (elem == NULL) {
			if (is_stack_access(fault_addr, f->esp)) { //user)) { // is accessing stack
				//printf("frame get 4\n");
				void *kpage = frame_get(PAL_USER, fault_page, true);
				pagedir_set_page(thread_current()->pagedir, fault_page, kpage,
						true);
				return;
			} else {
				//printf("page fault! not in s.p.t not stack access\n");
				exit(-1);
			}
		}
		// in supplemental page table
		struct suppl_page *spage = hash_entry(elem, struct suppl_page,
				hash_elem);
		if (!spage->writable && write) { // trying to write to read only page
			//printf("page fault! 0 page read only\n");
			exit(-1);
		}
		if (syslock)
			lock_acquire(&filesys_lock); //acquire syslock before fix

		bool writable = true;
		bool dirty = false;
		uint8_t *kpage = NULL;
		//printf("frame get 3\n");
		kpage = frame_get(fault_page, true, spage->writable); //get a frame in memory
		//printf("=====kpage: %p\n", kpage);
		if (spage->frame_sourcefile != NULL) { // is exec or file
			//printf("exec or fil\n");
			file_seek(spage->frame_sourcefile->filename,
					spage->frame_sourcefile->file_offset);
			int a;
			void * br = malloc(PGSIZE);

			if ((a = file_read(spage->frame_sourcefile->filename, br,
					spage->frame_sourcefile->content_length)) //read page from file into memory
			!= (int) spage->frame_sourcefile->content_length) {
				release_filesystem();
				lock_frames();
				frame_free(kpage);
				unlock_frames();
				free(br);
				//printf("page fault! 2 read error\n");
				exit(-1);
			}
			release_filesystem();
			frame_pin_kernel(kpage, PGSIZE);
			//printf("copying\n");
			memcpy(kpage, br, PGSIZE);
			frame_unpin_kernel(kpage, PGSIZE);
			free(br);

			memset(kpage + spage->frame_sourcefile->content_length, 0,
			PGSIZE - spage->frame_sourcefile->content_length); // set zeros
			if (spage->frame_sourcefile->writable) {
				//printf("dealling writable 2\n");
			} else {
				//printf("dealling not writable2 \n");
			}
			//printf("=====a==hgegewe========\n");
			frame_find_user(fault_page)->frame_sourcefile = spage->frame_sourcefile;

			//printf("=====a===fwf=======\n");
			writable = spage->frame_sourcefile->writable;
			//printf("=====a==========\n");
		} else if (spage->swap_slot != NULL) { // page in swap slot
			// load data from swap slot to memory
			frame_pin_kernel(kpage, PGSIZE);
			swap_load(kpage, spage->swap_slot);
			frame_unpin_kernel(kpage, PGSIZE);
			dirty = true;
		} else if (spage->zeropage != NULL) {
			memset(kpage, 0, PGSIZE);
		}
		//printf("=======bbb========\n");
		sema_down(&t->sema_pagedir);
		pagedir_clear_page(t->pagedir, fault_page);
		if (!pagedir_set_page(t->pagedir, fault_page, kpage, writable)) { // register page to the process's address space.
			sema_up(&t->sema_pagedir);
			lock_frames();
			frame_free(kpage);
			unlock_frames();
			//printf("page fault! 4 set page error\n");
			exit(-1);
		}
		pagedir_set_dirty(t->pagedir, fault_page, dirty);
		pagedir_set_accessed(t->pagedir, fault_page, true);
		sema_up(&t->sema_pagedir);
		//printf("=======b========\n");
	} else {
		//printf("not not present exit -1\n");
		if (write) {
			//printf("access to write\n");
		} else {
			//printf("access to read\n");
		}
		exit(-1);
	}

}

bool is_reserved(const void *p) {
	return false;
	//return (void *) 0xbfffef00 < p && p < (void *) 0xbfffefff;
	/*The code segment in Pintos starts at user virtual address 0x08084000, approximately 128
	 MB from the bottom of the address space. This value is specied in [SysV-i386] and has no
	 deep signicance.*/
}
