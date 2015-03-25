#include "./syscall.h"
#include "../threads/interrupt.h"
#include "../threads/vaddr.h"
#include "../lib/debug.h"
#include "../threads/thread.h"
#include "../threads/palloc.h"
#include "../devices/shutdown.h"
#include "../lib/stdio.h"
#include "../lib/syscall-nr.h"
#include "../lib/kernel/list.h"
#include "process.h"
#include "pagedir.h"
#include "../filesys/filesys.h"
#include "../devices/input.h"
#include "../filesys/file.h"
#include "../lib/kernel/stdio.h"
#include "threads/pte.h"

void lock_filesystem(void) {
	if (!lock_held_by_current_thread(&filesys_lock))
		lock_acquire(&filesys_lock);
}

void release_filesystem(void) {
	if (lock_held_by_current_thread(&filesys_lock))
		lock_release(&filesys_lock);
}

void dealling(void *fault_addr, struct intr_frame * f) {
	//printf("delll2 access\n");
	void * fault_page = (void *) (PTE_ADDR & (uint32_t) fault_addr);
	bool syslock = false;
	if (lock_held_by_current_thread(&filesys_lock)) {
		lock_release(&filesys_lock);
		syslock = true;
	}

	struct suppl_page *lpage = (struct suppl_page*) malloc(
			sizeof(struct suppl_page));
	lpage->upage = fault_page;
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

		}
	}
	// in supplemental page table
	struct suppl_page *spage = hash_entry(elem, struct suppl_page, hash_elem);
	if (!spage->writable) { // trying to write to read only page
		//printf("page fault! 0 page read only\n");
		//exit(-1);
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
	sema_down(&thread_current()->sema_pagedir);
	pagedir_clear_page(thread_current()->pagedir, fault_page);
	if (!pagedir_set_page(thread_current()->pagedir, fault_page, kpage,
			writable)) { // register page to the process's address space.
		sema_up(&thread_current()->sema_pagedir);
		lock_frames();
		frame_free(kpage);
		unlock_frames();
	//	printf("page fault! 4 set page error\n");
		exit(-1);
	}
	pagedir_set_dirty(thread_current()->pagedir, fault_page, dirty);
	pagedir_set_accessed(thread_current()->pagedir, fault_page, true);
	sema_up(&thread_current()->sema_pagedir);
	//printf("dealling access\n");
}

bool memory_writable(const void *p) // Check if the page has write access. If cannot locate the page in the page table, ignore the test and return true.
{
	//printf("=======\n");
	if (is_user_vaddr(p)) {

	} else {
	//	printf("memorywritbale not user\n");
		exit(-1);
	}
	if (p == NULL) {
		//printf("memory not writable p is null\n");
		return false;
	}

	if (is_reserved(p)) {
		//printf("memory  not writable p is reserverd\n");
		return false;
	}

	void *page_addr = pg_round_down(p);
	struct suppl_page *page = (struct suppl_page *) malloc(
			sizeof(struct suppl_page));
	page->upage = page_addr;
	struct hash_elem *elem = hash_find(&thread_current()->page_table,
			&page->hash_elem);
	free(page);
	if (elem == NULL) {
		//printf("memory writable can't find page\n");
		if (frame_find_user(page_addr) != NULL) {
			if (frame_find_user(page_addr)->writable) {
				//printf("frame found, writable \n");
				return true;
			} else {
				//printf("frame found, not writable %p\n", page_addr);
				return false;
			}
		} else {
			//printf("%p \n", page_addr);
			//if (pagedir_get_page(&thread_current()->pagedir, page_addr)) {
			//	printf("canit find frame!!!!!!!!!!! \n");
			//}
			//printf("canit find frame\n");

		}
		//printf("=======\n");
		return true;
	} else {
		//printf("memory writable found page\n");

	}

	struct suppl_page *page_entry = hash_entry(elem, struct suppl_page,
			hash_elem);
	if (page_entry->writable) {
		//printf("memory writable \n");
	} else {
		//printf("memory not writable \n");
	}
	//printf("=======\n");
	return page_entry->writable;
}

typedef int pid_t;

int argu_num = 0;

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&filesys_lock);
}

void * check_accessing_user_memory_using_intrframe(struct intr_frame * f) {
	//printf("check access\n");
	if (f == NULL) {
	//	printf("check access null -1\n");
		exit(-1);
		return NULL;
	}
	if (is_user_vaddr(f->esp + argu_num)) {
		if (pagedir_get_page(thread_current()->pagedir,
				f->esp + argu_num) != NULL) {
			return pagedir_get_page(thread_current()->pagedir,
					f->esp + argu_num);
		} else {
		//	printf("check access null\n");
			exit(-1);
			return NULL;
		}
	} else {
		//printf("check access null2\n");
		exit(-1);
		return NULL;
	}
}

void * check_return_kpage(void *esp, struct intr_frame * f) {
	//printf("check return page at %p\n", esp);
	//hex_dump(esp, esp, 300, 1);
	if (is_user_vaddr(esp)) {
		if (pagedir_get_page(thread_current()->pagedir, esp) != NULL) {
			return pagedir_get_page(thread_current()->pagedir, esp);
		} else {

			dealling(esp, f);
			if (pagedir_get_page(thread_current()->pagedir, esp) != NULL) {
				//	printf("check return dealling good \n");
				return pagedir_get_page(thread_current()->pagedir, esp);
			} else {
				//	printf("check return dealling not good \n");
			}
			//printf("esp : %p \n", esp);
			//printf("f->esp : %p \n", f->esp);
			if (is_stack_access(esp, f->esp)) { // stack growth
				void *kpage = frame_get(PAL_USER, pg_round_down(esp), true);
				pagedir_set_page(thread_current()->pagedir, pg_round_down(esp),
						kpage,
						true);
				return kpage + (esp - pg_round_down(esp));
			} else {
				dealling(esp, f);
				if (is_stack_access(esp, f->esp)) { // stack growth
					void *kpage = frame_get(PAL_USER, pg_round_down(esp), true);
					pagedir_set_page(thread_current()->pagedir,
							pg_round_down(esp), kpage,
							true);
					return kpage + (esp - pg_round_down(esp));
				} else {
					//printf("check return page at 1\n");
					return NULL;
				}
			}

		}

	} else {
		//printf("check return page at 2\n");
		return NULL;
	}
}

bool check(void *esp, struct intr_frame * f) {
//printf("check memory at %p\n", esp);
//hex_dump(esp, esp, 300, 1);
	if (is_user_vaddr(esp)) {
		if (pagedir_get_page(thread_current()->pagedir, esp) != NULL) {
			return false;
		} else {
			dealling(esp, f);
			if (pagedir_get_page(thread_current()->pagedir, esp) != NULL) {
				//printf("check dealling good \n");
				return false;
			} else {
				//	printf("check dealling not good \n");
			}
			//printf("esp : %p \n", esp);
			//printf("f->esp : %p \n", f->esp);
			if (is_stack_access(esp, f->esp)) { // stack growth
				void *kpage = frame_get(PAL_USER, pg_round_down(esp), true);
				pagedir_set_page(thread_current()->pagedir, pg_round_down(esp),
						kpage,
						true);
				return true;
			} else {
				dealling(esp, f);
				if (is_stack_access(esp, f->esp)) { // stack growth
					void *kpage = frame_get(PAL_USER, pg_round_down(esp), true);
					pagedir_set_page(thread_current()->pagedir,
							pg_round_down(esp), kpage,
							true);
					return true;
				} else {
					//	printf("check return page at 1\n");
					return false;
				}
			}

		}
	} else {
		return false;
	}
}

void * check_accessing_user_memory(void *esp, struct intr_frame * f) {
//	printf("check memory at %p\n", esp);
	//hex_dump(esp, esp, 300, 1);
	if (is_user_vaddr(esp)) {
		if (pagedir_get_page(thread_current()->pagedir, esp) != NULL) {
			//	printf("checka cc ess ok\n");
			return pagedir_get_page(thread_current()->pagedir, esp);
		} else {
			//	printf("exit access 1\n");
			exit(-1);
			return NULL;
		}
	} else {
		//printf("exit access 2\n");
		exit(-1);
		return NULL;
	}
}

int num_page_needed(int length) {
	int numPage = length / PGSIZE; // number of pages needed to read
	if (length % PGSIZE > 0) {
		numPage++;
	}
	return numPage;
}

void* get_argument(struct intr_frame *f) {
// check memory
	void *r = check_accessing_user_memory_using_intrframe(f);
	argu_num += sizeof(int);
	return r;
}

static void syscall_handler(struct intr_frame *f UNUSED) {
//printf("%s", "Called -----------------Sys handler \n");
	argu_num = 0;
	uint32_t syscall_id = *(int*) get_argument(f);
//printf("Sys call ID is %d \n", syscall_id);
//hex_dump(f->esp - 50, f->esp - 50, 300, 1);
	switch (syscall_id) {
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		f->eax = exit(*((int *) get_argument(f)));
		//printf("exit returned\n");
		break;
	case SYS_EXEC: {
		char * real_buffer = (char *) check_accessing_user_memory(
				*(void **) get_argument(f), f);
		f->eax = exec(real_buffer);
	}
		break;
	case SYS_WAIT:
		f->eax = wait(*(pid_t *) get_argument(f));
		//printf("wait returned\n");
		break;
	case SYS_CREATE: {
		//printf("creat called\n");
		void * fn = *(void **) get_argument(f);
		//printf("create fn %p\n", fn);
		if (fn == NULL) {
			//printf("create null\n");
			exit(-1);
		}
		char * real_file = (char *) check_accessing_user_memory(fn, f);
		unsigned size = *((unsigned *) get_argument(f));
		//printf("creating\n");
		f->eax = creat_file(real_file, size);
	}
		break;
	case SYS_REMOVE: {
		char * real_file = (char *) check_accessing_user_memory(
				*(void **) get_argument(f), f);
		f->eax = remove(real_file);
	}
		break;
	case SYS_OPEN: {
		//printf("open called \n");
		void *fn = *(void **) get_argument(f);
		//printf("open get argu  with %p\n", fn);
		f->eax = open(fn, f);
		//printf("open return with %d\n", f->eax);
	}
		break;
	case SYS_FILESIZE:
		f->eax = filesize(*((int *) get_argument(f)));
		break;
	case SYS_READ: {
			//printf("read called \n");
		int fd = *(int *) get_argument(f);
		//printf("fd: %d\n", fd);
		void *fn = *(void **) get_argument(f);
		//printf("fn: %p\n", fn);
		if (!memory_writable(fn)) {
		//	printf("check access 100\n");
			exit(-1);
		}
		unsigned size = *(unsigned *) get_argument(f);
			//printf("size: %d, read page needed : %d \n", size,
			//	num_page_needed(size));
		f->eax = read(fd, fn, size, f);
		//printf("size read: %d\n", f->eax);
		//printf("read return \n");
	}
		break;
	case SYS_WRITE: {
		//printf("write called \n");
		int fd = *(int *) get_argument(f);
		//printf("write called 0\n");
		void *fn = get_argument(f);
		//printf("write called 1\n");
		//printf("fd %d fn %s \n",fd, fn);
		//printf(" fn get argument: %p \n", fn);
		fn = *(void **) fn;
		//printf(" fn real user address %p , esp: %p\n", fn, f->esp);
		if (is_stack_access(fn, f->esp)) {
			//printf(" is stack access \n");
		} else {
			//printf(" is not stack access \n");
		}
		unsigned size = *(unsigned *) get_argument(f);
		//printf("size: %d, write page needed : %d \n", size,
		//	num_page_needed(size));
		//printf("write called 2\n");
		//memory_is_good(fn + size);
		//printf("write called 3===\n");
		char * real_buffer = (char *) check_accessing_user_memory(fn, f);
		//printf("write called 32===\n");
		//printf("fd %d rb %s s %d\n",fd, real_buffer, size);
		f->eax = write(fd, fn, real_buffer, size);
		//printf(" write return: %d \n", f->eax);
	}
		break;
	case SYS_SEEK: {
		int h = *(int *) get_argument(f);
		unsigned off = *(unsigned *) get_argument(f);
		seek(h, off);
	}
		break;
	case SYS_TELL:
		f->eax = tell(*((int *) get_argument(f)));
		break;
	case SYS_CLOSE:
		close(*(int *) get_argument(f));
		break;
	case SYS_MMAP: {
		//printf("mmap calledd\n");
		int mmap_fd = *(int *) get_argument(f);
		char * realaddr = (char *) check_accessing_user_memory(
				*(void **) get_argument(f), f);
		if (realaddr == NULL) {
			//printf("mmap nul!!!!!!!1\n");
		}
		f->eax = mmap(mmap_fd, realaddr);
		//printf("mmap returnedd\n");
	}
		break;
	case SYS_MUNMAP: {
		int mmap_fd2 = *(int *) get_argument(f);
		munmap(mmap_fd2);
	}
		break;
	default:
		printf("NOT REACCHED %i\n", syscall_id);
		NOT_REACHED ()
		;
	}

//printf("system call!\n");
//thread_exit();
}

void halt() {
	shutdown_power_off();
}

int exit(int status) {
	thread_current()->exit_status = status;
// unmap before close
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
	return status;

}

pid_t exec(const char *cmd_line) {
	lock_filesystem();
	tid_t id = process_execute(cmd_line);
	release_filesystem();
	return id;
}

int wait(pid_t pid) {
	if (pid <= 0) {
		return -1;
	}
	int r = process_wait(pid);
	return r;
}

int creat_file(void *file, unsigned initial_size) {
	lock_filesystem();
	int filesys_cr = filesys_create(file, initial_size) ? 1 : 0;
	release_filesystem();
	return filesys_cr;
}

int remove(void *file) {
	lock_filesystem();
	int rem = filesys_remove(file);
	release_filesystem();
	return rem;
}

int open(void *file2, struct intr_frame *f) { // pass in user memory address
//printf("open method called\n");
	char * file = (char *) check_accessing_user_memory(file2, f);
//printf("first kernel addr got %p \n",file);
	void * realfile = malloc(PGSIZE);
	void * pageaddr = pg_round_down(file2);
	long leftsize = file2 - pageaddr;
//printf(" left size: %d \n",leftsize);
	memcpy(realfile, file, leftsize);
//printf(" getting second \n");
	if (is_user_vaddr(pageaddr + PGSIZE)) {
		if (pagedir_get_page(thread_current()->pagedir,
				pageaddr + PGSIZE) != NULL) {
			file = (char *) check_accessing_user_memory(pageaddr + PGSIZE, f);
			//printf(" second file %s\n",file);
			//printf(" pgsize - left size: %d \n",PGSIZE-leftsize);
			memcpy(realfile + PGSIZE - leftsize, file, PGSIZE - leftsize);
			//printf(" raal file \n");
		}
	}

//hex_dump(realfile, realfile, 300, 1);

	/*bool checkvar = true;
	 int i = 0;
	 while (checkvar) {
	 checkvar = check(up, f);
	 up+=PGSIZE;
	 i++;
	 printf("cehck %d \n",i);
	 }*/

	lock_filesystem();
//printf("opening file at %p\n", realfile);
	struct file* newfile = filesys_open(realfile);
	free(realfile);
	release_filesystem();
	if (newfile == NULL) {
		return -1;
	}
	int ret = add_file_to_thread(newfile);
	return ret;
}

int filesize(int fd) {
	struct thread *t = thread_current();
	struct file *f = get_file_from_fd(fd);
	if (f == NULL)
		//printf("file size null access\n");
		exit(-1);
	return file_length(f);
}

int read(int fd, void *fn, unsigned size, struct intr_frame *f) {
	//printf("read method called, size: %d \n", size);
	char * buffer;
	if (is_user_vaddr(fn)) {
		if (pagedir_get_page(thread_current()->pagedir, fn) != NULL) {
			//printf("read check checka cc ess ok\n");
			buffer = pagedir_get_page(thread_current()->pagedir, fn);
		} else {
			dealling(fn, f);
			if (pagedir_get_page(thread_current()->pagedir, fn) != NULL) {
				//printf("read check checka cc ess ok\n");
				buffer = pagedir_get_page(thread_current()->pagedir, fn);
			} else {
				//printf("fn : %p \n", fn);
				//	printf("f->esp : %p \n", f->esp);
				if (is_stack_access(fn, f->esp)) { // stack growth
					//printf("is stack    %d\n",f->esp-fn);
					void *kpage = frame_get(PAL_USER, pg_round_down(fn), true);
					pagedir_set_page(thread_current()->pagedir,
							pg_round_down(fn), kpage,
							true);
					buffer = kpage + (fn - pg_round_down(fn));
				} else {
					//printf("is not  stack  \n");
					exit(-1);
				}
			}

		}
	} else {
		//printf("read exit access 2\n");
		exit(-1);
	}

	void *up = fn + PGSIZE;
	//printf("buffer: %p\n", buffer);
	bool checkvar = true;
	int i = 0;
	while (checkvar) {
		checkvar = check(up, f);
		up += PGSIZE;
		i++;
		//	printf("cehck %d, up: %p \n", i, up);
	}
	struct thread * t = thread_current();
	if (fd == STDOUT_FILENO) {
			//printf("read exit -1\n");
		exit(-1);
		return -1;
		//ERROR, try to read from std out
	} else if (fd == STDIN_FILENO) { // read from key board
		//printf("read e===2\n");
		int siz = 0;
		lock_filesystem();
		//frame_pin(buffer, size); //pin frame while read
		for (siz = 0; siz < size; siz++) {
			*(uint8_t*) (buffer + size) = input_getc();
		}
		//frame_unpin(buffer, size); // unpin
		release_filesystem();
		return size;
	} else {
		//printf("read e34343===\n");
		lock_filesystem();
		if (list_empty(&t->file_fd_list)) {
		//		printf("read exit 0\n");
			release_filesystem();
			exit(-1);
			return -1;
		}
		//	printf("read e===\n");
		struct file* f = get_file_from_fd(fd);
		if (f != NULL) {
			int size_read = 0;
			if (PGSIZE - ((int) buffer - (int) pg_round_down(buffer)) < size) {
				//printf("reading  not directly------------\n");
				int sizeleft = size;
				void * currentAddr = fn;
				while (sizeleft > 0) {
					size_t readLength =
					PGSIZE
							- ((int) currentAddr
									- (int) pg_round_down(currentAddr));
					if (readLength > sizeleft) {
						readLength = sizeleft;
					}
					//	printf("reading diff pages === read legnth: %d\n",
					//		readLength);
					void * kpage = check_return_kpage(currentAddr, f);
					//frame_pin(kage, readLength);
					//	printf("kpage: %p \n", kpage);
					//	printf("read file offsetl %d \n", size - sizeleft);
					size_read += (int) file_read_at(f, kpage, readLength,
							size - sizeleft);
					//frame_unpin(kpage, readLength);
					currentAddr += readLength;
					sizeleft -= readLength;
				}
				//	printf("\n read buffer  ==%p===  %s\n",
				//	pagedir_get_page(thread_current()->pagedir, fn),
				//		check_return_kpage(fn, f));
				//	printf("\n read buffer  =====  %s\n",
				//		check_return_kpage(pg_round_down(fn) + PGSIZE, f));
				//printf("\n read buffer end ===== \n");
			} else {
				//frame_pin(buffer, size); // pin frame while read#
				//	printf("reading  directly-----  -----buffer %p:--\n", buffer);
				size_read = (int) file_read(f, buffer, size);
				//	printf("\n read buffer  ==%p===  %s\n",
				//			pagedir_get_page(thread_current()->pagedir, fn),
				//			check_return_kpage(fn, f));
				//	printf("\n read buffer  =====  %s\n",
				//	check_return_kpage(pg_round_down(fn) + PGSIZE, f));
				//	printf("\n read buffer end ===== \n");
				////frame_pin(buffer, size);; // un pin
			}
			if (size_read == size) {
				release_filesystem();
				return size_read;
			} else if (size_read == file_length(f) && size_read != size) {
				release_filesystem();
				return 0;
			} else {
			//	printf("read exit 1\n");
				release_filesystem();
				exit(-1);
				return -1;
			}
		} else {
				//printf("read exit 2\n");
			release_filesystem();
			exit(-1);
			return -1;
		}
	}
	//printf("read e===========\n");
}

int write(int fd, void* fn, const void *buffer, unsigned size) {
//printf("write method222, buffer: %p , size : %d \n", buffer, size);
	struct thread * t = thread_current();
	if (fd == STDIN_FILENO) {
		exit(-1);
		return -1;
	} else if (fd == STDOUT_FILENO) { // to console
		lock_filesystem();
		int written = 0;
		//frame_pin(buffer, size); // pin frame when writing
		if (size < 200) {
			putbuf(buffer, size);
			written = size;
		} else {
			while (size > 200) {
				putbuf((buffer + written), 200);
				size -= 200;
				written += 200;
			}
			putbuf((buffer + written), size);
			written += size;
		}
		//frame_unpin(buffer, size); // un pin
		release_filesystem();
		return written;
	} else {
		if (list_empty(&t->file_fd_list)) {
		//	printf("list empty access\n");
			exit(-1);
			return -1;
		}
		struct file* f = get_file_from_fd(fd);
		if (f != NULL) {
			if (PGSIZE - ((int) buffer - (int) pg_round_down(buffer)) < size) {
				int d1 = (int) buffer - (int) pg_round_down(buffer);
				int d = PGSIZE - ((int) buffer - (int) pg_round_down(buffer));
				//printf("writing dealling === %d, %d \n", d1, d);

				//printf("write buffer: \n %s", check_return_kpage(fn, f));
				//printf("write buffer: \n %s",
				//check_return_kpage(pg_round_down(fn) + PGSIZE, f));

				int size_wrote = 0;
				int sizeleft = size;
				void * currentAddr = fn;
				lock_filesystem();
				while (sizeleft > 0) {
					size_t readLength =
					PGSIZE
							- ((int) currentAddr
									- (int) pg_round_down(currentAddr));
					if (readLength > sizeleft) {
						readLength = sizeleft;
					}
					//printf("writing diff pages ===\n");
					void * kpage = check_return_kpage(currentAddr, f);
					//frame_pin(kage, readLength);
					size_wrote += (int) file_write_at(f, kpage, readLength,
							size - sizeleft);
					//frame_unpin(kpage, readLength);
					currentAddr += readLength;
					sizeleft -= readLength;
				}
				//printf("\nwrite buffer end ===== \n");
				release_filesystem();
				return size_wrote;
			} else {
				//printf("writing not dealling ===\n");
				lock_filesystem();
				//frame_pin(buffer, size); // pin frame when writing
				//	printf("\nwrite buffer: \n %s", check_return_kpage(fn, f));
				//printf("\nwrite buffer: \n %s",
				//	check_return_kpage(pg_round_down(fn) + PGSIZE, f);
				int size_wrote = file_write(f, buffer, size);
				//printf("\nwrite buffer end ===== \n");
				//frame_unpin(buffer, size); // un pin
				release_filesystem();
				return size_wrote;
			}

		} else {
		//	printf("wtirrrrrrr access\n");
			exit(-1);
			return -1;
		}
	}
}

void seek(int fd, unsigned position) {
	struct thread * t = thread_current();
	struct file * f = get_file_from_fd(fd);
	if (f == NULL) {
	//	printf("seek access\n");
		exit(-1);
	}
	lock_filesystem();
	file_seek(f, position);
	release_filesystem();
}

int tell(int fd) {
	struct file * f = get_file_from_fd(fd);
	if (f == NULL)
		//printf("tell check access\n");
		exit(-1); // not getting file
	lock_filesystem();
	off_t position = file_tell(f);
	release_filesystem();
	return position;
}

void close(int fd) {
	if (list_empty(&thread_current()->file_fd_list)) {
		exit(-1); // no file to close
	}
	struct file *f = get_file_from_fd(fd);
	if (f == NULL) {
		exit(-1); // not getting file
	} else {
		lock_filesystem();
		file_close(f);      //Close file in the system
		delete_file_from_thread(fd); // delete file in file list
		release_filesystem();
	}

}

// mapid_t mmap (int fd, void *addr)
int mmap(int fd, void *uaddr) { // maps a file with the fd to memory address uaddr
//printf("enter mmap %d\n", fd);
	struct thread * current = thread_current();
	if (fd == 0 || fd == 1) { // check fd
		return -1;
	}
	struct file * f = get_file_from_fd(fd); // get file handle from fd
	if (f == NULL)
		exit(-1);

//printf("mmap file length\n");
//printf("mmap %d\n",fh->fd);
	int fillen = file_length(f); // get file length
//printf("mmap file length 2\n");
	if (fillen == 0 || uaddr == 0 || (int) uaddr % PGSIZE > 0) { // file length empty or address is zero or not page-aligned
		return -1;
	}

	lock_filesystem();
	int mmap_fd = thread_add_mmap_file(file_reopen(f)); //add mmap file
	release_filesystem();
//printf("mmap file length 3\n");
	struct file_fd * mmap_fh = get_filefd_from_fd_mmap(mmap_fd); // get mmap file handle
//printf("mmap file length 4\n");
	mmap_fh->userPage = uaddr;
	int numPage = fillen / PGSIZE; // number of pages needed
	if (fillen % PGSIZE > 0) {
		numPage++;
	}
//printf("mmap file length 42\n");
	int i;
	for (i = 0; i < numPage; i++) { // loop through pages needed to map
		size_t readLength = (i == numPage - 1) ? fillen % PGSIZE : PGSIZE;
		off_t offset = i * PGSIZE;
		int current_page_address = uaddr + offset;

		sema_down(&current->sema_pagedir);
		//void * currentKernelAddress =
		sema_up(&current->sema_pagedir);
		//printf("mmap file length 5\n");
		if (frame_find_kernel(current_page_address) != NULL) { // overlap with other data
			return -1;
		}
		//printf("mmap file length 51\n");
		void *kpage = frame_get(uaddr, true, true);
		//printf("mmap file length 52\n");

		if (kpage == NULL) {
			//printf("mmap file length 53\n");
			exit(-1);
		}
		struct frame *fme = frame_find_user(uaddr);
		//printf("mmap file length 54\n");
		//printf("%d\n", readLength);
		if (fme == NULL) {
			//printf("%s\n", "frame_null");
		}
		if (fme->frame_sourcefile == NULL) {
			//printf("%s\n", "file null");
		}
		fme->frame_sourcefile->content_length = readLength;
		//printf("mmap file length 562\n");
		fme->frame_sourcefile->file_offset = offset;
		//printf("mmap file length 56\n");
		fme->frame_sourcefile->filename = mmap_fh->fil;
		fme->frame_sourcefile->writable = true;
		//printf("mmap file length 57\n");
		add_supp_page(
				new_file_page(current_page_address, true, mmap_fh->fil, offset,
						readLength, true));

		//printf("mmap file length 55\n");
	}
//printf("mmap file length 6\n");
	return mmap_fd;
}

// void munmap (mapid t mapping)
void munmap(int mmap_fd) {
	struct thread * current = thread_current();
	struct file_fd * fh = get_fd_from_file(mmap_fd);
	void * file_startaddr = fh->userPage; // take user virtual page
	int32_t fil_len = file_length(fh->fil); // take file length
	int page_num = fil_len / PGSIZE; // number of pages needed to contains the file
	if (fil_len % PGSIZE > 0) {
		page_num++;
	}
	int i = 0;
	for (i = 0; i < page_num; i++) { //loop though pages
		int offset = i * PGSIZE; // offset from file start address
		void * page_addr = file_startaddr + offset; // current user page address
		sema_down(&current->sema_pagedir);
		bool dirty = pagedir_is_dirty(current->pagedir, page_addr);
		void * kpage = pagedir_get_page(current->pagedir, page_addr); // get kernel memory address
		sema_up(&current->sema_pagedir);
		if ((pg_ofs(kpage) == 0) && dirty) {
			int write_length = (i == page_num - 1) ? fil_len % PGSIZE : PGSIZE; // get write back length
			lock_filesystem();
			file_seek(fh->fil, offset);
			release_filesystem();

			lock_frames();
			//frame_pin(page_addr, PGSIZE); // pin frame
			unlock_frames();

			lock_filesystem();
			file_write(fh->fil, page_addr, write_length); // write page back to file
			release_filesystem();

			lock_frames();
			//frame_unpin(page_addr, PGSIZE); // unpin frame
			unlock_frames();
		}
		struct suppl_page *p = (struct suppl_page *) malloc(
				sizeof(struct suppl_page));
		p->upage = page_addr;
		hash_delete(&current->page_table,
				hash_find(&current->page_table, &p->hash_elem));
		free(p);
		sema_down(&current->sema_pagedir);
		pagedir_clear_page(current->pagedir, page_addr);
		sema_up(&current->sema_pagedir);
	}
	list_remove(&fh->file_fd_list_elem);
	file_close(fh->fil);
	free(fh);
}
