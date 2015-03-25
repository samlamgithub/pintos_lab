#include "vm/frame.h"
#include <stdio.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

static struct hash frames;
static struct lock frames_lock;

void lock_frames(void);
void unlock_frames(void);
bool frame_less(const struct hash_elem *, const struct hash_elem *, void *);
unsigned frame_hash(const struct hash_elem *, void *);
void frame_evit(struct frame *);
void frame_set_pin(void *, bool);
int get_class(uint32_t *, const void *);

void lock_frames() {
	lock_acquire(&frames_lock);
}

void unlock_frames() {
	lock_release(&frames_lock);
}

void frame_init() {
	hash_init(&frames, frame_hash, frame_less, NULL);
	lock_init(&frames_lock);
}

void * frame_get(void * upage, bool zero, bool writable) { // Allocates a new page, and adds it to the frame table
	void * kpage = palloc_get_page(PAL_USER | (zero ? PAL_ZERO : 0)); //try to get a new page(frame) in user pool
   // printf("get frame %p, %d \n",upage,writable);
	if (kpage == NULL) { // if not enough memory, evict a frame
		lock_frames();
		evict();
		kpage = palloc_get_page(PAL_USER | (zero ? PAL_ZERO : 0));
		unlock_frames();
	}

	if (kpage != NULL) { // now the frame should be ready
		struct frame * frame = (struct frame*) malloc(sizeof(struct frame));
		frame->addr = kpage;
		frame->upage = upage;
		frame->thread = thread_current();
		frame->pinned = false;
		frame->frame_sourcefile = (struct file_info *)malloc(sizeof(struct file_info));
		frame->writable = writable;
		lock_frames();
		hash_insert(&frames, &frame->hash_elem);
		unlock_frames();
	}

	return kpage;
}

bool frame_free(void * addr) { // free a frame, and the resource it consumed
	struct frame * frame;
	struct hash_elem * found_frame;
	struct frame frame_elem;
	frame_elem.addr = addr;

	found_frame = hash_find(&frames, &frame_elem.hash_elem);
	if (found_frame != NULL) {
		frame = hash_entry(found_frame, struct frame, hash_elem);
		palloc_free_page(frame->addr); // release physical memory
		hash_delete(&frames, &frame->hash_elem); // remove record in frame table
		if (frame->frame_sourcefile != NULL) {
			free(frame->frame_sourcefile);
		}
		free(frame); // free structure
		return true;
	} else {
		return false; // not found, return NULL
	}
}

void frame_set_pin(void * kpage, bool pinornot) { // set pin value of a frame
	struct frame * frame = frame_find_kernel(kpage);
	if (frame != NULL) {
		frame->pinned = pinornot;
	}
}

void frame_pin(void * vaddr, int len) { // pin frames start at user virtual memory address vaddr, and len as length
	if (!is_user_vaddr(vaddr)) {
		return;
	}
	struct thread * t = thread_current();
	int i;
	int pagecnt = len / PGSIZE;
	if (len % PGSIZE)
		pagecnt++;
	for (i = 0; i < pagecnt; i++) {
		sema_down(&t->sema_pagedir);
		void * kpage = pagedir_get_page(t->pagedir,
				pg_round_down(vaddr) + i * PGSIZE);
		sema_up(&t->sema_pagedir);
		if (kpage == 0 || pg_ofs(kpage) != 0)
			return;
		frame_set_pin(kpage, true);
	}
}

void frame_unpin(void * vaddr, int len) { // unpin frames start at user virtual memory address vaddr, and len as length
	if (!is_user_vaddr(vaddr)) {
		return;
	}
	struct thread * t = thread_current();
	int i;
	int pagecnt = len / PGSIZE;
	if (len % PGSIZE)
		pagecnt++;
	for (i = 0; i < pagecnt; i++) {
		sema_down(&t->sema_pagedir);
		void * kpage = pagedir_get_page(t->pagedir,
				pg_round_down(vaddr) + i * PGSIZE);
		sema_up(&t->sema_pagedir);
		if (kpage == 0 || pg_ofs(kpage) != 0)
			return;
		frame_set_pin(kpage, false);
	}
}

void frame_pin_kernel(void * kpage, int len) { //pin frames start at user physical memory address vaddr, and len as length
	int i;
	int pagecnt = len / PGSIZE;
	if (len % PGSIZE)
		pagecnt++;
	for (i = 0; i < pagecnt; i++) {
		if (kpage == 0 || pg_ofs(kpage) != 0)
			return;
		frame_set_pin(kpage, true);
	}
}

void frame_unpin_kernel(void * kpage, int len) { // unpin frames start at user physical memory address vaddr, and len as length
	int i;
	int pagecnt = len / PGSIZE;
	if (len % PGSIZE)
		pagecnt++;
	for (i = 0; i < pagecnt; i++) {
		if (kpage == 0 || pg_ofs(kpage) != 0)
			return;
		frame_set_pin(kpage, false);
	}
}

struct frame* frame_find_user(void * uaddr) { // find the frame maps to this user address, return NULL if not found
	struct frame * frame;
	struct hash_elem * found_frame;
	struct frame frame_elem;
	frame_elem.upage = uaddr;

	found_frame = hash_find(&frames, &frame_elem.hash_elem);
	if (found_frame != NULL) {
		frame = hash_entry(found_frame, struct frame, hash_elem);
		return frame;
	} else {
		return NULL;
	}
}

struct frame* frame_find_kernel(void * paddr) { // find the frame maps to this physical address, return NULL if not found
	struct frame * frame;
	struct hash_elem * found_frame;
	struct frame frame_elem;
	frame_elem.addr = paddr;

	found_frame = hash_find(&frames, &frame_elem.hash_elem);
	if (found_frame != NULL) {
		frame = hash_entry(found_frame, struct frame, hash_elem);
		return frame;
	} else {
		return NULL;
	}
}

bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_, // less compare function used in hase table
		void *aux UNUSED) {
	const struct frame * a = hash_entry(a_, struct frame, hash_elem);
	const struct frame * b = hash_entry(b_, struct frame, hash_elem);
	return a->upage < b->upage;
}

unsigned frame_hash(const struct hash_elem *fe, void *aux UNUSED) { // hash function used in hase table
	const struct frame * frame = hash_entry(fe, struct frame, hash_elem);
	return hash_int((unsigned) frame->upage);
}

int get_class(uint32_t * pd, const void * upage) { // find the status of a user page
	void * kpage = pagedir_get_page(pd, upage);
	if (kpage == NULL) // can't find kernel page
		return -1;
	bool dirty = pagedir_is_dirty(pd, upage);
	bool accessed = pagedir_is_accessed(pd, upage);
	return (accessed) ? ((dirty) ? 4 : 2) : ((dirty) ? 3 : 1);
	// not accessed not dirty: 1
	// accessed not dirty: 2
	// not accessed and dirty: 3
	// accessed and dirty: 4
}

void frame_evit(struct frame * frame) { // really evict a frame
	bool dirty = pagedir_is_dirty(frame->thread->pagedir, frame->upage); //see if page is modified

	if (dirty) {
		if (frame->frame_sourcefile != NULL) {
			// dirty and is memory mapped files
			lock_filesystem();
			frame_pin(frame->upage, PGSIZE);
			file_write_at(frame->frame_sourcefile->filename, frame->addr,
			PGSIZE, frame->frame_sourcefile->file_offset);
			// write file back to hard drive
			frame_unpin(frame->upage, PGSIZE);
			release_filesystem();

			add_supp_page(
					new_file_page(frame->upage, frame->writable,
							frame->frame_sourcefile->filename,
							frame->frame_sourcefile->file_offset,
							frame->frame_sourcefile->content_length,
							frame->writable));
			// add info of frame in supp page table
		} else {
			// dirty, should swap to swap slot
			struct swap_slot * swap = swap_slot_construct(frame);

			frame_pin(frame->upage, PGSIZE);
			swap_store(swap);
			frame_unpin(frame->upage, PGSIZE);

			add_supp_page(
					new_swap_page(frame->upage, frame->writable,
							swap->swap_frame, swap->swap_addr));
			// add info of frame in supp page table
		}
	} else {
		if (frame->frame_sourcefile != NULL) { // if this frame is a file
			add_supp_page(
					new_file_page(frame->upage, frame->writable,
							frame->frame_sourcefile->filename,
							frame->frame_sourcefile->file_offset,
							frame->frame_sourcefile->content_length,
							frame->writable));
			// add info of frame in supp page table
		} else {
			add_supp_page(new_zero_page(frame->upage, frame->writable));
		}
	}
	sema_down(&frame->thread->sema_pagedir);
	pagedir_clear_page(frame->thread->pagedir, frame->upage);
	sema_up(&frame->thread->sema_pagedir);

}

void evict() { // choose a frame to evict
	struct hash_iterator it;
	void * kpage = NULL;
	struct frame *f = NULL;
	int i;

	// Second chance page replacement
	for (i = 0; i < 2 && kpage == NULL; i++) {
		hash_first(&it, &frames);

		// Look for an element in the lowest class
		while (kpage == NULL && hash_next(&it)) {
			f = hash_entry(hash_cur(&it), struct frame, hash_elem);
			if (f->pinned)
				continue;
			sema_down(&f->thread->sema_pagedir);
			int class = get_class(f->thread->pagedir, f->upage);
			sema_up(&f->thread->sema_pagedir);
			if (class == 1) {
				frame_evit(f);
				kpage = f->addr;
			}
		}

		hash_first(&it, &frames);

		// if not class that is 1, look for an element in the higher class, at the same time lowering classes of passed elements
		while (kpage == NULL && hash_next(&it)) {
			f = hash_entry(hash_cur(&it), struct frame, hash_elem);
			if (f->pinned)
				continue;
			sema_down(&f->thread->sema_pagedir);
			int class = get_class(f->thread->pagedir, f->upage);
			sema_up(&f->thread->sema_pagedir);
			if (class == 3) {
				frame_evit(f);
				kpage = f->addr;
			} else if (class > 0) {
				pagedir_set_accessed(f->thread->pagedir, f->upage, false);
			}
		}
	}

	palloc_free_page(f->addr); // Free physical memory
	hash_delete(&frames, &f->hash_elem); // Free entry in the frame table
	free(f); // Delete the structure *
}

