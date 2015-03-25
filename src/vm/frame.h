#ifndef __VM_FRAME_H
#define __VM_FRAME_H

#include <hash.h>
#include "page.h"
#include "swap.h"

struct frame {
	void *addr;					// page's physical memory address
	void *upage;				// page's user virtual memory address
	struct thread *thread;		// owner thread of page
	bool pinned;				// whether page is pinned, if then can't be evict
	struct file_info *frame_sourcefile; //if frame is memory mapped file, information stored
    bool writable;
	struct hash_elem hash_elem; // hash elem used in hash table
};

struct file_info {
	struct file *filename;
	int file_offset;
	int content_length;
	bool writable;
};

void frame_init (void);
void evict (void);
struct frame *frame_find_user (void *);
struct frame *frame_find_kernel (void *);
void * frame_get(void * upage, bool zero, bool writable);
bool frame_free (void *);


void frame_pin (void *, int);
void frame_unpin (void *, int);
void frame_unpin_kernel (void *, int);
void frame_pin_kernel (void *, int);
void lock_frames (void);
void unlock_frames (void);


#endif /* vm/frame.h */
