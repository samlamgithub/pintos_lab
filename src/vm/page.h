#ifndef __VM_PAGE_H
#define __VM_PAGE_H

#include "devices/block.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include <stdbool.h>
#include <stdlib.h>

#define STACK_BOTTOM ((void *) (PHYS_BASE - (8 * 1024 * 1024)))

struct suppl_page {
	void *upage;
	bool writable;
	struct hash_elem hash_elem;
	struct file_info *frame_sourcefile; // info of file if page is in file sys
	struct swap_info *swap_slot; // info of swap slot if page is in swap space
	struct zero_page_info *zeropage; // if page is just all zeros
};

struct swap_info {
	struct frame * frame;		// Frame from a frame table
	block_sector_t swap_addr;// Address of the first segment where the page is stored
	struct hash_elem hash_elem;
};

struct zero_page_info {

};
void add_supp_page(struct suppl_page *page);
void page_init(struct hash *page_table);
struct suppl_page* new_file_page(void *upage, bool writable,
		struct file *filename, off_t file_offset, size_t length, bool writable2);
struct suppl_page* new_swap_page( void *upage,bool writable,
		struct frame * frame,block_sector_t swap_addr);
struct suppl_page* new_zero_page( void *upage,bool writable);


#endif // vm/page.h
