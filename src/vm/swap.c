#include "vm/swap.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/syscall.h"
#include <bitmap.h>
#include <hash.h>
#include <debug.h>
#include <stdio.h>

// Swap partition
static struct block *swap_space;
static struct lock swapslot_lock;
unsigned swapslot_size;

static struct bitmap * swap_slot_bitmap; // Bitmap of free swap slots.

block_sector_t swap_find_free(void);

void swap_init() {
	swap_space = block_get_role (BLOCK_SWAP);
	swapslot_size = block_size (swap_space);
	lock_init (&swapslot_lock);
	swap_slot_bitmap = bitmap_create (swapslot_size);
}

struct swap_slot * swap_slot_construct (struct frame * frame) { //construct a new swap slot of that frame and return
	struct swap_slot * swap_slot = malloc (sizeof (struct swap_slot));
	swap_slot->swap_frame = frame;
	return swap_slot;
}

block_sector_t swap_find_free () { // return free address in swap
	bool full = bitmap_all (swap_slot_bitmap, 0, swapslot_size);
	if(!full){
		block_sector_t first_free = bitmap_scan_and_flip (swap_slot_bitmap, 0, PGSIZE / BLOCK_SECTOR_SIZE, false);
		return first_free;
	} else {
		PANIC("SWAP is full! Memory exhausted.");
		return NULL;
	}
}


void swap_store (struct swap_slot * ss) { // store a frame in swap space
	int i;
	lock_acquire (&swapslot_lock);
	block_sector_t swap_addr = swap_find_free();
	for(i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++){
		block_write (swap_space, swap_addr + i, ss->swap_frame->upage + i * BLOCK_SECTOR_SIZE);
	}
	lock_release (&swapslot_lock);
	ss -> swap_addr = swap_addr;
}


void swap_load (void *upageaddr, struct swap_info * ss) { // Loads a page from swap to the memory
	int i;
	lock_acquire (&swapslot_lock);
	for( i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++ ){
		block_read (swap_space, ss->swap_addr + i, upageaddr + i * BLOCK_SECTOR_SIZE);
	}
	bitmap_set_multiple (swap_slot_bitmap, ss->swap_addr, PGSIZE / BLOCK_SECTOR_SIZE, false);
	lock_release (&swapslot_lock);
}

void swap_free(struct swap_slot * ss) { // free whole swap slot
	lock_acquire (&swapslot_lock);
	bitmap_set_multiple (swap_slot_bitmap, ss->swap_addr, PGSIZE / BLOCK_SECTOR_SIZE, false);
	lock_release (&swapslot_lock);
}


