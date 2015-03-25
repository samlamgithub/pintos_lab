#include "vm/swap.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/syscall.h"

#include <bitmap.h>
#include <hash.h>
#include <debug.h>
#include <stdio.h>

/* Swap partition */
static struct block *swap;
static struct lock swap_lock;
unsigned swap_size;

/* Bitmap of free swap slots. */
static struct bitmap * free_swap_bitmap;

block_sector_t swap_find_free(void);

/*
Constructor
*/
struct swap_slt * swap_slot (struct frame * frame)
{
	struct swap_slt * swap_slt = malloc (sizeof (struct swap_slt));
	swap_slt -> frame = frame;
	return swap_slt;
}

/*
Returns first address on the swap where we can store a page of memory
*/
block_sector_t
swap_find_free ()
{
	bool full = bitmap_all (free_swap_bitmap, 0, swap_size);
	if(!full){
		block_sector_t first_free = bitmap_scan_and_flip (free_swap_bitmap, 0, PGSIZE / BLOCK_SECTOR_SIZE, false);

		return first_free;
	} else {
		PANIC("SWAP is full! Memory exhausted.");
	}
}

/*
Stores a page from memory on the swap
*/
void
swap_store (struct swap_slt * swap_slt)
{
	int i;

	lock_acquire (&swap_lock);

	block_sector_t swap_addr = swap_find_free();

	for(i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++){
		block_write (swap, swap_addr + i, swap_slt -> frame -> addr + i * BLOCK_SECTOR_SIZE);
	}

	lock_release (&swap_lock);

	swap_slt -> swap_addr = swap_addr;
}

/*
Loads a page from swap to the memory
*/
void
swap_load (void *addr, struct swap_slt * swap_slt)
{
	int i;
	lock_acquire (&swap_lock);

	for( i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++ ){
		block_read (swap, swap_slt->swap_addr + i, addr + i * BLOCK_SECTOR_SIZE);
	}

	bitmap_set_multiple (free_swap_bitmap, swap_slt->swap_addr, PGSIZE / BLOCK_SECTOR_SIZE, false);
	lock_release (&swap_lock);
}

/*
Frees a swap slot
*/
void
swap_free(struct swap_slt * swap_slt){
	lock_acquire (&swap_lock);
	bitmap_set_multiple (free_swap_bitmap, swap_slt->swap_addr, PGSIZE / BLOCK_SECTOR_SIZE, false);
	lock_release (&swap_lock);
}

void swap_init(){
	swap = block_get_role (BLOCK_SWAP);
	swap_size = block_size (swap);
	lock_init (&swap_lock);
	free_swap_bitmap = bitmap_create (swap_size);
}
