#ifndef __VM_SWAP_H
#define __VM_SWAP_H

#include "vm/frame.h"
#include "devices/block.h"

struct swap_slot{
	struct frame *swap_frame;
	block_sector_t swap_addr;	// Address of the first segment where the page is stored
	struct hash_elem hash_elem;
};

void swap_init (void);
void swap_load (void *, struct swap_info*);
void swap_store (struct swap_slot *);
void swap_free (struct swap_slot *);
struct swap_slot* swap_slot_construct(struct frame *);

#endif // vm/swap.h
