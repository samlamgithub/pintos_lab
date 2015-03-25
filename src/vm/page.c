#include "vm/page.h"
#include "threads/malloc.h"

struct suppl_page *
new_zero_page ()
{
	struct suppl_page *new_page = (struct suppl_page *) malloc (sizeof (struct suppl_page));
	if(new_page == NULL) {
		PANIC("NOT ENOUGH MEMORY");
	}
	new_page->location = ZERO;
	new_page->origin = NULL;
	new_page->swap_elem = NULL;
	return new_page;
}

struct suppl_page *
new_file_page (struct file * source, off_t offset, size_t zero_after, bool writable, enum page_type location)
{
	struct suppl_page *new_page = (struct suppl_page *) malloc (sizeof (struct suppl_page));
	if(new_page == NULL) {
		PANIC("NOT ENOUGH MEMORY");
	}
	new_page->location = location;

	struct origin_info *origin = (struct origin_info *) malloc (sizeof (struct origin_info));
	if(origin == NULL) {
		PANIC("NOT ENOUGH MEMORY");
	}
	origin->source_file = source;
	origin->offset = offset;
	origin->zero_after = zero_after;
	origin->writable = writable;
	origin->location = location;

	new_page->origin = origin;
	new_page->swap_elem = NULL;
	return new_page;
}

struct suppl_page *
new_swap_page (struct swap_slt *swap_location)
{
	struct suppl_page *new_page = (struct suppl_page *) malloc (sizeof (struct suppl_page));
	if(new_page == NULL) {
		PANIC("NOT ENOUGH MEMORY");
	}
	new_page->location = SWAP;
	new_page->origin = NULL;
	new_page->swap_elem = swap_location;
	return new_page;
}

inline bool
is_stack_access (void * esp, void * address)
{
	return (address < PHYS_BASE) && (address > STACK_BOTTOM)
      && (address + 32 >= esp);
}
