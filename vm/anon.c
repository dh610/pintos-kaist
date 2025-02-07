/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

struct bitmap *swap_table;
const int sec_per_page = PGSIZE / DISK_SECTOR_SIZE;

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	swap_table = bitmap_create(disk_size(swap_disk) / sec_per_page);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->page_no = BITMAP_ERROR;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	for (int i = 0; i < sec_per_page; i++) {
		uint32_t sec_no = anon_page->page_no * sec_per_page + i;
		void *addr = kva + i * DISK_SECTOR_SIZE;
		disk_read(swap_disk, sec_no, addr);
	}

	bitmap_set(swap_table, anon_page->page_no, false);
	anon_page->page_no = BITMAP_ERROR;
	
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	anon_page->page_no = bitmap_scan_and_flip(swap_table, 0, 1, false);
	ASSERT(anon_page->page_no != BITMAP_ERROR);

	for (int i = 0; i < sec_per_page; i++) {
		uint32_t sec_no = anon_page->page_no * sec_per_page + i;
		void *addr = page->frame->kva + i * DISK_SECTOR_SIZE;
		disk_write(swap_disk, sec_no, addr);
	}

	pml4_clear_page(thread_current()->pml4, page->va);

	page->frame->page = NULL;
	page->frame = NULL;

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
