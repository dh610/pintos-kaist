/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	struct file_info *info = file_page->info;
	
	file_read_at(info->fp, kva, info->page_read_bytes, info->start_ofs);
	memset(kva + info->page_read_bytes, 0, info->page_zero_bytes);

	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	struct file_info *info = file_page->info;

	if (pml4_is_dirty(thread_current()->pml4, page->va)) {
		file_write_at(info->fp, page->frame->kva, info->page_read_bytes, info->start_ofs);
		pml4_set_dirty(thread_current()->pml4, page->va, false);
	}

	pml4_clear_page(thread_current()->pml4, page->va);

	page->frame->page = NULL;
	page->frame = NULL;

	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	free(file_page->info);
}

/* lazy loading function for memory mapped file */
static bool
mmap_lazy_load (struct page *page, void *aux) {
	struct file_info *info = (struct file_info *) aux;
	page->file.info = info;
	struct file *fp = info->fp;
	size_t page_read_bytes = info->page_read_bytes;
	size_t page_zero_bytes = info->page_zero_bytes;
	off_t ofs = info->start_ofs;
	void *kva = page->frame->kva;

	if (file_read_at(fp, kva, page_read_bytes, ofs) != (int) page_read_bytes) return false;
	memset(kva + page_read_bytes, 0, page_zero_bytes);

	return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	struct file *fp = file_reopen(file);
	void *head = addr;

	int read_bytes = file_length(fp) < length ? file_length(fp) : length;
	int zero_bytes = file_length(fp) < length ? length - read_bytes : 0;

	while (read_bytes > 0 || zero_bytes > 0) {
		struct file_info *info = (struct file_info *) malloc(sizeof(struct file_info));
		info->fp = fp;
		info->page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		info->page_zero_bytes = PGSIZE - info->page_read_bytes;
		info->start_ofs = offset;
		info->head = head;
		info->length = length;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, mmap_lazy_load, info)) return NULL;

		offset += info->page_read_bytes;
		read_bytes -= info->page_read_bytes;
		zero_bytes -= info->page_zero_bytes;
		addr += PGSIZE;
	}

	return head;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct file_info *info = spt_find_page(spt, addr)->file.info;
	ASSERT(info->head == addr);
	int length = info->length;
	struct file *fp = info->fp;

	while(length > 0) {
		struct page *page = spt_find_page(spt, addr);
		size_t page_read_bytes = page->file.info->page_read_bytes;
		off_t ofs = page->file.info->start_ofs;

		if (pml4_is_dirty(thread_current()->pml4, addr)) {
			file_write_at(fp, page->frame->kva, page_read_bytes, ofs);
			pml4_set_dirty(thread_current()->pml4, addr, false);
		}

		pml4_clear_page(thread_current()->pml4, addr);
		addr += PGSIZE;
		length -= PGSIZE;
		hash_delete(&spt->page_table, &page->elem);
		spt_remove_page(spt, page);
	}

	file_close(fp);
}
