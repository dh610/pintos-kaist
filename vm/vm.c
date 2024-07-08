/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

struct list frame_table;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *newpage = (struct page *) malloc(sizeof(struct page));
		bool (*initializer)(struct page *, enum vm_type, void *kva);

		switch (type)
		{
		case VM_ANON:
		case VM_ANON | VM_MARKER_0:
			initializer = anon_initializer;
			break;
		case VM_FILE:
			initializer = file_backed_initializer;
			break;
		}

		uninit_new(newpage, upage, init, type, aux, initializer);
		newpage->writable = writable;

		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, newpage);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	struct page find = {
		.va = pg_round_down(va)
	};
	struct hash_elem *e = hash_find(&spt->page_table, &find.elem);

	if (e != NULL) page = hash_entry(e, struct page, elem);

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	if (spt_find_page(spt, page->va) == NULL) {
		hash_insert(&spt->page_table, &page->elem);
		succ = true;
	}

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	victim = list_entry(list_pop_front(&frame_table), struct frame, elem);

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim->page);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	void *kva = palloc_get_page(PAL_USER);

	if (kva) {
		frame = (struct frame *) malloc(sizeof(struct frame));
		frame->kva = kva;
	} else frame = vm_evict_frame();

	frame->page = NULL;
	list_push_back(&frame_table, &frame->elem);

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true);
	vm_claim_page(addr);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	return false;
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if (is_kernel_vaddr(addr)) return false;

	/* bogus fault */
	if (!not_present) return false;

	page = spt_find_page(spt, addr);

	if (page == NULL) {
		uint64_t stack = user ? f->rsp : thread_current()->ursp;

		if (addr >= USER_STACK - (1 << 20) && addr <= USER_STACK && addr >= stack - 8) {
			thread_current()->spp -= PGSIZE;
			vm_stack_growth(thread_current()->spp);
			return true;
		}
		
		return false;
	}

	if (write && !page->writable) {
		return vm_handle_wp(page);
	}

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	ASSERT (page != NULL);

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) 
		return false;

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->page_table, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator i;
	struct file_info *info;
	hash_first(&i, src);
	while (hash_next(&i)) {
		struct page *src_page = hash_entry(hash_cur(&i), struct page, elem);
		struct page *dst_page = NULL;
		enum vm_type type = src_page->operations->type;
		struct file_info *info = NULL;

		switch (type)
		{
		case VM_UNINIT:
			info = (struct file_info *) malloc(sizeof(struct file_info));
			memcpy(info, src_page->uninit.aux, sizeof(struct file_info));
			info->fp = file_reopen(((struct file_info *)src_page->uninit.aux)->fp);
			thread_current()->open_file = info->fp;
			vm_alloc_page_with_initializer(page_get_type(src_page), src_page->va, src_page->writable, src_page->uninit.init, info);
			break;
		case VM_FILE:
			info = (struct file_info *) malloc(sizeof(struct file_info));
			memcpy(info, src_page->file.info, sizeof(struct file_info));
			info->fp = file_reopen(src_page->file.info->fp);
		case VM_ANON:
		case VM_ANON | VM_MARKER_0:
			vm_alloc_page_with_initializer(type, src_page->va, src_page->writable, NULL, info);
			dst_page = spt_find_page(dst, src_page->va);
			vm_do_claim_page(dst_page);
			memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
			break;
		}
	}

	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	void *arr[64] = { 0 };
	int cnt = 0;
	struct hash_iterator i;
	hash_first(&i, &spt->page_table);
	while(hash_next(&i)) {
		struct page *page = hash_entry(hash_cur(&i), struct page, elem);
		if (page->operations->type == VM_FILE && page->file.info->head == page->va) {
			arr[cnt] = page->va;
			cnt++;
		}
	}
	for (int i = 0; i < cnt; i++)
		do_munmap(arr[i]);
		
	hash_destroy(&spt->page_table, page_destroy);
}

unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
	const struct page *p = hash_entry (p_, struct page, elem);
	return hash_bytes (&p->va, sizeof p->va);
}

bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
	const struct page *a = hash_entry (a_, struct page, elem);
	const struct page *b = hash_entry (b_, struct page, elem);
	return a->va < b->va;
}

void
page_destroy (struct hash_elem *e, void *aux) {
	struct page *page = hash_entry(e, struct page, elem);
	if (page->frame != NULL) free(page->frame);
	spt_remove_page(&thread_current()->spt, page);
}
