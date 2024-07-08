#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include <string.h>
#ifdef VM
#include "vm/vm.h"
#endif

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void halt(void);
tid_t fork (const char *thread_name, struct intr_frame *f UNUSED);
int exec (const char *cmd_line);
int wait (tid_t tid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

bool syscall_valid_memory(void *mem) {
	return is_kernel_vaddr(mem);
}

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	thread_current()->ursp = f->rsp;
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	
	case SYS_EXIT:
		exit(f->R.rdi);
		break;

	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		break;
	
	case SYS_EXEC:
		if (exec(f->R.rdi) == -1) exit(-1);
		break;
	
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;

	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;

	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;

	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;

	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;

	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;

	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;

	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;

	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;

	case SYS_CLOSE:
		close(f->R.rdi);
		break;

	case SYS_MMAP:
		f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
		break;

	case SYS_MUNMAP:
		munmap(f->R.rdi);
		break;

	default:
		break;
	}
}

void is_addr_valid(uint64_t *addr) {
	struct thread *curr = thread_current();
	if (addr == NULL || !(is_user_vaddr(addr)) || spt_find_page(&curr->spt, addr) == NULL) 
		exit(-1);
}

void
halt(void) {
	power_off();
}

void
exit(int status) {
	struct thread *curr = thread_current();
	char *name = curr->name;
	int len = strlen(name);
	for (int i = 0; i < len; i++) {
		if (name[i] == ' ') break;
		printf("%c", name[i]);
	}
	printf(": exit(%d)\n", status);
	for (int i = 2; i < curr->fd_end; i++) close(i);
	thread_current()->exit_status = status;
	thread_exit();
}

tid_t
fork(const char *thread_name, struct intr_frame *f UNUSED) {
	return process_fork(thread_name, f);
}

int
exec(const char *cmd_line) {
	is_addr_valid(cmd_line);
	return process_exec(cmd_line);
}

int wait(tid_t tid) {
	return process_wait(tid);
}

int file_to_fd(struct file *fp) {
	int fd = 2;
	struct thread *curr = thread_current();
	while(curr->fd_table[fd] != NULL) fd++;
	curr->fd_table[fd] = fp;
	curr->fd_end = fd > curr->fd_end ? fd : curr->fd_end;
	return fd;
}

bool create (const char *file, unsigned initial_size) { 
	is_addr_valid(file);
	return filesys_create(file, initial_size);
}

bool remove (const char *file) {
	return filesys_remove(file);
}

int open (const char *file) {
	is_addr_valid(file);
	if (file == NULL) return -1;
	struct file *newfile = filesys_open(file);
	if (newfile == NULL) return -1;
	if (strcmp(thread_name(), file) == 0)
		file_deny_write(newfile);
	return file_to_fd(newfile);
}

int filesize (int fd) {
	if (fd < 2) return -1;
	return file_length(thread_current()->fd_table[fd]);
}

int read (int fd, void *buffer, unsigned size) {
	is_addr_valid(buffer);
	is_addr_valid(buffer + size - 1);

	if (!spt_find_page(&thread_current()->spt, buffer)->writable)
		exit(-1);

	if (fd == 0) {
		int i;
		for (i = 0; i < size; i++)
			*(char *)&buffer[i] = input_getc();
		return i;
	} else if (fd < 2 || fd >= 64) return -1;

	struct file *fp = thread_current()->fd_table[fd];
	if (fp == NULL) return -1;
	return file_read(fp, buffer, size);
}

int write (int fd, const void *buffer, unsigned size) {
	is_addr_valid(buffer);

	if(fd == 1) {
		putbuf(buffer, size);
		return size;
	} else if (fd < 2 || fd >= 64) exit(-1);

	struct file *fp = thread_current()->fd_table[fd];
	if (fp == NULL) exit(-1);
	return file_write(fp, buffer, size);
}

void seek (int fd, unsigned position) {
	if (fd < 2 || fd >= 64) exit(-1); 
	struct file *fp = thread_current()->fd_table[fd];
	if (fp == NULL) exit(-1);
	file_seek(fp, position);
}

unsigned tell (int fd) {
	if (fd < 2 || fd >= 64) exit(-1); 
	struct file *fp = thread_current()->fd_table[fd];
	if (fp == NULL) exit(-1);
	return file_tell(fp);
}

void remove_fd (int fd) {
	struct thread *curr = thread_current();
	curr->fd_table[fd] = NULL;
	if (fd == curr->fd_end) curr->fd_end--;
}

void close (int fd) {
	if (fd < 2 || fd >= 64) exit(-1);
	struct thread *curr = thread_current();
	struct file *fp = curr->fd_table[fd];
	remove_fd(fd);
	if (fp == NULL) return;
	file_close(fp);
}

void *mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	if (fd < 2) return NULL;
	if ((int)length <= 0) return NULL;
	if (addr == 0 || is_kernel_vaddr(addr) || addr != pg_round_down(addr) || offset != pg_round_down(offset)) return NULL;
	struct file *fp = thread_current()->fd_table[fd];
	if (fp == NULL) return NULL;
	return do_mmap(addr, length, writable, fp, offset);
}

void munmap (void *addr) {
	is_addr_valid(addr);
	do_munmap(addr);
}
