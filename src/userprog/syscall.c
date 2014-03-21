#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/process.h"
#include <list.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);

//TODO: create fd_elem struct definition

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *syscall;
  int retval;
  
  syscall = f->esp;
  switch (*syscall) {
	case SYS_WRITE: 
		retval = syscall_write((int)*(syscall + 1), (void*)*(syscall + 2), (unsigned)*(syscall + 3));
		break;
	case SYS_EXIT:
		syscall_exit((int)*(syscall + 1));
		break;
    case SYS_HALT:
        syscall_halt();
		break;
	case SYS_EXEC:
        retval = syscall_exec((char*)*(syscall + 1));
		break;
	case SYS_WAIT:
        retval = syscall_wait((pid_t)*(syscall + 1));
		break;
	case SYS_CREATE:
        retval = syscall_create((char*)*(syscall + 1), (unsigned)*(syscall + 2));
		break;
	case SYS_REMOVE:
        retval = syscall_remove((char*)*(syscall + 1));
		break;
	case SYS_OPEN:
        retval = syscall_open((char*)*(syscall + 1));
		break;
	case SYS_FILESIZE:
        retval = syscall_filesize((int)*(syscall + 1));
		break;
	case SYS_READ:
        retval = syscall_read((int)*(syscall + 1), (void*)*(syscall + 2), (unsigned)*(syscall + 3));
		break;
	case SYS_SEEK:
        syscall_seek((int)*(syscall + 1), (unsigned)*(syscall + 2));
		break;
	case SYS_TELL:
        retval = syscall_tell((int)*(syscall + 1));
		break;
	case SYS_CLOSE:
        syscall_close((int)*(syscall + 1));
		break;
	default:
		retval = -1;
  }

  if (retval != -1) {
    f->eax = retval;
  }
}

static void syscall_halt (void){
	shutdown_power_off();
}

static void syscall_exit (int status){
	struct thread *t;
	struct list_elem *l;
  
	t = thread_current ();
	while (!list_empty (&t->files)){
		l = list_begin (&t->files);
		syscall_close (list_entry (l, struct fd_elem, thread_elem)->fd);
	}
	
	thread_current()->return_code = status;
	thread_exit();
}

static pid_t syscall_exec (const char *file){
	pid_t ret;
  
	if (!file || !is_user_vaddr (file)) /* bad ptr */
		return -1;
	ret = process_execute (file);
	return ret;
}

static int syscall_wait (pid_t pid){
	return process_wait (pid);
}

static bool syscall_create (const char *file, unsigned initial_size){
	//return !file ? syscall_exit(-1) : filesys_create (file, initial_size);
	if (!file){
		syscall_exit(-1);
		return false;
	}
	else
		filesys_create (file, initial_size);
}

bool syscall_remove (const char *file){
	if (!file)
		return false;
	else if (!is_user_vaddr (file)){
		printf("invalid user virtual address");
		syscall_exit (-1); 
		return false;
	}
	else
		return filesys_remove (file);
}

static int syscall_open (const char *file){
	struct file *f;
	struct fd_elem *fde;
	int ret;

	ret = -1;
	if (!file)
		return -1;
	if (!is_user_vaddr (file)){
		syscall_exit (-1);
		return -1;
	}
		
	f = filesys_open (file);
	if (!f)
		return ret;

	fde = (struct fd_elem *)malloc (sizeof (struct fd_elem));
	if (!fde){
		printf("Not enough memory to allocate memory syscall open()");
		file_close (f);
		return ret;
	}
	
	/* allocate fde an ID, put fde in file_list, put fde in the current thread's file_list */
	fde->file = f; 
	//TODO: write allocator for fd
	fde->fd = alloc_fid ();
	list_push_back (&file_list, &fde->elem);
	list_push_back (&thread_current ()->files, &fde->thread_elem);
	ret = fde->fd;
	return ret;
}

static int syscall_filesize (int fd){
	struct file *f;

	//TODO: find file method
	f = find_fd_elem (fd)->file;
	return !f ? -1 : file_length(f);
}

static int syscall_read (int fd, void *buffer, unsigned length){
	struct file * f;
	unsigned i;
	int ret;

	ret = -1;
	//TODO: Add file_lock to thread
	lock_acquire (&file_lock);

	if (fd == STDIN_FILENO){
		lock_release (&file_lock);
		return ret;
	}
	else if (fd == STDOUT_FILENO){
		for (i = 0; i != length; ++i)
			*(uint8_t *)(buffer + i) = input_putc ();
		ret = length;
		lock_release (&file_lock);
		return ret;
	}
	else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + length)){
		lock_release (&file_lock);
		syscall_exit(-1);
	}
	switch(fd){
		case STDIN_FILENO:
			for (i = 0; i != length; ++i)
				*(uint8_t *)(buffer + i) = input_getc ();
			ret = length;
			lock_release (&file_lock);
			return ret;
		case STDOUT_FILENO:
			lock_release (&file_lock);
			return ret;
		default:
			f = find_fd_elem (fd)->file;
			if (!f){
				lock_release (&file_lock);
				return ret;
			}
			ret = file_read (f, buffer, length);
			lock_release (&file_lock);
			return ret;
	}
}

static int syscall_write (int fd, const void *buffer, unsigned length){
	if (fd == 1) {
		putbuf (buffer, length);
	}

	struct file * f;
	unsigned i;
	int ret;

	ret = -1;
	lock_acquire (&file_lock);
	if (fd == STDIN_FILENO){
		for (i = 0; i != length; ++i)
			*(uint8_t *)(buffer + i) = input_getc ();
		ret = length;
		lock_release (&file_lock);
		return ret;
	}
	else if (fd == STDOUT_FILENO){
		lock_release (&file_lock);
		return ret;
	}
	else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + length)){
		lock_release (&file_lock);
		syscall_exit(-1);
	}
	else{
		f = find_file_by_fd (fd);
		if (!f){
			lock_release (&file_lock);
			return ret;
		}
		ret = file_write (f, buffer, length);
		lock_release (&file_lock);
		return ret;
	}

	return length;
}

static void syscall_seek (int fd, unsigned position){
	struct file *f;
	
	//TODO: again, find file method
	f = find_fd_elem (fd)->file;
	if (!f)
		syscall_exit(-1);
	file_seek (f, (off_t)position);
}

static unsigned syscall_tell (int fd){
	struct file *f;
	
	//TODO: again, find file method
	f = find_fd_elem (fd)->file;
	if (!f)
		return -1;
	return file_tell (f);
}
static void syscall_close (int fd){
	//TODO: do this
	return syscall_exit(1);
}

////////////////////////////////////////////////////////////////////////////////////////
//Support methods
////////////////////////////////////////////////////////////////////////////////////////
static struct fd_elem * find_fd_elem (int fd){
	struct fd_elem *ret;
	struct list_elem *l;

	for (l = list_begin (&file_list); l != list_end (&file_list); l = list_next (l)){
		ret = list_entry (l, struct fd_elem, elem);
		if (ret->fd == fd)
			return ret;
	}
	return NULL;
}
