#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

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
        retval = syscall_seek((int)*(syscall + 1), (unsigned)*(syscall + 2));
		break;
	case SYS_TELL:
        retval = syscall_tell((int)*(syscall + 1));
		break;
	case SYS_CLOSE:
        retval = syscall_close((int)*(syscall + 1));
		break;
	default:
		retval = -1;
  }

  if (retval != -1) {
    f->eax = retval;
  }
}
