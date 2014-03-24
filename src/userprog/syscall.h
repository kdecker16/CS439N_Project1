#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include <limits.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "lib/user/syscall.h"
#include "devices/input.h"
#include <errno.h>

#define SYNCHRONIZE(syscall_func)              \
({                              \
  lock_acquire (&filesys_lock); \
  __typeof (syscall_func) _r = (syscall_func);  \
  lock_release (&filesys_lock); \
  _r;                           \
})

#define SYSCALL_FUNC_ARGS void              *arg1 UNUSED, \
  void              *arg2 UNUSED, \
  void              *arg3 UNUSED, \
  struct intr_frame *if_  UNUSED

#define SYSCALL_HANDLE_CASE(NAME) case NAME: \
  syscall_handler_##NAME (arg1, arg2, arg3, if_); \
  break;
						  
void syscall_init (void);

static signed get_strlen (const char *c);
static struct fd * retrieve_fd (unsigned fd);

static void syscall_handler_SYS_HALT (SYSCALL_FUNC_ARGS);
static void syscall_handler_SYS_EXIT (SYSCALL_FUNC_ARGS);
static void syscall_handler_SYS_EXEC (SYSCALL_FUNC_ARGS);
static void syscall_handler_SYS_WAIT (SYSCALL_FUNC_ARGS);
static void syscall_handler_SYS_CREATE (SYSCALL_FUNC_ARGS);
static void syscall_handler_SYS_REMOVE (SYSCALL_FUNC_ARGS);
static void syscall_handler_SYS_OPEN (SYSCALL_FUNC_ARGS);
static void syscall_handler_SYS_FILESIZE (SYSCALL_FUNC_ARGS);
static void syscall_handler_SYS_READ (SYSCALL_FUNC_ARGS);
static void syscall_handler_SYS_WRITE (SYSCALL_FUNC_ARGS);
static void syscall_handler_SYS_SEEK (SYSCALL_FUNC_ARGS);
static void syscall_handler_SYS_TELL (SYSCALL_FUNC_ARGS);
static void syscall_handler_SYS_CLOSE (SYSCALL_FUNC_ARGS);

#endif /* userprog/syscall.h */
