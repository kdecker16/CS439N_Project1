#include "userprog/syscall.h"
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

static void syscall_handler (struct intr_frame *);

static struct lock filesys_lock, stdin_lock;

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  lock_init (&stdin_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// nc drive
static void
syscall_handler (struct intr_frame *if_) 
{
  int  *nr       = &((int   *) if_->esp)[0];
  void *arg1     = &((void **) if_->esp)[1];
  void *arg2     = &((void **) if_->esp)[2];
  void *arg3     = &((void **) if_->esp)[3];
  
  if (!is_user_vaddr(nr))
    thread_exit ();
  

  
  switch (*nr) {
    SYSCALL_HANDLE_CASE (SYS_HALT);
    SYSCALL_HANDLE_CASE (SYS_EXIT);
    SYSCALL_HANDLE_CASE (SYS_EXEC);
    SYSCALL_HANDLE_CASE (SYS_WAIT);
    SYSCALL_HANDLE_CASE (SYS_CREATE);
    SYSCALL_HANDLE_CASE (SYS_REMOVE);
    SYSCALL_HANDLE_CASE (SYS_OPEN);
    SYSCALL_HANDLE_CASE (SYS_FILESIZE);
    SYSCALL_HANDLE_CASE (SYS_READ);
    SYSCALL_HANDLE_CASE (SYS_WRITE);
    SYSCALL_HANDLE_CASE (SYS_SEEK);
    SYSCALL_HANDLE_CASE (SYS_TELL);
    SYSCALL_HANDLE_CASE (SYS_CLOSE);

    default:
      printf ("Invalid system call!\n");
      thread_exit ();
  }
}


// kd drive
static void
syscall_handler_SYS_HALT (SYSCALL_FUNC_ARGS)
{
  // nothing to do, power off
  shutdown_power_off ();
}

// nc drive
static void
syscall_handler_SYS_EXIT (SYSCALL_FUNC_ARGS)
{
  if (!is_user_vaddr(arg1))
    thread_exit ();
  
  // call thread's exit
  thread_current ()->exit_code = *(int *) arg1;
  thread_exit ();
}

// kd drive
static void
syscall_handler_SYS_EXEC (SYSCALL_FUNC_ARGS)
{
  const char *file;
  signed len;
  
  if (!is_user_vaddr(arg1))
    thread_exit ();
  
  file = *(const char **) arg1;
  len = get_strlen (file);
  if (len < 0)
    thread_exit ();
  // call process' execute
  if_->eax = SYNCHRONIZE (process_execute (file));
}

// nc drive
static void
syscall_handler_SYS_WAIT (SYSCALL_FUNC_ARGS)
{
  tid_t child;
  
  if (!is_user_vaddr(arg1))
    thread_exit ();
  
  child = *(tid_t *) arg1;
  // call process' wait
  if_->eax = process_wait (child);
}

// kd drive
static void
syscall_handler_SYS_CREATE (SYSCALL_FUNC_ARGS)
{
  const char *filename;
  signed len;

  if (!is_user_vaddr(arg1))
    thread_exit ();
  
  filename = *(const char **) arg1;
  len = get_strlen (filename);
  if (len < 0)
    thread_exit ();
  // call filesystem's create
  if_->eax = SYNCHRONIZE (filesys_create (filename, *(unsigned *) arg2));
}

// kd drive
static void
syscall_handler_SYS_REMOVE (SYSCALL_FUNC_ARGS)
{

  if (!is_user_vaddr(arg1))
    thread_exit ();
  
  const char *filename = *(const char **) arg1;
  signed len = get_strlen (filename);
  if (len < 0)
    thread_exit ();
  // call filesystem's remove
  if_->eax = SYNCHRONIZE (filesys_remove (filename));
}

// nc drive
static void
syscall_handler_SYS_OPEN (SYSCALL_FUNC_ARGS)
{

  const char *filename;
  signed len;
  struct fd *fd_ptr;
  struct thread *current_thread;
  
  if (!is_user_vaddr(arg1))
    thread_exit ();
  
  filename = *(const char **) arg1;
  len = get_strlen (filename);;
  if (len < 0)
    thread_exit ();
  fd_ptr = calloc (1, sizeof (*fd_ptr));
  if (!fd_ptr)
    {
      if_->eax = -ENOMEM;
      return;
    }
  
  current_thread = thread_current ();
  
  // search for associated fd
  for (fd_ptr->fd = 3; fd_ptr->fd < INT_MAX; ++fd_ptr->fd)
      if (hash_find (&current_thread->fds, &fd_ptr->elem) == NULL)
        break;
  if (fd_ptr->fd == INT_MAX)
    {
      free (fd_ptr);
      if_->eax = -ENFILE;
      return;
    }
  
  //call filesystem's open
  fd_ptr->file = SYNCHRONIZE (filesys_open (filename));
  if (!fd_ptr->file)
    {
      free (fd_ptr);
      if_->eax = -ENOENT;
      return;
    }

  hash_insert (&current_thread->fds, &fd_ptr->elem);
  if_->eax = fd_ptr->fd;
}

// kd drive
static void
syscall_handler_SYS_FILESIZE (SYSCALL_FUNC_ARGS)
{
  struct fd *fd_data;
  
  if (!is_user_vaddr(arg1))
    thread_exit ();
  
  fd_data = retrieve_fd (*(unsigned *) arg1);
  if_->eax = fd_data ? SYNCHRONIZE (file_length (fd_data->file)) : -1;
}

// nc drive
static void
syscall_handler_SYS_READ (SYSCALL_FUNC_ARGS)
{
  unsigned fd = *(unsigned *) arg1;
  char *buffer = *(void **) arg2;
  unsigned length = *(unsigned *) arg3;
  struct fd *fd_data;
  char *dest;
  int result;
  
  if (!is_user_vaddr(fd) || !is_user_vaddr(buffer + length))
    thread_exit ();
  
    
  if (fd)
    {
      fd_data = retrieve_fd (fd);
      if (!fd_data)
        {
          if_->eax = -EBADF;
          return;
        }
      if_->eax = SYNCHRONIZE (file_read (fd_data->file, buffer, length));
    }
  else
    {
      dest = buffer;
      result = 0;
      lock_acquire (&stdin_lock);
      while (input_full () && (unsigned) result < length)
        {
          *dest = input_getc ();
          ++dest;
          ++result;
        }
      *dest = '\0';
      lock_release (&stdin_lock);
    }
}

// kd drive
static void
syscall_handler_SYS_WRITE (SYSCALL_FUNC_ARGS)
{
  unsigned fd = *(unsigned *) arg1;
  const char *buffer = *(const void **) arg2;
  unsigned length = *(unsigned *) arg3;
  struct fd *fd_data;
  
  if (!is_user_vaddr(fd) || !is_user_vaddr(buffer + length))
    thread_exit ();  
	
  else if (!fd || fd >= INT_MAX)
    {
      if_->eax = -EBADF;
      return;
    }
  else if (fd == 1 || fd == 2)
    {
      putbuf (buffer, length);
      if_->eax = length;
      return;
    }
  
  fd_data = retrieve_fd (fd);
  if (fd_data)
    {
      lock_acquire (&filesys_lock);
      if (!thread_is_file_currently_executed (fd_data->file))
        if_->eax = file_write (fd_data->file, buffer, length);
      else
        if_->eax = 0;
      lock_release (&filesys_lock);
    }
  else
    if_->eax = -EBADF;
}

// nc drive
static void
syscall_handler_SYS_SEEK (SYSCALL_FUNC_ARGS)
{
  unsigned fd;
  unsigned position;
  struct fd *fd_data;
  
  if (!is_user_vaddr(arg1))
    thread_exit ();
	
  fd = *(unsigned *) arg1;
  position = *(unsigned *) arg2;
  
  fd_data = retrieve_fd (fd);
	
  if (!fd_data)
    thread_exit ();
  SYNCHRONIZE((file_seek (fd_data->file, position), 0));
}

// kd drive
static void
syscall_handler_SYS_TELL (SYSCALL_FUNC_ARGS)
{
  struct fd *fd_data;
  
  if (!is_user_vaddr(arg1))
    thread_exit ();  
	
  fd_data = retrieve_fd (*(unsigned *) arg1);
  
  if (!fd_data)
    thread_exit ();
	
  // call filesystem's tell
  if_->eax = SYNCHRONIZE (file_tell (fd_data->file));
}

// nc drive
static void
syscall_handler_SYS_CLOSE (SYSCALL_FUNC_ARGS)
{
  struct fd search;
  struct hash_elem *e;
  struct fd *fd_data;
  
  if (!is_user_vaddr(arg1))
    thread_exit ();
  
  // check for associated fd
  memset (&search, 0, sizeof (search));
  search.fd = *(unsigned *) arg1;
  e = hash_delete (&thread_current ()->fds, &search.elem);
  if (!e)
    thread_exit ();
  fd_data = hash_entry (e, struct fd, elem);
  
  // call filesystem's close
  SYNCHRONIZE ((file_close (fd_data->file), 0));
  free (fd_data);
}



/* Support Methods */


// c lib strlen
static signed
get_strlen (const char *c)
{
	signed result;
	struct thread *t;
	const char *downfrom;
	const char *upto;
  if (!c)
    return -1;
  
  result = 0;
  t = thread_current ();
  while(true)
    {
      if ((void *) c >= PHYS_BASE)
        return -1;
      
      downfrom = (const char *) ((intptr_t) c & ~(PGSIZE-1));
      upto     = (const char *) ((intptr_t) c |  (PGSIZE-1));
      
      if (pagedir_get_page (t->pagedir, downfrom) == NULL)
        return -1;
      while (c <= upto)
        if (*(c++))
          ++result;
        else
          return result;
    }
}

// nc drive
static struct fd *
retrieve_fd (unsigned fd)
{
  struct fd search;
  struct hash_elem *e;
  
  memset (&search, 0, sizeof (search));
  search.fd = fd;
  e = hash_find (&thread_current ()->fds, &search.elem);
  return e ? hash_entry (e, struct fd, elem) : NULL;
}