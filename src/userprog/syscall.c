#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/stdio.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "userprog/process.h"
typedef int pid_t;

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);
static void syscall_exit_fail (void) NO_RETURN;
static bool is_valid_user_ptr (const void *uaddr);
static bool is_valid_user_buffer (const void *buffer, size_t size);
static bool is_valid_user_string (const char *ustr);
static void get_syscall_args (struct intr_frame *f, uint32_t *args, int n);
static struct file_descriptor *get_file_descriptor (int fd);

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
acquire_filesys_lock (void)
{
  lock_acquire (&filesys_lock);
}

void
release_filesys_lock (void)
{
  lock_release (&filesys_lock);
}

static void
syscall_exit_fail (void)
{
  struct thread *cur = thread_current ();
  #ifdef USERPROG
    cur->exit_status = -1;
  #endif  
  thread_exit ();
}

/* Validates that a user address is non-null, below PHYS_BASE,
   and currently mapped in the active process's page directory. */
static bool
is_valid_user_ptr (const void *uaddr)
{
  if (uaddr == NULL || !is_user_vaddr (uaddr))
    return false;
  return pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL;
}

/* Validates that every byte in a buffer of length SIZE is within
   the user virtual address space and mapped to a physical page. */
static bool
is_valid_user_buffer (const void *buffer, size_t size)
{
  if (size == 0)
    return true;
  if (buffer == NULL)
    return false;

  const uint8_t *start = (const uint8_t *) buffer;
  const uint8_t *end = start + size - 1;

  /* Check for pointer overflow/wraparound. */
  if (end < start)
    return false;

  /* Check that both bounds are in user virtual address space. */
  if (!is_user_vaddr (start) || !is_user_vaddr (end))
    return false;

  /* Inspect each page spanned by the buffer. */
  uint32_t *pd = thread_current ()->pagedir;
  const uint8_t *curr = (const uint8_t *) pg_round_down (start);
  while (curr <= end)
    {
      if (pagedir_get_page (pd, curr) == NULL)
        return false;
      curr += PGSIZE;
    }
  return true;
}

/* Validates that a null-terminated string is entirely in valid
   user virtual memory without page-faulting. */
static bool
is_valid_user_string (const char *ustr)
{
  if (ustr == NULL || !is_user_vaddr (ustr))
    return false;

  uint32_t *pd = thread_current ()->pagedir;
  const char *p = ustr;

  while (is_user_vaddr (p))
    {
      void *kaddr = pagedir_get_page (pd, p);
      if (kaddr == NULL)
        return false;

      size_t bytes_left = PGSIZE - pg_ofs (p);
      size_t i;
      for (i = 0; i < bytes_left; i++)
        {
          if (p[i] == '\0')
            return true;
        }
      p += bytes_left;
    }
  return false;
}

/* Safely retrieves N 32-bit arguments from the user stack.
   Terminates the process if any part of the stack is invalid. */
static void
get_syscall_args (struct intr_frame *f, uint32_t *args, int n)
{
  if (!is_valid_user_buffer ((uint32_t *) f->esp + 1, n * sizeof (uint32_t)))
    syscall_exit_fail ();
  for (int i = 0; i < n; i++)
    args[i] = *((uint32_t *) f->esp + 1 + i);
}

/* Returns the file_descriptor entry matching FD for the current thread,
   or NULL if not found. */
static struct file_descriptor *
get_file_descriptor (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  for (e = list_begin (&cur->fds); e != list_end (&cur->fds); e = list_next (e))
    {
      struct file_descriptor *fdesc = list_entry (e, struct file_descriptor, elem);
      if (fdesc->fd == fd)
        return fdesc;
    }
  return NULL;
}

static void
sys_halt (void)
{
  shutdown_power_off ();
}

static void
sys_exit (int status)
{
  struct thread *cur = thread_current ();
  #ifdef USERPROG
    cur->exit_status = status;  
  #endif
  thread_exit ();
}

static pid_t
sys_exec (const char *cmd_line)
{
  if (!is_valid_user_string (cmd_line))
    syscall_exit_fail ();
  return process_execute (cmd_line);
}

static int
sys_wait (pid_t pid)
{
  return process_wait (pid);
}

static bool
sys_create (const char *file, unsigned initial_size)
{
  if (!is_valid_user_string (file))
    syscall_exit_fail ();
  if (strlen (file) == 0)
    return false;

  acquire_filesys_lock ();
  bool success = filesys_create (file, initial_size);
  release_filesys_lock ();
  return success;
}

static bool
sys_remove (const char *file)
{
  if (!is_valid_user_string (file))
    syscall_exit_fail ();
  if (strlen (file) == 0)
    return false;

  acquire_filesys_lock ();
  bool success = filesys_remove (file);
  release_filesys_lock ();
  return success;
}

static int
sys_open (const char *file)
{
  if (!is_valid_user_string (file))
    syscall_exit_fail ();
  if (strlen (file) == 0)
    return -1;

  acquire_filesys_lock ();
  struct file *opened_file = filesys_open (file);
  release_filesys_lock ();
  if (opened_file == NULL)
    return -1;

  struct file_descriptor *fdesc = malloc (sizeof *fdesc);
  if (fdesc == NULL)
    {
      acquire_filesys_lock ();
      file_close (opened_file);
      release_filesys_lock ();
      return -1;
    }

  struct thread *cur = thread_current ();
  fdesc->fd = cur->next_fd++;
  fdesc->file = opened_file;
  list_push_back (&cur->fds, &fdesc->elem);
  return fdesc->fd;
}

static int
sys_filesize (int fd)
{
  struct file_descriptor *fdesc = get_file_descriptor (fd);
  if (fdesc == NULL)
    return -1;

  acquire_filesys_lock ();
  int length = file_length (fdesc->file);
  release_filesys_lock ();
  return length;
}

static int
sys_read (int fd, void *buffer, unsigned size)
{
  if (!is_valid_user_buffer (buffer, size))
    syscall_exit_fail ();
  if (size == 0)
    return 0;

  if (fd == 0) /* STDIN */
    {
      uint8_t *buf = (uint8_t *) buffer;
      for (unsigned i = 0; i < size; i++)
        buf[i] = input_getc ();
      return size;
    }
  if (fd == 1) /* STDOUT is not readable */
    return -1;

  struct file_descriptor *fdesc = get_file_descriptor (fd);
  if (fdesc == NULL)
    return -1;

  acquire_filesys_lock ();
  int bytes_read = file_read (fdesc->file, buffer, size);
  release_filesys_lock ();
  return bytes_read;
}

static int
sys_write (int fd, const void *buffer, unsigned size)
{
  if (!is_valid_user_buffer (buffer, size))
    syscall_exit_fail ();
  if (size == 0)
    return 0;

  if (fd == 1) /* STDOUT */
    {
      putbuf ((const char *) buffer, size);
      return size;
    }
  if (fd == 0) /* STDIN is not writable */
    return -1;

  struct file_descriptor *fdesc = get_file_descriptor (fd);
  if (fdesc == NULL)
    return -1;

  acquire_filesys_lock ();
  int bytes_written = file_write (fdesc->file, buffer, size);
  release_filesys_lock ();
  return bytes_written;
}

static void
sys_seek (int fd, unsigned position)
{
  struct file_descriptor *fdesc = get_file_descriptor (fd);
  if (fdesc != NULL)
    {
      acquire_filesys_lock ();
      file_seek (fdesc->file, position);
      release_filesys_lock ();
    }
}

static unsigned
sys_tell (int fd)
{
  struct file_descriptor *fdesc = get_file_descriptor (fd);
  if (fdesc == NULL)
    return 0;

  acquire_filesys_lock ();
  unsigned pos = file_tell (fdesc->file);
  release_filesys_lock ();
  return pos;
}

static void
sys_close (int fd)
{
  if (fd < 2)
    return;

  struct file_descriptor *fdesc = get_file_descriptor (fd);
  if (fdesc != NULL)
    {
      acquire_filesys_lock ();
      file_close (fdesc->file);
      release_filesys_lock ();
      list_remove (&fdesc->elem);
      free (fdesc);
    }
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* Validate that the stack pointer is in user space and mapped. */
  if (!is_valid_user_buffer (f->esp, sizeof (uint32_t)))
    syscall_exit_fail ();

  int syscall_nr = *(int *) f->esp;
  uint32_t args[3];

  switch (syscall_nr)
    {
    case SYS_HALT:
      sys_halt ();
      break;

    case SYS_EXIT:
      get_syscall_args (f, args, 1);
      sys_exit ((int) args[0]);
      break;

    case SYS_EXEC:
      get_syscall_args (f, args, 1);
      f->eax = sys_exec ((const char *) args[0]);
      break;

    case SYS_WAIT:
      get_syscall_args (f, args, 1);
      f->eax = sys_wait ((pid_t) args[0]);
      break;

    case SYS_CREATE:
      get_syscall_args (f, args, 2);
      f->eax = sys_create ((const char *) args[0], (unsigned) args[1]);
      break;

    case SYS_REMOVE:
      get_syscall_args (f, args, 1);
      f->eax = sys_remove ((const char *) args[0]);
      break;

    case SYS_OPEN:
      get_syscall_args (f, args, 1);
      f->eax = sys_open ((const char *) args[0]);
      break;

    case SYS_FILESIZE:
      get_syscall_args (f, args, 1);
      f->eax = sys_filesize ((int) args[0]);
      break;

    case SYS_READ:
      get_syscall_args (f, args, 3);
      f->eax = sys_read ((int) args[0], (void *) args[1], (unsigned) args[2]);
      break;

    case SYS_WRITE:
      get_syscall_args (f, args, 3);
      f->eax = sys_write ((int) args[0], (const void *) args[1], (unsigned) args[2]);
      break;

    case SYS_SEEK:
      get_syscall_args (f, args, 2);
      sys_seek ((int) args[0], (unsigned) args[1]);
      break;

    case SYS_TELL:
      get_syscall_args (f, args, 1);
      f->eax = sys_tell ((int) args[0]);
      break;

    case SYS_CLOSE:
      get_syscall_args (f, args, 1);
      sys_close ((int) args[0]);
      break;

    default:
      syscall_exit_fail ();
      break;
    }
}
