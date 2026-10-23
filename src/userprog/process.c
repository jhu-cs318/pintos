#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void child_release (struct process_child *child);
static bool push_args (int argc, char **argv, void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  struct process_child *child;
  char process_name[16];
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Extract program name for thread naming (skipping leading spaces). */
  const char *prog_start = file_name;
  while (*prog_start == ' ')
    prog_start++;
  if (*prog_start == '\0')
    {
      palloc_free_page (fn_copy);
      return TID_ERROR;
    }

  const char *prog_end = prog_start;
  while (*prog_end != ' ' && *prog_end != '\0')
    prog_end++;
  size_t prog_len = prog_end - prog_start;
  if (prog_len >= sizeof process_name)
    prog_len = sizeof process_name - 1;
  memcpy (process_name, prog_start, prog_len);
  process_name[prog_len] = '\0';

  child = malloc (sizeof *child);
  if (child == NULL)
    {
      palloc_free_page (fn_copy);
      return TID_ERROR;
    }
  sema_init (&child->load_sema, 0);
  sema_init (&child->exit_sema, 0);
  child->load_success = false;
  child->exited = false;
  child->waited = false;
  child->exit_status = -1;
  child->refs = 2;
  child->cmdline = fn_copy;
  list_push_back (&thread_current ()->children, &child->elem);

  /* Create a new thread to execute the program. */
  tid = thread_create (process_name, PRI_DEFAULT, start_process, child);
  if (tid == TID_ERROR)
    {
      list_remove (&child->elem);
      child_release (child);
      child_release (child);
    }
  else
    {
      child->tid = tid;
      sema_down (&child->load_sema);
      if (!child->load_success)
        {
          list_remove (&child->elem);
          child_release (child);
          tid = TID_ERROR;
        }
    }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  struct process_child *child = file_name_;
  char *file_name = child->cmdline;
  struct intr_frame if_;
  bool success;

  thread_current ()->child_record = child;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  child->load_success = success;
  sema_up (&child->load_sema);
  if (!success)
    {
      thread_current ()->exit_status = -1;
      thread_exit ();
    }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid) 
{
  struct list_elem *e;
  struct process_child *child = NULL;
  int status;

  for (e = list_begin (&thread_current ()->children);
       e != list_end (&thread_current ()->children); e = list_next (e))
    {
      struct process_child *candidate = list_entry (e, struct process_child, elem);
      if (candidate->tid == child_tid)
        {
          child = candidate;
          break;
        }
    }
  if (child == NULL || child->waited)
    return -1;

  child->waited = true;
  sema_down (&child->exit_sema);
  status = child->exit_status;
  list_remove (&child->elem);
  child_release (child);
  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Print process termination message for user processes that loaded. */
  if (cur->user_loaded)
    printf ("%s: exit(%d)\n", cur->name, cur->exit_status);

  /* Close all open files. */
  while (!list_empty (&cur->fds))
    {
      struct file_descriptor *fd =
        list_entry (list_pop_front (&cur->fds), struct file_descriptor, elem);
      acquire_filesys_lock ();
      file_close (fd->file);
      release_filesys_lock ();
      free (fd);
    }

  /* Close running executable to re-enable writes. */
  if (cur->executable != NULL)
    {
      acquire_filesys_lock ();
      file_allow_write (cur->executable);
      file_close (cur->executable);
      release_filesys_lock ();
      cur->executable = NULL;
    }

  /* In case filesys_lock was left held by the exiting thread. */
  if (lock_held_by_current_thread (&filesys_lock))
    release_filesys_lock ();

  /* Release children child_record references. */
  while (!list_empty (&cur->children))
    {
      struct process_child *child =
        list_entry (list_pop_front (&cur->children),
                    struct process_child, elem);
      child_release (child);
    }

  /* Notify parent of process exit. */
  if (cur->child_record != NULL)
    {
      struct process_child *child = cur->child_record;
      child->exit_status = cur->exit_status;
      child->exited = true;
      sema_up (&child->exit_sema);
      child_release (child);
      cur->child_record = NULL;
    }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

static void
child_release (struct process_child *child)
{
  enum intr_level old_level = intr_disable ();
  child->refs--;
  bool should_free = (child->refs == 0);
  intr_set_level (old_level);

  if (should_free)
    {
      if (child->cmdline != NULL)
        palloc_free_page (child->cmdline);
      free (child);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   in the file. */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Pushes argument strings, pointers, argc, and return address onto user stack. */
static bool
push_args (int argc, char **argv, void **esp)
{
  uintptr_t arg_addrs[128];
  int i;

  /* 1. Push argument strings in reverse order. */
  for (i = argc - 1; i >= 0; i--)
    {
      size_t len = strlen (argv[i]) + 1;
      *esp = (char *) *esp - len;
      if ((uint8_t *) *esp < (uint8_t *) PHYS_BASE - PGSIZE)
        return false;
      memcpy (*esp, argv[i], len);
      arg_addrs[i] = (uintptr_t) *esp;
    }

  /* 2. Word align stack pointer to 4-byte boundary. */
  uintptr_t align = (uintptr_t) *esp % 4;
  if (align != 0)
    {
      *esp = (char *) *esp - align;
      if ((uint8_t *) *esp < (uint8_t *) PHYS_BASE - PGSIZE)
        return false;
      memset (*esp, 0, align);
    }

  /* 3. Push null sentinel: argv[argc] = NULL. */
  *esp = (char **) *esp - 1;
  if ((uint8_t *) *esp < (uint8_t *) PHYS_BASE - PGSIZE)
    return false;
  *(char **) *esp = NULL;

  /* 4. Push addresses of argument strings in reverse order. */
  for (i = argc - 1; i >= 0; i--)
    {
      *esp = (uintptr_t *) *esp - 1;
      if ((uint8_t *) *esp < (uint8_t *) PHYS_BASE - PGSIZE)
        return false;
      *(uintptr_t *) *esp = arg_addrs[i];
    }

  /* 5. Push argv (pointer to argv[0]). */
  uintptr_t argv_ptr = (uintptr_t) *esp;
  *esp = (uintptr_t *) *esp - 1;
  if ((uint8_t *) *esp < (uint8_t *) PHYS_BASE - PGSIZE)
    return false;
  *(uintptr_t *) *esp = argv_ptr;

  /* 6. Push argc. */
  *esp = (int *) *esp - 1;
  if ((uint8_t *) *esp < (uint8_t *) PHYS_BASE - PGSIZE)
    return false;
  *(int *) *esp = argc;

  /* 7. Push fake return address (NULL). */
  *esp = (void **) *esp - 1;
  if ((uint8_t *) *esp < (uint8_t *) PHYS_BASE - PGSIZE)
    return false;
  *(void **) *esp = NULL;

  return true;
}

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

/* Parse arguments from file_name (which is the full command line). */
  char *cmd_copy = malloc (strlen (file_name) + 1);
  if (cmd_copy == NULL)
    goto done;

  char *argv[128];
  int argc = 0;
  char *token, *save_ptr;

  strlcpy (cmd_copy, file_name, strlen (file_name) + 1);
  for (token = strtok_r (cmd_copy, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr))
    {
      if (argc < 128)
        argv[argc++] = token;
      else
        goto done; /* Too many arguments */
    }

  if (argc == 0)
    goto done;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  acquire_filesys_lock ();
  file = filesys_open (argv[0]);
  if (file == NULL) 
    {
      release_filesys_lock ();
      printf ("load: %s: open failed\n", argv[0]);
      goto done; 
    }
  file_deny_write (file);
  release_filesys_lock ();

  /* Read and verify executable header. */
  acquire_filesys_lock ();
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      release_filesys_lock ();
      printf ("load: %s: error loading executable\n", argv[0]);
      goto done; 
    }
  release_filesys_lock ();

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      acquire_filesys_lock ();
      if (file_ofs < 0 || file_ofs > file_length (file))
        {
          release_filesys_lock ();
          goto done;
        }
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        {
          release_filesys_lock ();
          goto done;
        }
      release_filesys_lock ();

      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  if (!push_args (argc, argv, esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if (success)
    {
      t->executable = file;
      t->user_loaded = true;
    }
  else
    {
      if (file != NULL)
        {
          acquire_filesys_lock ();
          file_close (file);
          release_filesys_lock ();
        }
    }
    if (cmd_copy != NULL)     
      free (cmd_copy);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  acquire_filesys_lock ();
  file_seek (file, ofs);
  release_filesys_lock ();

  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      acquire_filesys_lock ();
      int bytes_read = file_read (file, kpage, page_read_bytes);
      release_filesys_lock ();

      if (bytes_read != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
