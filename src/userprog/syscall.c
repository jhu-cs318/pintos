#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define MAX_ARGS 3
#define STD_INPUT 0
#define STD_OUTPUT 1

//decleration
int get_page (const void *vaddr);
void children_remove (void);
struct child_process* find_child (int pid);
struct file* get_file(int filedes);
int add_file (struct file *file_name);
void syscall_halt (void);
bool create(const char* file_name, unsigned starting_size);
bool remove(const char* file_name);
int open(const char * file_name);
int filesize(int filedes);
int read(int filedes, void *buffer, unsigned length);
int write (int filedes, const void * buffer, unsigned byte_size);
void seek (int filedes, unsigned new_position);
unsigned tell(int fildes);
void ptr_validator (const void* vaddr);
void str_validator (const void* str);
void buf_validator (const void* buf, unsigned byte_size);
pid_t exec(const char* cmdline);
void exit (int status);
void close_file (int file_descriptor);
static void syscall_handler (struct intr_frame *);
void stack_access (struct intr_frame *f, int *arg, int num_of_args);
bool FILE_LOCK_INIT = false;

/*
 * System call initializer
 * It handles the set up for system call operations.
 */
void
syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/*
 * This method handles for various case of system command.
 * This handler invokes the proper function call to be carried
 * out base on the command line.
 */
static void
syscall_handler (struct intr_frame *f UNUSED) {

  if (!FILE_LOCK_INIT) {
    lock_init(&fs_lock);
    FILE_LOCK_INIT = true;
  }
  
  int arg[MAX_ARGS];
  int esp = get_page((const void *) f->esp);
  
  switch (* (int *) esp) {
    
    /* Halt the operating system. */
    case SYS_HALT:

      //shutdown
      shutdown_power_off();
      break;



    /* Terminate this process. */  
    case SYS_EXIT:

      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);

      //exit the process
      exit(arg[0]);

      break;



    /* Start another process. */  
    case SYS_EXEC: 
      exec((const char *) arg[0]); 

      break;



    /* Wait for child process to die. */  
    case SYS_WAIT:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);

      // execute
      f->eax = process_wait(arg[0]);
      break;



    /* Create a file. */  
    case SYS_CREATE:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 2);
      
      // check validity
      str_validator((const void *)arg[0]);
      
      // get page pointer
      arg[0] = get_page((const void *) arg[0]);
      
      // create this file
      f->eax = create((const char *)arg[0], (unsigned)arg[1]);  
    
      break;



    /* Delete a file. */  
    case SYS_REMOVE:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);
      
      // check validity 
      str_validator((const void*)arg[0]);
      
      // get page pointer
      arg[0] = get_page((const void *) arg[0]);
      
      // remove this file
      f->eax = remove((const char *)arg[0]);  
    
      break;



    /* Open a file. */  
    case SYS_OPEN:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);
      
      // check validity  
      str_validator((const void*)arg[0]);
     
     // get page pointer
      arg[0] = get_page((const void *)arg[0]);
      
      // open this file
      f->eax = open((const char *)arg[0]);  
    
      break;



    /* Obtain a file's size. */  
    case SYS_FILESIZE:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);
    
      // obtain file size
      f->eax = filesize(arg[0]);  
    
      break;



    /* Read from a file. */  
    case SYS_READ:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 3);
      
      // check validity 
      buf_validator((const void*)arg[1], (unsigned)arg[2]);
       
      // get page pointer
      arg[1] = get_page((const void *)arg[1]); 
      
      //read file
      f->eax = read(arg[0], (void *) arg[1], (unsigned) arg[2]);
    
      break;



    /* Write to a file. */  
    case SYS_WRITE:
      
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 3);
      
      // check validity 
      buf_validator((const void*)arg[1], (unsigned)arg[2]);

      // get page pointer
      arg[1] = get_page((const void *)arg[1]); 

      //write to the file
      f->eax = write(arg[0], (const void *) arg[1], (unsigned) arg[2]);

      break;



    /* Change position in a file. */  
    case SYS_SEEK:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 2);

      //change position
      seek(arg[0], (unsigned)arg[1]);
    
      break;



    /* Report current position in a file. */  
    case SYS_TELL:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);

      //get current position in file
      f->eax = tell(arg[0]);
    
      break;
    


    /* Close a file. */
    case SYS_CLOSE:
    
      // take all the arguments needed to the arg from stack
      stack_access (f, &arg[0], 1);

      //close file
      lock_acquire(&fs_lock);
      close_file(arg[0]);
      lock_release(&fs_lock);
    
      break;
      

    default:

      break;
  }
}


void
stack_access (struct intr_frame *f, int *args, int num_of_args) {

  int *ptr;
  for (int i = 0; i < num_of_args; i++) {
    ptr = (int *) f->esp + i + 1;
    ptr_validator((const void *) ptr);
    args[i] = *ptr;
  }
}


void
exit (int status) {

  struct thread *curr_thread = thread_current();
  
  if (check_thread_active(curr_thread->parent) && curr_thread->child_pr) { 
    if (status < 0)
      status = -1;
    curr_thread->child_pr->status = status;
  }

  printf("%s: exit(%d)\n", curr_thread->name, status);
  thread_exit();
}


bool
create(const char* file_name, unsigned initial_size) {
  
  lock_acquire(&fs_lock);
  bool success = filesys_create(file_name, initial_size);
  lock_release(&fs_lock);

  return success;
}


bool
remove(const char* file_name) {
  
  lock_acquire(&fs_lock);
  bool success = filesys_remove(file_name);
  lock_release(&fs_lock);

  return success;
}


int
open(const char *file_name) {
  
  lock_acquire(&fs_lock);
  struct file *file_ptr = filesys_open(file_name);
  
  if (!file_ptr) {
    lock_release(&fs_lock);
    return SYS_ERROR;
  }

  int file_des = add_file(file_ptr);
  lock_release(&fs_lock);

  return file_des;
}


int
add_file (struct file *file_name) {
  
  struct process_file *file_ptr = malloc(sizeof(struct process_file));
  
  if (!file_ptr)
    return SYS_ERROR;
    
  file_ptr->file = file_name;
  file_ptr->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back(&thread_current()->file_list, &file_ptr->elem);

  return file_ptr->fd;
}


int
read(int filedes, void *buffer, unsigned length) {
  
  if (length <= 0)
    return length;
  
  if (filedes == STD_INPUT) {
    unsigned i = 0;
    uint8_t *buf = (uint8_t *) buffer;
    
    for (;i < length; i++)
      buf[i] = input_getc(); 
    return length;
  }
  
  lock_acquire(&fs_lock);
  struct file *file_ptr = get_file(filedes);
  
  if (!file_ptr) {
    lock_release(&fs_lock);
    return SYS_ERROR;
  }

  int size = file_read(file_ptr, buffer, length);
  lock_release (&fs_lock);

  return size;
}


int 
write (int filedes, const void * buffer, unsigned byte_size) {
    
    if (byte_size <= 0)
      return byte_size;

    if (filedes == STD_OUTPUT) {
      putbuf (buffer, byte_size);
      return byte_size;
    }
    
    lock_acquire(&fs_lock);
    struct file *file_ptr = get_file(filedes);

    if (!file_ptr) {
      lock_release(&fs_lock);
      return SYS_ERROR;
    }

    int size = file_write(file_ptr, buffer, byte_size); 
    lock_release (&fs_lock);

    return size;
}


struct file*
get_file (int filedes) {

  struct thread *t = thread_current();
  struct list_elem* next;
  struct list_elem* e = list_begin(&t->file_list);
  
  for (; e != list_end(&t->file_list); e = next) {
    next = list_next(e);
    struct process_file *ptr_processing_file = list_entry(e, struct process_file, elem);

    if (filedes == ptr_processing_file->fd)
      return ptr_processing_file->file;
  }
  
  return NULL;
}


pid_t
exec(const char* cmdline) {
    //tobe
}


int
filesize(int filedes) {

  lock_acquire(&fs_lock);
  struct file *file_ptr = get_file(filedes);

  if (!file_ptr) {
    lock_release(&fs_lock);
    return SYS_ERROR;
  }

  int filesize = file_length(file_ptr);
  lock_release(&fs_lock);

  return filesize;
}


void
seek (int filedes, unsigned new_position) {

  lock_acquire(&fs_lock);
  struct file *file_ptr = get_file(filedes);

  if (!file_ptr){
    lock_release(&fs_lock);
    return;
  }

  file_seek(file_ptr, new_position);
  lock_release(&fs_lock);
}


unsigned
tell(int filedes) {

  lock_acquire(&fs_lock);
  struct file *file_ptr = get_file(filedes);

  if (!file_ptr) {
    lock_release(&fs_lock);
    return SYS_ERROR;
  }

  off_t offset = file_tell(file_ptr);
  lock_release(&fs_lock);

  return offset;
}


void
ptr_validator (const void *vaddr) {
    if (vaddr < USER_VADDR_BOTTOM || !is_user_vaddr(vaddr))
      exit(SYS_ERROR);
}


void
str_validator (const void* str) {
    for (; * (char *) get_page(str) != 0; str = (char *) str + 1);
}


void
buf_validator(const void* buf, unsigned byte_size) {

  unsigned i = 0;
  char* local_buffer = (char *)buf;

  for (; i < byte_size; i++) {
    ptr_validator((const void*)local_buffer);
    local_buffer++;
  }
}



int
get_page(const void *vaddr) {
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);

  if (!ptr)
    exit(SYS_ERROR);

  return (int)ptr;
}


struct child_process* find_child(int pid) {

  struct thread *t = thread_current();
  struct list_elem *e;
  struct list_elem *next;
  
  for (e = list_begin(&t->child_list); e != list_end(&t->child_list); e = next) {
    next = list_next(e);
    struct child_process *child_pr = list_entry(e, struct child_process, elem);

    if (pid == child_pr->pid)
      return child_pr;
  }

  return NULL;
}




/* remove all child processes */
void children_remove (void) {

  struct thread *t = thread_current();
  struct list_elem *next;
  struct list_elem *e = list_begin(&t->child_list);
  
  for (;e != list_end(&t->child_list); e = next) {
    next = list_next(e);
    struct child_process *child_pr = list_entry(e, struct child_process, elem);
    list_remove(&child_pr->elem);
    free(child_pr);
  }
}


void
close_file (int file_descriptor) {

  struct thread *t = thread_current();
  struct list_elem *next;
  struct list_elem *e = list_begin(&t->file_list);
  
  for (;e != list_end(&t->file_list); e = next) {
    next = list_next(e);
    struct process_file *ptr_processing_file = list_entry (e, struct process_file, elem);

    if (file_descriptor == ptr_processing_file->fd || file_descriptor == ALL_FDESC_CLOSE) {
      file_close(ptr_processing_file->file);
      list_remove(&ptr_processing_file->elem);
      free(ptr_processing_file);

      if (file_descriptor != ALL_FDESC_CLOSE)
        return;
    }
  }
}