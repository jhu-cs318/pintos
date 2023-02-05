#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"

#define SYS_ERROR -1
#define NOT_LOADED 0
#define LOAD_FAILED 2
#define LOADED 1
#define ALL_FDESC_CLOSE -1
#define USER_VADDR_BOTTOM ((void *) 0x08048000)

struct lock fs_lock;

struct process_file {
    struct file *file;
    int fd;
    struct list_elem elem;
};

struct child_process {
  int pid, load_status, wait, exit, status;
  struct semaphore load_sema, exit_sema;
  struct list_elem elem;
};

void syscall_init (void);

#endif /* userprog/syscall.h */