#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include <list.h>

/* Defines the file descriptor used by both syscall.c and process.c */
struct file_descriptor 
  {
    int fd;
    struct file *file;
    struct list_elem elem;
  };

extern struct lock filesys_lock;
void acquire_filesys_lock (void);
void release_filesys_lock (void);

void syscall_init (void);

#endif /* userprog/syscall.h */