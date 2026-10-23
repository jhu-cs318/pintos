#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

/* Defines the child status tracking structure */
struct process_child 
  {
    tid_t tid;                  /* Thread ID of the child. */
    int exit_status;            /* Child's exit status. */
    bool load_success;          /* True if executable loaded successfully. */
    bool exited;                /* True if child has exited. */
    bool waited;                /* True if parent already called wait(). */
    int refs;                   /* Reference count (parent + child = 2). */
    char *cmdline;              /* Command line string. */
    struct semaphore load_sema; /* Semaphores for load and exit synchronization. */
    struct semaphore exit_sema;
    struct list_elem elem;      /* List element for parent's children list. */
  };

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */