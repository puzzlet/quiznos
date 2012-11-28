#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

/* This is a skeleton system call handler */

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  hex_dump((uintptr_t)f->esp, f->esp, 64, true);
  switch (*((int*)(f->esp)))
    {
      case SYS_HALT:
      case SYS_EXIT:
      case SYS_EXEC:
      case SYS_WAIT:
      case SYS_CREATE: 
      case SYS_REMOVE:
      case SYS_OPEN:
      case SYS_FILESIZE:
      case SYS_READ:
      case SYS_WRITE:
      case SYS_SEEK:
      case SYS_TELL:
      case SYS_CLOSE:
          break;
    }
  thread_exit ();
}
