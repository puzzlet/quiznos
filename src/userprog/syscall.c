#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "lib/stdio.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/pte.h"
#include "threads/vaddr.h"

/* This is a skeleton system call handler */

struct file;
struct inode;
struct inode_disk;
static struct file *file_descripters[1024] = {NULL, };

bool check_user_vaddr (const void *vaddr);
int sys_exit (const uint32_t arg1);
int sys_create (const uint32_t arg1, const uint32_t arg2);
int sys_remove (const uint32_t arg1);
int sys_open (const uint32_t arg1);
int sys_filesize (const uint32_t arg1);
int sys_read (const uint32_t arg1, const uint32_t arg2, const uint32_t arg3);
int sys_write (const uint32_t arg1, const uint32_t arg2, const uint32_t arg3);
int sys_seek (const uint32_t arg1, const uint32_t arg2);
int sys_tell (const uint32_t arg1);
int sys_close (const uint32_t arg1);
static void syscall_handler (struct intr_frame *);

bool
check_user_vaddr (const void *vaddr)
{
  return is_user_vaddr(vaddr) &&
      (*(thread_current()->pagedir + pd_no(vaddr)));
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

int
sys_exit (const uint32_t arg1)
{
  printf("exit(%d)\n", arg1);
  // TODO: process name
  thread_exit();
  return arg1;
}

int
sys_create (const uint32_t arg1, const uint32_t arg2)
{
  const char *file_name = (char*)arg1;
  if (!check_user_vaddr(file_name))
    sys_exit(-1);
  return (int)filesys_create(file_name, arg2);
}

int
sys_remove (const uint32_t arg1)
{
  const char *file_name = (char*)arg1;
  if (!check_user_vaddr(file_name))
    sys_exit(-1);
  return (int)filesys_remove(file_name);
}

int
sys_open (const uint32_t arg1)
{
  const char *file_name = (char*)arg1;
  if (!check_user_vaddr(file_name))
    sys_exit(-1);
  struct file *fp = filesys_open(file_name);
  if (fp == NULL)
    return -1;
  int i;
  for (i = 3; i < 1024; i++)
    {
      if (file_descripters[i] == NULL)
        break;
    }
  if (i >= 1024)
    return -1;
  file_descripters[i] = fp;
  return i;
}

int
sys_filesize (const uint32_t arg1)
{
  struct file *fp = file_descripters[arg1];
  return fp->inode->data.length;
}

int
sys_read (const uint32_t arg1, const uint32_t arg2, const uint32_t arg3)
{
  struct file *fp = file_descripters[arg1];
  void *buffer = (void*)arg2;
  if (!check_user_vaddr(buffer))
    sys_exit(-1);
  unsigned int size = arg3;
  int ret = file_read(fp, buffer, size);
  return ret;
}

int
sys_write (const uint32_t arg1, const uint32_t arg2, const uint32_t arg3)
{
  struct file *fp = file_descripters[arg1];
  const void *buffer = (void*)arg2;
  if (!check_user_vaddr(buffer))
    sys_exit(-1);
  unsigned int size = arg3;
  switch (arg1)
    {
      case 1:
        putbuf(buffer, size);
        return size;
      default:
        if (fp == NULL) return 0;
        return file_write(fp, buffer, size);
    }
  return 0;
}

int
sys_seek (const uint32_t arg1, const uint32_t arg2)
{
  struct file *fp = file_descripters[arg1];
  if (fp == NULL)
    return -1;
  file_seek(fp, arg2);
  return 0;
}

int
sys_tell (const uint32_t arg1)
{
  struct file *fp = file_descripters[arg1];
  if (fp == NULL)
    return -1;
  return file_tell(fp);
}

int
sys_close (const uint32_t arg1)
{
  struct file *fp = file_descripters[arg1];
  if (fp == NULL)
    return -1;
  file_close(fp);
  file_descripters[arg1] = NULL;
  return 0;
}

static void
syscall_handler (struct intr_frame *f)
{
  uint32_t code = *(uint32_t*)(f->esp);
  uint32_t arg1 = *((uint32_t*)(f->esp) + 1);
  uint32_t arg2 = *((uint32_t*)(f->esp) + 2);
  uint32_t arg3 = *((uint32_t*)(f->esp) + 3);
  switch (code)
    {
      case SYS_HALT:
        // TODO
        break;
      case SYS_EXIT:
        sys_exit(arg1);
        break;
      case SYS_EXEC:
      case SYS_WAIT:
        break;
      case SYS_CREATE:
        f->eax = sys_create(arg1, arg2);
        break;
      case SYS_REMOVE:
        f->eax = sys_remove(arg1);
        break;
      case SYS_OPEN:
        f->eax = sys_open(arg1);
        break;
      case SYS_FILESIZE:
        f->eax = sys_filesize(arg1);
        break;
      case SYS_READ:
        f->eax = sys_read(arg1, arg2, arg3);
        break;
      case SYS_WRITE:
        f->eax = sys_write(arg1, arg2, arg3);
        break;
      case SYS_SEEK:
        f->eax = sys_seek(arg1, arg2);
        break;
      case SYS_TELL:
        f->eax = sys_tell(arg1);
        break;
      case SYS_CLOSE:
        f->eax = sys_close(arg1);
        break;
    }
}
