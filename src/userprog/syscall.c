#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

static struct lock filesys_lock;

static bool is_valid_ptr (const void *ptr);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static void validate_ptr (const void *ptr);
static void validate_string (const char *str);
static void validate_buffer (const void *buffer, unsigned size);

static void sys_halt (void);
static void sys_exit (int status);
static tid_t sys_exec (const char *cmdline);
static int sys_wait (tid_t pid);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int *esp = (int *) f->esp;
  
  validate_ptr (esp);
  
  int syscall_num = *esp;
  
  switch (syscall_num)
    {
    case SYS_HALT:
      sys_halt ();
      break;
      
    case SYS_EXIT:
      validate_ptr (esp + 1);
      sys_exit (*(esp + 1));
      break;
      
    case SYS_EXEC:
      validate_ptr (esp + 1);
      validate_string ((const char *) *(esp + 1));
      f->eax = sys_exec ((const char *) *(esp + 1));
      break;
      
    case SYS_WAIT:
      validate_ptr (esp + 1);
      f->eax = sys_wait (*(esp + 1));
      break;
      
    case SYS_CREATE:
      validate_ptr (esp + 1);
      validate_ptr (esp + 2);
      validate_string ((const char *) *(esp + 1));
      f->eax = sys_create ((const char *) *(esp + 1), *(esp + 2));
      break;
      
    case SYS_REMOVE:
      validate_ptr (esp + 1);
      validate_string ((const char *) *(esp + 1));
      f->eax = sys_remove ((const char *) *(esp + 1));
      break;
      
    case SYS_OPEN:
      validate_ptr (esp + 1);
      validate_string ((const char *) *(esp + 1));
      f->eax = sys_open ((const char *) *(esp + 1));
      break;
      
    case SYS_FILESIZE:
      validate_ptr (esp + 1);
      f->eax = sys_filesize (*(esp + 1));
      break;
      
    case SYS_READ:
      validate_ptr (esp + 1);
      validate_ptr (esp + 2);
      validate_ptr (esp + 3);
      validate_buffer ((void *) *(esp + 2), *(esp + 3));
      f->eax = sys_read (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
      break;
      
    case SYS_WRITE:
      validate_ptr (esp + 1);
      validate_ptr (esp + 2);
      validate_ptr (esp + 3);
      validate_buffer ((const void *) *(esp + 2), *(esp + 3));
      f->eax = sys_write (*(esp + 1), (const void *) *(esp + 2), *(esp + 3));
      break;
      
    case SYS_SEEK:
      validate_ptr (esp + 1);
      validate_ptr (esp + 2);
      sys_seek (*(esp + 1), *(esp + 2));
      break;
      
    case SYS_TELL:
      validate_ptr (esp + 1);
      f->eax = sys_tell (*(esp + 1));
      break;
      
    case SYS_CLOSE:
      validate_ptr (esp + 1);
      sys_close (*(esp + 1));
      break;
      
    default:
      printf ("Unknown system call: %d\n", syscall_num);
      sys_exit (-1);
    }
}

static void
validate_ptr (const void *ptr)
{
  if (!is_valid_ptr (ptr))
    sys_exit (-1);
}

static bool
is_valid_ptr (const void *ptr)
{
  struct thread *cur = thread_current ();
  if (ptr == NULL || !is_user_vaddr (ptr))
    return false;
  if (pagedir_get_page (cur->pagedir, ptr) == NULL)
    return false;
  return true;
}

static void
validate_string (const char *str)
{
  if (str == NULL || !is_user_vaddr (str))
    sys_exit (-1);
  
  while (true)
    {
      if (!is_valid_ptr (str))
        sys_exit (-1);
      if (*str == '\0')
        break;
      str++;
    }
}

static void
validate_buffer (const void *buffer, unsigned size)
{
  unsigned i;
  const char *buf = (const char *) buffer;
  
  for (i = 0; i < size; i++)
    {
      if (!is_valid_ptr (buf + i))
        sys_exit (-1);
    }
}

static int
get_user (const uint8_t *uaddr)
{
  if (!is_user_vaddr (uaddr))
    return -1;
    
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

static bool
put_user (uint8_t *udst, uint8_t byte)
{
  if (!is_user_vaddr (udst))
    return false;
    
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
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
  cur->exit_status = status;
  thread_exit ();
}

static tid_t
sys_exec (const char *cmdline)
{
  tid_t tid;
  
  lock_acquire (&filesys_lock);
  tid = process_execute (cmdline);
  lock_release (&filesys_lock);
  
  return tid;
}

static int
sys_wait (tid_t pid)
{
  return process_wait (pid);
}

static bool
sys_create (const char *file, unsigned initial_size)
{
  bool success;
  
  if (file == NULL)
    sys_exit (-1);
  
  lock_acquire (&filesys_lock);
  success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  
  return success;
}

static bool
sys_remove (const char *file)
{
  bool success;
  
  if (file == NULL)
    sys_exit (-1);
  
  lock_acquire (&filesys_lock);
  success = filesys_remove (file);
  lock_release (&filesys_lock);
  
  return success;
}

static int
sys_open (const char *file)
{
  struct file *f;
  struct thread *cur = thread_current ();
  int fd = -1;
  
  if (file == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  f = filesys_open (file);
  
  if (f == NULL)
    {
      lock_release (&filesys_lock);
      return -1;
    }
  
  while (cur->next_fd < 128 && cur->fd_table[cur->next_fd] != NULL)
    cur->next_fd++;
  
  if (cur->next_fd >= 128)
    {
      file_close (f);
      lock_release (&filesys_lock);
      return -1;
    }
  
  fd = cur->next_fd;
  cur->fd_table[fd] = f;
  cur->next_fd++;
  
  lock_release (&filesys_lock);
  return fd;
}

static int
sys_filesize (int fd)
{
  struct thread *cur = thread_current ();
  
  if (fd < 2 || fd >= 128 || cur->fd_table[fd] == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  int size = file_length (cur->fd_table[fd]);
  lock_release (&filesys_lock);
  
  return size;
}

static int
sys_read (int fd, void *buffer, unsigned size)
{
  struct thread *cur = thread_current ();
  int bytes_read = 0;
  
  if (fd == 0)
    {
      unsigned i;
      uint8_t *buf = (uint8_t *) buffer;
      for (i = 0; i < size; i++)
        buf[i] = input_getc ();
      return size;
    }
  
  if (fd < 2 || fd >= 128 || cur->fd_table[fd] == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  bytes_read = file_read (cur->fd_table[fd], buffer, size);
  lock_release (&filesys_lock);
  
  return bytes_read;
}

static int
sys_write (int fd, const void *buffer, unsigned size)
{
  struct thread *cur = thread_current ();
  int bytes_written = 0;
  
  if (fd == 1)
    {
      putbuf (buffer, size);
      return size;
    }
  
  if (fd < 2 || fd >= 128 || cur->fd_table[fd] == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  bytes_written = file_write (cur->fd_table[fd], buffer, size);
  lock_release (&filesys_lock);
  
  return bytes_written;
}

static void
sys_seek (int fd, unsigned position)
{
  struct thread *cur = thread_current ();
  
  if (fd < 2 || fd >= 128 || cur->fd_table[fd] == NULL)
    return;
  
  lock_acquire (&filesys_lock);
  file_seek (cur->fd_table[fd], position);
  lock_release (&filesys_lock);
}

static unsigned
sys_tell (int fd)
{
  struct thread *cur = thread_current ();
  unsigned position = 0;
  
  if (fd < 2 || fd >= 128 || cur->fd_table[fd] == NULL)
    return 0;
  
  lock_acquire (&filesys_lock);
  position = file_tell (cur->fd_table[fd]);
  lock_release (&filesys_lock);
  
  return position;
}

static void
sys_close (int fd)
{
  struct thread *cur = thread_current ();
  
  if (fd < 2 || fd >= 128 || cur->fd_table[fd] == NULL)
    return;
  
  lock_acquire (&filesys_lock);
  file_close (cur->fd_table[fd]);
  lock_release (&filesys_lock);
  
  cur->fd_table[fd] = NULL;
}
