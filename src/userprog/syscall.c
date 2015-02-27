#include "./syscall.h"
#include "../threads/interrupt.h"
#include "../threads/vaddr.h"
#include "../lib/debug.h"
#include "../threads/thread.h"
#include "../devices/shutdown.h"
#include "../lib/stdio.h"
#include "../lib/syscall-nr.h"
#include "../lib/kernel/list.h"
#include "process.h"

/*
 * static struct lock filesys_lock;

void lock_filesystem (void)
{
  if (!lock_held_by_current_thread (&filesys_lock))
    lock_acquire (&filesys_lock);
}

void release_filesystem (void)
{
  if (lock_held_by_current_thread (&filesys_lock))
    lock_release (&filesys_lock);
}*/

typedef int pid_t;

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void * check_accessing_user_memory(struct intr_frame * f) {
	if (f == NULL) {
		exit(-1);
		return NULL;
	}
	if (is_user_vaddr(f->esp)) {
		if (pagedir_get_page(thread_current()->pagedir, f->esp) != NULL) {
			return pagedir_get_page(thread_current()->pagedir, f->esp);
		} else {
			exit(-1);
			return NULL;
		}
	} else {
		exit(-1);
		return NULL;
	}
}

void * check_accessing_user_memory2(void *esp) {
	if (is_user_vaddr(esp)) {
		if (pagedir_get_page(thread_current()->pagedir, esp) != NULL) {
			return pagedir_get_page(thread_current()->pagedir, esp);
		} else {
			return NULL;
		}
	} else {
		return NULL;
	}
}

void* get_argument(struct intr_frame *f) {
	// check memory
//	while (f->esp <= PHYS_BASE) {
	printf("   address:    %p\n", f->esp);
	//	f->esp += 4;

	//}
	void * r = check_accessing_user_memory(f);
	printf("   content:    %d\n", *(int *) r);
		printf("  content2:    %s\n\n", (char *) r);
	f->esp += sizeof(char*);
	return r;
}

static void syscall_handler(struct intr_frame *f UNUSED) {
	printf("%s", "Called -----------------Sys handler\n");
	printf("   address:    %p\n", f->esp);
	printf("  abc is :    %s\n", check_accessing_user_memory2((void *) 0xbffffffc));
	printf("  echo is :    %s\n", check_accessing_user_memory2((void *) 0xbffffff7));
	hex_dump(0, f->esp, 200, 1);
	//uint32_t *stack_pointer = f->esp;
	uint32_t syscall_id = *(int*) get_argument(f);
	printf("Sys call ID is %d \n", syscall_id);
	switch (syscall_id) {
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(*((int *) get_argument(f)));
		break;
	case SYS_EXEC:
		f->eax = exec((char *) get_argument(f));
		break;
	case SYS_WAIT:
		f->eax = wait(*(pid_t *) get_argument(f));
		break;
	case SYS_CREATE:
		//f->eax = creat_file((char *) get_argument(f),
		//		*((unsigned *) get_argument(f)));
		break;
	case SYS_REMOVE:
		f->eax = remove((char *) get_argument(f));
		break;
	case SYS_OPEN:
		f->eax = open((char *) get_argument(f));
		break;
	case SYS_FILESIZE:
		f->eax = filesize(*((int *) get_argument(f)));
		break;
	case SYS_READ:
		f->eax = read(*(int *) get_argument(f), get_argument(f),
				*(unsigned *) get_argument(f));
		break;
	case SYS_WRITE:
		f->eax = write(*(int *) get_argument(f), get_argument(f),
				*(unsigned *) get_argument(f));
		break;
	case SYS_SEEK:
		f->eax = seek(*(int *) get_argument(f), *(unsigned *) get_argument(f));
		break;
	case SYS_TELL:
		f->eax = tell(*((int *) get_argument(f)));
		break;
	case SYS_CLOSE:
		close(*(int *) get_argument(f));
		break;
	 default:
	            printf("%i\n", syscall_id);
	            NOT_REACHED ();
	}
	printf("system call!\n");
	thread_exit();
}

void halt() {
	shutdown_power_off();
}

void exit(int status) {
	/*Terminates the current user program, sending its exit status to the kernel. If the process's
	 parent waits for it (see below), this is the status that will be returned. Conventionally, a
	 status of 0 indicates success and nonzero values indicate errors.
	 */
	/* struct thread *exiting_thread = thread_current();

  /* Print the terminating message
  printf("%s: exit(%d)\n", exiting_thread->name, status);

  /* Set some information about the child, for process_wait
  struct thread *parent = exiting_thread->parent;
  struct child_info *child = NULL;

  struct list_elem *elem = list_tail (&parent->children);
  while ((elem = list_prev (elem)) != list_head (&parent->children))
    {
      child = list_entry(elem, struct child_info, infoelem);
      if (child->id == exiting_thread->tid)
        break;
    }

  ASSERT (child != NULL);

  lock_acquire (&parent->cond_lock);
  child->has_exited = true;
  child->return_status = status;
  lock_release (&parent->cond_lock);

  struct list_elem *e, *next;
  for (e = list_begin (&exiting_thread->open_fds);
       e != list_end (&exiting_thread->open_fds);
       e = next)
    {
      struct fd *fd = list_entry (e, struct fd, elem);
      next = list_next (e); /* Need to remember where we're going next, since
                               close will remove itself from the list.
      close (fd->fd);
    }

  struct hash_iterator i;
  hash_first (&i, &exiting_thread->file_map);
  while (hash_next (&i))
    {
      struct hash_elem *e = hash_cur (&i);
      struct mapping *m = hash_entry (e, struct mapping, elem);

      ASSERT (m != NULL);

      munmap (m->mapid, false);
    }
  hash_clear (&exiting_thread->file_map, mapping_destroy);

  thread_exit();*/
	thread_current()->exit_st = status;
	thread_exit();
	process_exit();
}

pid_t exec(const char *cmd_line) {
	/*Runs the executable whose name is given in cmd line, passing any given arguments, and
	 returns the new process's program id (pid). Must return pid -1, which otherwise should not
	 be a valid pid, if the program cannot load or run for any reason. Thus, the parent process
	 cannot return from the exec until it knows whether the child process successfully loaded its
	 executable. You must use appropriate synchronization to ensure this.*/
	/**if (is_safe_user_ptr (cmd_line))
    {
      struct thread *current = thread_current ();

      current->child_status = LOADING;
      tid_t child_tid = process_execute (cmd_line);

      lock_acquire (&current->cond_lock);
      while (current->child_status == LOADING)
        cond_wait (&current->child_waiter, &current->cond_lock);
      lock_release (&current->cond_lock);

      return (current->child_status == FAILED) ? -1 : child_tid;
    }*/

	return process_execute(cmd_line);
}

int wait(pid_t pid) {
	/*
	 * if (!pid direct child) { // direct child if call exec receive pid
	 *   return -1;
	 * }
	 *
	 * if (already waiting) {
	 *  return -1;
	 * }
	 *
	 *
	 * get child_process = get_process_from_pid(pid);
	 * if (isAlive(child_process)) {
	 *   while (!terminate) {
	 *
	 *   }
	 *   if (called exit()) {
	 *    return get_exit_status(child_proess);
	 *   } else {
	 *   return -1;
	 *   }
	 *
	 * } else {
	 *
	 *
	 * }
	 * */
	return process_wait (pid);
}

bool creat_file(const char *file, unsigned initial_size) {
	/*Creates a new file called file initially initial size bytes in size. Returns true if successful, false
	 otherwise. Creating a new file does not open it: opening the new file is a separate operation
	 which would require a open system call.*/
	/*if (is_safe_user_ptr (file))
    {
      lock_filesystem ();
      bool status = filesys_create (file, initial_size);
      release_filesystem ();
      return status;
    }*/
	return filesys_create(file, initial_size);
}

int remove(const char *file) {
	printf(" %s ", " ---remove called---\n");
	/*Deletes the file called file. Returns true if successful, false otherwise. A file may be removed
	 regardless of whether it is open or closed, and removing an open file does not close it. See
	 [Removing an Open File], page 36, for details.*/
	/*if (is_safe_user_ptr (file))
    {
      lock_filesystem ();
      bool status = filesys_remove (file);
      release_filesystem ();
      return status;
    }*/
	if (filesys_remove(file)) {
		return 1;
	} else {
		return 0;
	}
}

int open(const char *file) {
	printf(" %s ", " ---open called---\n");
	/*Opens the file called file. Returns a nonnegative integer handle called a \file descriptor" (fd),
	 or -1 if the file could not be opened.
	 File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is stan-
	 dard input, fd 1 (STDOUT_FILENO) is standard output. The open system call will never return
	 either of these file descriptors, which are valid as system call arguments only as explicitly
	 described below.
	 Each process has an independent set of file descriptors. File descriptors are not inherited by
	 child processes.
	 When a single file is opened more than once, whether by a single process or different processes,
	 each open returns a new file descriptor. Different file descriptors for a single file are closed
	 independently in separate calls to close and they do not share a file position.*/
	/* if (is_safe_user_ptr (filename))
    {
      lock_filesystem ();

      struct file *open_file = filesys_open (filename);
      if (open_file == NULL)
        {
          release_filesystem ();
          return -1;
        }

      /* Allocate an fd.
      struct fd_node *node = malloc (sizeof (struct fd_node));
      if (node == NULL)
        PANIC ("Failed to allocate memory for file descriptor node");

      node->fd = next_fd++;
      node->thread = thread_current ();
      node->file = open_file;
      hash_insert (&fd_hash, &node->hash_elem);

      struct fd *fd = malloc (sizeof (struct fd));
      if (fd == NULL)
        PANIC ("Failed to allocate memory for file descriptor list node");
      fd->fd = node->fd;

      list_push_back (&thread_current ()->open_fds, &fd->elem);

      release_filesystem ();
      return node->fd;
    }*/

	struct file* newfile = filesys_open(file);
	return 0;
}

int filesize(int fd) {
	printf(" %s ", " ---file size called---\n");
	/*turns the size, in bytes, of the file open as fd.**/

	/*lock_filesystem ();
  int length = file_length (fd_to_file (fd));
  release_filesystem ();
  return length;*/
	return filesize(fd);
}

int read(int fd, void *buffer, unsigned size) {
	printf(" %s ", " ---Read called---\n");
	/*Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually
	 read (0 at end of file), or -1 if the file could not be read (due to a condition other than
	 end of file). Fd 0 reads from the keyboard using input_getc(), which can be found in
	 `src/devices/input.h'.*/
	if (fd == 0) { // read from key board
		int siz = 0;
		for (siz = 0; siz < size; siz++) {
			*(uint8_t*) (buffer + size) = input_getc();
		}
		return size;
	} else {
		struct file* f = get_file_from_fd(fd);
		if (f != NULL) {
			struct inode *inod = file_get_inode(f);
			struct file* newfile = file_open(inod);
			if (newfile != NULL) {
				int size_read = (int) file_read(newfile, buffer, size);
				if (size_read == file_length(newfile)) {
					return 0;
				} else if (size_read == size) {
					return size_read;
				} else {
					return -1;
				}
			} else {
				return -1;
			}
			file_close(newfile);
		} else {
			return -1;
		}
	}

}

int write(int fd, const void *buffer, unsigned size) {
	/*Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
	 written, which may be less than size if some bytes could not be written.
	 Writing past end-of-file would normally extend the file, but file growth is not implemented
	 by the basic file system. The expected behavior is to write as many bytes as possible up to
	 end-of-file and return the actual number written, or 0 if no bytes could be written at all.
	 Fd 1 writes to the console. Your code to write to the console should write all of buffer in
	 one call to putbuf(), at least as long as size is not bigger than a few hundred bytes. (It is
	 reasonable to break up larger buffers.) Otherwise, lines of text output by different processes
	 may end up interleaved on the console, confusing both human readers and our grading scripts.*/

	int temp = fd;
	fd = size;
	size = temp;

	printf(" %s ", " ---Write called---\n");
	printf("fd is %d \n", fd);
	printf(" buffer is  %s\n", (char *) buffer);
	printf(" size is %d \n", size);
	if (fd == 1) { // to console
		if (size < 100) {
			printf("size is %d", size);
			putbuf(buffer, size);
		} else {
			putbuf(buffer, 100);
			putbuf(buffer + 100, size - 100);
		}
		return size;
	} else {
		struct file* f = get_file_from_fd(fd);
		if (f != NULL) {
			struct inode *inod = file_get_inode(f);
			struct file* newfile = file_open(inod);
			if (newfile != NULL) {
				int size_wrote = file_write(newfile, buffer, size);
				return size_wrote;
			} else {
				return 0;
			}
		} else {
			return 0;
		}
	}
}

void seek(int fd, unsigned position) {
	/*Changes the next byte to be read or written in open file fd to position, expressed in bytes
	 from the beginning of the file. (Thus, a position of 0 is the file's start.)
	 A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating
	 end of file. A later write extends the file, filling any unwritten gap with zeros. (However, in
	 Pintos files have a fixed length until task 4 is complete, so writes past end of file will return
	 an error.) These semantics are implemented in the file system and do not require any special
	 effort in system call implementation.

	 lock_filesystem ();
  file_seek (fd_to_file (fd), position);
  release_filesystem ();
	 */
}

int tell(int fd) {
	/*Returns the position of the next byte to be read or written in open file fd, expressed in bytes
	 from the beginning of the file.

	  lock_filesystem ();
  unsigned next = file_tell (fd_to_file (fd));
  release_filesystem ();
  return next;
	 */
	return 0;
}

void close(int fd) {
	file_close(get_file_from_fd(fd));
	/*Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file
	 descriptors, as if by calling this function for each one.*/
}

/**
 /* Reads a byte at user virtual address UADDR.
 UADDR must be below PHYS_BASE.
 Returns the byte value if successful, -1 if a segfault
 occurred.
 static int
 get_user (const uint8_t *uaddr)
 {
 int result;
 asm ("movl $1f, %0; movzbl %1, %0; 1:"
 : "=&a" (result) : "m" (*uaddr));
 return result;
 }
 /* Writes BYTE to user address UDST.
 UDST must be below PHYS_BASE.
 Returns true if successful, false if a segfault occurred.
 static bool
 put_user (uint8_t *udst, uint8_t byte)
 {
 int error_code;
 asm ("movl $1f, %0; movb %b2, %1; 1:"
 : "=&a" (error_code), "=m" (*udst) : "q" (byte));
 return error_code != -1;
 }
 */

