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
#include "pagedir.h"
#include "../filesys/filesys.h"
#include "../devices/input.h"
#include "../filesys/file.h"
#include "../lib/kernel/stdio.h"

void lock_filesystem(void) {
	if (!lock_held_by_current_thread(&filesys_lock))
		lock_acquire(&filesys_lock);
}

void release_filesystem(void) {
	if (lock_held_by_current_thread(&filesys_lock))
		lock_release(&filesys_lock);
}

typedef int pid_t;

int argu_num = 0;

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&filesys_lock);
}

void * check_accessing_user_memory(struct intr_frame * f) {
	if (f == NULL) {
		exit(-1);
		return NULL;
	}
	if (is_user_vaddr(f->esp + argu_num)) {
		if (pagedir_get_page(thread_current()->pagedir,
				f->esp + argu_num) != NULL) {
			//printf("    addd:    %p\n", f->esp+argu_num);
			return pagedir_get_page(thread_current()->pagedir,
					f->esp + argu_num);
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
	//printf("   addd:    %p\n", esp);
	if (is_user_vaddr(esp)) {
		//printf("acces 2 success 1\n");
		if (pagedir_get_page(thread_current()->pagedir, esp) != NULL) {
			//printf("acces 2 success\n");
			return pagedir_get_page(thread_current()->pagedir, esp);
		} else {
			exit(-1);
			return NULL;
		}
	} else {
		//printf("acces 2 fail\n");
		exit(-1);
		return NULL;
	}
}

void* get_argument(struct intr_frame *f) {
	// check memory
//	while (f->esp <= PHYS_BASE) {
	//printf("   address:    %p\n", f->esp+argu_num);
	//	f->esp += 4;

	//}
	void *r = check_accessing_user_memory(f);
	//printf("   content:    %d\n", *(int *) r);
	//	printf("  content2:    %s\n", (char *) r);
	//printf("  content3:    %p\n", r);
	//	printf("  content4:    %s\n", (char *)check_accessing_user_memory2(r));
	//if (argu_num == 8){
	//	printf("  content5:    %s\n\n", *(char***)r);
	//printf("  content6:    %s\n\n", (char *)*(int*)r);
	//}
	argu_num += sizeof(int);
	return r;
}

static void syscall_handler(struct intr_frame *f UNUSED) {
	//printf("%s", "Called -----------------Sys handler \n");
	argu_num = 0;
	//printf("   address:    %p\n", f->esp);
//	printf("  abc is :    %s\n", check_accessing_user_memory2((void *) 0xbffffffc));
//	printf("  echo is :    %s\n", check_accessing_user_memory2((void *) 0xbffffff7));
//	printf("  abc is :    %s\n", *(void **)(f->esp+8));--------
	//putbuf(f->esp+8, 4);
	//hex_dump(f->esp, f->esp, 200, 1);
	//uint32_t *stack_pointer = f->esp;
	uint32_t syscall_id = *(int*) get_argument(f);
	//printf("Sys call ID is %d \n", syscall_id);
	switch (syscall_id) {
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		f->eax = exit(*((int *) get_argument(f)));
		//printf("exit returned\n");
		break;
	case SYS_EXEC: {
		char * real_buffer = (char *) check_accessing_user_memory2(
				*(void **) get_argument(f));
		f->eax = exec(real_buffer);
	}
		break;
	case SYS_WAIT:
		f->eax = wait(*(pid_t *) get_argument(f));
		printf(" debug wait 3\n");
		//printf("wait returned\n");
		break;
	case SYS_CREATE: {
		void * fn = get_argument(f);
		unsigned size = *((unsigned *) get_argument(f));
		f->eax = creat_file(fn, size);
	}
		break;
	case SYS_REMOVE:
		f->eax = remove(get_argument(f));
		break;
	case SYS_OPEN:
		f->eax = open(get_argument(f));
		break;
	case SYS_FILESIZE:
		f->eax = filesize(*((int *) get_argument(f)));
		break;
	case SYS_READ: {
		//printf("read called \n");
		int fd = *(int *) get_argument(f);
		//printf("fd: %d\n", fd);
		char * real_buffer = (char *) check_accessing_user_memory2(
				*(void **) get_argument(f));
		//printf("buffer: %s\n", (char*) real_buffer);
		unsigned size = *(unsigned *) get_argument(f);
		//printf("size: %d\n", size);
		f->eax = read(fd, real_buffer, size);
		//printf("size read: %d\n", f->eax);
		//write(1, real_buffer, size);

		//printf("size should be  read: %d\n", strlen((char*) real_buffer));
	}
		break;
	case SYS_WRITE: {
		//printf("write called \n");
		int fd = *(int *) get_argument(f);
		char * real_buffer = (char *) check_accessing_user_memory2(
				*(void **) get_argument(f));
		unsigned size = *(unsigned *) get_argument(f);
		//printf("fd %d rb %s s %d\n",fd, real_buffer, size);
		f->eax = write(fd, real_buffer, size);
		//printf(" write return: %d \n",f->eax);
	}
		break;
	case SYS_SEEK: {
		//hex_dump(f->esp-30, f->esp-30, 100, 1);

		int h = *(int *) get_argument(f);
		unsigned off = *(unsigned *) get_argument(f);
//printf("handle = %d\n", h);
//printf("off = %d\n", off);
		seek(h, off);
	}

		break;
	case SYS_TELL:
		f->eax = tell(*((int *) get_argument(f)));
		break;
	case SYS_CLOSE:
		close(*(int *) get_argument(f));
		break;
	default:
		printf("NOT REACCHED %i\n", syscall_id);
		NOT_REACHED ()
		;
	}

	//printf("system call!\n");
	//thread_exit();
}

void halt() {
	shutdown_power_off();
}

int exit(int status) {
	/*Terminates the current user program, sending its exit status to the kernel. If the process's
	 parent waits for it (see below), this is the status that will be returned. Conventionally, a
	 status of 0 indicates success and nonzero values indicate errors.
	 */
	//printf("::::::::::thread %d exit called with %d ::::::::::::\n",
		//	thread_current()->tid, status);
	thread_current()->exit_status = status;
	printf("%s: exit(%d),%d,\n", thread_current()->name,thread_current()->tid, status);
	///printf("exit call thread exit \n");
	thread_exit();
	//printf(" :::::::::::::::::thread exit return to exit\n");
	//printf(":::::::::: exit return  with %d ::::::::::::\n", status);
	return status;

}

pid_t exec(const char *cmd_line) {
	//printf(" %s ", " ---exec called---\n");
	/*Runs the executable whose name is given in cmd line, passing any given arguments, and
	 returns the new process's program id (pid). Must return pid -1, which otherwise should not
	 be a valid pid, if the program cannot load or run for any reason. Thus, the parent process
	 cannot return from the exec until it knows whether the child process successfully loaded its
	 executable. You must use appropriate synchronization to ensure this.*/
	//printf("exe get calles ;;;;;;;;;;;;;;;;;\n");
	lock_filesystem();
	//printf("exec call process execute\n");
	tid_t id = process_execute(cmd_line);
	//printf(" process execute return to exec\n");
	release_filesystem();
	//printf("----exec return---- %d \n", id);
	return id;
}

int wait(pid_t pid) {
	//printf(" %s ", " ---wait called---\n");
	printf("-debug wait 1----- %d waits for id : %d \n", thread_current()->tid, pid);
	//printf(" debug wait 1\n");
	if (pid == -1) {
		//printf(" ----wait return error code: -1 \n");
		return -1;
	}
	int r = process_wait(pid);
	printf(" debug wait 2\n");
	//printf(" ---- %d waits for something return : %d \n", thread_current()->tid,
		//	r);
	return r;
}

int creat_file(void *file, unsigned initial_size) {
	/*Creates a new file called file initially initial size bytes in size. Returns true if successful, false
	 otherwise. Creating a new file does not open it: opening the new file is a separate operation
	 which would require a open system call.*/
	lock_filesystem();
	char * real_file = (char *) check_accessing_user_memory2(*(void **) file);
	//printf(" real file %s\n",real_file);
	//printf("%d\n",initial_size);
	int filesys_cr = filesys_create(real_file, initial_size) ? 1 : 0;
	//printf("%d\n",filesys_cr);
	release_filesystem();
	return filesys_cr;
}

int remove(void *file) {
	//printf(" %s ", " ---remove called---\n");
	/*Deletes the file called file. Returns true if successful, false otherwise. A file may be removed
	 regardless of whether it is open or closed, and removing an open file does not close it. See
	 [Removing an Open File], page 36, for details.*/
	lock_filesystem();
	char * real_file = (char *) check_accessing_user_memory2(*(void **) file);
	int rem = filesys_remove(real_file);
	release_filesystem();
	return rem;
}

int open(void *file) {
	//printf(" %s ", " ---open called---\n");
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

	lock_filesystem();
	char * real_file = (char *) check_accessing_user_memory2(*(void **) file);
	struct file* newfile = filesys_open(real_file);
	release_filesystem();
	if (newfile == NULL) {
		//printf("not getting file in open\n");
		return -1;
	}
	int ret = add_file_to_thread(newfile);
	//printf("open returning %d\n",ret);
	return ret;
}

int filesize(int fd) {
	//printf(" %s ", " ---file size called---\n");
	/*turns the size, in bytes, of the file open as fd.**/

	struct thread *t = thread_current();
	struct file *f = get_file_from_fd(fd);
	if (f == NULL)
		//printf("not getting file in file size\n");
	exit(-1);
	return file_length(f);
}

int read(int fd, void *buffer, unsigned size) {
	//printf(" %s ", " ---Read called---\n");
	/*Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually
	 read (0 at end of file), or -1 if the file could not be read (due to a condition other than
	 end of file). Fd 0 reads from the keyboard using input_getc(), which can be found in
	 `src/devices/input.h'.*/
	//printf("read called \n");
	struct thread * t = thread_current();
	if (fd == 1) {
		//printf(" %s ", "error\n");
		exit(-1);
		return -1;
		//ERROR, try to read from std out
	} else if (fd == 0) { // read from key board
		//printf(" %s ", "read from key board\n");
		int siz = 0;
		lock_filesystem();
		for (siz = 0; siz < size; siz++) {
			*(uint8_t*) (buffer + size) = input_getc();
		}
		release_filesystem();
		return size;
	} else {
		lock_filesystem();
		//printf("leng th %d\n",list_size(&t->file_fd_list));
		if (list_empty(&t->file_fd_list)) {
		//	printf("fd list empty -----\n");
			release_filesystem();
			exit(-1);
			return -1;
		}
		struct file* f = get_file_from_fd(fd);
		if (f != NULL) {
			//	printf("reading with %d  %p  %d\n",fd,buffer,size);
			//file_seek(f, 0);
			int l = file_length(f);
			//	printf("file length: %d\n", l);
			//			int	size_read = (int) file_read(f, buffer, l );
			//		printf("size read long: %d\n", size_read);
			//	printf("buffer read: long %s\n", buffer);
			//file_seek(f, 260);
			int size_read = (int) file_read(f, buffer, size);
			//printf("size read real: %d\n", size_read);
			//	printf("buffer after read: %s\n", (char*) buffer);
			if (size_read == size) {
				release_filesystem();
				return size_read;
			} else if (size_read == file_length(f) && size_read != size) {
				release_filesystem();
				return 0;
			} else {
				//printf("read exit -1 1 %d\n");
				release_filesystem();
				exit(-1);
				return -1;
			}

		} else {
			//printf("NULL -----\n");
			release_filesystem();
			exit(-1);
			return -1;
		}
	}

}

int write(int fd, const void *buffer, unsigned size) {
	struct thread * t = thread_current();

	if (fd == 0) {
		exit(-1);
		return -1;
	} else if (fd == 1) { // to console
		lock_filesystem();
		int written = 0;
		if (size < 200) {
			putbuf(buffer, size);
			written = size;
		} else {
			while (size > 200) {
				putbuf((buffer + written), 200);
				size -= 200;
				written += 200;
			}
			putbuf((buffer + written), size);
			written += size;
		}
		release_filesystem();
		return written;
	} else {
		if (list_empty(&t->file_fd_list)) {
			//printf("fd list empty -----\n");
			//release_filesystem();
			exit(-1);
			return -1;
		}
		struct file* f = get_file_from_fd(fd);
		if (f != NULL) {
			lock_filesystem();
			if (f != NULL) {
				//printf("writing ing \n");
				//printf("writing with %d  %p  %d\n",fd,buffer,size);
				int size_wrote = file_write(f, buffer, size);
				//write(1,buffer,size);
				//printf("wrtoe : %d\n", size_wrote);
				release_filesystem();
				return size_wrote;
			} else {

				release_filesystem();
				return 0;
			}
		} else {
			//printf("wrtie exiting with -1\n");
			exit(-1);
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
	 */
	struct thread * t = thread_current();
	struct file * f = get_file_from_fd(fd);
	if (f == NULL) {
		//printf("not getting file in seek\n");
		exit(-1);
	}
	lock_filesystem();
	file_seek(f, position);
	release_filesystem();
}

int tell(int fd) {
	/*Returns the position of the next byte to be read or written in open file fd, expressed in bytes
	 from the beginning of the file.
	 */
	struct thread * t = thread_current();
	struct file * f = get_file_from_fd(fd);
	if (f == NULL)
		//printf("not getting file in tell\n");
	exit(-1); // not getting file
	lock_filesystem();
	off_t position = file_tell(f);
	release_filesystem();
	return position;
}

void close(int fd) {
	if (list_empty(&thread_current()->file_fd_list)) {
		//printf("file list empty in close\n");
		exit(-1); // no file to close
	}
	struct file * f = delete_file_from_thread(fd);
	if (f == NULL) {
		//printf("not getting file in close\n");
		exit(-1); // not getting file
	} else {
		lock_filesystem();
		file_close(f);      //Close file in the system
		release_filesystem();
	}

}
/*mapid_t mmap (int fd, void *addr) [System Call]
Maps the le open as fd into the process's virtual address space. The entire le is mapped
into consecutive virtual pages starting at addr.
Your VM system must lazily load pages in mmap regions and use the mmaped le itself as
backing store for the mapping. That is, evicting a page mapped by mmap writes it back to
the le it was mapped from.
If the le's length is not a multiple of PGSIZE, then some bytes in the nal mapped page
\stick out" beyond the end of the le. Set these bytes to zero when the page is faulted in
from the le system, and discard them when the page is written back to disk.
If successful, this function returns a \mapping ID" that uniquely identies the mapping within
the process. On failure, it must return -1, which otherwise should not be a valid mapping id,
and the process's mappings must be unchanged.
A call to mmap may fail if the le open as fd has a length of zero bytes. It must fail if addr is
not page-aligned or if the range of pages mapped overlaps any existing set of mapped pages,
including the stack or pages mapped at executable load time. It must also fail if addr is 0,
because some Pintos code assumes virtual page 0 is not mapped. Finally, le descriptors 0
and 1, representing console input and output, are not mappable.
void munmap (mapid t mapping) [System Call]
Unmaps the mapping designated by mapping, which must be a mapping ID returned by a
previous call to mmap by the same process that has not yet been unmapped.*/

/*
// void mmap( int, void * ) - Mmaps a file with the given descriptor to the address in memory
static void
syscall_mmap (int *args, struct intr_frame *f UNUSED)
{
  struct thread * t = thread_current ();

  if(args[1] == 0 || args[1] == 1){
    f->eax = -1;
    return;
  }
  struct file_handle * fh = thread_get_file (&t->files, args[1]);
  if(fh == NULL) syscall_t_exit (t -> name, -1);

  size_t fl = file_length (fh->file);
  if(fl == 0 || args[2] == 0 || args[2] % PGSIZE > 0){
    f->eax = -1;
    return;
  }

  // Book the memory
  int mmap_fd = thread_add_mmap_file (file_reopen (fh->file));
  struct file_handle * mmap_fh = thread_get_file (&t->mmap_files, mmap_fd);

  void * upage = (void*)args[2];
  mmap_fh->upage = upage;
  int pages = fl / PGSIZE;
  if(fl % PGSIZE > 0){
    pages++;
  }

  int i;
  for(i = 0; i < pages; i++){
    size_t zero_after = (i == pages - 1) ? fl % PGSIZE : PGSIZE;
    off_t offset = i * PGSIZE;
    struct suppl_page *new_page = new_file_page (mmap_fh->file, offset, zero_after, true, FILE);

    sema_down (&t->pagedir_mod);
    void * overlapControl = pagedir_get_page (t->pagedir, upage + offset);
    sema_up (&t->pagedir_mod);

    if(overlapControl != 0){
      free (new_page);
      f->eax = -1;
      return;
    }
    sema_down (&t->pagedir_mod);
    pagedir_set_page_suppl (t->pagedir, upage + offset, new_page);
    sema_up (&t->pagedir_mod);
  }

  f->eax = mmap_fd;
}
/*
// void munmap( mapid_t ) - Unmaps a file with the given descriptor
static void
syscall_munmap (int *args, struct intr_frame *f UNUSED)
{
  struct thread * t = thread_current ();
  struct file_handle * fh = thread_get_file (&t->mmap_files, args[1]);
  void * upage = fh->upage;
  size_t fl = file_length (fh->file);
  int pages = fl / PGSIZE;
  if(fl % PGSIZE > 0){
    pages++;
  }

  int i;
  for(i = 0; i < pages; i++){
    void * uaddr = upage + i*PGSIZE;
    sema_down (&t->pagedir_mod);
    bool dirty = pagedir_is_dirty (t->pagedir, uaddr);
    void * kpage = pagedir_get_page(t->pagedir, uaddr);
    sema_up (&t->pagedir_mod);
    if(pg_ofs (kpage) == 0 && dirty) {
      int zero_after = (i == pages - 1) ? fl%PGSIZE : PGSIZE;
      file_seek (fh->file, i*PGSIZE);

      frame_pin (uaddr, PGSIZE);

      filesys_lock_acquire ();
      file_write (fh->file, uaddr, zero_after);
      filesys_lock_release ();

      frame_unpin (uaddr, PGSIZE);
    }
    sema_down (&t->pagedir_mod);
    pagedir_clear_page (t->pagedir, uaddr);
    sema_up (&t->pagedir_mod);
  }

  list_remove (&fh->elem);
  file_close (fh->file);
  free (fh);
}*/

