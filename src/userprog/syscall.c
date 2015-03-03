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

static struct lock filesys_lock;

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
			//printf("   addd:    %p\n", f->esp+argu_num);
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
	//printf("%s", "Called -----------------Sys handler\n");
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
		break;
	case SYS_EXEC:
	{

		char * real_buffer = (char *) check_accessing_user_memory2(
						*(void **) get_argument(f));
		f->eax = exec(real_buffer);
	}
		break;
	case SYS_WAIT:
		f->eax = wait(*(pid_t *) get_argument(f));
		break;
	case SYS_CREATE:
		//hex_dump(f->esp, f->esp, 200, 1);

		//printf("  content2:    %s\n", (char *) fn);
		//	printf("  content3:    %p\n", fn);
	{
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
		//printf("read called 1\n");
		int fd = *(int *) get_argument(f);
		//printf("fd: %d\n", fd);
		char * real_buffer = (char *) check_accessing_user_memory2(
				*(void **) get_argument(f));
		//printf("buffer: %s\n", (char*) real_buffer);
		unsigned size = *(unsigned *) get_argument(f);
		//printf("size: %d\n", size);
		f->eax = read(fd, real_buffer, size);
		//printf("size read: %d\n", f->eax);
		//printf("buffer after read: %s\n", (char*) real_buffer);
		//printf("size should be  read: %d\n", strlen((char*) real_buffer));
	}
		break;
	case SYS_WRITE: {
		int fd = *(int *) get_argument(f);
		char * real_buffer = (char *) check_accessing_user_memory2(
				*(void **) get_argument(f));
		unsigned size = *(unsigned *) get_argument(f);
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
	//printf(":::::::::: exit called with %d ::::::::::::\n", status);
	thread_current()->exit_status = status;
	struct list_elem *e;
	struct file_fd *fh;
	for (e = list_begin(&thread_current()->file_fd_list);
			e != list_end(&thread_current()->file_fd_list); e = list_next(e)) {
		fh = list_entry(e, struct file_fd, file_fd_list_elem);
		close(fh->fd);
	}
	printf("%s: exit(%d)\n", thread_current()->name, status);
	///printf("exit call thread exit \n");
	thread_exit();
	//printf(" thread exit return to exit\n");
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
	//printf(" wait for id : %d \n", pid);
	if (pid == -1) {
		//printf(" ----wait return : -1 \n");
		return -1;
	}
	int r = process_wait(pid);
	//printf(" ----wait return : %d \n", r);
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
			//printf("fd list empty -----\n");
			release_filesystem();
			exit(-1);
			return -1;
		}
		struct file* f = get_file_from_fd(fd);
		if (f != NULL) {

				//printf("file length: %d\n", file_length(f));
				//printf("reading with %d",fd);
				int size_read = (int) file_read(f, buffer, size);
				//printf("size read: %d\n", size_read);
				if (size_read == size) {
					release_filesystem();
					return size_read;
				} else if (size_read == file_length(f)
						&& size_read != size) {
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
	/*Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
	 written, which may be less than size if some bytes could not be written.
	 Writing past end-of-file would normally extend the file, but file growth is not implemented
	 by the basic file system. The expected behavior is to write as many bytes as possible up to
	 end-of-file and return the actual number written, or 0 if no bytes could be written at all.
	 Fd 1 writes to the console. Your code to write to the console should write all of buffer in
	 one call to putbuf(), at least as long as size is not bigger than a few hundred bytes. (It is
	 reasonable to break up larger buffers.) Otherwise, lines of text output by different processes
	 may end up interleaved on the console, confusing both human readers and our grading scripts.*/
	struct thread * t = thread_current();
//printf(" %s ", " ---Write called---\n");
//printf("fd is %d \n", fd);
//printf(" buffer is  %s\n", (char*)buffer);
//printf(" size is %d \n", size);
	if (fd == 0) {
		//ERROR trying to write to std in
	} else if (fd == 1) { // to console
		lock_filesystem();
		int written = 0;
		if (size < 200) {
			//printf("puting... size is %d\n", size);
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
			release_filesystem();
			exit(-1);
			return -1;
		}
		struct file* f = get_file_from_fd(fd);
		if (f != NULL) {
			lock_filesystem();
			struct inode *inod = file_get_inode(f);
			struct file* newfile = file_open(inod);
			if (newfile != NULL) {
				//printf("writing ing \n");
				int size_wrote = file_write(newfile, buffer, size);
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

	//printf("seek called\n ");
	struct thread * t = thread_current();
	struct file * f = get_file_from_fd(fd);
	if (f == NULL) {
		//printf("seek called but NULL\n ");
			exit(-1);
	}


	lock_filesystem();
	//printf("seeking\n ");
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
		exit(-1);

	lock_filesystem();
	off_t position = file_tell(f);
	release_filesystem();
	return position;
}

void close(int fd) {
	/*Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file
	 descriptors, as if by calling this function for each one.*/
//printf("close called \n");
	struct thread * t = thread_current();
//printf("leng th %d\n",list_size(&t->file_fd_list));
	if (list_empty(&t->file_fd_list)) {
		//printf("list empty\n");
		exit(-1);
	}
	struct file * f = get_file_from_fd(fd);
	if (f == NULL)
		exit(-1);

	lock_filesystem();
//printf("leng th %d\n",list_size(&t->file_fd_list));
	int x = delete_file_from_thread(f);      //Remove file from files table
	if (x == -1) {
		exit(-1);
	}
	file_close(f);      //Close file in the system
//printf("leng th %d\n",list_size(&t->file_fd_list));

	release_filesystem();
}

