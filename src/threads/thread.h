#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H
#include <stdint.h>
#include <stdbool.h>
#include "../lib/debug.h"
#include "../lib/kernel/list.h"

#include "synch.h"
/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING, /* Running thread. */
	THREAD_READY, /* Not running but ready to run. */
	THREAD_BLOCKED, /* Waiting for an event to trigger. */
	THREAD_DYING /* About to be destroyed. */
};

/* Thread identifier type.
 You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

 Each thread structure is stored in its own 4 kB page.  The
 thread structure itself sits at the very bottom of the page
 (at offset 0).  The rest of the page is reserved for the
 thread's kernel stack, which grows downward from the top of
 the page (at offset 4 kB).  Here's an illustration:

 4 kB +---------------------------------+
 |          kernel stack           |
 |                |                |
 |                |                |
 |                V                |
 |         grows downward          |
 |                                 |
 |                                 |
 |                                 |
 |                                 |
 |                                 |
 |                                 |
 |                                 |
 |                                 |
 +---------------------------------+
 |              magic              |
 |                :                |
 |                :                |
 |               name              |
 |              status             |
 0 kB +---------------------------------+

 The upshot of this is twofold:

 1. First, `struct thread' must not be allowed to grow too
 big.  If it does, then there will not be enough room for
 the kernel stack.  Our base `struct thread' is only a
 few bytes in size.  It probably should stay well under 1
 kB.

 2. Second, kernel stacks must not be allowed to grow too
 large.  If a stack overflows, it will corrupt the thread
 state.  Thus, kernel functions should not allocate large
 structures or arrays as non-static local variables.  Use
 dynamic allocation with malloc() or palloc_get_page()
 instead.

 The first symptom of either of these problems will probably be
 an assertion failure in thread_current(), which checks that
 the `magic' member of the running thread's `struct thread' is
 set to THREAD_MAGIC.  Stack overflow will normally change this
 value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 the run queue (thread.c), or it can be an element in a
 semaphore wait list (synch.c).  It can be used these two ways
 only because they are mutually exclusive: only a thread in the
 ready state is on the run queue, whereas only a thread in the
 blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid; /* Thread identifier. */
	enum thread_status status; /* Thread state. */
	char name[16]; /* Name (for debugging purposes). */
	uint8_t *stack; /* Saved stack pointer. */
	int priority; /* Priority. */
	struct list_elem allelem; /* List element for all threads list. */
	/* Shared between thread.c and synch.c. */
	struct list_elem elem; /* List element. */

	// added
	int64_t wakeup_time;                     // wake up time of thread.
	struct list_elem sleep_list_elem;       // sleep list's list element
	struct semaphore thread_semaphore; // semaphore for blocking and unblocking the thread.
	int orig_priority;             //  thread's priority when created
	struct list donating_threads_list; // list of threads donating priority to this thread
	struct thread *donee;              // the thread this thread is donating to.
	struct list_elem donating_threads_elem;  // List element for donating list
	struct lock * waiting_lock;              // the clock is waiting for
	int64_t nice;                            // niceness advanced scheduler
	int32_t recent_cpu;                      // recent cpu advanced scheduler
	struct list_elem alive_list_elem;   //list element for list of alive threads

	int fd_distibution;
	struct list file_fd_list;
	/* MOVE TO USERPROG SECTION LATER */
	int exit_st; // exit status of the thread
	// added


	/* Owned by userprog/process.c. */
	uint32_t *pagedir; /* Page directory. */

	// added
	// added


	/* Owned by thread.c. */
	unsigned magic; /* Detects stack overflow. */

};


struct file_fd {
   struct list_elem file_fd_list_elem;
   struct file * fil;
   int fd;
};

/* If false (default), use round-robin scheduler.
 If true, use multi-level feedback queue scheduler.
 Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

//added
bool thread_lower_priority(const struct list_elem *a_,
		const struct list_elem *b_, void *aux UNUSED); //compare priorities of two threads
void thread_yield_to_higher_priority_(void); //check and let the thread with higher priority run
void thread_donate_priority(struct thread *donor);  // donate priority
void thread_return_to_old_priority(struct thread *releaser, struct lock *lock); //revert the changes after donating priority
void thread_priority_recompute(struct thread *t); //recompute priority of the thread
static int32_t load_average; //estimate of the average number of threads ready to run over past minute
struct list thread_list; // list of all live threads

//added

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func(struct thread *t, void *aux);
void thread_foreach(thread_action_func *, void *);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

#endif /* threads/thread.h */
