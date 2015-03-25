#include <stddef.h>

#include <stdio.h>
#include <string.h>
#include "../lib/kernel/list.h"
#include "synch.h"
#include "thread.h"
#include "interrupt.h"
#include "palloc.h"
#include "switch.h"
#include "vaddr.h"
#include "../lib/string.h"
#include "fixed-point.h"
#include "../devices/timer.h"
#include "malloc.h"
#include "../userprog/process.h"
#include "../filesys/file.h"

#define NICE_DEFAULT 0
#define NICE_MAX 20
#define NICE_MIN 20

#define RECENT_CPU_DEFAULT 0

/* Random value for struct thread's `magic' member.
 Used to detect stack overflow.  See the big comment at the top
 of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
 that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
 when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame {
	void *eip; /* Return address. */
	thread_func *function; /* Function to call. */
	void *aux; /* Auxiliary data for function. */
};

/* Statistics. */
static long long idle_ticks; /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks; /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

static int32_t load_average;

/* If false (default), use round-robin scheduler.
 If true, use multi-level feedback queue scheduler.
 Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *running_thread(void);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static bool is_thread(struct thread *) UNUSED;
static void *alloc_frame(struct thread *, size_t size);
static void schedule(void);
void thread_schedule_tail(struct thread *prev);
static tid_t allocate_tid(void);

/* Initializes the threading system by transforming the code
 that's currently running into a thread.  This can't work in
 general and it is possible in this case only because loader.S
 was careful to put the bottom of the stack at a page boundary.

 Also initializes the run queue and the tid lock.

 After calling this function, be sure to initialize the page
 allocator before trying to create any threads with
 thread_create().

 It is not safe to call thread_current() until this function
 finishes. */
void thread_init(void) {
	ASSERT(intr_get_level() == INTR_OFF);

	lock_init(&tid_lock);
	list_init(&ready_list);
	list_init(&all_list);
	list_init(&thread_list);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread();
	init_thread(initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid();
	initial_thread->nice = 0;
	initial_thread->recent_cpu = 0;
	load_average = 0;
}

/* Starts preemptive thread scheduling by enabling interrupts.
 Also creates the idle thread. */
void thread_start(void) {
	/* Create the idle thread. */
	list_push_back(&thread_list, &initial_thread->alive_list_elem);
	struct semaphore idle_started;
	sema_init(&idle_started, 0);
	thread_create("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
 Thus, this function runs in an external interrupt context. */
void thread_tick(void) {
	struct thread *t = thread_current();
	struct list_elem *e;
	int i = 0;
	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pagedir != NULL)
	user_ticks++;
#endif
	else
		kernel_ticks++;

	thread_ticks++;

	if (thread_mlfqs) {
		t->recent_cpu += convert_to_fixed(!(t == idle_thread)); // increment recent cpu each tick
		if (timer_ticks() % TIMER_FREQ == 0) { // each second
			int ready_threads = list_size(&ready_list) + (t != idle_thread);

			// recompute load avg
			load_average = (((int64_t) (59 * F / 60) * load_average / F)
					+ ((F / 60) * ready_threads));

			for (e = list_begin(&thread_list); e != list_end(&thread_list); e =
					list_next(e)) {
				// recompute recent cpu
				struct thread *t = list_entry(e, struct thread,
						alive_list_elem);
				//recent_cpu = quotient * recent_cpu + nice.
				//quotient = (2 * load_avg) / (2 * load_avg + 1)
				int32_t quotient = (((int64_t) (2 * load_average)) * F
						/ (2 * load_average + F));
				t->recent_cpu = (((int64_t) quotient) * (t->recent_cpu) / F)
						+ (t->nice) * F;
			}
		}

		if (!(timer_ticks() % 4)) { // every time slice (1/25 second)
			for (e = list_begin(&thread_list); e != list_end(&thread_list); e =
					list_next(e)) {
				struct thread *t = list_entry(e, struct thread,
						alive_list_elem);
				// priority = PRI_MAX - (recent_cpu / 4) - (nice * 2).
				int new_priority = convert_to_int_nearest_rounding(
						PRI_MAX*F - ((t->recent_cpu)/4) - ((t->nice)*F) * 2);

				//if as a result of calculation priority is out of boundaries - update priority to fix limits
				//priority = min(old, pri_max) && max(old, pri_min)
				new_priority =
						(new_priority < PRI_MIN) ? PRI_MIN :
						(new_priority > PRI_MAX) ? PRI_MAX : new_priority;
				//new_priority = (new_priority > PRI_MAX) ? PRI_MAX : new_priority;
				t->orig_priority = new_priority;
				t->priority = new_priority;
			}

		}

	}

	if (thread_ticks >= TIME_SLICE)
		intr_yield_on_return();
}

/* Prints thread statistics. */
void thread_print_stats(void) {
	printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
 PRIORITY, which executes FUNCTION passing AUX as the argument,
 and adds it to the ready queue.  Returns the thread identifier
 for the new thread, or TID_ERROR if creation fails.

 If thread_start() has been called, then the new thread may be
 scheduled before thread_create() returns.  It could even exit
 before thread_create() returns.  Contrariwise, the original
 thread may run for any amount of time before the new thread is
 scheduled.  Use a semaphore or some other form of
 synchronization if you need to ensure ordering.

 The code provided sets the new thread's `priority' member to
 PRIORITY, but no actual priority scheduling is implemented.
 Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char *name, int priority, thread_func *function,
		void *aux) {
	struct thread *t;
	struct kernel_thread_frame *kf;
	struct switch_entry_frame *ef;
	struct switch_threads_frame *sf;
	tid_t tid;
	enum intr_level old_level;

	ASSERT(function != NULL);

	/* Allocate thread. */
	t = palloc_get_page(PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread(t, name, priority);
	tid = t->tid = allocate_tid();
//printf("create 2 ===========%d\n",tid);

	/* Prepare thread for first run by initializing its stack.
	 Do this atomically so intermediate values for the 'stack'
	 member cannot be observed. */
	old_level = intr_disable();

	if (thread_mlfqs) {
		//set thread's fields for advanced scheduler
		//change thread's priority to initial priority for advanced scheduler
		//overwriting priority passed to init_thread()
		struct thread *cur = thread_current();
		t->nice = cur->nice;
		t->recent_cpu = cur->recent_cpu;
		t->priority = PRI_MAX - (t->recent_cpu / (4 * F)) - (t->nice * 2);
		t->orig_priority = t->priority;
	}

	/* Stack frame for kernel_thread(). */
	kf = alloc_frame(t, sizeof *kf);
	kf->eip = NULL;
	kf->function = function;
	kf->aux = aux;

	/* Stack frame for switch_entry(). */
	ef = alloc_frame(t, sizeof *ef);
	ef->eip = (void (*)(void)) kernel_thread;

	/* Stack frame for switch_threads(). */
	sf = alloc_frame(t, sizeof *sf);
	sf->eip = switch_entry;
	sf->ebp = 0;

	list_push_back(&thread_list, &t->alive_list_elem); // we added

	intr_set_level(old_level);

	/* Add to run queue. */
	thread_unblock(t);
	thread_yield_to_higher_priority_();
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
 again until awoken by thread_unblock().

 This function must be called with interrupts turned off.  It
 is usually a better idea to use one of the synchronization
 primitives in synch.h. */
void thread_block(void) {
	ASSERT(!intr_context());
	ASSERT(intr_get_level() == INTR_OFF);
	thread_current()->status = THREAD_BLOCKED;
	schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
 This is an error if T is not blocked.  (Use thread_yield() to
 make the running thread ready.)

 This function does not preempt the running thread.  This can
 be important: if the caller had disabled interrupts itself,
 it may expect that it can atomically unblock a thread and
 update other data. */
void thread_unblock(struct thread *t) {
	enum intr_level old_level;
	ASSERT(is_thread(t));
	old_level = intr_disable();
	ASSERT(t->status == THREAD_BLOCKED);
	list_push_back(&ready_list, &t->elem);
	t->status = THREAD_READY;
	intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name(void) {
	return thread_current()->name;
}

/* Returns the running thread.
 This is running_thread() plus a couple of sanity checks.
 See the big comment at the top of thread.h for details. */
struct thread *
thread_current(void) {
	struct thread *t = running_thread();

	/* Make sure T is really a thread.
	 If either of these assertions fire, then your thread may
	 have overflowed its stack.  Each thread has less than 4 kB
	 of stack, so a few big automatic arrays or moderate
	 recursion can cause stack overflow. */
	ASSERT(is_thread(t));
	ASSERT(t->status == THREAD_RUNNING);
	return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void) {
	return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  Never
 returns to the caller. */
void thread_exit(void) {
	printf("%s", "Thread exit called!\n");
	ASSERT(!intr_context());

#ifdef USERPROG

	struct list_elem *e;
	struct file_fd * fh;
	struct return_status * rs;

    printf("%s", "debug 1\n");
	while(!list_empty(&thread_current()->file_fd_list)) {
		e = list_pop_front(&thread_current()->file_fd_list);
		fh = list_entry(e, struct file_fd, file_fd_list_elem);
		file_close(fh->fil);
		free(fh);
	}

	//for (e = list_begin(&thread_current()->file_fd_list);
	//e != list_end(&thread_current()->file_fd_list); e = list_next(e)) {
	//	free(fh);
	//}
printf("%s", "debug 2\n");
	while (!list_empty(&thread_current()->children_return)) {
		e = list_pop_front(&thread_current()->children_return);
		rs = list_entry(e, struct return_status, returnelem);
		free(rs);
	}
printf("%s", "debug 3\n");
	if (thread_current()->parent != NULL) {
		struct return_status * return_status = malloc(
				sizeof(struct return_status));
		return_status->tid = thread_current()->tid;
		return_status->return_code = thread_current()->exit_status;
		list_push_back(&thread_current()->parent->children_return, &return_status->returnelem);
	}
printf("%s", "debug 4\n");
	//printf("thread exit call process exit \n");
	process_exit ();
	printf("%s", "debug 5\n");
	//printf("process exit returned tid: %d\n", thread_current()->tid);
#endif

	/* Remove thread from all threads list, set our status to dying,
	 and schedule another process.  That process will destroy us
	 when it calls thread_schedule_tail(). */
	intr_disable();
	list_remove(&thread_current()->allelem);
	list_remove(&thread_current()->child);
	list_remove(&thread_current()->alive_list_elem);
	thread_current()->status = THREAD_DYING;
	schedule();
	NOT_REACHED ()
	;
}

/* Yields the CPU.  The current thread is not put to sleep and
 may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void) {
	struct thread *cur = thread_current();
	enum intr_level old_level;

	ASSERT(!intr_context());

	old_level = intr_disable();
	if (cur != idle_thread)
		list_push_back(&ready_list, &cur->elem);
	cur->status = THREAD_READY;
	schedule();
	intr_set_level(old_level);

}

/* Invoke function 'func' on all threads, passing along 'aux'.
 This function must be called with interrupts off. */
void thread_foreach(thread_action_func *func, void *aux) {
	struct list_elem *e;
	ASSERT(intr_get_level() == INTR_OFF);
	for (e = list_begin(&all_list); e != list_end(&all_list);
			e = list_next(e)) {
		struct thread *t = list_entry(e, struct thread, allelem);
		func(t, aux);
	}
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority) {
	enum intr_level old_level = intr_disable();
	struct thread *c = thread_current();
	c->orig_priority = new_priority;
	thread_priority_recompute(c);
	intr_set_level(old_level);
	thread_yield_to_higher_priority_();

}

/* Returns the current thread's priority. */
int thread_get_priority(void) {
	enum intr_level old_level = intr_disable();
	int tmp = thread_current()->priority;
	intr_set_level(old_level);
	return tmp;
}

void thread_donate_priority(struct thread *donor) { // Donor wants to donate priority
	ASSERT(donor != NULL);
	ASSERT(donor->waiting_lock != NULL);
	struct thread *holder_thread = donor->waiting_lock->holder; //get lock holder
	ASSERT(holder_thread != NULL);
	list_push_back(&holder_thread->donating_threads_list,
			&donor->donating_threads_elem); // adds it self to holder's donating list
	thread_priority_recompute(holder_thread); // recompute donee's priority
	thread_yield_to_higher_priority_(); // let max priority thread run
}

void thread_return_to_old_priority(struct thread *releaser, struct lock *lock) {

	ASSERT(releaser != NULL);
	if (list_empty(&releaser->donating_threads_list)) { // empty donating list
		releaser->priority = releaser->orig_priority;
		releaser->donee = NULL;
		thread_priority_recompute(releaser); // recompute priority
	} else {  // not empty donating list
		enum intr_level old_level = intr_disable();
		//releaser->donee = NULL;
		releaser->priority = releaser->orig_priority; // set priority to original one
		intr_set_level(old_level);
		struct list_elem *e;
		struct list_elem *e2;
		for (e = list_begin(&releaser->donating_threads_list);
				e != list_end(&releaser->donating_threads_list); e) { // remove threads that are
			// waiting for the lock out of donating list
			struct thread *temp2 = list_entry(e, struct thread,
					donating_threads_elem);
			if (temp2->waiting_lock != NULL) {
				if (temp2->waiting_lock == lock) {
					temp2->donee = NULL;
					temp2->waiting_lock = NULL;
					e2 = e->next;
					list_remove(e);
					e = e2;
				} else {
					e = list_next(e);
				}
			} else {
				e = list_next(e);
			}

		}
		thread_priority_recompute(releaser); // recompute priority
	}

}

void thread_priority_recompute(struct thread *c) {

	ASSERT(c != NULL);
	enum intr_level old_level = intr_disable();
	int max_p = c->orig_priority;
	if (!list_empty(&c->donating_threads_list)) {
		struct thread *max =
				list_entry(
						list_max(&c->donating_threads_list, thread_lower_priority, NULL),
						struct thread, donating_threads_elem);
		if (max->priority > max_p) {
			max_p = max->priority;
		}
		c->priority = max_p;
		if (c->donee != NULL) {
			thread_priority_recompute(c->donee);
		}
	} else {
		c->priority = max_p;
	}
	intr_set_level(old_level);

}

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED) {
	//Sets the current thread's nice value to new nice and recalculates the thread's priority based
	//on the new value . If the running thread no
	//longer has the highest priority, yields.
	enum intr_level old_level = intr_disable();
	struct thread *t = thread_current();
	if (t == idle_thread)
		return;
	t->nice = nice; //set nice
	//same calculations for new priority as in thread_tick()
	int new_priority = PRI_MAX - (t->recent_cpu / (4 * F)) - (t->nice * 2);
	new_priority = (new_priority < PRI_MIN) ? PRI_MIN :
					(new_priority > PRI_MAX) ? PRI_MAX : new_priority;
	thread_set_priority(new_priority);
	intr_set_level(old_level);
}

/* Returns the current thread's nice value. */
int thread_get_nice(void) {
	return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void) {
	//Returns 100 times the current system load average, rounded to the nearest integer.
	return convert_to_int_nearest_rounding(100 * load_average);
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void) {
	//Returns 100 times the current thread's recent cpu value, rounded to the nearest integer.
	return (100 * convert_to_int_nearest_rounding(thread_current()->recent_cpu));
}

/* Idle thread.  Executes when no other thread is ready to run.

 The idle thread is initially put on the ready list by
 thread_start().  It will be scheduled once initially, at which
 point it initializes idle_thread, "up"s the semaphore passed
 to it to enable thread_start() to continue, and immediately
 blocks.  After that, the idle thread never appears in the
 ready list.  It is returned by next_thread_to_run() as a
 special case when the ready list is empty. */
static void idle(void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;
	idle_thread = thread_current();
	sema_up(idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable();
		thread_block();

		/* Re-enable interrupts and wait for the next one.

		 The `sti' instruction disables interrupts until the
		 completion of the next instruction, so these two
		 instructions are executed atomically.  This atomicity is
		 important; otherwise, an interrupt could be handled
		 between re-enabling interrupts and waiting for the next
		 one to occur, wasting as much as one clock tick worth of
		 time.

		 See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		 7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void kernel_thread(thread_func *function, void *aux) {
	ASSERT(function != NULL);

	intr_enable(); /* The scheduler runs with interrupts off. */
	function(aux); /* Execute the thread function. */
	thread_exit(); /* If function() returns, kill the thread. */
	//println("===kernel thread exited\n");
}

/* Returns the running thread. */
struct thread *
running_thread(void) {
	uint32_t *esp;

	/* Copy the CPU's stack pointer into `esp', and then round that
	 down to the start of a page.  Because `struct thread' is
	 always at the beginning of a page and the stack pointer is
	 somewhere in the middle, this locates the curent thread. */
	asm ("mov %%esp, %0" : "=g" (esp));
	return pg_round_down(esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool is_thread(struct thread *t) {
	return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
 NAME. */
static void init_thread(struct thread *t, const char *name, int priority) {

	ASSERT(t != NULL);
	ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT(name != NULL);

	memset(t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy(t->name, name, sizeof t->name);
	t->stack = (uint8_t *) t + PGSIZE;
	t->priority = priority;

#ifdef USERPROG
	sema_init(&t->child_alive, 0);
	sema_init(&t->child_loading, 0);
	sema_init(&t->ret_sema, 0);
	t->parent = NULL;
	list_init(&t->children);
	list_init(&t->file_fd_list);
	list_init(&t->children_return);
	t->fd_distibution = 2;
	t->load_good = false;
	t->waited = false;
#endif

	t->magic = THREAD_MAGIC;

	t->wakeup_time = 0;
	sema_init(&t->thread_semaphore, 0);
	t->orig_priority = t->priority;            // Initialise original priority
	list_init(&t->donating_threads_list); // Initialise the list of threads that have donated
	//list_init(&t->file_fd_list);
	t->waiting_lock = NULL;  // set the lock used while acquiring a lock to null
	t->donee = NULL;

	list_push_back(&all_list, &t->allelem);
	// Added for BSD scheduler
	t->nice = NICE_DEFAULT;
	t->recent_cpu = RECENT_CPU_DEFAULT;
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
 returns a pointer to the frame's base. */
static void *
alloc_frame(struct thread *t, size_t size) {
	/* Stack data is always allocated in word-size units. */
	ASSERT(is_thread(t));
	ASSERT(size % sizeof(uint32_t) == 0);

	t->stack -= size;
	return t->stack;
}

bool thread_lower_priority(const struct list_elem *a_,
		const struct list_elem *b_, void *aux UNUSED) { // compare priorities of two threads
	const struct thread *a = list_entry(a_, struct thread, elem);
	const struct thread *b = list_entry(b_, struct thread, elem);
	return a->priority < b->priority;
}

void thread_yield_to_higher_priority_(void) {
	enum intr_level old_level = intr_disable();
	if (!list_empty(&ready_list)) {
		struct thread *cur = thread_current();
		struct thread *max = list_entry(
				list_max(&ready_list, thread_lower_priority, NULL),
				struct thread, elem); // take thread with max priority
		if (max->priority > cur->priority) { // if current less then max thread
			if (intr_context())
				intr_yield_on_return();
			else {
				thread_yield(); // current yield
			}
		}
	}
	intr_set_level(old_level);

}

/* Chooses and returns the next thread to be scheduled.  Should
 return a thread from the run queue, unless the run queue is
 empty.  (If the running thread can continue running, then it
 will be in the run queue.)  If the run queue is empty, return
 idle_thread. */
static struct thread *
next_thread_to_run(void) {
	if (list_empty(&ready_list)) {
		return idle_thread;
	} else {
		struct thread *th = list_entry(
				list_max(&ready_list, thread_lower_priority, NULL),
				struct thread, elem); // take max priority thread
		list_remove(&th->elem); // remove from ready list
		return th;
	}
}

/* Completes a thread switch by activating the new thread's page
 tables, and, if the previous thread is dying, destroying it.

 At this function's invocation, we just switched from thread
 PREV, the new thread is already running, and interrupts are
 still disabled.  This function is normally invoked by
 thread_schedule() as its final action before returning, but
 the first time a thread is scheduled it is called by
 switch_entry() (see switch.S).

 It's not safe to call printf() until the thread switch is
 complete.  In practice that means that printf()s should be
 added at the end of the function.

 After this function and its caller returns, the thread switch
 is complete. */
void thread_schedule_tail(struct thread *prev) {
	struct thread *cur = running_thread();

	ASSERT(intr_get_level() == INTR_OFF);

	/* Mark us as running. */
	cur->status = THREAD_RUNNING;
	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate();
#endif

	/* If the thread we switched from is dying, destroy its struct
	 thread.  This must happen late so that thread_exit() doesn't
	 pull out the rug under itself.  (We don't free
	 initial_thread because its memory was not obtained via
	 palloc().) */

	if (prev != NULL && prev->status == THREAD_DYING
			&& prev != initial_thread) {
		//printf("distroy : %d, %d\n",prev->tid,thread_current()->tid);
		ASSERT(prev != cur);
		palloc_free_page(prev);
	}
}

/* Schedules a new process.  At entry, interrupts must be off and
 the running process's state must have been changed from
 running to some other state.  This function finds another
 thread to run and switches to it.

 It's not safe to call printf() until thread_schedule_tail()
 has completed. */
static void schedule(void) {

	struct thread *cur = running_thread();
	struct thread *next = next_thread_to_run();
	struct thread *prev = NULL;

	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(cur->status != THREAD_RUNNING);
	ASSERT(is_thread(next));

	if (cur != next)
		prev = switch_threads(cur, next);
	thread_schedule_tail(prev);
}

/* Returns a tid to use for a new thread. */
static tid_t allocate_tid(void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire(&tid_lock);
	tid = next_tid++;
	lock_release(&tid_lock);
	//printf("----------------------- allocate tid %d \n",tid);
	return tid;
}

/* Offset of `stack' member within `struct thread'.
 Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof(struct thread, stack);

//#ifdef USERPROG
int distribute_fd() {
	struct thread* t = thread_current();
	int d = t->fd_distibution;
	t->fd_distibution++;
	return d;
}

int add_file_to_thread(struct file* f) {
	struct file_fd* new_file = (struct file_fd*) malloc(sizeof(struct file_fd));
	new_file->fd = distribute_fd();
	new_file->fil = f;
	list_push_back(&thread_current()->file_fd_list,
			&new_file->file_fd_list_elem);
	return new_file->fd;
}

struct file* delete_file_from_thread(int fdd) {

	struct list_elem *e;

	for (e = list_begin(&thread_current()->file_fd_list);
			e != list_end(&thread_current()->file_fd_list); e = list_next(e)) {

		struct file_fd *filefd = list_entry(e, struct file_fd,
				file_fd_list_elem);
		if (filefd->fd == fdd) {
			list_remove(&filefd->file_fd_list_elem);
			struct file* f = filefd->fil;
			free(filefd);
			return f;
		}
	}
	return NULL;
}

struct file* get_file_from_fd(int fd2) {

	struct list_elem *e;

	for (e = list_begin(&thread_current()->file_fd_list);
			e != list_end(&thread_current()->file_fd_list); e = list_next(e)) {

		struct file_fd *filefd = list_entry(e, struct file_fd,
				file_fd_list_elem);
		if (filefd->fd == fd2) {

			if (filefd->fil == NULL) {
				//printf("should not happen\n");
				return NULL;
			}
			return filefd->fil;
		}
	}

	return NULL;
}

int get_fd_from_file(struct file *file) {
	struct list_elem *e;
	for (e = list_begin(&thread_current()->file_fd_list);
			e != list_end(&thread_current()->file_fd_list); e = list_next(e)) {

		struct file_fd *filefd = list_entry(e, struct file_fd,
				file_fd_list_elem);
		if (filefd->fil == file) {
			return filefd->fd;
		}
	}
	return -1;

}

struct thread *
get_thread_by_tid(tid_t id) {
	struct list_elem *e;

	for (e = list_begin(&all_list); e != list_end(&all_list);
			e = list_next(e)) {
		struct thread *t = list_entry(e, struct thread, allelem);
		if (t->tid == id)
			return t;
	}

	return NULL;
}

void thread_add_child(struct thread * parent, tid_t child_id) {
	struct thread * child = get_thread_by_tid(child_id);
	child->parent = parent;
	list_push_back(&parent->children, &child->child);
}

struct return_status *
thread_get_child_status(int cid) {
	struct return_status * rs_found;
	struct list_elem *e;

	for (e = list_begin(&thread_current()->children_return);
			e != list_end(&thread_current()->children_return);
			e = list_next(e)) {
		rs_found = list_entry(e, struct return_status, returnelem);
		if (rs_found->tid == cid)
			return rs_found;
	}

	return NULL;
}

struct thread *thread_get_child_by_tid(int tid) {
	struct thread * thread_found;
	struct list_elem *e;
	for (e = list_begin(&thread_current()->children);
			e != list_end(&thread_current()->children); e = list_next(e)) {
		thread_found = list_entry(e, struct thread, child);
		if (thread_found->tid == tid)
			return thread_found;
	}
	return NULL;
}

//#endif

