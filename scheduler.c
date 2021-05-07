#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <assert.h>

#include <sys/wait.h>
#include <sys/types.h>

#include "proc-common.h"
//#include "request.h"
//#include "SimpleListInC.h"

struct node_t {
  pid_t mypid;
  struct node_t *next;
};

typedef struct node_t node;

struct list_t {
  node *head;
  node *tail;
}; // h list 8a ulopoih8ei me oura, head = front kai tail = rear

typedef struct list_t list;


list createList(void)
{
  list result;

  result.head = NULL;
  result.tail = NULL;
  return result;
}

void remove_head(list *l) {
    node *temp1 = (*l).head;
    (*l).head = temp1->next;
    free(temp1);
}

void insert_at_rear(list *l,pid_t pid) {
    node *temp = (node *)malloc(sizeof(node));
    temp->mypid = pid;
    temp->next = NULL;
    if ((*l).head == NULL) 
        (*l).head = temp;
    else 
        (*l).tail->next = temp;
    (*l).tail = temp;
}

int isEmpty(list *l)
{
  node *p;
  p = (*l).head;
  if (p == NULL)
  return 1;
  else return 0;
  free(p);
}

/* Compile-time parameters. */
#define SCHED_TQ_SEC 2                /* time quantum */
#define TASK_NAME_SZ 60               /* maximum size for a task's name */

list proclist; /*global so that the signal handler can access it*/

void child(char executable[]) {

    char *newargv[] = { executable, NULL, NULL, NULL };
	char *newenviron[] = { NULL };

	printf("I am child process with PID = %ld\n", (long)getpid());
	printf("About to replace myself with the executable %s...\n",
		executable);
	raise(SIGSTOP);
    printf("Child process with PID = %ld just received sigcont \n", (long)getpid());

	execve(executable, newargv, newenviron);

	/* execve() only returns on error */
	perror("execve");
	exit(1);
}

/*
 * SIGALRM handler
 */
static void
sigalrm_handler(int signum)
{
	//assert(0 && "Please fill me!");
    if (signum != SIGALRM) {
		fprintf(stderr, "Internal error: Called for signum %d, not SIGALRM\n",
			signum);
		exit(1);
	}

	printf("Time quantum expired! %d seconds have passed.\n", SCHED_TQ_SEC);
    /*send SIGSTOP to the head of the queue,
     * that is, the process being executed at 
      the time sigstop arrives */
    kill(proclist.head->mypid,SIGSTOP); // and now you'll receive a sigchld from the stopped process
    /*add the process to the end of the process list,
     * then remove it from the front */
    //insert_at_rear(&proclist,proclist.head->mypid);//adds element at the end of the list
    //remove_head(&proclist); //removes the 1st element
    
	/* the alarm is set up again in sigchld_handler, so that 
    * every child process gets a full time quantum */
}

/* 
 * SIGCHLD handler
 */
static void
sigchld_handler(int signum)
{
	//assert(0 && "Please fill me!");

    pid_t p;
	int status;

	if (signum != SIGCHLD) {
		fprintf(stderr, "Internal error: Called for signum %d, not SIGCHLD\n",
			signum);
		exit(1);
	}

	/*
	 * Something has happened to one of the children.
	 * We use waitpid() with the WUNTRACED flag, instead of wait(), because
	 * SIGCHLD may have been received for a stopped, not dead child.
	 *
	 * A single SIGCHLD may be received if many processes die at the same time.
	 * We use waitpid() with the WNOHANG flag in a loop, to make sure all
	 * children are taken care of before leaving the handler.
	 */

	for (;;) {
		p = waitpid(-1, &status, WUNTRACED | WNOHANG);
		if (p < 0) {
			perror("waitpid");
			exit(1);
		}
		if (p == 0)
			break;

		explain_wait_status(p, status);

		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			/* A child has died */
			printf("Parent: Received SIGCHLD, child on top of the list is dead. Removing it from the list.\n");
            remove_head(&proclist); //removes the 1st element
            if (isEmpty(&proclist)) {
                printf("All tasks completed, exiting...");
                exit(0);
            }
		}
		if (WIFSTOPPED(status)) {
			/* A child has stopped due to SIGSTOP/SIGTSTP, etc... */
			printf("Parent: Child has been stopped. Moving right along...\n");
            insert_at_rear(&proclist,proclist.head->mypid);//adds element at the end of the list
            remove_head(&proclist); //removes the 1st element
		}
        /*now the 1st element = the next process that should be continued*/
        /* Setup the alarm again */
	    if (alarm(SCHED_TQ_SEC) < 0) {
		perror("alarm");
		exit(1);
        }
        kill(proclist.head->mypid,SIGCONT);
	}
}

/* Install two signal handlers.
 * One for SIGCHLD, one for SIGALRM.
 * Make sure both signals are masked when one of them is running.
 */
static void
install_signal_handlers(void)
{
	sigset_t sigset;
	struct sigaction sa;

	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGCHLD);
	sigaddset(&sigset, SIGALRM);
	sa.sa_mask = sigset;
	if (sigaction(SIGCHLD, &sa, NULL) < 0) {
		perror("sigaction: sigchld");
		exit(1);
	}

	sa.sa_handler = sigalrm_handler;
	if (sigaction(SIGALRM, &sa, NULL) < 0) {
		perror("sigaction: sigalrm");
		exit(1);
	}

	/*
	 * Ignore SIGPIPE, so that write()s to pipes
	 * with no reader do not result in us being killed,
	 * and write() returns EPIPE instead.
	 */
	if (signal(SIGPIPE, SIG_IGN) < 0) {
		perror("signal: sigpipe");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	int nproc,i;
    pid_t pid, pap;
    proclist = createList();
    
    /*
	 * For each of argv[1] to argv[argc - 1],
	 * create a new child process, add it to the process list.
	 */
    for (i = 1; i < argc; i++) {
        pid = fork();
        insert_at_rear(&proclist,pid);
        if (pid == 0) {
            child(argv[i]);
        }
    }
	

	nproc = argc - 1; /* number of proccesses goes here */
    if (nproc == 0) {
		fprintf(stderr, "Scheduler: No tasks. Exiting...\n");
		exit(1);
	}
	/* Wait for all children to raise SIGSTOP before exec()ing. */
	wait_for_ready_children(nproc);

	/* Install SIGALRM and SIGCHLD handlers. */
	install_signal_handlers();
    
    /*node *ptr = proclist.head;
    while(ptr != NULL) {
        pap = ptr->mypid;
        printf("pid : %ld ", (long)pap);
        ptr = ptr->next;
    }*/
    
    /* Arrange for an alarm after 2 sec */
	if (alarm(SCHED_TQ_SEC) < 0) {
		perror("alarm");
		exit(1);
	}

    /*start exec()ing */
    kill(proclist.head->mypid,SIGCONT);

	/*loop forever  until we exit from inside a signal handler. */
	while (pause())
		;

	/* Unreachable */
	fprintf(stderr, "Internal error: Reached unreachable point\n");
	return 0;
}
