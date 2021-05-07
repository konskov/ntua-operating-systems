#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "proc-common.h"
#include "request.h"

/* Compile-time parameters. */
#define SCHED_TQ_SEC 2                /* time quantum */
#define TASK_NAME_SZ 60               /* maximum size for a task's name */
#define SHELL_EXECUTABLE_NAME "shell" /* executable for shell */

struct node_t {
  pid_t mypid;
  int myid;
  char* my_executable;
  struct node_t *next;
  //bool priority;
};

typedef struct node_t node;

struct list_t {
  node *head;
  node *tail;
}; /* implement list as queue, head = front and tail = rear */

typedef struct list_t list;

/* our global variables */
list high_list;
list low_list;
int id_to_give = 1;
bool priority_lowered = false;


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

void insert_at_rear(list *l,pid_t pid,char *executable) {
    node *temp = (node *)malloc(sizeof(node));
    temp->mypid = pid;
    temp->my_executable = executable;
    temp->myid = id_to_give;
    temp->next = NULL;
    if ((*l).head == NULL) 
        (*l).head = temp;
    else 
        (*l).tail->next = temp;
    (*l).tail = temp;
    id_to_give = id_to_give + 1;
}

void insert_at_rear_and_remove_head(list *l) {
    node *temp = (node *)malloc(sizeof(node));
        (*temp).myid = (*l).head->myid;
        (*temp).mypid = (*l).head->mypid;
        (*temp).my_executable = (*l).head->my_executable;
        (*temp).next = NULL;
        if ((*l).head == NULL)
                (*l).head = temp;
        else
                (*l).tail->next = temp;
        (*l).tail = temp;
        node *temp1 = (*l).head;
        (*l).head = temp1->next;
        free(temp1);
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

void print_list(list *l) {
node *temp = l->head;
    printf("high_list is: \n");
    while (temp != NULL){
        printf("%d \n", temp->myid);
        temp = temp->next;
    }
}


void find_and_remove(pid_t pid) {
    /*check both lists to find pid */
    //first search high
    bool found = false;
    node *temp = high_list.head;
    node *previous;
    printf("in find and remove! \n");
    print_list(&high_list);
    if (temp != NULL && temp->mypid == pid) {
        found = true;
        remove_head(&high_list);
        printf("found_and removed! pid = %ld\n", (long)pid);
    }
    if(!found) {
        while (temp->next != NULL) {
                    printf("in second check..\n");
                    previous = temp;
                    temp = temp->next;
                    if (temp->mypid == pid) {
                        found = true;
                        printf("yes! found it in high_list! \n");
                        previous->next = temp->next;
                        free(temp);
                        print_list(&high_list);
                        break;
                    }
        }
    }
    if (!found) { /* also search low_list */
        temp = low_list.head;
        printf("did i go on?? \n");
        if (temp!= NULL && temp->mypid == pid) {
            found = true;
            remove_head(&low_list);
        }
        while (temp->next != NULL) {
                    previous = temp;
                    temp = temp->next;
                    if (temp->mypid == pid) {
                        found = true;
                        previous->next = temp->next;
                        free(temp);
                        break;
                    }
        }
    }

}

                
void insert_already_existent_node(list *l, node n) {
    node *temp = (node *)malloc(sizeof(node));
    temp->mypid = n.mypid;
    temp->my_executable = n.my_executable;
    temp->myid = n.myid;
    temp->next = NULL; // tha mpei sto telos
    if ((*l).head == NULL) 
        (*l).head = temp;
    else 
        (*l).tail->next = temp;
    (*l).tail = temp;
}                

/* Print a list of all tasks currently being scheduled.  */
/* Implements 'p' command */
static void
sched_print_tasks(void)
{
	node *temp;
    temp = high_list.head;
    printf("List of HIGH running processes: \n");
    printf("Currently running is (HIGH) process with id = %d, pid = %ld and the name %s \n", temp->myid, (long)temp->mypid, temp->my_executable);
    temp = temp->next;
    while(temp != NULL) {
        printf("HIGH Process with id = %d, pid = %ld and the name %s \n", temp->myid, (long)temp->mypid, temp->my_executable);  
        temp = temp->next;
    }
    temp = low_list.head;
    printf("List of LOW running processes: \n");
    while(temp != NULL) {
        printf("LOW Process with id = %d, pid = %ld and the name %s \n", temp->myid, (long)temp->mypid, temp->my_executable);  
        temp = temp->next;
    }
}

/*helper function called within kill_task_by_pid to find the corresponding pid from given id*/
pid_t 
sched_find_task_by_id(int id)
{
    node *temp;
    pid_t retval = (pid_t)0;
    bool found = false;
    for(temp = high_list.head; temp != NULL; temp = temp->next){
        if (id == temp->myid){
            retval = temp->mypid;
            found = true;
            break;
        }
    }
    if (!found) {
        for(temp = low_list.head; temp != NULL; temp = temp->next){
        if (id == temp->myid){
            retval = temp->mypid;
            found = true;
            break;
        }
        }
    }
    return retval;
}

/* Send SIGKILL to a task determined by the value of its
 * scheduler-specific id.
   Implemets 'k' command*/
static int /* TODO write function to remove from the list */
sched_kill_task_by_id(int id)
{
	pid_t to_kill = sched_find_task_by_id(id);
    if ((int)to_kill == 0) {
        printf("No process with id %d exists! \n",id);
    }
    else {
        printf("Killing process with id %d...\n", id);
        kill(to_kill, SIGKILL);
    }
	return -ENOSYS;
}


/* Create a new task.  */
/* Implements 'e' command */
static void
sched_create_task(char *executable)
{
	char *newargv[] = { executable, NULL, NULL, NULL };
        char *newenviron[] = { NULL };
        pid_t p;
        p = fork();
        if (p < 0) {
                perror("scheduler: fork");
                exit(1);
        }
        if (p == 0) {
                /* child process changes code */
                execve(executable,newargv,newenviron);
                /* execve() only returns on error */
                perror("execve");
                exit(0);
        }
        /* since child code is not fixed, we must stop the child from the parent process (hopefully in time) */
        insert_at_rear(&low_list,p,executable); /* new process so call insert_at_rear to give it new id */
        kill(p,SIGSTOP);
        
}

void set_new_priority(int id, list *l)
{
    /*check both lists to find pid */
    //first search low
    bool found = false;
    node *temp = low_list.head;
    node *previous;
    node ret_copy;
    if (temp->myid == id) {
        found = true;
        ret_copy = (*temp);
        remove_head(&low_list);
    }
    if(!found) {
        while (temp->next != NULL) {
                    previous = temp;
                    temp = temp->next;
                    if (temp->myid == id) {
                        found = true;
                        ret_copy = (*temp);
                        previous->next = temp->next;
                        free(temp);
                        break;
                    }
        }
    }
    if (!found) { /* also search high_list */
        temp = high_list.head;
        while (temp->next != NULL) {
                    previous = temp;
                    temp = temp->next;
                    if (temp->myid == id) {
                        found = true;
                        printf("found you!\n");
                        ret_copy = (*temp);
                        kill(temp->mypid, SIGSTOP); /* handler should remove it from high priority list */
                        break;
                    }
        }
    }
    if (!found) {
        printf("There is no process with id = %d!\n", id);
    }
    if (found) {
        insert_already_existent_node(l, ret_copy);
    }
}

void sched_set_high_by_id(int id) {
    set_new_priority(id,&high_list);
}

void sched_set_low_by_id(int id) {
    set_new_priority(id, &low_list);
    priority_lowered = true;
}


/* Process requests by the shell.  */
static int
process_request(struct request_struct *rq)
{
	switch (rq->request_no) {
		case REQ_PRINT_TASKS:
			sched_print_tasks();
			return 0;

		case REQ_KILL_TASK:
			return sched_kill_task_by_id(rq->task_arg);

		case REQ_EXEC_TASK:
			sched_create_task(rq->exec_task_arg);
			return 0;
        case REQ_HIGH_TASK :    /* set ->task_arg to be of high priority */
	        sched_set_high_by_id(rq->task_arg);
            return 0;


        case REQ_LOW_TASK :    /* set ->task_arg to be of low priority */
            sched_set_low_by_id(rq->task_arg);
            return 0;

		default:
			return -ENOSYS;
	}
}

/* 
 * SIGALRM handler
 */
static void
sigalrm_handler(int signum)
{
	if (signum != SIGALRM) {
		fprintf(stderr, "Internal error: Called for signum %d, not SIGALRM\n",
			signum);
		exit(1);
	}

    /*send SIGSTOP to the head of the queue,
     * that is, the process being executed at 
      the time sigstop arrives */
    /* if there are high processes, signal head of high queue */
    /* if there are only low procs, we are not in the shell */
    if (isEmpty(&high_list))
        kill(low_list.head->mypid,SIGSTOP); // and now you'll receive a sigchld from the stopped process
    else 
        kill(high_list.head->mypid,SIGSTOP);
    
	/* the alarm is set up again in sigchld_handler, so that 
    * every child process gets a full time quantum */
}

/* 
 * SIGCHLD handler
 */
static void
sigchld_handler(int signum)
{
	pid_t p, is_head;
	int status;
    list *cur_list;
    bool set_alrm = false;

	if (signum != SIGCHLD) {
		fprintf(stderr, "Internal error: Called for signum %d, not SIGCHLD\n",
			signum);
		exit(1);
	}
    
    if (isEmpty(&high_list)) {
        cur_list = &low_list;
    }
    else {
        cur_list = &high_list;
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

        for(;;){
                p = waitpid(-1, &status, WUNTRACED | WNOHANG);
                if (p < 0){
                        perror("waitpid");
                        exit(1);
                }
                if (p == 0)
                        return;

                explain_wait_status(p, status);
                if (WIFEXITED(status) || WIFSIGNALED(status)){
                        is_head = p;
                        if (cur_list->head->mypid == is_head) // then we must set an alarm
                            set_alrm = true;
                        find_and_remove(p);
                        if (isEmpty(&high_list) && isEmpty(&low_list)) {
                            printf("All tasks completed, exiting...");
                            exit(0);
                        }
                }

                if (WIFSTOPPED(status)){
                    if (!isEmpty(&low_list) && priority_lowered) {
                        find_and_remove(p);
                        priority_lowered = false;
                    }
                    is_head = p;
                    if (isEmpty(&high_list)) {
                        cur_list = &low_list;
                    }
                    else {
                        cur_list = &high_list;
                    }           
                    is_head = cur_list->head->mypid; 
                    if (p == is_head) {// then it is the head that was stopped because time quantum expired and a new alarm must be set
                        insert_at_rear_and_remove_head(cur_list);//adds element at the end of the list
                        set_alrm = true;
                    }
                }
                if (set_alrm) {
                        if (alarm(SCHED_TQ_SEC) < 0) {
		                    perror("alarm");
		                    exit(1);
                        }
                }
                kill(cur_list->head->mypid,SIGCONT); // if not stopped then sigcont is simply ignored
        }
}




/* Disable delivery of SIGALRM and SIGCHLD. */
static void
signals_disable(void)
{
	sigset_t sigset;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigaddset(&sigset, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sigset, NULL) < 0) {
		perror("signals_disable: sigprocmask");
		exit(1);
	}
}

/* Enable delivery of SIGALRM and SIGCHLD.  */
static void
signals_enable(void)
{
	sigset_t sigset;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigaddset(&sigset, SIGCHLD);
	if (sigprocmask(SIG_UNBLOCK, &sigset, NULL) < 0) {
		perror("signals_enable: sigprocmask");
		exit(1);
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

static void
do_shell(char *executable, int wfd, int rfd)
{
	char arg1[10], arg2[10];
	char *newargv[] = { executable, NULL, NULL, NULL };
	char *newenviron[] = { NULL };

	sprintf(arg1, "%05d", wfd);
	sprintf(arg2, "%05d", rfd);
	newargv[1] = arg1;
	newargv[2] = arg2;

	raise(SIGSTOP);
	execve(executable, newargv, newenviron);

	/* execve() only returns on error */
	perror("scheduler: child: execve");
	exit(1);
}

/* Create a new shell task.
 *
 * The shell gets special treatment:
 * two pipes are created for communication and passed
 * as command-line arguments to the executable.
 */
static void
sched_create_shell(char *executable, int *request_fd, int *return_fd)
{
	pid_t p;
	int pfds_rq[2], pfds_ret[2];

	if (pipe(pfds_rq) < 0 || pipe(pfds_ret) < 0) {
		perror("pipe");
		exit(1);
	}

	p = fork();
	if (p < 0) {
		perror("scheduler: fork");
		exit(1);
	}

	if (p == 0) {
		/* Child */
		close(pfds_rq[0]);
		close(pfds_ret[1]);
		do_shell(executable, pfds_rq[1], pfds_ret[0]);
		assert(0);
	}
	/* Parent */
    insert_at_rear(&high_list,p,executable); // do this so the shell executable is always present in the process list 
	close(pfds_rq[1]);
	close(pfds_ret[0]);
	*request_fd = pfds_rq[0];
	*return_fd = pfds_ret[1];
}

static void
shell_request_loop(int request_fd, int return_fd)
{
	int ret;
	struct request_struct rq;

	/*
	 * Keep receiving requests from the shell.
	 */
	for (;;) {
		if (read(request_fd, &rq, sizeof(rq)) != sizeof(rq)) {
			perror("scheduler: read from shell");
			fprintf(stderr, "Scheduler: giving up on shell request processing.\n");
			break;
		}

		signals_disable();
		ret = process_request(&rq);
		signals_enable();

		if (write(return_fd, &ret, sizeof(ret)) != sizeof(ret)) {
			perror("scheduler: write to shell");
			fprintf(stderr, "Scheduler: giving up on shell request processing.\n");
			break;
		}
	}
}

/*global, implementation defined id that we use to identify each process 
* each time a process is created, do id_to_give++ */

int main(int argc, char *argv[])
{
	int nproc, i;
    high_list = createList();
    low_list = createList();
	/* Two file descriptors for communication with the shell */
	static int request_fd, return_fd;

	/* Create the shell. */
	sched_create_shell(SHELL_EXECUTABLE_NAME, &request_fd, &return_fd);
	/* TODO: add the shell to the scheduler's tasks */
    nproc = 1; /* since the shell was added to the list of processes */

	/*
	 * For each of argv[1] to argv[argc - 1],
	 * create a new child process, add it to the process list.
	 */

    for(i = 1; i < argc; i++){
                pid_t p;
                p = fork();
                if(p < 0){
                        perror("main: fork");
                        exit(1);
                }
                else if(p == 0) {
                        char *newargv[] = { argv[i], NULL, NULL, NULL };
	                    char *newenviron[] = { NULL };
                        execve(argv[i],newargv,newenviron);
                        /* execve() only returns on error */
	                    perror("execve");
	                    exit(1);
                }
                nproc++;
                insert_at_rear(&low_list, p, argv[i]);
                kill(p,SIGSTOP);
                
        }
   
	/* Wait for all children to raise SIGSTOP before exec()ing. */
	wait_for_ready_children(nproc);

	/* Install SIGALRM and SIGCHLD handlers. */
	install_signal_handlers();

	if (nproc == 0) {
		fprintf(stderr, "Scheduler: No tasks. Exiting...\n");
		exit(1);
	}
    kill(high_list.head->mypid,SIGCONT);
    alarm(SCHED_TQ_SEC);
    shell_request_loop(request_fd, return_fd);

	/* Now that the shell is gone, just loop forever
	 * until we exit from inside a signal handler.
	 */
	while (pause())
		;

	/* Unreachable */
	fprintf(stderr, "Internal error: Reached unreachable point\n");
	return 1;
}
