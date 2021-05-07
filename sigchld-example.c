/*
 * sigchld-test.c
 *
 * A program to demonstrate use of SIGCHLD
 * by a parent process, so it may be notified of
 * state changes in children processes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include "proc-common.h"


#define SLEEP_SEC 3
#define ALARM_SEC 2

int send_sigcont = 0;
int send_sigstop = 0;
pid_t pglob;

void child(char malakia[])
{
	pid_t pid = getpid();
    printf("%s\n", malakia);
    //int i;
	//for (i = 0; i < 1; i++) {
		printf("I am child %ld, sleeping for %d sec...\n",
			(long)pid, SLEEP_SEC);
		sleep(SLEEP_SEC);
        exit(3);
	//}
}

/*
 * A handler for SIGALRM in the parent
 */
void sigalrm_handler(int signum)
{
	if (signum != SIGALRM) {
		fprintf(stderr, "Internal error: Called for signum %d, not SIGALRM\n",
			signum);
		exit(1);
	}

	printf("ALARM! %d seconds have passed.\n", ALARM_SEC);
    kill(pglob,SIGSTOP);

	/* Setup the alarm again */
	if (alarm(ALARM_SEC) < 0) {
		perror("alarm");
		exit(1);
	}
}

/*
 * A handler for SIGCHLD in the parent
 */
void sigchld_handler(int signum)
{
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
			printf("Parent: Received SIGCHLD, child is dead. Exiting.\n");
			exit(0);
		}
		if (WIFSTOPPED(status)) {
			/* A child has stopped due to SIGSTOP/SIGTSTP, etc... */
			printf("Parent: Child has been stopped. Moving right along...\n");
            kill(pglob,SIGCONT);
		}
	}
}

int main(void)
{
	//pid_t p;

	/* Install SIGCHLD handler */
	if (signal(SIGCHLD, sigchld_handler) < 0) {
		perror("signal");
		exit(1);
	}

	/* Install SIGALRM handler */
	if (signal(SIGALRM, sigalrm_handler) < 0) {
		perror("signal");
		exit(1);
	}

	/* Arrange for an alarm after 2 sec */
	if (alarm(ALARM_SEC) < 0) {
		perror("alarm");
		exit(1);
	}

	printf("Parent: Creating child...\n");
	pglob = fork();
	if (pglob < 0) {
		/* fork failed */
		perror("fork");
		exit(1);
	}
	if (pglob == 0) {
		/* In child process */
		child("papari");
		/*
		 * Should never reach this point,
		 * child() does not return
		 */
		assert(0);
	}

	/*
	 * In parent process.
	 */
	
	/*
	 * Do nothing until the child terminates.
	 * The handler will exit().
	 */
	printf("Parent: Created child with PID = %ld, waiting for it to terminate...\n",
		(long)pglob);
	while (pause())
		;

	return 0;
}

