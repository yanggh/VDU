#include "head.h"

int totalflag;
int flag = 0;
int exitflag = 0;
extern pthread_cond_t writecond;
void sig_handler(int signo)
{
	if (signo == SIGUSR2) {
		flag = 1;
		puts("hello world"); 
	} else if (signo == SIGUSR1)
		flag = 0;
	else if (signo == SIGALRM) {
#if 0
		if (totalflag == 0)
			totalflag = 1;
		else if (totalflag == 1)
			totalflag = 0;
		pthread_cond_signal(&writecond);
#endif 
		PR_DEBUG("%s\n", "================================SIGALRM======================================");
	} else if (signo == SIGINT) {
		exitflag = 1;
	}
}
