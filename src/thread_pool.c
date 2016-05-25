/*
 * @author: boyce
 * @contact: boyce.ywr#gmail.com (# -> @)
 * @version: 1.02
 * @created: 2011-07-25
 * @modified: 2011-08-04
 * @modified: 2012-05-14
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "thread_pool.h"

//#define __DEBUG__

#ifdef __DEBUG__
#define DEBUG(format,...)	printf(format,##__VA_ARGS__)
#else
#define DEBUG(format,...) 
#endif

static TpThreadInfo *tp_add_thread(TpThreadPool *pTp, process_job proc_fun, void *job);
static int tp_delete_thread(TpThreadPool *pTp); 
static int tp_get_tp_status(TpThreadPool *pTp); 

static void *tp_work_thread(void *pthread);
static void *tp_manage_thread(void *pthread);

/**
 * user interface. creat thread pool.
 * para:
 * 	num: min thread number to be created in the pool
 * return:
 * 	thread pool struct instance be created successfully
 */
TpThreadPool *tp_create(unsigned min_num, unsigned max_num) {
	TpThreadPool *pTp;
	pTp = (TpThreadPool*) malloc(sizeof(TpThreadPool));

	memset(pTp, 0, sizeof(TpThreadPool));

	//init member var
	pTp->min_th_num = min_num;
	pTp->cur_th_num = min_num;
	pTp->max_th_num = max_num;
	pthread_mutex_init(&pTp->tp_lock, NULL);
	pthread_cond_init(&pTp->tp_cond, NULL);
	pthread_mutex_init(&pTp->loop_lock, NULL);
	pthread_cond_init(&pTp->loop_cond, NULL);

	//malloc mem for num thread info struct
	if (NULL != pTp->thread_info)
		free(pTp->thread_info);
	pTp->thread_info = (TpThreadInfo*) malloc(sizeof(TpThreadInfo) * pTp->max_th_num);
	memset(pTp->thread_info, 0, sizeof(TpThreadInfo) * pTp->max_th_num);

	return pTp;
}

/**
 * member function reality. thread pool init function.
 * para:
 * 	pTp: thread pool struct instance ponter
 * return:
 * 	true: successful; false: failed
 */
int tp_init(TpThreadPool *pTp) {
	int i;
	int err;
	TpThreadInfo *pThi;

	//init_queue(&pTp->idle_q, NULL);
	pTp->idle_q = ts_queue_create();
	pTp->stop_flag = FALSE;
	pTp->busy_threshold = BUSY_THRESHOLD;
	pTp->manage_interval = MANAGE_INTERVAL;

	//create work thread and init work thread info
	for (i = 0; i < pTp->min_th_num; i++) {
		pThi = pTp->thread_info + i;
		pThi->tp_pool = pTp;
		pThi->is_busy = FALSE;
		pthread_cond_init(&pThi->thread_cond, NULL);
		pthread_mutex_init(&pThi->thread_lock, NULL);
		pThi->proc_fun = NULL;
		pThi->arg = NULL;
		ts_queue_enq_data(pTp->idle_q, pThi);

		err = pthread_create(&pThi->thread_id, NULL, tp_work_thread, pThi);
		if (0 != err) {
			perror("tp_init: create work thread failed.");
			ts_queue_destroy(pTp->idle_q);
			return -1;
		}
		printf("%d create thread %lu\n", i, pThi->thread_id);
	}

	//create manage thread
	err = pthread_create(&pTp->manage_thread_id, NULL, tp_manage_thread, pTp);
	if (0 != err) {//clear_queue(&pTp->idle_q);
		ts_queue_destroy(pTp->idle_q);
		fprintf(stderr, "tp_init: creat manage thread failed\n");
		return 0;
	}
	
	//wait for all threads are ready
	while(i++ < pTp->cur_th_num){
		pthread_mutex_lock(&pTp->tp_lock);
		pthread_cond_wait(&pTp->tp_cond, &pTp->tp_lock);
		pthread_mutex_unlock(&pTp->tp_lock);
	}
	DEBUG("All threads are ready now\n");
	return 0;
}

/**
 * let the thread pool wait until {@link #tp_exit} is called
 * @params:
 *	pTp: pointer of thread pool
 * @return
 *	none
 */
void tp_run(TpThreadPool *pTp){
	pthread_mutex_lock(&pTp->loop_lock);
	pthread_cond_wait(&pTp->loop_cond, &pTp->loop_lock);
	pthread_mutex_unlock(&pTp->loop_lock);
	tp_close(pTp, TRUE);
}

/**
 * let the thread pool exit, this function will wake up {@link #tp_loop}
 * @params:
 *	pTp: pointer of thread pool
 * @return
 *	none
 */
void tp_exit(TpThreadPool *pTp){
	pthread_cond_signal(&pTp->loop_cond);
}

/**
 * member function reality. thread pool entirely close function.
 * para:
 * 	pTp: thread pool struct instance ponter
 * return:
 */
void tp_close(TpThreadPool *pTp, BOOL wait) {
	unsigned i;

	pTp->stop_flag = TRUE;
	if (wait) {
		printf("current number of threads: %u\n", pTp->cur_th_num);
		for (i = 0; i < pTp->cur_th_num; i++) {
			pthread_cond_signal(&pTp->thread_info[i].thread_cond);
			printf("%u send signal to thread %lu success.\n", i, pTp->thread_info[i].thread_id);
		}
		for (i = 0; i < pTp->cur_th_num; i++) {
			if(0 != pthread_join(pTp->thread_info[i].thread_id, NULL)){
				perror("pthread_join");
			}
			//DEBUG("join a thread success.\n");
			printf("%u join thread %lu success.\n", i, pTp->thread_info[i].thread_id);
			pthread_mutex_destroy(&pTp->thread_info[i].thread_lock);
			pthread_cond_destroy(&pTp->thread_info[i].thread_cond);
		}
	} else {
		//close work thread
		for (i = 0; i < pTp->cur_th_num; i++) {
			kill((pid_t)pTp->thread_info[i].thread_id, SIGKILL);
			pthread_mutex_destroy(&pTp->thread_info[i].thread_lock);
			pthread_cond_destroy(&pTp->thread_info[i].thread_cond);
		}
	}
	//close manage thread
	kill((pid_t)pTp->manage_thread_id, SIGKILL);
	pthread_mutex_destroy(&pTp->tp_lock);
	pthread_cond_destroy(&pTp->tp_cond);
	pthread_mutex_destroy(&pTp->loop_lock);
	pthread_cond_destroy(&pTp->loop_cond);

	//clear_queue(&pTp->idle_q);
	ts_queue_destroy(pTp->idle_q);
	//free thread struct
	free(pTp->thread_info);
	pTp->thread_info = NULL;
}

/**
 * member function reality. main interface opened.
 * after getting own worker and job, user may use the function to process the task.
 * para:
 * 	pTp: thread pool struct instance ponter
 *	worker: user task reality.
 *	job: user task para
 * return:
 */
int tp_process_job(TpThreadPool *pTp, process_job proc_fun, void *arg) {
	TpThreadInfo *pThi ;
	//fill pTp->thread_info's relative work key
	pThi = (TpThreadInfo *) ts_queue_deq_data(pTp->idle_q);
	if(pThi){
		DEBUG("Fetch a thread from pool.\n");
		pThi->is_busy = TRUE;
		pThi->proc_fun = proc_fun;
		pThi->arg = arg;
		//let the thread to deal with this job
		DEBUG("wake up thread %u\n", pThi->thread_id);
		pthread_cond_signal(&pThi->thread_cond);
	}
	else{
		//if all current thread are busy, new thread is created here
		if(!(pThi = tp_add_thread(pTp, proc_fun, arg))){
			DEBUG("The thread pool is full, no more thread available.\n");
			return -1;
		}
		/* should I wait? */
		//pthread_mutex_lock(&pTp->tp_lock);
		//pthread_cond_wait(&pTp->tp_cond, &pTp->tp_lock);
		//pthread_mutex_unlock(&pTp->tp_lock);
		
		DEBUG("No more idle thread, a new thread is created.\n");
	}
	return 0;
}

/**
 * member function reality. add new thread into the pool and run immediately.
 * para:
 * 	pTp: thread pool struct instance ponter
 * 	proc_fun:
 * 	job:
 * return:
 * 	pointer of TpThreadInfo
 */
static TpThreadInfo *tp_add_thread(TpThreadPool *pTp, process_job proc_fun, void *arg) {
	int err;
	TpThreadInfo *new_thread;

	pthread_mutex_lock(&pTp->tp_lock);
	if (pTp->max_th_num <= pTp->cur_th_num){
		pthread_mutex_unlock(&pTp->tp_lock);
		return NULL;
	}

	//malloc new thread info struct
	new_thread = pTp->thread_info + pTp->cur_th_num; 
	pTp->cur_th_num++;
	pthread_mutex_unlock(&pTp->tp_lock);

	new_thread->tp_pool = pTp;
	//init new thread's cond & mutex
	pthread_cond_init(&new_thread->thread_cond, NULL);
	pthread_mutex_init(&new_thread->thread_lock, NULL);

	//init status is busy, only new process job will call this function
	new_thread->is_busy = TRUE;
	new_thread->proc_fun = proc_fun;
	new_thread->arg = arg;

	err = pthread_create(&new_thread->thread_id, NULL, tp_work_thread, new_thread);
	if (0 != err) {
		perror("tp_add_thread: pthread_create");
		free(new_thread);
		return NULL;
	}
	return new_thread;
}

/**
 * member function reality. delete idle thread in the pool.
 * only delete last idle thread in the pool.
 * para:
 * 	pTp: thread pool struct instance ponter
 * return:
 * 	true: successful; false: failed
 */
int tp_delete_thread(TpThreadPool *pTp) {
//	unsigned idx;
	TpThreadInfo *pThi;
	TpThreadInfo tT;

	//printf("cur_th_num: %d, min_th_num: %d\n", pTp->cur_th_num, pTp->min_th_num);
	//current thread num can't < min thread num
	if (pTp->cur_th_num <= pTp->min_th_num)
		return 0;
	//all threads are busy
	pThi = (TpThreadInfo *) ts_queue_deq_data(pTp->idle_q);
	if(!pThi)
		return -1;
	
	//after deleting idle thread, current thread num -1
	pthread_mutex_lock(&pTp->tp_lock);
	pTp->cur_th_num--;
	/** swap this thread to the end, and free it! **/
	memcpy(&tT, pThi, sizeof(TpThreadInfo));
	memcpy(pThi, pTp->thread_info + pTp->cur_th_num, sizeof(TpThreadInfo));
	memcpy(pTp->thread_info + pTp->cur_th_num, &tT, sizeof(TpThreadInfo));
	pthread_mutex_unlock(&pTp->tp_lock);

	//kill the idle thread and free info struct
	kill((pid_t)tT.thread_id, SIGKILL);
	pthread_mutex_destroy(&tT.thread_lock);
	pthread_cond_destroy(&tT.thread_cond);

	return 0;
}

/**
 * internal interface. real work thread.
 * @params:
 * 	arg: args for this method
 * @return:
 *	none
 */
static void *tp_work_thread(void *arg) {
	TpThreadInfo *pTinfo = (TpThreadInfo *) arg;
	TpThreadPool *pTp = pTinfo->tp_pool;

	//wake up waiting thread, notify it I am ready
	pthread_cond_signal(&pTp->tp_cond);
	while (!(pTp->stop_flag)) {
		//process
		if(pTinfo->proc_fun){
			DEBUG("thread %u is running\n", pTinfo->thread_id);
			pTinfo->proc_fun(pTinfo->arg);
			//thread state shoulde be set idle after work
			pTinfo->is_busy = FALSE;
			pTinfo->proc_fun = NULL;
			//I am idle now
			ts_queue_enq_data(pTp->idle_q, pTinfo);
		}
			
		//wait cond for processing real job.
		if (!(pTinfo->tp_pool->stop_flag)) {
			DEBUG("thread %u is waiting for a job\n", pTinfo->thread_id);
			pthread_mutex_lock(&pTinfo->thread_lock);
			printf("come into thread %lu pthread_cond_wait\n", pTinfo->thread_id);
			pthread_cond_wait(&pTinfo->thread_cond, &pTinfo->thread_lock);
			printf("come out from thread %lu pthread_cond_wait\n", pTinfo->thread_id);
			pthread_mutex_unlock(&pTinfo->thread_lock);
			DEBUG("thread %u end waiting for a job\n", pTinfo->thread_id);
		}
		if(pTinfo->tp_pool->stop_flag){
			DEBUG("thread %u stop\n", pTinfo->thread_id);
			break;
		}
	}
	DEBUG("Job done, thread %u is idle now.\n", pTinfo->thread_id);
	printf("Job done, thread %lu is idle now.\n", pTinfo->thread_id);
	return NULL;
}

/**
 * member function reality. get current thread pool status:idle, normal, busy, .etc.
 * para:
 * 	pTp: thread pool struct instance ponter
 * return:
 * 	0: idle; 1: normal or busy(don't process)
 */
int tp_get_tp_status(TpThreadPool *pTp) {
	float busy_num = 0.0;
//	int i;

	//get busy thread number
	busy_num = pTp->cur_th_num - ts_queue_count(pTp->idle_q);

	DEBUG("Current thread pool status, current num: %u, busy num: %u, idle num: %u\n", pTp->cur_th_num, (unsigned)busy_num, ts_queue_count(pTp->idle_q));
	if(busy_num / (pTp->cur_th_num) < pTp->busy_threshold)
		return 0;//idle status
	else
		return 1;//busy or normal status	
}

/**
 * internal interface. manage thread pool to delete idle thread.
 * para:
 * 	pthread: thread pool struct ponter
 * return:
 */
static void *tp_manage_thread(void *arg) {
	TpThreadPool *pTp = (TpThreadPool*) arg;//main thread pool struct instance

	//1?
	sleep(pTp->manage_interval);

	do {
		if (tp_get_tp_status(pTp) == 0) {
			do {
				if (!tp_delete_thread(pTp))
					break;
			} while (TRUE);
		}//end for if

		//1?
		sleep(pTp->manage_interval);
	} while (!pTp->stop_flag);
	return NULL;
}

float tp_get_busy_threshold(TpThreadPool *pTp){
	return pTp->busy_threshold;
}

int tp_set_busy_threshold(TpThreadPool *pTp, float bt){
	if(bt <= 1.0 && bt > 0.)
		pTp->busy_threshold = bt;
	return 0;
}

unsigned tp_get_manage_interval(TpThreadPool *pTp){
	return pTp->manage_interval;
}

int tp_set_manage_interval(TpThreadPool *pTp, unsigned mi){
	pTp->manage_interval = mi;
	return 0;
}
