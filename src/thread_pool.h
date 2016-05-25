/*
 * @author: boyce
 * @contact: boyce.ywr#gmail.com (# -> @)
 * @version: 1.02
 * @created: 2011-07-25
 * @modified: 2011-08-04
 * @modified: 2012-05-14
 */

#ifndef __THREAD_POOL_H
#define __THREAD_POOL_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pthread.h>
#include <signal.h>

#include "tsqueue.h"

#ifndef BOOL
#define BOOL int
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define BUSY_THRESHOLD 0.5	//(busy thread)/(all thread threshold)
#define MANAGE_INTERVAL 30	//tp manage thread sleep interval, every MANAGE_INTERVAL seconds, manager thread will try to recover idle threads as BUSY_THRESHOLD

typedef struct tp_thread_info_s TpThreadInfo;
typedef struct tp_thread_pool_s TpThreadPool;

typedef void (*process_job)(void *arg);

//thread info
struct tp_thread_info_s {
	pthread_t thread_id; //thread id num
	BOOL is_busy; //thread status:true-busy;flase-idle
	pthread_cond_t thread_cond;
	pthread_mutex_t thread_lock;
	process_job proc_fun;
	void *arg;
	TpThreadPool *tp_pool;
};

//main thread pool struct
struct tp_thread_pool_s {
	unsigned min_th_num; //min thread number in the pool
	unsigned cur_th_num; //current thread number in the pool
	unsigned max_th_num; //max thread number in the pool
	pthread_mutex_t tp_lock;
	pthread_cond_t tp_cond;
	pthread_mutex_t loop_lock;
	pthread_cond_t loop_cond;
	
	TpThreadInfo *thread_info;
	TSQueue *idle_q; //idle queue
	BOOL stop_flag; //whether stop the threading pool
	
	pthread_t manage_thread_id; //manage thread id num
	float busy_threshold; //
	unsigned manage_interval; //
};

TpThreadPool *tp_create(unsigned min_num, unsigned max_num);
int tp_init(TpThreadPool *pTp);
void tp_loop(TpThreadPool *pTp);
void tp_exit(TpThreadPool *pTp);
void tp_close(TpThreadPool *pTp, BOOL wait);
int tp_process_job(TpThreadPool *pTp, process_job proc_fun, void *arg);

float tp_get_busy_threshold(TpThreadPool *pTp);
int tp_set_busy_threshold(TpThreadPool *pTp, float bt);
unsigned tp_get_manage_interval(TpThreadPool *pTp);
int tp_set_manage_interval(TpThreadPool *pTp, unsigned mi); //mi - manager interval time, in second

#endif
