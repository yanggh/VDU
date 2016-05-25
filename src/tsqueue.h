/*
 * =====================================================================================
 *
 *       Filename:  tsqueue.h
 *
 *    Description:  it's a thread safe queue
 *
 *        Version:  1.0
 *        Created:  05/09/2012 11:42:42 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  boyce
 *   Organization:  gw
 *
 * =====================================================================================
 */

#ifndef B_TS_QUEUE_H__
#define B_TS_QUEUE_H__

#ifndef BOOL
#define BOOL int
#endif

#ifndef TRUE
#define TRUE 1
#endif 

#ifndef FALSE
#define FALSE 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ts_queue_item TSQItem;

struct ts_queue_item{
	void *data;
	struct ts_queue_item *next;
};

typedef struct ts_queue TSQueue;

struct ts_queue{
	TSQItem *head;
	TSQItem *tail;
	pthread_mutex_t lock;
	
	TSQItem *cqi_freelist;
	pthread_mutex_t cqi_freelist_lock;
	
	unsigned count;
};

TSQueue *ts_queue_create();
void ts_queue_destroy(TSQueue *cq);
void ts_queue_init(TSQueue *cq);
TSQItem *ts_queue_item_new(TSQueue *cq);
void ts_queue_item_free(TSQueue *cq, TSQItem *item);

TSQItem *ts_queue_head(TSQueue *cq);
TSQItem *ts_queue_tail(TSQueue *cq);
TSQItem *ts_queue_peek(TSQueue *cq);

TSQItem *ts_queue_deq(TSQueue *cq);
void *ts_queue_deq_data(TSQueue *cq);
void ts_queue_enq(TSQueue *cq, TSQItem *item);
int ts_queue_enq_data(TSQueue *cq, void *data);

unsigned ts_queue_count(TSQueue *cq);
BOOL ts_queue_is_empty(TSQueue *cq);

#ifdef __cplusplus
}
#endif

#endif
