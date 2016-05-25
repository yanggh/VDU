/*
 * =====================================================================================
 *
 *       Filename:  tsqueue.c
 *
 *    Description:  it's a thread safe queue
 *
 *        Version:  1.0
 *        Created:  05/08/2012 09:53:42 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  boyce
 *   Organization:  gw
 *
 * =====================================================================================
 */
 #include <stdlib.h>
 #include <pthread.h>
 #include "tsqueue.h"

#define ITEMS_PER_ALLOC 32

TSQueue *ts_queue_create(){
	TSQueue *cq = (TSQueue *) malloc(sizeof(TSQueue));
	ts_queue_init(cq);
	return cq;
}

void ts_queue_destroy(TSQueue *cq){
	if(!cq)
		return;
	pthread_mutex_destroy(&cq->lock);
	pthread_mutex_destroy(&cq->cqi_freelist_lock);
	free(cq);
}

void ts_queue_init(TSQueue *cq){
	if(!cq)
		return;
	pthread_mutex_init(&cq->lock, NULL);
	cq->head = NULL;
	cq->tail = NULL;
	cq->cqi_freelist = NULL;
	pthread_mutex_init(&cq->cqi_freelist_lock, NULL);
	cq->count = 0;
}

TSQItem *ts_queue_item_new(TSQueue *cq) {
	TSQItem *item = NULL;
	if(!cq)
		return NULL;
	pthread_mutex_lock(&cq->cqi_freelist_lock);
	if (cq->cqi_freelist) {
		item = cq->cqi_freelist;
		cq->cqi_freelist = item->next;
	}
	pthread_mutex_unlock(&cq->cqi_freelist_lock);

	if (NULL == item) {
		int i;
		item = (TSQItem *) malloc(sizeof(TSQItem) * ITEMS_PER_ALLOC);
		if (NULL == item){
			//perror("error to malloc cq item");
			return NULL;
		}
		for (i = 2; i < ITEMS_PER_ALLOC; i++)
			item[i - 1].next = &item[i];

		pthread_mutex_lock(&cq->cqi_freelist_lock);
		item[ITEMS_PER_ALLOC - 1].next = cq->cqi_freelist;
		cq->cqi_freelist = &item[1];
		pthread_mutex_unlock(&cq->cqi_freelist_lock);
	}

	return item;
}

void ts_queue_item_free(TSQueue *cq, TSQItem *item){
	if(!cq || !item)
		return;
	pthread_mutex_lock(&cq->cqi_freelist_lock);
	item->next = cq->cqi_freelist;
	cq->cqi_freelist = item;
	pthread_mutex_unlock(&cq->cqi_freelist_lock);
}

TSQItem *ts_queue_head(TSQueue *cq){
//	TSQItem *item;
	if(!cq)
		return NULL;
	return cq->head;
}

TSQItem *ts_queue_tail(TSQueue *cq){
//	TSQItem *item;
	if(!cq)
		return NULL;
	return cq->tail;
}

TSQItem *ts_queue_peek(TSQueue *cq){
	return ts_queue_head(cq);
}

TSQItem *ts_queue_deq(TSQueue *cq){
	TSQItem *item;
	if(!cq)
		return NULL;

	pthread_mutex_lock(&cq->lock);
	item = cq->head;
	if(NULL != item){
		cq->head = item->next;
		if(NULL == cq->head)
			cq->tail = NULL;
		cq->count--;
	}
	pthread_mutex_unlock(&cq->lock);

	return item;
}

void *ts_queue_deq_data(TSQueue *cq){
	void *data;
	TSQItem *item;
	if(!cq)
		return NULL;
	item = ts_queue_deq(cq);
	if(!item){
		//
		return NULL;
	}
	data = item->data;
	ts_queue_item_free(cq, item);
	return data;
}

void ts_queue_enq(TSQueue *cq, TSQItem *item) {
	if(!cq || !item)
		return;
	item->next = NULL;
	pthread_mutex_lock(&cq->lock);
	if (NULL == cq->tail)
		cq->head = item;
	else
		cq->tail->next = item;
	cq->tail = item;
	cq->count++;
	pthread_mutex_unlock(&cq->lock);
}

int ts_queue_enq_data(TSQueue *cq, void *data){
	TSQItem *item;
	if(!cq || !data)
		return -1;
	item = ts_queue_item_new(cq);
	if(!item){
		//perror("ts_queue_push_data");
		return -1;
	}
	item->data = data;
	ts_queue_enq(cq, item);
	return 0;
}

unsigned ts_queue_count(TSQueue *cq){
	return cq->count;
}

BOOL ts_queue_is_empty(TSQueue *cq){
	return cq->count ? TRUE : FALSE;
}
