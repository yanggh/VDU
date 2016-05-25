#ifndef __LIKN_H_
#define __LIKN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdint.h>
typedef struct node
{
	void *data;
	int flag;
	int data_len;
	struct node *next;
} *PNODE, NODE;

typedef struct queue 
{
	uint64_t count;
	PNODE front;
	PNODE rear;
} *PQUEUE, QUEUE;


extern PQUEUE create_queue();
extern int is_empty_queue(PQUEUE head);
extern int queue_delete(PQUEUE head, void *data);
extern int queue_insert(PQUEUE head, void *data, int len);
extern PNODE create_node(void *data, int len);
extern int is_one_node(PQUEUE head);
extern void destory_queue(PQUEUE lq);
//extern int compare(void *listdata, void *data);
#endif

