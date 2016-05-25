#include "link.h"

PNODE create_node(void *data, int len)
{
	if (data == NULL || len < 0)
		return NULL;
	PNODE tmp = NULL;

	tmp = (PNODE)malloc(sizeof(NODE));

	if (tmp == NULL) {
		syslog(LOG_ERR, "malloc fail");
		return NULL;
	}
	memset(tmp, 0, sizeof(NODE));
	tmp->data = malloc(len);
	if (tmp->data == NULL) {
		syslog(LOG_ERR, "malloc fail");
		return NULL;
	}
	memcpy(tmp->data, data, len);
	tmp->data_len = len;
	tmp->next = NULL;

	return tmp;
}

int is_one_node(PQUEUE head)
{
	if (head != NULL)
		return head->front->next == head->rear ? 1 : 0;
	else 
		return -1;
}

PQUEUE create_queue()
{
	PQUEUE head = NULL;
	PNODE node = NULL;
	int num = 0;

	node = create_node((void *)(&num), sizeof(num));

	head = (PQUEUE)malloc(sizeof(QUEUE));
	head->front = node;
	head->rear = node;
	head->count = 0;

	return head;
}

int  is_empty_queue(PQUEUE head)
{
	if (head != NULL)
		return head->front == head->rear ? 1 : 0;
	else 
		return -1;
}


int queue_insert(PQUEUE head, void *data, int len)
{
	if (head == NULL || data == NULL || len <= 0)
		return -1;
	PNODE tmp = NULL;
	
	if (len < 0 || data == NULL)
		return -1;

	tmp = create_node(data, len);
	if (tmp == NULL)
		return -1;
	head->count ++;
	head->rear->next = tmp;
	head->rear = tmp;

	return 0;
}

int queue_delete(PQUEUE head, void *data)
{
	if (head == NULL || data == NULL)
		return -1;
	if (is_empty_queue(head))
		return -1;

	PNODE tmp, queuenode;

	tmp = head->front->next;

	//printf("data : %p tmp->data : %p tmp->data_len : %d\n", data, tmp->data, tmp->data_len);
	if (tmp->data != NULL)
		memcpy(data, tmp->data, tmp->data_len);
	
	queuenode = head->front;
	head->front = head->front->next;

	if (queuenode->data) 
		free(queuenode->data);
	free(queuenode);
	queuenode->data = NULL;
	queuenode = NULL;
	head->count --;
	
	return 0;
}

void destory_queue(PQUEUE head)
{
	if (head == NULL)
		return ;
	PNODE tmp = head->front;

	while (tmp != NULL)
	{
		head->front = tmp->next;
		if (tmp->data != NULL) {
			free(tmp->data);
			tmp->data = NULL;
		}
		free(tmp);
		tmp = NULL;
	}

	free(head);
	head = NULL;
}


