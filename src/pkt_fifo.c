#include <stdio.h>
#include <string.h>
#include "pkt_fifo.h"

extern pkt_fifo_t pkt_fifos[WORKER_NUM];
extern uint64_t unhandle_packet, pcap_packet, recv_packet, send_packet, handle_packet, lose_packet;

void init_pkt_fifo(void)
{
    int i;
    memset(pkt_fifos, 0, sizeof(pkt_fifo_t) * WORKER_NUM);
    for (i = 0; i < WORKER_NUM; i++) {
        pkt_fifos[i].size = PKT_FIFO_SIZE;
        atomic32_init(&pkt_fifos[i].count);
		printf("pkt_fifos[%d].in = %d out = %d size = %d\n", i, pkt_fifos[i].in, pkt_fifos[i].out, pkt_fifos[i].size);
    }
}


inline int pkt_fifo_put(pkt_fifo_t *fifo, pkt_node_t *node)
{
    uint32_t in = fifo->in;
    uint32_t size = fifo->size;
    uint32_t count = atomic32_read(&fifo->count);
    pkt_buf_t *pkt = fifo->pkt;

    if (unlikely(count >= size)) {
        applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_IO, 
                "pkt_fifo_put count: %u, size: %u, fifo no space for new node\n", count, size);
        return -1;
    }
    memcpy(pkt[in].pkt, node->pkt, node->pkt_len);
    pkt[in].pkt_len = node->pkt_len;

    atomic32_add(&fifo->count, 1);
    in = in + 1;
    if (unlikely(in >= size)) {
        in = 0;
    }
    fifo->in = in;

    return 0;
}


inline int pkt_fifo_get(pkt_fifo_t *fifo, pkt_node_t *node)
{
    uint32_t out;
    uint32_t size;
    uint32_t count;
    pkt_buf_t *pkt;

    if (fifo == NULL || node == NULL) {
        applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_WORKER, "pkt_fifo_get fifo: %p, node: %p", fifo, node);
        return -1; //no data in fifo
    }

    out = fifo->out;
    size = fifo->size;
    count = atomic32_read(&fifo->count);
    pkt = fifo->pkt;

    if (count <= 0) {
        return -2;
    }
    if (unlikely(out >= size)) {
        applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_WORKER, "pkt_fifo_get out: %u, size: %u", out, size);
        return -3;
    }
    node->pkt = pkt[out].pkt;
    node->pkt_len = pkt[out].pkt_len;
    atomic32_sub(&fifo->count, 1);
    out = out + 1;
    if (unlikely(out >= size)) {
        out = 0;
    }
    fifo->out = out;
    return 0;
}


