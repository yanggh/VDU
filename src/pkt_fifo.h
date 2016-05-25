#ifndef __PKT_FIFO_H__
#define __PKT_FIFO_H__

#include "vpu.h"
#include "atomic.h"

typedef struct pkt_node_
{
    uint8_t *pkt;
    uint32_t pkt_len;
} pkt_node_t;

typedef struct pkt_buf_
{
    uint8_t pkt[MAX_ETH_PACKET_LEN];
    uint32_t pkt_len;
} pkt_buf_t;


typedef struct pkt_fifo_
{
    uint32_t in;
    uint32_t out;
    uint32_t size;
    atomic32_t count;
    pkt_buf_t pkt[PKT_FIFO_SIZE];
} pkt_fifo_t;

extern pkt_fifo_t pkt_fifos[WORKER_NUM];


void init_pkt_fifo(void);
inline int pkt_fifo_put(pkt_fifo_t *fifo, pkt_node_t *node);
inline int pkt_fifo_get(pkt_fifo_t *fifo, pkt_node_t *node);

#endif
