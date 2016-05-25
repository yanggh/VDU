#ifndef __VPU_H__
#define __VPU_H__

#include "atomic.h"
#include "applog.h"


#define SVM_STOP    (1 << 0)
#define SVM_KILL    (1 << 1)
#define SVM_DONE    (1 << 2)


#define MAX_ETH_PACKET_LEN      1518
#define PCAP_ETH_PROMISC        1
#define PCAP_TIMEOUT            0

#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif

#define PKT_FIFO_SIZE  1024
#define WORKER_NUM     8
#define min(x, y) ({                \
        typeof(x) _min1 = (x);          \
        typeof(y) _min2 = (y);          \
        (void) (&_min1 == &_min2);      \
        _min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({                \
        typeof(x) _max1 = (x);          \
        typeof(y) _max2 = (y);          \
        (void) (&_max1 == &_max2);      \
        _max1 > _max2 ? _max1 : _max2; })



extern uint8_t svm_signal_flags;
#endif
