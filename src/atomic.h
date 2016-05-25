#ifndef __ATOMIC_T__
#define __ATOMIC_T__


#include <stdint.h>

typedef struct {
	volatile uint16_t cnt; /**< An internal counter value. */
} atomic16_t;

#define ATOMIC16_INIT(val) { (val) }

static inline void atomic16_init(atomic16_t *v)
{
	v->cnt = 0;
}

static inline uint16_t atomic16_read(const atomic16_t *v)
{
	return v->cnt;
}

static inline void atomic16_set(atomic16_t *v, uint16_t new_value)
{
	v->cnt = new_value;
}

static inline uint16_t atomic16_add(atomic16_t *v, uint16_t inc)
{
	return __sync_fetch_and_add(&v->cnt, inc);
}

static inline uint16_t atomic16_sub(atomic16_t *v, uint16_t dec)
{
	return __sync_fetch_and_sub(&v->cnt, dec);
}

static inline void atomic16_inc(atomic16_t *v)
{
	atomic16_add(v, 1);
}

static inline void atomic16_dec(atomic16_t *v)
{
	atomic16_sub(v, 1);
}

static inline uint16_t atomic16_add_return(atomic16_t *v, uint16_t inc)
{
	return __sync_add_and_fetch(&v->cnt, inc);
}

static inline uint16_t atomic16_sub_return(atomic16_t *v, uint16_t dec)
{
	return __sync_sub_and_fetch(&v->cnt, dec);
}

static inline void atomic16_clear(atomic16_t *v)
{
	v->cnt = 0;
}



typedef struct {
	volatile uint32_t cnt; /**< An internal counter value. */
} atomic32_t;

#define RTE_ATOMIC32_INIT(val) { (val) }

static inline void atomic32_init(atomic32_t *v)
{
	v->cnt = 0;
}

static inline uint32_t atomic32_read(const atomic32_t *v)
{
	return v->cnt;
}

static inline void atomic32_set(atomic32_t *v, uint32_t new_value)
{
	v->cnt = new_value;
}

static inline uint32_t atomic32_add(atomic32_t *v, uint32_t inc)
{
	return __sync_fetch_and_add(&v->cnt, inc);
}

static inline uint32_t atomic32_sub(atomic32_t *v, uint32_t dec)
{
	return __sync_fetch_and_sub(&v->cnt, dec);
}

static inline void atomic32_inc(atomic32_t *v)
{
	atomic32_add(v, 1);
}

static inline void atomic32_dec(atomic32_t *v)
{
	atomic32_sub(v,1);
}

static inline uint32_t atomic32_add_return(atomic32_t *v, uint32_t inc)
{
	return __sync_add_and_fetch(&v->cnt, inc);
}

static inline uint32_t atomic32_sub_return(atomic32_t *v, uint32_t dec)
{
	return __sync_sub_and_fetch(&v->cnt, dec);
}

static inline int atomic32_inc_and_test(atomic32_t *v)
{
	return (__sync_add_and_fetch(&v->cnt, 1) == 0);
}

static inline void atomic32_clear(atomic32_t *v)
{
	v->cnt = 0;
}


typedef struct {
    volatile uint64_t cnt;
} atomic64_t;


static inline void atomic64_init(atomic64_t *v)
{
	v->cnt = 0;
}

static inline uint64_t atomic64_read(const atomic64_t *v)
{
	return v->cnt;
}

static inline void atomic64_set(atomic64_t *v, uint64_t new_value)
{
	v->cnt = new_value;
}

static inline uint32_t atomic64_add(atomic64_t *v, uint64_t inc)
{
	return __sync_fetch_and_add(&v->cnt, inc);
}

static inline uint32_t atomic64_sub(atomic64_t *v, uint64_t dec)
{
	return __sync_fetch_and_sub(&v->cnt, dec);
}

static inline void atomic64_inc(atomic64_t *v)
{
	atomic64_add(v, 1);
}

static inline void atomic64_dec(atomic64_t *v)
{
	atomic64_sub(v, 1);
}

static inline uint32_t atomic64_add_return(atomic64_t *v, uint64_t inc)
{
	return __sync_add_and_fetch(&v->cnt, inc);
}

static inline uint32_t atomic64_sub_return(atomic64_t *v, uint64_t dec)
{
	return __sync_sub_and_fetch(&v->cnt, dec);
}

static inline int atomic64_inc_and_test(atomic64_t *v)
{
	return (__sync_add_and_fetch(&v->cnt, 1) == 0);
}

static inline void atomic64_clear(atomic64_t *v)
{
	v->cnt = 0;
}

#endif
