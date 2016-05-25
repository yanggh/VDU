#ifndef __CONF_H__
#define __CONF_H__


#define COLLECTOR_YAML_FILE "/usr/local/etc/collector.yaml"

#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif
/*
 * Tail queue definitions.
 */
#define TAILQ_HEAD(name, type) 			\
struct name { 							\
	struct type *tqh_first; /* first element */   			\
	struct type **tqh_last; /* addr of last next element */ \
}

#define TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
}

/**
 * Structure of a configuration parameter.
 */
typedef struct ConfNode_ {
	char *name;
	char *val;

	int is_seq;
	int allow_override;

	struct ConfNode_ *parent;
	TAILQ_HEAD(, ConfNode_) head;
	TAILQ_ENTRY(ConfNode_) next;
} ConfNode;

#define SCCalloc(nm,a) ({ 			\
		void *ptrmem = NULL;		\
				\
		ptrmem = calloc((nm),(a));	\
		(void *)ptrmem;				\
})

#define SCStrdup(a) ({				\
		char *ptrmem = NULL;		\
				\
		ptrmem = strdup((a));		\
		(void *)ptrmem;				\
})

#define SCMalloc(a) ({				\
	void *ptrmem = NULL;			\
				\
	ptrmem = malloc((a));			\
	(void *)ptrmem;					\
})

#define TAILQ_INIT(head) do {		\
	(head)->tqh_first = NULL;		\
	(head)->tqh_last = &(head)->tqh_first;			\
}while(0)

#define TAILQ_INSERT_TAIL(head,elm,field) do {		\
	(elm)->field.tqe_next = NULL;					\
	(elm)->field.tqe_prev = (head)->tqh_last;		\
	*(head)->tqh_last = (elm);						\
	(head)->tqh_last = &(elm)->field.tqe_next;		\
}while(0)

#define TAILQ_FIRST(head)	((head)->tqh_first)
#define TAILQ_END(head)		NULL
#define TAILQ_NEXT(elm,field)		((elm)->field.tqe_next)
#define TAILQ_FOREACH(var,head,field)				\
	for((var) = TAILQ_FIRST(head);					\
		(var) != TAILQ_END(head);					\
		(var) = TAILQ_NEXT(var,field))

#define SCFree(a) ({	\
	free(a);			\
})

/* wrapper around memcmp to match the retvals of the SIMD implementations */
#define SCMemcmp(a,b,c) ({ \
    memcmp((a), (b), (c)) ? 1 : 0; \
})

#define _Q_INVALIDATE(a) ((a) = ((void *)-1))

#define TAILQ_REMOVE(head, elm, field) do {				\
	if (((elm)->field.tqe_next) != NULL)				\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    (elm)->field.tqe_prev;				\
	else								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = (elm)->field.tqe_next;			\
	_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_Q_INVALIDATE((elm)->field.tqe_next);				\
} while (0)

void ConfInit(void);
ConfNode *ConfNodeNew(void);
ConfNode *ConfGetRootNode(void);
ConfNode *ConfGetNode(const char *key);
int ConfGet(const char *name, char **vptr);
ConfNode *ConfNodeLookupChild(ConfNode *node, const char *name);
void ConfNodeFree(ConfNode *node);
void ConfNodeRemove(ConfNode *node);
ConfNode *ConfGetAlertNode(void);
int ConfAlertDataIMG(ConfNode *alert);
int ConfYamlLoadFile(const char *filename);
int ConfValIsTrue(const char *val);
size_t strlcpy(char *dst, const char *src, size_t siz);
size_t strlcat(char *dst, const char *src, size_t siz);
void ConfDeInit(void);
void ConfDump(void);

#endif // __CONF_H__
