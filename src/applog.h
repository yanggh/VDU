

#include <syslog.h>

#define DEF_APP_SYSLOG_FACILITY LOG_LOCAL0
#define DEF_APP_LOG_LEVEL LOG_INFO

#define APP_LOG_LEVEL_INFO       LOG_INFO
#define APP_LOG_LEVEL_EMERG      LOG_EMERG
#define APP_LOG_LEVEL_ALERT      LOG_ALERT
#define APP_LOG_LEVEL_CRIT       LOG_CRIT
#define APP_LOG_LEVEL_ERR        LOG_ERR
#define APP_LOG_LEVEL_WARNING    LOG_WARNING
#define APP_LOG_LEVEL_NOTICE     LOG_NOTICE
#define APP_LOG_LEVEL_DEBUG      LOG_DEBUG


#define APP_LOG_MASK_BASE	0x01
#define APP_LOG_MASK_MA		0x02
#define APP_LOG_MASK_SIGNAL	0x04
#define APP_LOG_MASK_FILTER	0x08
#define APP_LOG_MASK_CDR	0x10

#define APP_VPU_LOG_MASK_BASE	    0x20
#define APP_VPU_LOG_MASK_MA	        0x40
#define APP_VPU_LOG_MASK_IO	        0x80
#define APP_VPU_LOG_MASK_WORKER	    0x100
#define APP_VPU_LOG_MASK_FILESRV	0x200
#define APP_VPU_LOG_MASK_FAX	    0x400
#define APP_VPU_LOG_MASK_CDR	    0x800
#define APP_VPU_LOG_MASK_CYCLE	    0x1000

extern unsigned int g_app_debug_mask;
extern unsigned int g_app_log_level;

#define open_applog openlog
#define applog(x, y, ...)  if ((g_app_log_level >= x)||(g_app_debug_mask&y)) \
                           {  \
                               syslog(x, __VA_ARGS__); \
                           }
#define close_applog closelog

void applog_set_debug_mask(unsigned int mask);
void applog_set_log_level(unsigned int level);
void get_log_para(void);
