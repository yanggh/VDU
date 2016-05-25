

#include <string.h>
#include <stdlib.h>
#include "applog.h"
#include "conf.h"

unsigned int g_app_debug_mask = APP_LOG_MASK_BASE;
unsigned int g_app_log_level =	DEF_APP_LOG_LEVEL;

void applog_set_debug_mask(const unsigned int mask)
{
	g_app_debug_mask = mask;
}

void applog_set_log_level(const unsigned int level)
{
	g_app_log_level = level;
}

void get_log_para(void)
{
	char *value;
	unsigned int level = DEF_APP_LOG_LEVEL;

	if (ConfGet("log.level", &value) == 1)
	{
		if(strcmp("info", value) == 0)
			level = APP_LOG_LEVEL_INFO;
		else if(strcmp("emerg", value) == 0)
			level = APP_LOG_LEVEL_EMERG;
		else if(strcmp("crit", value) == 0)
			level = APP_LOG_LEVEL_CRIT;
		else if(strcmp("err", value) == 0)
			level = APP_LOG_LEVEL_ERR;
		else if(strcmp("alert", value) == 0)
			level = APP_LOG_LEVEL_ALERT;
		else if(strcmp("debug", value))
			level = APP_LOG_LEVEL_DEBUG;
		else if(strcmp("notice", value) == 0)
			level = APP_LOG_LEVEL_NOTICE;
		else if(strcmp("warning", value) == 0)
			level = APP_LOG_LEVEL_WARNING;
		else
			applog(LOG_ERR, APP_LOG_MASK_BASE, "Invalid value of log level"); 
	}
	applog_set_log_level(level);

	if (ConfGet("log.mask", &value) == 1)
	{
		applog_set_debug_mask(atoi(value));
	}
	applog(LOG_INFO, APP_LOG_MASK_BASE, "Log parameters Level:%d, mask:%d\n", g_app_log_level, g_app_debug_mask);
}
