#include "head.h"
#include "link.h"
#include "conn_serv.h"
#include "util-daemon.h"
#include "pkt_fifo.h"
#include "atomic.h"
PQUEUE queue;
CONF_T conf_para;
session_t voice_info[SR155_NUM][E1_NUM][TS_NUM];
pkt_fifo_t pkt_fifos[WORKER_NUM];
//TpThreadPool *tp_pool; 
vrs_t *vrs_msg;
pthread_mutex_t mutex;

int main(int argc, const char *argv[])
{
	Daemonize();
	open_applog("vdu", LOG_NDELAY, LOG_LOCAL0);
	applog_set_debug_mask(0);
	memset(&conf_para, 0, sizeof(conf_para));
	//tp_pool = tp_create(TP_NUM, TP_NUM);
	//tp_init(tp_pool);
	param_parser(argc, (char **)argv);
	get_conf_para();
	get_vrs_conf();
	get_dms_conf();		
	init_atomic_counter();
	init_vrs_msg();
	init_pkt_fifo();
	init_voice_info();
	pthread_t pid, 
	//		  voice_handle_id, 
			  voice_handle_id[WORKER_NUM], 
			  vrs_id, 
			  recv_vrs_id,
			  register_sguard_id,
			  connect_ma_id,
			  stop_cmd_id;
	int ret = 0;
	uint64_t i;

	pthread_mutex_init(&mutex, NULL);
	queue = create_queue();
	ret = pthread_create(&pid, NULL, thread_delivery, NULL);
	if (ret == -1) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "create pthread is fail");
		return -1;
	}
#if 0
	ret = pthread_create(&voice_handle_id, NULL, thread_voice_handle, NULL);
	if (ret == -1) {
		syslog(LOG_INFO, "create thread_voice_handle is fail");
		return -1;
	}
#endif
	for (i = 0; i < WORKER_NUM; i ++) {
		ret = pthread_create(&voice_handle_id[i], NULL, thread_voice_handle, (void *)(uint64_t)i);
		if (ret == -1) {
			applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "create thread_voice_handle is fail");
			return -1;
		}
	}
	ret = pthread_create(&vrs_id, NULL, get_vrs_stop_cmd, NULL);
	if (ret == -1) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "create get_vrs_stop_cmd is fail");
		return -1;
	}

	ret = pthread_create(&recv_vrs_id, NULL, thread_stop_session, NULL);
	if (ret == -1) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "create thread_stop_session is fail");
		return -1;
	}
	ret = pthread_create(&stop_cmd_id, NULL, thread_get_stop_cmd, NULL);
	if (ret == -1) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "create thread_get_stop_cmd is fail");
		return -1;
	}
	ret = pthread_create(&register_sguard_id, NULL, thread_register_sguard, NULL);
	if (ret == -1) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "create thread_register_sguard is fail");
		return -1;
	}
	
	ret = pthread_create(&connect_ma_id, NULL, thread_connect_ma, NULL);
	if (ret == -1) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "create thread_connect_ma is fail");
		return -1;
	}

	pthread_join(connect_ma_id, NULL);
	pthread_join(stop_cmd_id, NULL);
	pthread_join(register_sguard_id, NULL);
	pthread_join(recv_vrs_id, NULL);
	//pthread_join(voice_handle_id, NULL);
#if 1
	for (i = 0; i < WORKER_NUM; i ++) {
		pthread_join(voice_handle_id[i], NULL);
	}
#endif
	pthread_join(vrs_id, NULL);
	pthread_join(pid, NULL);	
//	tp_close(tp_pool, 1 );
	pthread_mutex_destroy(&mutex);	
	release_memory();

	return 0;
}
