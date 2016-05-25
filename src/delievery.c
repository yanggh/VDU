#include "head.h"
#include "conf.h"
#include "link.h"
#include "conn_serv.h"
#include "pkt_fifo.h"
#include "atomic.h"
count_t counter;
mutex_num_t mutexnum;
extern pthread_mutex_t mutex;
extern CONF_T conf_para;
extern PQUEUE queue;
PQUEUE vrsqueue;
extern int exitflag;
uint64_t callnum, endnum, timeoutnum;
time_t overtime, lasttime, curtime;
unsigned char tovrs_mac[MAC_SIZE], recv_sr155_mac[MAC_SIZE], send_sr155_mac[MAC_SIZE];
extern vrs_t *vrs_msg;
char *sr155_nic, *vrs_nic, ip[16];
pcap_t *dev_sr155, *dev_vrs;
int tcp_fd[MAX];
int maxfd, conn_num;
fd_set rdfds;
uint16_t port;
extern pkt_fifo_t pkt_fifos[WORKER_NUM];
session_t call_info[SR155_NUM][E1_NUM][TS_NUM];
CALL_T call_array[SR155_NUM][E1_NUM][TS_NUM];
//extern TpThreadPool *tp_pool; 
extern int pacp_flag;
//uint64_t unhandle_packet, pcap_packet, recv_packet, send_packet, handle_packet, lose_packet;
atomic64_t all_packet, unhandle_packet, pcap_packet, 
		   recv_packet, send_packet, handle_packet, 
		   lose_packet, sessnum, sessover, sessovertime,
		   cmdstop, confupdate, cmdstatus, cmdcounter;

void init_atomic_counter(void)
{
	atomic64_init(&unhandle_packet);
	atomic64_init(&pcap_packet);
	atomic64_init(&recv_packet);
	atomic64_init(&send_packet);
	atomic64_init(&handle_packet);
	atomic64_init(&lose_packet);
	atomic64_init(&all_packet);
	atomic64_init(&sessnum);
	atomic64_init(&sessover);
	atomic64_init(&sessovertime);
	atomic64_init(&cmdstop);
	atomic64_init(&confupdate);
	atomic64_init(&cmdstatus);
	atomic64_init(&cmdcounter);
}

void init_vrs_msg(void)
{
	int j, k, l;

	for (j = 0; j < SR155_NUM; j ++) {
		for (k = 0; k < E1_NUM; k ++) {
			for (l = 0; l < TS_NUM; l ++) {
				memset(&call_info[j][k][l], 0, sizeof(session_t));
			}
		}
	}
}

int init_voice_info(void)
{
	return 0;
}

void *thread_delivery(void *arg)
{
	char errbuf[ERR_SIZE], filter_buf[BUFF_SIZE];
	const u_char *voice_packet = NULL;
	struct pcap_pkthdr pkthdr;
    uint64_t callid;
	uint32_t pos;
    uint8_t ts_no = 0;
	vdata_t tmpdata;
	memset(errbuf, 0, sizeof(errbuf));
	pkt_node_t node;

	dev_sr155 = pcap_open_live(conf_para.sr155_nic, PACKET_LENGTH, PROMISCUOUS_STATE, OVERTIME, errbuf);
	if (dev_sr155 == NULL) {
   		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "fail to open network device %s", sr155_nic);
		pthread_exit(NULL);
	}

	dev_vrs = pcap_open_live(vrs_nic, PACKET_LENGTH, PROMISCUOUS_STATE, OVERTIME, errbuf);
	if (dev_vrs == NULL) {
   		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "fail to open network device %s", vrs_nic);
		pthread_exit(NULL);
	} 
	sprintf(filter_buf, "ether src %x:%x:%x:%x:%x:%x and ether dst %x:%x:%x:%x:%x:%x", send_sr155_mac[0], send_sr155_mac[1], send_sr155_mac[2], send_sr155_mac[3], send_sr155_mac[4], send_sr155_mac[5],
			recv_sr155_mac[0], recv_sr155_mac[1], recv_sr155_mac[2], recv_sr155_mac[3], recv_sr155_mac[4], recv_sr155_mac[5]);
	while (1) {
		if (exitflag == 1) {
			pcap_close(dev_sr155);
			pcap_close(dev_vrs);
			break;
		}
		
		if (pacp_flag == 1) {
			pacp_flag = 0;
			pcap_close(dev_sr155);
			pcap_close(dev_vrs);
			dev_sr155 = pcap_open_live(conf_para.sr155_nic, PACKET_LENGTH, PROMISCUOUS_STATE, OVERTIME, errbuf);
			if (dev_sr155 == NULL) {
   				applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "fail to open network device %s", sr155_nic);
				pthread_exit(NULL);
			}

			dev_vrs = pcap_open_live(vrs_nic, PACKET_LENGTH, PROMISCUOUS_STATE, OVERTIME, errbuf);
			if (dev_vrs == NULL) {
   				applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "fail to open network device %s", vrs_nic);
				pthread_exit(NULL);
			} 
		}
		
		usleep(10);
		voice_packet = pcap_next(dev_sr155, &pkthdr);
		time(&curtime);
		atomic64_add(&all_packet, 1);
		if (curtime - lasttime > 10) {
			printf("callnum = %lu endnum = %lu timeout = %lu\n", callnum, endnum, timeoutnum);
			printf("callmutexlock = %lu callmutexunlock = %lu sessionmutexlock = %lu sessionmutexunlock = %lu\n", 
					mutexnum.callmutexlock, mutexnum.callmutexunlock, mutexnum.sessionmutexlock, mutexnum.sessionmutexunlock);
			lasttime = curtime;
		}

		if (voice_packet == NULL)
			continue;
		memset(&tmpdata, 0, sizeof(tmpdata));
		if (pkthdr.len > PACKET_LENGTH)
			continue;
		if (check_voice_packet(voice_packet) == -1) 
			continue;
		memcpy(&callid, voice_packet + 20, 8);
		pos = (callid >> 15) & 0x1ffff;
		ts_no = pos & 0x1f;

		//pcap_packet ++;
		atomic64_add(&pcap_packet, 1);
		memset(&node, 0, sizeof(node));
		node.pkt = (uint8_t *)voice_packet;	
		node.pkt_len = pkthdr.len;
		pkt_fifo_put(&pkt_fifos[ts_no % WORKER_NUM], &node);
#if 0
		memcpy((void *)tmpdata.packet, (void *)voice_packet, pkthdr.len);
		memcpy((void *)&(tmpdata.pkthdr), (void *)&pkthdr, sizeof(pkthdr)); 
		queue_insert(queue, (void *)&tmpdata, sizeof(tmpdata));
#endif 
	}

	pthread_exit(NULL);
}

int check_voice_packet(const u_char *packet)
{
	if (packet == NULL)
		return -1;
	unsigned char endflag = 0, payload_type;
	endflag = *(packet + 33);
	payload_type = *(packet + 16);
	if (packet[12] != POST_TYPE1 || packet[13] != POST_TYPE2)
		return -1;
	if (!(payload_type == PAYLOAD_VOICE_TYPE || payload_type == PAYLOAD_SIGNAL_TYPE))
		return -1;
	if (!(endflag == FIRST_VOICE_PACKET || endflag == LAST_VOICE_PACKET || endflag == VOICE_PACKET))
		return -1;
	return 0;
}

void *thread_voice_handle(void *arg)
{
	uint64_t thread_id = (uint64_t)arg;
	vdata_t tmpdata;
//	vdata_t data_array[TP_NUM];
	pkt_node_t node;

	//memset(data_array, 0, sizeof(vdata_t) * TP_NUM);
	time_t now, last = 0;

	time(&now);
	while (1) {
		if (exitflag == 1)
			break;
		memset(&node, 0, sizeof(node));
		memset(&tmpdata, 0, sizeof(tmpdata));
	
		time(&now);

		if (last == 0 || now - last == 10) {
			last = now;
			applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_BASE, "thread_id = %lu node num = %u", thread_id, atomic32_read(&pkt_fifos[thread_id].count));
		}

		if (0 != pkt_fifo_get(&pkt_fifos[thread_id], &node)) {
			usleep(100);
			continue;
		}
		memcpy((void *)tmpdata.packet, (void *)node.pkt, node.pkt_len);
		tmpdata.pkthdr.len = node.pkt_len;

#if 0
		if (queue_delete(queue, (void *)&tmpdata) == -1) {
			usleep(1);
			continue;
		}
		for (i = 0; i < TP_NUM;) {
			if (data_array[i].flag == 0)
				break;
			i ++;
			if (i == TP_NUM) {
				usleep(100);
				i = 0; 
			}
		}
		memset(&data_array[i], 0, sizeof(vdata_t));
		memcpy((void *)data_array[i].packet, (void *)node.pkt, node.pkt_len);
		data_array[i].pkthdr.len = node.pkt_len;
		data_array[i].flag = 1;
#endif

//		tp_process_job(tp_pool,(process_job)delievery_send_to_vrs, (void *)(vdata_t *)&tmpdata);					

		//pthread_mutex_lock(&mutex);
		//handle_packet ++;
		//pthread_mutex_unlock(&mutex);
		atomic64_add(&handle_packet, 1);
		delievery_send_to_vrs(dev_vrs, tmpdata.packet, &(tmpdata.pkthdr));
	}

	pthread_exit(NULL);
}


int delievery_send_to_vrs(pcap_t *dev, const u_char *packet, struct pcap_pkthdr *pkthdr)
//void delievery_send_to_vrs(void *arg)
{
	if (dev == NULL || packet == NULL || pkthdr == NULL)
		return -1;
	uint64_t callid;
	unsigned char buf[BUFF_SIZE], endflag = 0, payload_type;
	int ret = 0, i;
	int j;
    uint32_t pos;
    uint8_t sr155_no = 0;
    uint8_t e1_no = 0;
    uint8_t ts_no = 0;
	int  vrsid = -1;
	int session_num = 0;
	uint16_t voice_len;
	time_t now = 0, last = 0;

	memset(buf, 0, BUFF_SIZE);
	memcpy(&callid, packet + 20, 8);
	memcpy(&voice_len, packet + 35, 2);
	endflag = *(packet + 33);
	payload_type = *(packet + 16);
	
	i = 0;

	if (packet[12] != POST_TYPE1 || packet[13] != POST_TYPE2) {
		atomic64_add(&unhandle_packet, 1);
		applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "the packet POST_TYPE is not correct");
		return -1;
	}
	if (!(payload_type == PAYLOAD_VOICE_TYPE || payload_type == PAYLOAD_SIGNAL_TYPE)) {
		atomic64_add(&unhandle_packet, 1);
		applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "the packet PAYLOAD_TYPE is not correct");
		return -1;
	}
	if (!(endflag == FIRST_VOICE_PACKET || endflag == LAST_VOICE_PACKET || endflag == VOICE_PACKET)) {
		atomic64_add(&unhandle_packet, 1);
		applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "the packet VOICE_TYPE is not correct");
		return -1;
	}
	pos = (callid >> 15) & 0x1ffff;
	sr155_no = pos >> 11;
	e1_no = (pos >> 5) & 0x3f;
	ts_no = pos & 0x1f;

	for (i = 0; i < conf_para.vrsnum; i ++) {
		if (vrs_msg[i].state == RUNNING)
			break;
	}

	time(&now);
	if (i == conf_para.vrsnum) {
		atomic64_add(&unhandle_packet, 1);
		if (now -last >= 10) {
			last = now;
			applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "there is no more VRS RUNNING");
		}
		return 0;
	}

	//recv_packet ++;
	atomic64_add(&recv_packet, 1);
	if (call_array[sr155_no][e1_no][ts_no].status == 1 && call_array[sr155_no][e1_no][ts_no].callid == callid) {
		if (endflag == LAST_VOICE_PACKET) {
			call_array[sr155_no][e1_no][ts_no].endtime ++;
			if (call_array[sr155_no][e1_no][ts_no].endtime == 2) {
				memset(&call_array[sr155_no][e1_no][ts_no], 0, sizeof(CALL_T));
				counter.session_over ++;
				atomic64_add(&sessover, 1);
			}
		}
		return -1;
	}


	if (call_info[sr155_no][e1_no][ts_no].callid == 0) {
		counter.session_num ++;
		atomic64_add(&sessnum, 1);
		if (call_info[sr155_no][e1_no][ts_no].data_len == NULL)
			call_info[sr155_no][e1_no][ts_no].data_len = (uint16_t *)malloc(VOICE_NUM * STOR_TIME * sizeof(uint16_t));
		bzero(call_info[sr155_no][e1_no][ts_no].data_len, 0);
		if (call_info[sr155_no][e1_no][ts_no].voice_data == NULL)
			call_info[sr155_no][e1_no][ts_no].voice_data = (data_t *)malloc(VOICE_NUM * STOR_TIME * sizeof(data_t));
		bzero(call_info[sr155_no][e1_no][ts_no].voice_data, 0);
		call_info[sr155_no][e1_no][ts_no].callid = callid;
		call_array[sr155_no][e1_no][ts_no].callid = callid;
		call_array[sr155_no][e1_no][ts_no].status = 0;
		if (endflag != LAST_VOICE_PACKET)
			call_array[sr155_no][e1_no][ts_no].endtime = 0;
		else
			call_array[sr155_no][e1_no][ts_no].endtime ++;

		memcpy(call_info[sr155_no][e1_no][ts_no].voice_data[call_info[sr155_no][e1_no][ts_no].count].vdata, packet, pkthdr->len);
		call_info[sr155_no][e1_no][ts_no].data_len[call_info[sr155_no][e1_no][ts_no].count] = pkthdr->len;
		for (i = 0; i < conf_para.vrsnum; i ++) {
			if (vrs_msg[i].state != RUNNING)
				continue;
			if (session_num == 0 || session_num > vrs_msg[i].session_num) {
				session_num = vrs_msg[i].session_num;
				vrsid = vrs_msg[i].vrsid;
			}	
		}
		if (vrsid == -1) {
			applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "there is no more VRS is running");
			return -1;
		}
		call_info[sr155_no][e1_no][ts_no].vrsid = vrsid;
		call_info[sr155_no][e1_no][ts_no].starttime = time(NULL);
		call_info[sr155_no][e1_no][ts_no].count ++;
		for (i = 0; i < conf_para.vrsnum; i ++) {
			if (vrsid == vrs_msg[i].vrsid) {
				vrs_msg[i].callid[vrs_msg[i].session_num] = callid;
				vrs_msg[i].session_num ++;
				call_info[sr155_no][e1_no][ts_no].vrsindex = i;
			}
		}
	} else if (call_info[sr155_no][e1_no][ts_no].callid == callid) {
		if (call_info[sr155_no][e1_no][ts_no].count == VOICE_NUM * STOR_TIME)
			goto STOP_FLAG;
		memcpy(call_info[sr155_no][e1_no][ts_no].voice_data[call_info[sr155_no][e1_no][ts_no].count].vdata, packet, pkthdr->len);
		call_info[sr155_no][e1_no][ts_no].data_len[call_info[sr155_no][e1_no][ts_no].count] = pkthdr->len;
		call_info[sr155_no][e1_no][ts_no].count ++;
	} else if (call_info[sr155_no][e1_no][ts_no].callid != 0 && call_info[sr155_no][e1_no][ts_no].callid != callid) {
		counter.session_num ++;
		atomic64_add(&sessnum, 1);
		for (i = 0; i < vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].session_num; i ++) {
			if (vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].callid[i] == call_info[sr155_no][e1_no][ts_no].callid) {
				for (j = i; j < vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].session_num - 1; j ++) {
					vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].callid[j] = vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].callid[j + 1];
				}
				vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].callid[j] = 0;
			}
		}
		vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].session_num --;
		init_call_msg(&call_info[sr155_no][e1_no][ts_no]);		
		call_info[sr155_no][e1_no][ts_no].callid = callid;
		memset(&call_array[sr155_no][e1_no][ts_no], 0, sizeof(CALL_T));
		if (endflag != LAST_VOICE_PACKET)
			call_array[sr155_no][e1_no][ts_no].endtime = 0;
		else
			call_array[sr155_no][e1_no][ts_no].endtime ++;
		call_array[sr155_no][e1_no][ts_no].callid = callid;
		call_array[sr155_no][e1_no][ts_no].status = 0;
		memcpy(call_info[sr155_no][e1_no][ts_no].voice_data[call_info[sr155_no][e1_no][ts_no].count].vdata, packet, pkthdr->len);
		call_info[sr155_no][e1_no][ts_no].data_len[call_info[sr155_no][e1_no][ts_no].count] = pkthdr->len;
		for (i = 0; i < conf_para.vrsnum; i ++) {
			if (vrs_msg[i].state != RUNNING)
				continue;
			if (session_num == 0 || session_num > vrs_msg[i].session_num) {
				session_num = vrs_msg[i].session_num;
				vrsid = vrs_msg[i].vrsid;
			}	
		}
		if (vrsid == -1) {
			applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "there is no more VRS is running");
			return -1;
		}
		call_info[sr155_no][e1_no][ts_no].vrsid = vrsid;
		call_info[sr155_no][e1_no][ts_no].starttime = time(NULL);
		call_info[sr155_no][e1_no][ts_no].count ++;
		for (i = 0; i < conf_para.vrsnum; i ++) {
			if (vrsid == vrs_msg[i].vrsid) {
				vrs_msg[i].callid[vrs_msg[i].session_num] = callid;
				vrs_msg[i].session_num ++;
				call_info[sr155_no][e1_no][ts_no].vrsindex = i;
			}
		}
	}
	
	memcpy(buf, packet, pkthdr->len);
	printf("vrsindex = %d\n", call_info[sr155_no][e1_no][ts_no].vrsindex);
	memcpy(buf, vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].vrs_mac, 6);
	memcpy(buf + 6, conf_para.tovrs_mac, 6);
	//send_packet ++;
	atomic64_add(&send_packet, 1);
	ret = pcap_inject(dev, buf, pkthdr->len);
	if (ret == -1) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "fail to data to vrs");
		return -1;
	}

STOP_FLAG:
	if (endflag == LAST_VOICE_PACKET)
		call_info[sr155_no][e1_no][ts_no].endtimes ++;
	if (call_info[sr155_no][e1_no][ts_no].endtimes == 2) {
		counter.session_over ++;
		atomic64_add(&sessover, 1);
		for (i = 0; i < vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].session_num; i ++) {
			if (vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].callid[i] == callid) {
				for (j = i; j < vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].session_num - 1; j ++) {
					vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].callid[j] = vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].callid[j + 1];
				}
				vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].callid[j] = 0;
			}
		}
		vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].session_num --;
	//	init_call_msg(&call_info[sr155_no][e1_no][ts_no]);		
		clear_call_msg(&call_info[sr155_no][e1_no][ts_no]);		
	}
	
	return 0;
}

int clear_call_msg(session_t *data)
{
	data->callid = 0;
	data->count = 0;
	data->voice_len = 0;
	data->stopflag = 0;
	data->endtimes = 0;
	data->endcmd = 0;
	data->vrsid = 0;
	if (data->data_len)
		free(data->data_len);
	data->data_len = NULL;
	data->starttime = 0;
	if (data->voice_data)
		free(data->voice_data);
	data->voice_data = NULL;
	return 0;
}
int init_call_msg(session_t *data)
{
	data->callid = 0;
	data->count = 0;
	data->voice_len = 0;
	data->stopflag = 0;
	data->endtimes = 0;
	data->endcmd = 0;
	data->vrsid = 0;
	bzero(data->data_len, 0);
	data->starttime = 0;
	bzero(data->voice_data, 0);
	return 0;
}

uint32_t get_data_len(session_t *call)
{
	uint32_t len = 0, i;
	for (i = 0; i < call->count; i ++) {
		printf("call->data_len[%d] = %u\n", i, call->data_len[i]);
		len += call->data_len[i];
	}
	return len;
}


int get_conf_para(void)
{
	char *value = NULL;
	ConfInit();
	if (ConfYamlLoadFile(CONF_PATH) != 0) 
	{
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "can`t find the file of %s", CONF_PATH);
		return -1;
	}	

	if (ConfGet("id", &value) == 1) {
		conf_para.id = atoi(value);
	}

	if (ConfGet(RECV_SR155_DEV, &value) == 1) {
		if (conf_para.sr155_nic == NULL) {
			sr155_nic = (char *)malloc(strlen(value) + 1);
			conf_para.sr155_nic = (char *)malloc(strlen(value) + 1);
		}
		strcpy(sr155_nic, value);
		strcpy(conf_para.sr155_nic, value);
		printf("sr155_nic : %s\n", sr155_nic);
	}
	if (ConfGet(SEND_VRS_DEV, &value) == 1) {
		if (conf_para.vrs_nic == NULL) {
			vrs_nic = (char *)malloc(strlen(value) + 1);
			conf_para.vrs_nic = (char *)malloc(strlen(value) + 1);
		}
		strcpy(conf_para.vrs_nic, value);
		strcpy(vrs_nic, value);
		printf("vrs_nic : %s\n", vrs_nic);
	}
	
	get_local_mac(conf_para.vrs_nic, (unsigned char *)conf_para.tovrs_mac);
		

	if (ConfGet(TIMEOUT, &value) == 1) {
		overtime = (time_t)atoi(value);
		conf_para.overtime = (time_t)atoi(value);
		printf("TIMEOUT : %lus\n", conf_para.overtime);
	}

	if (ConfGet("log.level", &value) == 1) {
		conf_para.log_level = (char *)malloc(strlen(value) + 1);
		strcpy(conf_para.log_level, value);
		puts(value);
	}

	if (ConfGet("log.mask", &value) == 1) {
		conf_para.log_mask = atoi(value);
	}

	get_log_para(); 

	ConfDeInit();

	return 0;
}

int check_ip_format(char *ip)
{
	applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_BASE, "ip : %s", ip);
	char *p = ip;
	int i = 0;
	char buff[8];
	unsigned char num = 0;
	int count = 0, flag = 0, numcount = 0;
	memset(buff, 0, sizeof(buff));
	while (*p != '\0') {
		if (*p >= '0' && *p <= '9') {
			flag = 1;
			buff[i] = *p;
			i ++;
		} else if (*p == '.') {
			if (flag == 1)
				numcount ++;
			else {
				applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "befor . is .");
				return -1;
			}
			flag = 0;
			i = 0;
			
			num = atoi(buff);
			if (num > 255 || num < 0) {
				applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "the number beyond the range num = %d buff = %s", num, buff);
				return -1;
			}
			count ++;
		} else {
			applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "the para is %x", *p);
			return -1;
		}
		p ++;
	}
	if (flag == 1) {
		numcount ++;
		num = atoi(buff);
		if (num > 255 || num < 0) {
			applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "the number beyond the range num = %d buff = %s", num, buff);
			return -1;
		}
	} else
		return -1;
	if (count != 3 || numcount != 4) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "count = %d numcount = %d", count, numcount);
		return -1;
	}

	return 0;
}

int check_mac_format(char *mac)
{
	applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_BASE, "mac is %s", mac);
	char *p = mac;
	char buff[4];
	int i = 0;
	int num = 0;
	int count = 0, flag = 0, numcount = 0;

	while (*p != '\0') {
		if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
			buff[i] = *p;
			i ++;
			flag = 1;
		} else if (*p == '-') {
			if (flag == 1) {
				numcount ++;
			} else 
				return -1;
			flag = 0;
			i = 0;
			sscanf(buff, "%x", &num);
			if (num < 0 || num > 0xff)
				return -1;
			count ++;
		} else 
			return -1;
		p ++;
	}

	if (flag == 1) {
		numcount ++;
		sscanf(buff, "%x", &num);
		if (num < 0 || num > 0xff)
			return -1;
	}

	if (count != 5 || numcount != 6)
		return -1;

	return 0;
}



int get_vrs_conf(void) 
{
	int i = 0;
	ConfNode *base, *child, *subchild;
	ConfInit();
	if (ConfYamlLoadFile(PUB_CONF_PATH) != 0) 
	{
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "can`t find the file of %s", PUB_CONF_PATH);
		return -1;
	}	
	base = ConfGetNode("vdu");
	if (base != NULL) {
		TAILQ_FOREACH(child, &base->head, next) {
			TAILQ_FOREACH(subchild, &child->head, next) {
				printf("name : %s val : %s\n", subchild->name, subchild->val);
				if (0 == strcmp(subchild->name, "id")) {
					if (conf_para.id != atoi(subchild->val))
						break;
				} else if (0 == strcmp(subchild->name, "ip")) {
					if (conf_para.ip == NULL)
						conf_para.ip = (char *)malloc(strlen(subchild->val) + 1);
					if (-1 == check_ip_format(subchild->val)) {
						applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "ip format is error");
						exit(1);
					}
					strcpy(conf_para.ip, subchild->val);
					printf("ip : %s\n", conf_para.ip);
				} else if (0 == strcmp(subchild->name, "port")) {
					conf_para.port = atoi(subchild->val);
					printf("port : %d\n", conf_para.port);
				}
			}
		}
	}
	if (conf_para.port == 0) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "configure file is error, not find ip or port");
		exit(-1);
	}
	base = ConfGetNode("groups");
	char *p, *q = NULL;

	if (base != NULL) {
		TAILQ_FOREACH(child, &base->head, next) {
			TAILQ_FOREACH(subchild, &child->head, next) {
				printf("name : %s val : %s\n", subchild->name, subchild->val);
				if (0 == strcmp(subchild->name, "vdu")) {
					if (conf_para.id != atoi(subchild->val))
						break;
				} else if (0 == strcmp(subchild->name, "vpw")) {
					p = subchild->val;
					q = strtok(p, " ");
					if (q == NULL)
						break;
					conf_para.vrsid[conf_para.vrsnum] = atoi(q);
					conf_para.vrsnum ++;
					printf("vrsid = %d\n", atoi(q));
					while (NULL != (q = strtok(NULL, " "))) {
						conf_para.vrsid[conf_para.vrsnum] = atoi(q);
						conf_para.vrsnum ++;
						printf("vrsid = %d\n", atoi(q));
					}
				}
			}
		}
	}

	applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "vpw have %d", conf_para.vrsnum);

	int j = 0;
	if (conf_para.vrsnum != 0) {
		vrs_msg = (vrs_t *)malloc(conf_para.vrsnum * sizeof(vrs_t));
		bzero(vrs_msg, 0);
		for (j = 0; j < conf_para.vrsnum; j ++) {
			pthread_mutex_init(&vrs_msg[j].mutex, NULL); 
		}
	}

	base = ConfGetNode("vpw");

	if (base != NULL) {
		TAILQ_FOREACH(child, &base->head, next) {
			TAILQ_FOREACH(subchild, &child->head, next) {
				printf("name : %s val : %s\n", subchild->name, subchild->val);
				if (!strcmp(subchild->name, "mac")) {
					if (-1 == check_mac_format(subchild->val)) {
						applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "the mac format is error");
						exit(1);
					}
					get_mac(subchild->val, vrs_msg[i].vrs_mac);
					printf("%s i = %d: %x:%x:%x:%x:%x:%x\n", subchild->name, i,
							(unsigned int)vrs_msg[i].vrs_mac[0],
							(unsigned int)vrs_msg[i].vrs_mac[1],
							(unsigned int)vrs_msg[i].vrs_mac[2],
							(unsigned int)vrs_msg[i].vrs_mac[3],
							(unsigned int)vrs_msg[i].vrs_mac[4],
							(unsigned int)vrs_msg[i].vrs_mac[5]
						  );
				} else if (!strcmp(subchild->name, ID)) {
					for (j = 0; j < conf_para.vrsnum; j ++) {
						if (conf_para.vrsid[j] == atoi(subchild->val))
							break;
					}
					if (j == conf_para.vrsnum)
						break;
					vrs_msg[i].vrsid = atoi(subchild->val);
					printf("%s : %d\n", subchild->name, vrs_msg[i].vrsid);
				} else if (!strcmp(subchild->name, IP)) {
					strcpy((char *)vrs_msg[i].ip, (const char *)subchild->val);
					printf("%s : %s\n", subchild->name, vrs_msg[i].ip);
				}
			}
			if (j != conf_para.vrsnum) {
		//		vrs_msg[i].state = 1;
				i ++;
			}
		}
	}

	ConfDeInit();

	return 0;
}

int get_dms_conf(void)
{
    char dump_config = 0;
    char filename[256] = {0};

    ConfInit();

  	snprintf(filename, 255, "%s%s", conf_para.conf_path, "dms.yaml");
	printf("filename : %s\n", filename);
    if (ConfYamlLoadFile(filename) != 0) {
        exit(EXIT_FAILURE);
    }

    if (dump_config) {
        ConfDump();
    }

    get_sguard_port();
    get_ma_port();

    ConfDeInit();

    return 0;
}
int get_ma_port(void)
{
    char *value;

    conf_para.maport = 2001;
    if (ConfGet("ma.maport", &value) == 1) {
        conf_para.maport = atoi(value);
    } else {
    }

	if (conf_para.maip == NULL)
		conf_para.maip = (char *)malloc(strlen(SERV_IP) + 1);
    strncpy(conf_para.maip, SERV_IP, 15);

    return 0;
}
int get_sguard_port(void)
{
    char *value;

    conf_para.sguardport = 2000;
    if (ConfGet("ma.sguardport", &value) == 1) {
        conf_para.sguardport = atoi(value);
    } else {
        applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "get sguard server port failed\n");
    }

	if (conf_para.sguardip == NULL)
		conf_para.sguardip = (char *)malloc(strlen(SERV_IP) + 1);
    strncpy(conf_para.sguardip, SERV_IP, 15);

    return 0;
}

int get_mac(char *value, unsigned char *mac)
{
	unsigned int tmpmac[6];
	memset(tmpmac, 0, sizeof(tmpmac));
	sscanf(value, "%x-%x-%x-%x-%x-%x", &tmpmac[0], &tmpmac[1], &tmpmac[2], &tmpmac[3], &tmpmac[4], &tmpmac[5]);
	mac[0] = (unsigned char)tmpmac[0];
	mac[1] = (unsigned char)tmpmac[1];
	mac[2] = (unsigned char)tmpmac[2];
	mac[3] = (unsigned char)tmpmac[3];
	mac[4] = (unsigned char)tmpmac[4];
	mac[5] = (unsigned char)tmpmac[5];

	return 0;
}

int change_vrs_status(uint32_t id, uint16_t status)
{
	vrs_t *p;
	int i = 0, j = 0;
	int vrsid = -1;
	uint32_t session_num = 0;


	p = vrs_msg;
    applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "change_vrs_status id = %d status = %d", id, status);
	for (i = 0; i < conf_para.vrsnum; i ++) {
		if (p->vrsid == id) {
			if (p->state == RUNNING && status != RUNNING) {
				p->state = (uint32_t)status;
				for (j = 0; j < conf_para.vrsnum; j ++) {
					if (vrs_msg[j].state != RUNNING)
						continue;
					if (session_num == 0 || session_num > vrs_msg[j].session_num) {
						session_num = vrs_msg[j].session_num;
						vrsid = vrs_msg[j].vrsid;
					}	
				}
				if (vrsid == -1) {
					delete_voice_info(id);
					bzero(p->callid, 0);
					p->session_num = 0;
					return -1;
				}
				send_voice_data_to_another_vrs(id, vrsid);
				break;
			} else { 
				p->state = (uint32_t)status;
				return 0;
			}
		}
		p ++;
	}

	return 0;
}

void delete_voice_info(int id)
{
	int i, j, k;
	for (i = 0; i < SR155_NUM; i ++){
		for (j = 0; j < E1_NUM; j ++) {
			for (k = 0; k < TS_NUM; k ++) {
				if (call_info[i][j][k].vrsid == id) {
					free(call_info[i][j][k].data_len);
					free(call_info[i][j][i].voice_data);
					memset(&call_info[i][j][k], 0, sizeof(session_t));
				}
			}
		}
	}
}

int send_voice_data_to_another_vrs(int srcid, int dstid)
{
	int i, j;
	uint64_t callid;
    uint32_t pos;
    uint8_t sr155_no = 0;
    uint8_t e1_no = 0;
    uint8_t ts_no = 0;
	int dst = 0, src = 0;

	for (i = 0; i < conf_para.vrsnum; i ++) {
		if (vrs_msg[i].vrsid == dstid) {
			dst = i;
		}
		if (vrs_msg[i].vrsid == srcid)
			src = i;
	}

	if (i == conf_para.vrsnum)
		return 0;

	for (i = 0; i < vrs_msg[src].session_num; i ++) {
		callid = vrs_msg[src].callid[i];
		pos = (callid >> 15) & 0x1ffff;
		sr155_no = pos >> 11;
		e1_no = (pos >> 5) & 0x3f;
		ts_no = pos & 0x1f;
		call_info[sr155_no][e1_no][ts_no].vrsid = dstid;
		for (j = 0; j < call_info[sr155_no][e1_no][ts_no].count; j ++) {
			pcap_inject(dev_vrs, call_info[sr155_no][e1_no][ts_no].voice_data[j].vdata, call_info[sr155_no][e1_no][ts_no].data_len[j]);	
		}
		vrs_msg[dst].callid[vrs_msg[dst].session_num] = callid;
		vrs_msg[dst].session_num ++;
	}
	
	bzero(vrs_msg[src].callid, 0);
	vrs_msg[src].session_num = 0;
	vrs_msg[src].send_flag = 0;
	vrs_msg[src].fd = 0;
	return 0;
}


void *get_vrs_stop_cmd(void *arg)
{
#if 0
	int socketfd, tcp_listen_fd;	
	char str[32];
	struct pkt_header head;
	int i, ret;
	struct sockaddr_in clientaddr;
	struct timeval tv;
	char buff[BUFF_SIZE];
	
	vrsqueue = create_queue();
	socklen_t addrlen = sizeof(clientaddr);
	while (-1 == (socketfd = create_server_socket(conf_para.ip, conf_para.port))) {
		usleep(1000);
		continue;
	}
	
	if (socketfd == -1) {
		printf("fail to create socket\n");
	}
	conn_num = 0;
	maxfd = socketfd;

	while (1) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&rdfds);
		FD_SET(socketfd, &rdfds);

		for (i = 0; i < MAX; i ++) {
			if (tcp_fd[i] != 0)
				FD_SET(tcp_fd[i], &rdfds);
		}

		if (exitflag == 1)
			break;

		ret = select(maxfd + 1, &rdfds, NULL, NULL, &tv);

		if (ret == -1) {
			continue;
		} else if (ret == 0) {
			continue;
		}

		for (i = 0; i < MAX; i ++) {
			ret = 0;
			if (FD_ISSET(tcp_fd[i], &rdfds)) {
				ret = sock_recv_buf(tcp_fd[i], buff, 8);
				if (ret)
					goto err;
				memcpy(&head, buff, 8);
				ret = check_package_format(&head);
				if (ret == -1)
					goto err;
				ret = sock_recv_buf(tcp_fd[i], buff + 8, ntohs(head.len) - 8);
err:
				if (ret < 0) {
					memset(buff, '\0', BUFF_SIZE);	
				} else {
					queue_insert(vrsqueue, buff, ntohs(head.len));	
					memset(buff, '\0', BUFF_SIZE);
				}
			}
		}


		if (FD_ISSET(socketfd, &rdfds)) {
			tcp_listen_fd = accept(socketfd, (struct sockaddr *)&clientaddr, &addrlen);

			if (tcp_listen_fd <= 0) {
				continue;
			}
			inet_ntop(AF_INET, &clientaddr.sin_addr.s_addr, str, 32);
			change_vrs_fd(str, tcp_listen_fd);
	
			syslog(LOG_INFO, "dev : %s connect success...", str);

			if (conn_num < MAX) {
				for (i = 0; i < MAX; i ++) {
					if (tcp_fd[i] == 0) {
						tcp_fd[i] = tcp_listen_fd;
						conn_num ++;
						break;
					}
				}
				maxfd = maxfd > tcp_listen_fd ? maxfd : tcp_listen_fd;
			} else {
				close(tcp_listen_fd);
				continue;
			}
		}
	}

	destory_queue(vrsqueue);
#endif
	pthread_exit(NULL);
}

int change_vrs_fd(char *ip, int fd)
{
	int i, j;

	for (i = 0; i < conf_para.vrsnum; i ++) {
		if (strlen((char *)vrs_msg[i].ip)) {
			if (!strcmp((char *)ip, (char *)vrs_msg[i].ip)) {
				if (vrs_msg[i].fd != 0) {
					close(vrs_msg[i].fd);
					FD_CLR(vrs_msg[i].fd, &rdfds);
					conn_num --;
					if (vrs_msg[i].fd == maxfd)
						maxfd --;
					for (j = 0; j < MAX; j ++) {
						if (tcp_fd[j] == vrs_msg[i].fd) {
							tcp_fd[i] = 0;
							break;
						}
					}
				}
				vrs_msg[i].fd = fd;
				return 1;
			}
		}
	}
	return 0;
}

int sock_recv_buf(int fd, char *buf, int size)
{
	int ret;
	int len = 0;

	while (len < size)
	{
		ret = recv(fd, &buf[len], (size-len), 0);
		if (ret <= 0)
			return -1;
		len += ret;
	}
	return 0;
}

int check_package_format(struct pkt_header *head)
{
	if (head == NULL)
		return -1;
	if (head->ver != 1 || !(head->reply == 0 || head->reply == 1))
		return -1;
	if (ntohs(head->cmd) > 100 || ntohs(head->cmd) < 1)
		return -1;
	if (ntohs(head->num) < 0 || ntohs(head->num) > 65535)
		return -1;
	if (ntohs(head->len) < 8 || ntohs(head->len) > 65535)
		return -1;

	return 0;
}

int create_server_socket(char *ip, uint16_t port)
{
	if (ip == NULL || port < 1 || port > 65535)
		return -1;
	int tcp_server_fd;
	int yes = 1;
	struct sockaddr_in serveraddr;
	if (-1 == (tcp_server_fd = socket(AF_INET, SOCK_STREAM, 0))) {
		exit(-1);
	}
	
	if (setsockopt(tcp_server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		exit(-1);
	}

	memset(&serveraddr , 0, sizeof(serveraddr));

	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(port);
	serveraddr.sin_addr.s_addr = inet_addr(ip);


	if (bind(tcp_server_fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) == -1) {
		exit(-1);
	}

	if (listen(tcp_server_fd, MAX) == -1) {
		exit(-1);
	}

	return tcp_server_fd;
}

void *thread_stop_session(void *arg)
{
	char buff[BUFF_SIZE];
	time_t last = 0, now = 0;
	time_t total = 0;

	while (1) {
		time(&now);
		if (exitflag == 1)
			break;
		if (now - total >= 10) {
			total = now;
        	applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_BASE, "session_num = %lu session_over = %lu all_packet = %lu pcap_packet = %lu recv_packet = %lu send_packet = %lu, handle_packet = %lu, unhandle_packet = %lu", 
					counter.session_num, counter.session_over, atomic64_read(&all_packet), atomic64_read(&pcap_packet), atomic64_read(&recv_packet), atomic64_read(&send_packet), atomic64_read(&handle_packet), atomic64_read(&unhandle_packet));
		}
		if (now - last >= 1) {
			last = now;
			check_voice_overtime(vrs_msg);
		}
		if (queue_delete(vrsqueue, (void *)buff) == -1) {
			usleep(10);
			continue;
		}
		
    	applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "get a stop cmd from vrs");
		stop_session_send_to_vrs(buff);
	}

	pthread_exit(NULL);
}

int stop_session_send_to_vrs(char *packet)
{
	uint64_t callid = 0;

	callid = get_callid_from_cmd(packet);
	if (callid == -1)
		return -1;

	stop_session_by_callid(callid);
	return 0;
}

int stop_session_by_callid(uint64_t callid)
{
	int i;
    uint32_t pos;
    uint8_t sr155_no = 0;
    uint8_t e1_no = 0;
    uint8_t ts_no = 0;

	pos = (callid >> 15) & 0x1ffff;
	sr155_no = pos >> 11;
	e1_no = (pos >> 5) & 0x3f;
	ts_no = pos & 0x1f;
	if (call_info[sr155_no][e1_no][ts_no].callid == callid) {
		pthread_mutex_lock(&call_info[sr155_no][e1_no][ts_no].mutex);
		applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_BASE, "get a stop callid = %lu session", callid);
		call_info[sr155_no][e1_no][ts_no].endcmd ++;
		if (call_info[sr155_no][e1_no][ts_no].endcmd != 2) {
			pthread_mutex_unlock(&call_info[sr155_no][e1_no][ts_no].mutex);
			return -1;
		}
		applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_BASE, "sr155_no = %d e1_no = %d ts_no = %d", sr155_no, e1_no, ts_no);
		if (call_array[sr155_no][e1_no][ts_no].callid != callid)
			call_array[sr155_no][e1_no][ts_no].callid = callid;
		call_array[sr155_no][e1_no][ts_no].status = 1;
		//init_call_msg(&call_info[sr155_no][e1_no][ts_no]);
		clear_call_msg(&call_info[sr155_no][e1_no][ts_no]);
		call_info[sr155_no][e1_no][ts_no].stopflag = 1;
		for (i = 0; i < vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].session_num; i ++) {
			if (vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].callid[i] == callid) {
				int j;
				for (j = i; j < vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].session_num - 1; j ++) {
					vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].callid[j] = vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].callid[j + 1];
				}
				vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].callid[j] = 0;
			}
		}
		vrs_msg[call_info[sr155_no][e1_no][ts_no].vrsindex].session_num --;		
		pthread_mutex_unlock(&call_info[sr155_no][e1_no][ts_no].mutex);
		return 1;
	}

	return 0;
}

uint64_t get_callid_from_cmd(char *data) 
{
	if (data == NULL)
		return -1;

	uint16_t len = 0, datalen = 0, type = 0, sublen = 0;
	struct pkt_header head;
	char *p = data + 8;
	uint64_t callid = 0;

	memcpy(&head, data, 8);
	datalen = ntohs(head.len) - 8;
	//syslog(LOG_INFO, "datalen = %u", datalen);
	while (len < datalen) {
		memcpy(&type, p + len, 2);
		memcpy(&sublen, p + len + 2, 2);
		switch (ntohs(type)) {
			case 1:
				memcpy(&callid, p + 4, ntohs(sublen));
				applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_BASE, "receive a cmd to stop callid = %lu session", be64toh(callid));
				break;
			default:
				return -1;
		}
		len = len + ntohs(sublen) + 4;
		p = p + ntohs(sublen) + 4;
	}
	
	return be64toh(callid);
}

void release_memory(void)
{
	int i, j, k, l;
	destory_queue(queue);
	for (l = 0; l < conf_para.vrsnum; l ++) {
		pthread_mutex_destroy(&vrs_msg[l].mutex);
	}
	for (i = 0; i < SR155_NUM; i ++) {
		for (j = 0; j < E1_NUM; j ++) {
			for (k = 0; k < TS_NUM; k ++) {
				if (call_info[i][j][k].voice_data)
					free(call_info[i][j][k].voice_data);
				if (call_info[i][j][k].data_len)
					free(call_info[i][j][k].data_len);
				pthread_mutex_destroy(&call_info[i][j][k].mutex);
			}
		}
	}
	destory_conf(&conf_para);

}

int change_call_msg_index(int index, int vrsid)
{
	int i, j, k;
	for (i = 0; i < SR155_NUM; i ++) {
		for (j = 0; j < E1_NUM; j ++) {
			for (k = 0; k < TS_NUM; k ++) {
				if (call_info[i][j][k].vrsid == vrsid)
					call_info[i][j][k].vrsindex = index;
			}
		}
	}
	return 0;
}

void destory_conf(CONF_T *conf_para)
{
	if (conf_para->ip)
		free(conf_para->ip);
	if (conf_para->maip)
		free(conf_para->maip);
	if (conf_para->sguardip)
		free(conf_para->sguardip);
	if (conf_para->conf_path)
		free(conf_para->conf_path);
	if (conf_para->app_name)
		free(conf_para->app_name);
	if (conf_para->sr155_nic)
		free(conf_para->sr155_nic);
	if (conf_para->vrs_nic)
		free(conf_para->vrs_nic);
	if (conf_para->log_level)
		free(conf_para->log_level);
}

int check_voice_overtime(vrs_t *vrsmsg)
{
	if (vrsmsg == NULL)
		return -1;
	
	int i, j, k, l;
	time_t cur;
	uint32_t pos;
	uint8_t sr155_no = 0;
	uint8_t e1_no = 0;
	uint8_t ts_no = 0;
	uint64_t callid = 0;

	for (j = 0; j < SR155_NUM; j ++) {
		for (k = 0; k < E1_NUM; k ++) {
			for (l = 0; l < TS_NUM; l ++) {
				if (call_info[j][k][l].callid == 0)
					continue;
				time(&cur);
				if (cur - call_info[j][k][l].starttime >= conf_para.overtime) {
					atomic64_add(&sessovertime, 1);
					pthread_mutex_lock(&call_info[j][k][l].mutex);
					callid = call_info[j][k][l].callid;
					pos = (callid >> 15) & 0x1ffff;
					sr155_no = pos >> 11;
					e1_no = (pos >> 5) & 0x3f;
					ts_no = pos & 0x1f;
					if (call_array[sr155_no][e1_no][ts_no].callid != callid)
						call_array[sr155_no][e1_no][ts_no].callid = callid;

					call_array[sr155_no][e1_no][ts_no].status = 1;
					atomic64_add(&sessovertime, 1);
					timeoutnum ++;
					for (i = 0; i < vrs_msg[call_info[j][k][l].vrsindex].session_num; i ++) {
						if (vrs_msg[call_info[j][k][l].vrsindex].callid[i] == callid) {
							int h;
							for (h = i; h < vrs_msg[call_info[j][k][l].vrsindex].session_num - 1; h ++) {
								vrs_msg[call_info[j][k][l].vrsindex].callid[h] = vrs_msg[call_info[j][k][l].vrsindex].callid[h + 1];
							}
							vrs_msg[call_info[j][k][l].vrsindex].callid[h] = 0;
							break;
						}
					}
					vrs_msg[call_info[j][k][l].vrsindex].session_num --;	
					//init_call_msg(&call_info[j][k][l]);
					clear_call_msg(&call_info[j][k][l]);
					pthread_mutex_unlock(&call_info[j][k][l].mutex);
				}
			}
		}
	}
	return 0;
}

void *thread_get_stop_cmd(void *arg)
{
#if 1
	int ret = 0;
	int count = 0;
	int sockfd = 0;
	socklen_t len = 0;
	struct sockaddr_in clientaddr;
	char buff[BUFF_SIZE];
	struct pkt_header head;
	len = sizeof(clientaddr);

	vrsqueue = create_queue();
	while (-1 == create_udp_server(&sockfd)) {
		sleep(1);
		count ++;
    	applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "create udp server fail...");
		if (count == 10) {
    		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "fail to create udp server...");
			pthread_exit(NULL);
		}
	}

   	applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "create socket success , sockfd = %d\n", sockfd);
	printf("create socket success , sockfd = %d\n", sockfd);

	while (1) {
		if (exitflag == 1) {
   			applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "thread_get_stop_cmd is exit");
			close(sockfd);
			destory_queue(vrsqueue);
			pthread_exit(NULL);
		}
		memset(buff, 0, BUFF_SIZE);
		if (0 >= (ret = recvfrom(sockfd, buff, BUFF_SIZE, 0, (struct sockaddr *)&clientaddr, &len))) {
			usleep(100);
			continue;
		}
#if 0
		recvfrom(sockfd, buff, BUFF_SIZE, 0, (struct sockaddr *)&clientaddr, &len);
		ret = sock_recvfrom_buf(sockfd, buff, 8);
		//printf("ret = %d\n", ret);
		if (ret) {
			memset(buff, 0, BUFF_SIZE);
			continue;
		}
		memcpy(&head, buff, 8);
		ret = check_package_format(&head);
		if (ret == -1) {
			memset(buff, 0, BUFF_SIZE);
			continue;
		}
		ret = sock_recvfrom_buf(sockfd, buff + 8, ntohs(head.len) - 8);
		printf("head.len = %d\n", ntohs(head.len));
#endif
		memcpy(&head, buff, 8);
		printf("head.len = %d\n", ntohs(head.len));
		ret = check_package_format(&head);
//		syslog(LOG_INFO, "get stop cmd callid = %lu", be64toh(*((uint64_t *)(buff + 12))));	
		if (ret < 0) {
			memset(buff, 0, BUFF_SIZE);
			continue;
		}
		atomic64_add(&cmdstop, 1);
		queue_insert(vrsqueue, buff, ntohs(head.len));
	}
#endif
}
int create_udp_server(int *udp_server_fd)
{
	int fd_flag;
	struct sockaddr_in serveraddr;
	socklen_t len;
	
	if (-1 == (*udp_server_fd = socket(AF_INET, SOCK_DGRAM, 0))) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "pthread_ma_udp fail to create socket");
		return -1;
	}

	len = sizeof(serveraddr);
	memset(&serveraddr, 0, sizeof(serveraddr));

	//printf("ip = %s port = %d\n", conf_para.ip, conf_para.port);
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(conf_para.port);
	serveraddr.sin_addr.s_addr = inet_addr(conf_para.ip);

	if (bind(*udp_server_fd, (struct sockaddr *)&serveraddr, len) == -1) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "pthread_ma_udp fail to bind.");
		close(*udp_server_fd);
		return -1;
	}

	fd_flag = fcntl(*udp_server_fd, F_GETFL, 0);
	fcntl(*udp_server_fd, F_SETFL, fd_flag | O_NONBLOCK);
	return 0;
}
int sock_recvfrom_buf(int fd, char *buf, int size)
{
	int ret;
	int len = 0;

	while (len < size)
	{
		ret = recvfrom(fd, &buf[len], (size-len), 0, NULL, NULL);
		if (ret <= 0)
			return -1;
		len += ret;
	}
	return 0;
}
int get_local_mac(char *dev, unsigned char *mac)
{
	struct ifreq ifreq;
	int sock = 0;

	sock = socket(AF_INET,SOCK_STREAM,0);
	if(sock < 0)
	{
		applog(LOG_ERR, APP_LOG_MASK_BASE, "Get mac: Create socket error!");
		return 1;
	}

	strcpy(ifreq.ifr_name, dev);
	if(ioctl(sock,SIOCGIFHWADDR,&ifreq) < 0)
	{
		applog(LOG_ERR, APP_LOG_MASK_BASE, "Get mac: ioctl get MAC error!");
		return 2;
	}
	memcpy(mac, ifreq.ifr_hwaddr.sa_data, 6);
	close(sock);

	applog(LOG_INFO, APP_LOG_MASK_BASE, "Local interface %s MAC is %02x:%02x:%02x:%02x:%02x:%02x",
			dev, mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	return 0;
}
