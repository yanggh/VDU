#ifndef __HEAD_H__
#define __HEAD_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <stdint.h>
#include <pthread.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/times.h>
#include <sys/select.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <signal.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <error.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <endian.h>
#include "applog.h"
#include "log.h"
#include "conf.h"
//#include "thread_pool.h"
//#include "tsqueue.h"

#define TP_NUM 4
#define PORT "port"
#define IP_SIZE 16
#define MAC_SIZE 6
#define BUFF_SIZE 4096
#define VRS_NUM 8
#define PACKET_LENGTH 1518
#define SESSION_NUM 1<<15
#define PROMISCUOUS_STATE 1
#define RUNNING 1
#define OVERTIME 0
#define ERR_SIZE 128
#define POST_TYPE1 0x80
#define POST_TYPE2 0x52
#define PAYLOAD_VOICE_TYPE 0x3
#define PAYLOAD_SIGNAL_TYPE 0x1
#define PAYLOAD_STOP_TYPE 0x4
#define FIRST_VOICE_PACKET 0x1
#define LAST_VOICE_PACKET 0x2
#define VOICE_PACKET 0x3
#define SIGNAL_END_FLAG 0x10
#define RECV_SR155_DEV "recv-sr155-dev"
#define SEND_VRS_DEV "send-vrs-dev"
#define SEND_VRS_MAC "send-vrs-mac"
#define SEND_SR155_MAC "send-sr155-mac"
#define RECV_SR155_MAC "recv-sr155-mac"
#define TIMEOUT "timeout"
#define VRS "vrs"
#define ID "id"
#define MAC "mac"
#define IP "ip"
#define CONF_PATH "/usr/local/etc/vdu/vdu.yaml"
#define PUB_CONF_PATH "/usr/local/etc/vrs.yaml"
#define MAX 128
#define CFGMNG_TASK_NAME_LEN 1024
#define THREAD_NUM 4
#define SR155_NUM       64
#define E1_NUM          64
#define TS_NUM          32

#define VOICE_NUM 16
#define STOR_TIME 180
#define MAX_SESSION 2000	

typedef struct data {
	uint8_t vdata[PACKET_LENGTH];
} data_t;

typedef struct session {
	uint64_t callid;
	uint64_t voice_len;
	uint32_t count;
	uint8_t stopflag;
	uint8_t endcmd;
	uint8_t endtimes;
//	uint32_t endcmd;
	uint16_t *data_len;
	//uint16_t data_len[VOICE_NUM * STOR_TIME];
	time_t starttime;
	data_t *voice_data;
	uint32_t vrsid;
	int vrsindex;
	//char voice_data[VOICE_NUM * PACKET_LENGTH * STOR_TIME];
	pthread_mutex_t mutex;
//	vrs_t vrs_msg;
}session_t;


typedef struct vrs {
	//session_t callid_msg[SESSION_NUM];
//	session_t callid_msg[SR155_NUM][E1_NUM][TS_NUM];
	uint64_t callid[SR155_NUM * E1_NUM * TS_NUM];
	//session_t callid_msg[MAX_SESSION];
	uint32_t session_num;
	uint32_t vrsid;
	uint8_t state;
	uint8_t send_flag;
	uint32_t fd;
	unsigned char vrs_mac[6];
	unsigned char ip[IP_SIZE];
	pthread_mutex_t mutex;
}vrs_t;

typedef struct mutex {
	uint64_t callmutexlock;
	uint64_t callmutexunlock;
	uint64_t sessionmutexlock;
	uint64_t sessionmutexunlock;
}mutex_num_t;

typedef struct voice_data
{
	int flag;
	const u_char packet[PACKET_LENGTH];
	struct pcap_pkthdr pkthdr;
} vdata_t;

typedef struct call_state {
	uint32_t status;
	uint32_t endtime;
	uint64_t callid;
}CALL_T;

struct pkt_header {
    uint8_t ver;
    uint8_t reply;
    uint16_t cmd;
    uint16_t num;
    uint16_t len;
};

typedef struct conf_para {
	int id;
	char *sr155_nic;
	char *vrs_nic;
	char tovrs_mac[MAC_SIZE];
	char send_sr155_mac[MAC_SIZE];
	char recv_sr155_mac[MAC_SIZE];
	time_t overtime;
	char *ip;
	int vrsnum;
	int vrsid[VRS_NUM];
	uint16_t port;
	char *maip;
	char *sguardip;
	uint16_t maport;
	uint16_t sguardport;
	uint32_t sgno;
	uint32_t serial_number;
	uint32_t log_mask;
	char *log_level;
	char *conf_path;
	char *app_name;
}CONF_T;

typedef struct packet_head {
	unsigned char version;
	unsigned char flag;
	unsigned short cmd;
	unsigned short No;
	unsigned short length;
}DATA_HEAD;
typedef struct _data_
{
	unsigned short type;
	unsigned short length;
	char *data;
}DATA;
typedef struct sg {
	pid_t pid;
	char name[128];
	unsigned int no;
}SGMEG; 

typedef struct counter {
	uint64_t pkt_pcap;
	uint64_t pkt_send;
	uint64_t session_num;
	uint64_t session_over;
	uint64_t session_overtime;
	uint64_t pkt_handle;
	uint64_t stop_cmd;
	uint64_t update_conf;
	uint64_t status;
	uint64_t counter;
	uint64_t pkts;
}count_t;

extern void *thread_delivery(void *arg);
extern void *thread_stop_session(void *arg);
extern int clear_call_msg(session_t *data);
extern void *thread_voice_handle(void *arg);
extern void *get_vrs_stop_cmd(void *arg);
extern void release_memory(void);
extern void init_atomic_counter(void);
extern int get_mac(char *value, unsigned char *mac);
extern int check_voice_packet(const u_char *packet);
extern int delievery_send_to_vrs(pcap_t *dev, const u_char *packet, struct pcap_pkthdr *pkthdr);
//extern void delievery_send_to_vrs(void *arg);
extern int stop_session_by_callid(uint64_t callid);
extern void init_vrs_msg(void);
extern int find_vrs(uint64_t callid, vrs_t **tovrs);
extern int get_conf_para(void);
extern int change_vrs_status(uint32_t id, uint16_t status);
extern int send_voice_data_to_vrs(vrs_t *vrsnode);
extern int change_vrs_fd(char *ip, int fd);
extern int sock_recv_buf(int fd, char *buf, int size);
extern int sock_recvfrom_buf(int fd, char *buf, int size);
extern int get_local_mac(char *dev, unsigned char *mac);
extern int check_voice_overtime(vrs_t *vrsmsg);
extern void *thread_get_stop_cmd(void *arg);
extern int create_udp_server(int *udp_server_fd);
extern int check_package_format(struct pkt_header *head);
extern int create_server_socket(char *ip, uint16_t port);
extern int stop_session_send_to_vrs(char *packet);
extern int get_vrs_conf(void);
extern uint32_t get_data_len(session_t *call);
extern uint64_t get_callid_from_cmd(char *data);
extern void *thread_register_sguard(void *arg);
extern int cfgmng_get_taskname(char *ac, int len);
extern int pack_head(DATA_HEAD *head, char *buff);
extern void destory_conf(CONF_T *conf);
extern int pack_data(DATA *data, char *buff);
extern int pack_sguard_keepalive_msg(char *tmpbuf, unsigned short pkt_serial_number);
extern int pack_sguard_msg(char *buff, unsigned short pkt_serial_number, CONF_T *conf);
extern void sig_handler(int signo);
extern void *thread_connect_ma(void *arg);
extern int init_voice_info(void);
extern int init_call_msg(session_t *data); 
extern int send_voice_data_to_another_vrs(int srcid, int dstid);
extern int compare_vrs_conf(CONF_T *tmpconf, vrs_t *tmpvrs); 
extern int change_call_msg_index(int index, int vrsid);
extern void delete_voice_info(int id);
extern int show_conf_vrs(CONF_T *tmpconf, vrs_t *tmpvrs);
extern int check_mac_format(char *mac);
extern int check_ip_format(char *ip);
#endif /* __HEAD_H__ */
