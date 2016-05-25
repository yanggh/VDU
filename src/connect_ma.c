#include "head.h"
#include "atomic.h"
#include "conn_serv.h"
extern uint16_t pkt_serial_number;
uint8_t dms_sguard_reload = 0;
extern count_t counter;
uint8_t dms_ma_reload = 0;
extern CONF_T conf_para;
extern vrs_t *vrs_msg;
extern int exitflag;
int vdu_flag;
extern atomic64_t all_packet, unhandle_packet, pcap_packet, 
		   recv_packet, send_packet, handle_packet, 
		   lose_packet, sessnum, sessover, sessovertime,
		   cmdstop, confupdate, cmdstatus, cmdcounter;
#define VDU_BUFSIZE 1024
int pacp_flag;

void *thread_connect_ma(void *arg)
{
    int sockfd;
    uint8_t pkt[VDU_BUFSIZE];
    uint32_t pkt_len, write_len;
    int ret;
    struct timeval tv;
    fd_set readfds;
    int nfds;
    uint32_t conn_times;

    if (conf_para.maport == 0 || conf_para.sgno == 0) {
        //applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_MA, "ma port: %d, sn: %d", 
         //       vpu_conf.port_ma, vpu_conf.sn);
        return NULL;
    }

	syslog(LOG_INFO, "connect2ma");
    sockfd = -1;
    conn_times = 0;
    while (1) {
#if 0
        if (unlikely(svm_signal_flags & SVM_DONE)) {
            break;
        }

#endif
		if (exitflag == 1)
			break;
        if (unlikely(dms_ma_reload == 1)) {
            close(sockfd);
            sockfd = -1;
            dms_ma_reload = 0;
        }
		if (sockfd == -1) {
            if ((sockfd = connect2ma()) == -1) {
                if (++conn_times >= 60) {
                    conn_times = 0;
                    //applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_MA, "connect to ma failed");
                }
                sleep(1);
                continue;
            }
            pkt_len = fill_regma_packet(pkt, pkt_serial_number ++);
            write_len = write(sockfd, pkt, pkt_len);
			applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "send register info %d bytes to ma", write_len);
            //applog(APP_LOG_LEVEL_INFO, APP_VPU_LOG_MASK_MA, "send regist info %d bytes to ma", pkt_len);
        }

        tv.tv_sec = 1;
        tv.tv_usec = 0;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        nfds = sockfd + 1;
        ret = select(nfds, &readfds, NULL, NULL, &tv);
        if (ret <= 0) {
            continue;
        }

        ret = read(sockfd, pkt, VDU_BUFSIZE);
        if (ret <= 0) {
            //applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_MA, "read ma socket return %d", ret);
            close(sockfd);
            sockfd = -1;
            continue;
        }
        //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "recv %d bytes from ma socket", ret);
        applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_MA, "receive %d bytes from ma socket", ret);
		ma_cmd_parser(pkt, ret, sockfd);
    }

    close(sockfd);
    //applog(APP_LOG_LEVEL_INFO, APP_VPU_LOG_MASK_MA, "pthread conn_ma exit");

    pthread_exit(NULL);	
}

int fill_ma_count_info_struct(unsigned char *pkt, unsigned short pkt_head_num, char *soft_name, char *proc_name, unsigned int field_num, struct count_struct *field_array)
{
	struct pkt_header *pst_ph = NULL;	
	unsigned char *pkt_start = pkt;
	
	if( pkt==NULL || soft_name==NULL || field_num==0 || field_array==NULL || proc_name==NULL )
	{
		return 0;
	}

	//packet head	
	pst_ph = (struct pkt_header *)pkt;
	pst_ph->ver = 1;
	pst_ph->reply = 1;
	pst_ph->cmd = htons(39);	
	pst_ph->num = htons(pkt_head_num);
	pst_ph->len = 0;
	pkt += sizeof(struct pkt_header);
	
	//software name
	*(unsigned short *)pkt = htons(1);
	pkt += 2;
	*(unsigned short *)pkt = htons(strlen(soft_name)+1);
	pkt += 2;
	memcpy (pkt, soft_name, strlen(soft_name)+1);	
	pkt += strlen(soft_name)+1;

	//proccess name
	*(unsigned short *)pkt = htons(4);
	pkt += 2;
	*(unsigned short *)pkt = htons(strlen(proc_name)+1);
	pkt += 2;
	memcpy (pkt, proc_name, strlen(proc_name)+1);	
	pkt += strlen(proc_name)+1;

	// filed total numbler
	*(unsigned short *)pkt = htons(2);
	pkt += 2;
	*(unsigned short *)pkt = htons(sizeof(unsigned int));
	pkt += 2;
	*(unsigned int *)pkt = htonl(field_num);
	pkt += 4;
	
	// filed name array
	*(unsigned short *)pkt = htons(3);
	pkt += 2;
	*(unsigned short *)pkt = htons(sizeof(struct count_struct)*field_num);
	pkt += 2;
	memcpy (pkt, (void *)field_array, sizeof(struct count_struct)*field_num);	
	pkt += (sizeof(struct count_struct)*field_num);

	//fill packet head length
	pst_ph->len = htons((pkt-pkt_start));
	
	return (pkt-pkt_start);
}
uint16_t fill_info(uint8_t *pkt, uint8_t *info, uint16_t len, uint16_t type)
{
    uint16_t n_len;
    uint16_t n_type;

    if (pkt == NULL || info == NULL) {
        return 0;
    }

    n_type = htons(type);
    memcpy(pkt, &n_type, 2);
    n_len = htons(len);
    memcpy(pkt + 2, &n_len, 2);
    memcpy(pkt + 4, info, len);

    return len + 4;
}
int connect2ma(void)
{
    int sockfd;
    struct sockaddr_in servaddr;
    struct timeval timeo = {3, 0};
    socklen_t len = sizeof(timeo);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "create socket to ma fail");
        return -1;
    }

    //set the timeout period
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeo, len);

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(conf_para.maport);
    if(inet_pton(AF_INET, conf_para.maip, &servaddr.sin_addr) != 1){  
        //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "inet_pton error for %s", vpu_conf.ip_ma);  
        close(sockfd);
        return -1; 
    }

    if(connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0){
        if (errno == EINPROGRESS) {
            //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "connect to ma timeout");
        }
        //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "connect to ma error");
        close(sockfd);
        return -1;
    }
    //applog(APP_LOG_LEVEL_INFO, APP_VPU_LOG_MASK_MA, "connect to ma(ip: %s, port: %d) success", 
      //      vpu_conf.ip_ma, vpu_conf.port_ma);

    return sockfd;
}
uint32_t fill_regma_packet(uint8_t *pkt, uint16_t num)
{
    DATA_HEAD *header;
    uint8_t *payload;
    uint16_t len;
    uint16_t payload_len;
    pid_t pid;
    uint32_t n_pid;
    uint32_t n_sn;

    if (pkt == NULL) {
        return 0;
    }

    header = (DATA_HEAD *)pkt;
    header->flag = 0;
    header->version = 1;
    header->cmd = htons(16);
    header->No = htons(num);

    payload = pkt + sizeof(DATA_HEAD) + 4;
    payload_len = 0;

    pid = getpid();
    n_pid = htonl(pid);
    len = 4;
    payload_len = fill_info(payload + payload_len, (uint8_t *)&n_pid, len, 1);

    len = 4;
    n_sn = htonl(conf_para.sgno);
    payload_len += fill_info(payload + payload_len, (uint8_t *)&n_sn, len, 2);

    payload = pkt + sizeof(DATA_HEAD);
    *((uint16_t *)payload) = htons(2);
    *((uint16_t *)(payload + 2)) = htons(payload_len);

    header->length = htons(payload_len + 4 + sizeof(DATA_HEAD));

    return payload_len + 4 + sizeof(DATA_HEAD);
}
int ma_cmd_parser(uint8_t *pkt, uint32_t pkt_len, int sockfd)
{
   	DATA_HEAD *header;
    uint16_t header_len;
    uint8_t *data;
    uint32_t data_len;
    uint8_t *left;
    uint32_t left_len;
    uint16_t cmd;
	uint16_t no;

    if (pkt == NULL) {
        return 0;
    }


	memcpy(&no, pkt + 4, 2);
	no = ntohs(no);
    header_len = sizeof(DATA_HEAD);
	left = pkt;
    left_len = pkt_len;
    while (left_len >= header_len) {
        header = (DATA_HEAD *)left;
        data = left + header_len;
        data_len = ntohs(header->length) - header_len;

        cmd = ntohs(header->cmd);
        switch (cmd) {
            case RELOAD:
                //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "get a ma reload config file cmd");
                applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_CMD, "get a ma reload config file cmd");
				atomic64_add(&confupdate, 1);
				ma_cmd_reload(data, data_len);
                break;
            case GET_COUNTER:
                //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "get a ma counter cmd");
                applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_CMD, "get a counter cmd");
				atomic64_add(&cmdcounter, 1);
				ma_cmd_get_counter(sockfd, no);
                break;
            case SOFTWARE_STATUS:
                //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "get a ma software status");
                applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_CMD, "get a ma software status");
				atomic64_add(&cmdstatus, 1);
				ma_cmd_software_status(data, data_len);
                break;
			case COUNTER_STRUCT:
				ma_cmd_register_counter(sockfd, header);
				break;
            default:
				applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_CMD, "cmd no is %d from ma", cmd);
                //applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_MA, "unknown cmd %d form ma", cmd);
                break;
        }

        left = left + header_len + data_len;
        left_len = left_len - header_len - data_len;
    }

    return 0;
}

int ma_cmd_register_counter(int fd, DATA_HEAD *header)
{
	uint32_t count_num;
	int i;
	count_num = sizeof(count_t) / sizeof(uint64_t);
	struct count_struct vdu_count[count_num],
						tmpcount;

	memset(vdu_count, 0, sizeof(struct count_struct) * count_num);

	for (i = 0; i < count_num; i ++) {
		switch(i) {
			case 0:
				strcpy(tmpcount.name, "pkt_pcap");
				tmpcount.len = sizeof(uint64_t);
				break;
			case 1:
				strcpy(tmpcount.name, "pkt_send");
				tmpcount.len = sizeof(uint64_t);
				break;
			case 2:
				strcpy(tmpcount.name, "session_num");
				tmpcount.len = sizeof(uint64_t);
				break;
			case 3:
				strcpy(tmpcount.name, "session_over");
				tmpcount.len = sizeof(uint64_t);
				break;
			case 4:
				strcpy(tmpcount.name, "session_overtime");
				tmpcount.len = sizeof(uint64_t);
				break;
			case 5:
				strcpy(tmpcount.name, "pkt_handle");
				tmpcount.len = sizeof(uint64_t);
				break;
			case 6:
				strcpy(tmpcount.name, "stop_cmd");
				tmpcount.len = sizeof(uint64_t);
				break;
			case 7:
				strcpy(tmpcount.name, "update_conf");
				tmpcount.len = sizeof(uint64_t);
				break;
			case 8:
				strcpy(tmpcount.name, "status");
				tmpcount.len = sizeof(uint64_t);
				break;
			case 9:
				strcpy(tmpcount.name, "cmdcounter");
				tmpcount.len = sizeof(uint64_t);
				break;
			case 10:
				strcpy(tmpcount.name, "all_pkts");
				tmpcount.len = sizeof(uint64_t);
				break;
		}
		memcpy(&vdu_count[i], &tmpcount, sizeof(struct count_struct));
	}

	char softname[32], proname[32];
	unsigned char databuff[2048];
	unsigned int filed_num, length = 0;
	unsigned short pkt_no;
	strcpy((char *)softname, "vdu");
	strcpy((char *)proname, "vdu");
	pkt_no = ntohs(header->No);
	filed_num = count_num;
	length = fill_ma_count_info_struct(databuff, pkt_no, softname, proname, filed_num, vdu_count);

	if (length > 0) {
		send(fd, databuff, length, 0);
	}

	return 0;
}

int ma_cmd_reload(uint8_t *data, uint32_t data_len)
{
    uint16_t type;
    uint16_t length;
    char filename[255];
    uint32_t left;

    if (data == NULL || data_len == 0) {
        return 0;
    }

    left = data_len;
    while (left >= 4) {
        type = ntohs(*(uint16_t *)data);
        length = ntohs(*(uint16_t *)(data + 2));
        data += 4;
        left -= 4;
        if (left < length || length > 255 || length <= 8) {
            return -1;
        }
        if (type == 1) {
            memcpy(filename, data, length);
            filename[length] = '\0';
			applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_MA, "reload configure file %s", filename);
            //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "reload config file %s", filename);
            if (memcmp(filename, "vrs.yaml", 8) == 0) {
				reload_vrs_conf(filename);
            } else if (memcmp(filename, "dms.yaml", 8) == 0) {
                reload_dms_conf(filename);
            } else if (memcmp(filename, "vdu.yaml", 8) == 0) {
                reload_vdu_conf(filename);
				//reload_vpu_conf(filename);
            } else {
                applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "reload config file %s error", filename);
            }
        } else {
            return -1;
        }
        data += length;
        left += length;
    }

    return 0;
}

int reload_vrs_conf(char *filename)
{
	if (filename == NULL)
		return -1;

	
	CONF_T tmpconf;
	vrs_t *tmpvrs = NULL;
	memset(&tmpconf, 0, sizeof(tmpconf));
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
				applog(APP_LOG_LEVEL_DEBUG, VDU_LOG_MASK_MA, "name : %s val : %s\n", subchild->name, subchild->val);
				if (0 == strcmp(subchild->name, "id")) {
					if (conf_para.id != atoi(subchild->val))
						break;
				} else if (0 == strcmp(subchild->name, "ip")) {
					if (tmpconf.ip == NULL)
						tmpconf.ip = (char *)malloc(strlen(subchild->val) + 1);
					strcpy(tmpconf.ip, subchild->val);
					printf("ip : %s\n", tmpconf.ip);
				} else if (0 == strcmp(subchild->name, "port")) {
					tmpconf.port = atoi(subchild->val);
					printf("port : %d\n", tmpconf.port);
				}
			}
		}
	}
	if (tmpconf.port == 0) {
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
					tmpconf.vrsid[tmpconf.vrsnum] = atoi(q);
					tmpconf.vrsnum ++;
					printf("vrsid = %d\n", atoi(q));
					while (NULL != (q = strtok(NULL, " "))) {
						tmpconf.vrsid[tmpconf.vrsnum] = atoi(q);
						tmpconf.vrsnum ++;
						printf("vrsid = %d\n", atoi(q));
					}
				}
			}
		}
	}

	applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "vpw have %d", tmpconf.vrsnum);

	int j = 0;
	if (tmpconf.vrsnum != 0) {
		tmpvrs = (vrs_t *)malloc(tmpconf.vrsnum * sizeof(vrs_t));
		bzero(tmpvrs, 0);
		for (j = 0; j < tmpconf.vrsnum; j ++) {
			pthread_mutex_init(&tmpvrs[j].mutex, NULL); 
		}
	}

	base = ConfGetNode("vpw");

	if (base != NULL) {
		TAILQ_FOREACH(child, &base->head, next) {
			TAILQ_FOREACH(subchild, &child->head, next) {
				printf("name : %s val : %s\n", subchild->name, subchild->val);
				if (!strcmp(subchild->name, "mac")) {
					get_mac(subchild->val, tmpvrs[i].vrs_mac);
					printf("%s i = %d: %x:%x:%x:%x:%x:%x\n", subchild->name, i,
							(unsigned int)tmpvrs[i].vrs_mac[0],
							(unsigned int)tmpvrs[i].vrs_mac[1],
							(unsigned int)tmpvrs[i].vrs_mac[2],
							(unsigned int)tmpvrs[i].vrs_mac[3],
							(unsigned int)tmpvrs[i].vrs_mac[4],
							(unsigned int)tmpvrs[i].vrs_mac[5]
						  );
				} else if (!strcmp(subchild->name, ID)) {
					for (j = 0; j < tmpconf.vrsnum; j ++) {
						if (tmpconf.vrsid[j] == atoi(subchild->val))
							break;
					}
					if (j == tmpconf.vrsnum)
						break;
					tmpvrs[i].vrsid = atoi(subchild->val);
					printf("%s : %d\n", subchild->name, tmpvrs[i].vrsid);
				} else if (!strcmp(subchild->name, IP)) {
					strcpy((char *)tmpvrs[i].ip, (const char *)subchild->val);
					printf("%s : %s\n", subchild->name, tmpvrs[i].ip);
				}
			}
			if (j != tmpconf.vrsnum) {
		//		vrs_msg[i].state = 1;
				i ++;
			}
		}
	}

	ConfDeInit();
	compare_vrs_conf(&tmpconf, tmpvrs);

	//show_conf_vrs(&tmpconf, tmpvrs);

	return 0;
}

int show_conf_vrs(CONF_T *tmpconf, vrs_t *tmpvrs)
{
	syslog(LOG_INFO, "tmpvrsnum = %d tmpip : %s\n", tmpconf->vrsnum, tmpconf->ip);
	int i;
	for (i = 0; i < tmpconf->vrsnum; i ++) {
		syslog(LOG_INFO, "tmpvrs id = %d", tmpvrs[i].vrsid);
	}
	syslog(LOG_INFO, "vrsnum = %d ip : %s\n", conf_para.vrsnum, conf_para.ip);
	for (i = 0; i < conf_para.vrsnum; i ++) {
		syslog(LOG_INFO, "vrs id = %d", vrs_msg[i].vrsid);
	}

	return 0;

}
int compare_vrs_conf(CONF_T *tmpconf, vrs_t *tmpvrs)
{
	int i, j;

	for (i = 0; i < conf_para.vrsnum; i ++) {
		for (j = 0; j < tmpconf->vrsnum; j ++) {
			if (tmpvrs[j].vrsid == vrs_msg[i].vrsid) {
				if (0 != memcmp(tmpvrs[j].vrs_mac, vrs_msg[i].vrs_mac, 6) && vrs_msg[i].state == RUNNING) {
					change_vrs_status(tmpvrs[j].vrsid, 0);	
				} else if (0 == memcmp(tmpvrs[j].vrs_mac, vrs_msg[i].vrs_mac, 6)) {
					memcpy(&tmpvrs[j], &vrs_msg[i], sizeof(vrs_t));
				}
				break;
			}
		}
		if (j == tmpconf->vrsnum || vrs_msg[i].state == RUNNING) {
			change_vrs_status(vrs_msg[i].vrsid, 0);
		}
	}

	for (i = 0; i < tmpconf->vrsnum; i ++) {
		for (j = 0; j < conf_para.vrsnum; j ++) {
			if (vrs_msg[j].vrsid == tmpvrs[i].vrsid && vrs_msg[j].state == RUNNING) {
				memcpy(&tmpvrs[i], &vrs_msg[j], sizeof(vrs_t));
				if (i != j) {
					change_call_msg_index(i, vrs_msg[j].vrsid);
				}
			}
		}
	}

	if (strcmp(tmpconf->ip, conf_para.ip) != 0 || tmpconf->port != conf_para.port) {
		vdu_flag = 1;
	}
	conf_para.vrsnum = tmpconf->vrsnum;
	memcpy(conf_para.vrsid, tmpconf->vrsid, sizeof(conf_para.vrsid));
	
	vrs_t *p;
	p = vrs_msg;
	vrs_msg = tmpvrs;
	free(p);
	destory_conf(tmpconf);
	return 0;
}


int reload_vdu_conf(char *filename)
{
	if (filename == NULL)
		return -1;
	char *value = NULL;
	ConfInit();
	if (ConfYamlLoadFile(CONF_PATH) != 0) 
	{
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "can`t find the file of %s", CONF_PATH);
		return -1;
	}	

	if (ConfGet(RECV_SR155_DEV, &value) == 1) {
		if (conf_para.sr155_nic == NULL) {
			conf_para.sr155_nic = (char *)malloc(strlen(value) + 1);
		} else 
			conf_para.sr155_nic = (char *)realloc(conf_para.sr155_nic, strlen(value) + 1);
		if (strcmp(value, conf_para.sr155_nic) != 0) {
			pacp_flag = 1;
			strcpy(conf_para.sr155_nic, value);
		}
	}
	if (ConfGet(SEND_VRS_DEV, &value) == 1) {
		if (conf_para.vrs_nic == NULL) {
			conf_para.vrs_nic = (char *)malloc(strlen(value) + 1);
		} else 
			conf_para.vrs_nic = (char *)realloc(conf_para.vrs_nic, strlen(value) + 1);
		if (0 != strcmp(conf_para.vrs_nic, value)) {
			pacp_flag = 1;
			strcpy(conf_para.vrs_nic, value);
			get_local_mac(conf_para.vrs_nic, (unsigned char *)conf_para.tovrs_mac);
		}
	}
	
	
	if (ConfGet(TIMEOUT, &value) == 1) {
		conf_para.overtime = (time_t)atoi(value);
	}

	get_log_para();
	ConfDeInit();
	return 0;
}

int reload_sguard_port(void)
{
    char *value;
    uint16_t port = 0;

    if (ConfGet("ma.sguardport", &value) == 1) {
        port = atoi(value);
        //applog(APP_LOG_LEVEL_INFO, APP_VPU_LOG_MASK_BASE, "reload sguard server port: %d\n", port);
    } else {
        //applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_BASE, "reload sguard server port failed\n");
        return -1;
    }

    if (port != 0 && port != conf_para.sguardport) {
        dms_sguard_reload = 1;
    }
    return 0;
}
int reload_dms_conf(char *cfg_file)
{
    char dump_config = 0;
    char filename[256] = {0};

    if (cfg_file == NULL) {
        return -1;
    }

    ConfInit();

    snprintf(filename, 255, "%s%s", conf_para.conf_path, cfg_file);
    if (ConfYamlLoadFile(filename) != 0) {
        //applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_BASE, "reload dms config file %s error\n", cfg_file);
        return -1;
    }

    if (dump_config) {
        //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_BASE, "Dump all config variable:\n");
        ConfDump();
    }


    reload_sguard_port();
    reload_ma_port();

    ConfDeInit();

    return 0;
}
int param_parser(int argc, char *argv[])
{
    int n;
    int ret;
	int config_flag = 0;

    memset(&conf_para, 0, sizeof(CONF_T));
	conf_para.app_name = (char *)malloc(strlen(argv[0]) + 1);
    strcpy(conf_para.app_name, argv[0]);
    //strcpy(vpu_conf.conf_file, VPU_FILE);
    //strcpy(vpu_conf.dms_conf_file, DMS_FILE);
    //applog(APP_LOG_LEVEL_INFO, APP_VPU_LOG_MASK_BASE, "app name: %s\n", argv[0]);

#if 0
    if (strlen(argv[0]) >= 64 || argc < 3) {
       // applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_BASE, "argc: %d, app name: %s\n", argc, argv[0]);
        return 0;
    }
#endif
    n = 1;
    while (n < argc) {
        if (strcmp(argv[n], "--sn") == 0) {
            n++;
            ret = sn_parser(argc - n, argv + n);
            if (ret <= 0) {
          //      applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_BASE, "sn_parser fail\n");
                return -1;
            }
            n += ret;
        } else if (strcmp(argv[n], "--config") == 0) {
            n++;
			config_flag = 1;
            n += config_parser(argc - n, argv + n);
        } else {
            //applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_BASE, "%dth param %s error\n", n, argv[n]);
            n++;
        }
    }

	if (config_flag == 0) {
		conf_para.conf_path = (char *)malloc(strlen("/usr/local/etc/") + 1);
		strcpy(conf_para.conf_path, "/usr/local/etc/");
	}

	puts(conf_para.conf_path);

    return 0;
}
int sn_parser(int argc, char *argv[])
{
    int len;
    int i;
    char *sn;

    if (argc < 1) {
       // applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_BASE, "no sn value\n");
        return 0;
    }

    sn = argv[0];
    len = strlen(sn);
    for (i = 0; i < len; i++) {
        if (0 == isdigit(sn[i])) {
     //       applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_BASE, "error sn value\n");
            conf_para.sgno = 0;
            return -1;
        }
    }

    conf_para.sgno = atoi(sn);
	printf("--sn : %d\n", conf_para.sgno);
   // applog(APP_LOG_LEVEL_INFO, APP_VPU_LOG_MASK_BASE, "app sn is %d\n", vpu_conf.sn);

    return 1;
}
int config_parser(int argc, char *argv[])
{
    int len;

    if (argc < 1) {
 //       applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_BASE, "no config value\n");
        return 0;
    }

    len = strlen(argv[0]);
    if (len >= 128) {
  //      applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_BASE, "config filename %s to long\n", argv[0]);
        return 0;
    }

	if (conf_para.conf_path == NULL)
		conf_para.conf_path = (char *)malloc(strlen(argv[0]) + 1);
    strcpy(conf_para.conf_path, argv[0]);

    //applog(APP_LOG_LEVEL_INFO, APP_VPU_LOG_MASK_BASE, "conf file is %s\n", vpu_conf.conf_file);

    puts(conf_para.conf_path);
	return 1;
}
int reload_ma_port(void)
{
    char *value;
    uint16_t port = 0;

    if (ConfGet("ma.maport", &value) == 1) {
        port = atoi(value);
        //applog(APP_LOG_LEVEL_INFO, APP_VPU_LOG_MASK_BASE, "reload ma server port: %d\n", port);
    } else {
        //applog(APP_LOG_LEVEL_ERR, APP_VPU_LOG_MASK_BASE, "reload ma server port failed\n");
        return -1;
    }

    if (port != 0 && port != conf_para.maport) {
        dms_ma_reload = 1;
    }
    return 0;
}
int ma_cmd_software_status(uint8_t *data, uint32_t data_len)
{
    uint16_t type;
    uint16_t length;
    uint32_t left;
    uint16_t sub_type;
    uint16_t sub_length;
    uint32_t sub_left;
    uint8_t *sub_data;
    uint8_t vpu_flag;
    uint32_t status = 0;
    uint32_t vrs_id = 0;

    if (data == NULL || data_len < 4) {
        return 0;
    }

    vpu_flag = 0;
    left = data_len;
    while (left >= 4) {
        type = ntohs(*(uint16_t *)data);
        length = ntohs(*(uint16_t *)(data + 2));
        data += 4;
        left -= 4;
        if (left < length) {
            return -1;
        }
        if (type == 1) {
            if (memcmp(data, "vdu", 3) != 0) {
                return -2;
            }
            //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "software statut to vpu");
            vpu_flag = 1;
        } else if (type == 2 && vpu_flag == 1) {
            sub_data = data;
            sub_left = length;
            while (sub_left >= 4) {
                sub_type = ntohs(*(uint16_t *)sub_data);
                sub_length = ntohs(*(uint16_t *)(sub_data + 2));
                sub_data += 4;
                sub_left -= 4;
                if (sub_left < sub_length) {
                    return -1;
                }
                if (sub_type == 1 && sub_length == 4) {
                    status = ntohl(*(uint32_t *)sub_data);
                } else if (sub_type == 2) {
                } else if (sub_type == 3) {
                    if (memcmp(sub_data, "vpw", 3) != 0) {
                        return -2;
                    }
                    //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "software fpu statut to vpu");
                } else if (sub_type == 4 && sub_length == 4) {
                    vrs_id = ntohl(*(uint32_t *)sub_data);
                    //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "software fpu %u statut to vpu", vrs_id);
                } else {
                    return 0;
                }
                sub_data += sub_length;
                sub_left -= sub_length;
            }
            change_vrs_status(vrs_id, status);
        } else {
            return -1;
        }
        data += length;
        left += length;
    }
    return 0;
}

int ma_cmd_get_counter(int sockfd, uint16_t no)
{
    uint8_t pkt_buf[1500];
    uint16_t pkt_len;
    DATA_HEAD *header;
    uint8_t *payload;
    uint16_t payload_len;
    uint16_t version;
    time_t count_time;
    //all_count_t total_count;
    int ret;

    //memset(&total_count, 0, sizeof(all_count_t));

	count_t tmpcount;
    header = (DATA_HEAD *)pkt_buf;
    header->flag = 1;
    header->version = 1;
    header->cmd = htons(19);
    header->No = htons(no);
    pkt_len = sizeof(DATA_HEAD);
    payload = pkt_buf + pkt_len;

    version = htons(1);
    payload_len = fill_info(payload, (uint8_t *)&version, 2, 2);
    pkt_len += payload_len;
    payload = payload + payload_len;

    count_time = time(NULL);
    count_time = htobe64(count_time);
    payload_len = fill_info(payload, (uint8_t *)&count_time, sizeof(time_t), 1000);
    pkt_len += payload_len;
    payload = payload + payload_len;

	counter.pkt_handle = atomic64_read(&handle_packet);
	counter.pkt_pcap =	atomic64_read(&pcap_packet);
	counter.pkts = atomic64_read(&all_packet);
	counter.pkt_send = atomic64_read(&send_packet);
	counter.session_num = atomic64_read(&sessnum);
	counter.session_over = atomic64_read(&sessover);
	counter.session_overtime = atomic64_read(&sessovertime);
	counter.stop_cmd = atomic64_read(&cmdstop);
	counter.update_conf = atomic64_read(&confupdate);
	counter.status = atomic64_read(&cmdstatus);
	counter.counter = atomic64_read(&cmdcounter);

	tmpcount.pkt_handle = htobe64(counter.pkt_handle);
	tmpcount.pkt_pcap = htobe64(counter.pkt_pcap);
	tmpcount.pkt_send = htobe64(counter.pkt_send);
	tmpcount.session_num = htobe64(counter.session_num);
	tmpcount.session_over = htobe64(counter.session_over);
	tmpcount.session_overtime = htobe64(counter.session_overtime);
	tmpcount.status = htobe64(counter.status);
	tmpcount.stop_cmd = htobe64(counter.stop_cmd);
	tmpcount.update_conf = htobe64(counter.update_conf);
	tmpcount.counter = htobe64(counter.counter);
    tmpcount.pkts = htobe64(counter.pkts);

	pkt_len += fill_info(payload, (uint8_t *)&tmpcount, sizeof(count_t), 20);

    header->length = htons(pkt_len);
    ret = write(sockfd, pkt_buf, pkt_len);
    if (ret != pkt_len) {
        //applog(APP_LOG_LEVEL_DEBUG, APP_VPU_LOG_MASK_MA, "write counter data %dbytes less than pkt_len %dbytes", ret, pkt_len);
    }

    return 0;
}
