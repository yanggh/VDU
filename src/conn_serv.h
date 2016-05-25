#ifndef __CONN_SERV_H__
#define __CONN_SERV_H__



#define RELOAD              23
#define GET_COUNTER         19
#define SOFTWARE_STATUS     14
#define COUNTER_STRUCT 39

#define SERV_IP         "127.0.0.1"
#if 0
struct pkt_header {
    uint8_t ver;
    uint8_t reply;
    uint16_t cmd;
    uint16_t num;
    uint16_t len;
};
#endif
struct count_struct
{
	char name[32];
	unsigned int len;
};
uint16_t fill_info(uint8_t *pkt, uint8_t *info, uint16_t len, uint16_t type);
uint32_t fill_regsguard_packet(uint8_t *pkt, uint16_t num, char *name);
uint32_t fill_alive_packet(uint8_t *pkt, uint16_t num);
uint32_t fill_regma_packet(uint8_t *pkt, uint16_t num);

int ma_cmd_get_counter(int sockfd, uint16_t no);
int ma_cmd_reload(uint8_t *data, uint32_t data_len);
int ma_cmd_parser(uint8_t *pkt, uint32_t pkt_len, int sockfd);
int ma_cmd_software_status(uint8_t *data, uint32_t data_len);
int reload_sguard_port(void);
int reload_dms_conf(char *cfg_file);
int reload_ma_port(void);
int reload_vdu_conf(char *filename);
int param_parser(int argc, char *argv[]);
int reload_vrs_conf(char *filename);
int ma_cmd_register_counter(int fd, DATA_HEAD *header);
int config_parser(int argc, char *argv[]);
int get_dms_conf(void);
int get_ma_port(void);
int get_sguard_port(void);
int sn_parser(int argc, char *argv[]);

void *conn_sguard(void *arg);
void *conn_ma(void *arg);

int connect2ma(void);
int connect2sguard(void);

extern int fill_ma_count_info_struct(unsigned char *pkt, unsigned short pkt_head_num, char *soft_name, char *proc_name, unsigned int filed_num, struct count_struct *filed_array);

#endif
