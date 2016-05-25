#include "head.h"

int exitflag = 0;

int pack_sguard_msg(char *buff, unsigned short pkt_serial_number, CONF_T *conf)
{
	if (buff == NULL || pkt_serial_number < 0 || conf == NULL)
		return -1;

	DATA_HEAD head;
	DATA data;
	char tmpbuf[BUFF_SIZE];
	SGMEG *sg;

	sg = (SGMEG *)malloc(sizeof(SGMEG));

	cfgmng_get_taskname(sg->name, 128);
	sg->pid = getpid();
	sg->no = conf->sgno;

	head.version = 1;
	head.cmd = 16;
	head.flag = 0;

	int len = 0;

	data.type = 1;
	data.length = strlen(sg->name) + 1;
	data.data = (char *)malloc(data.length);
	strcpy(data.data, sg->name);
	pack_data(&data, tmpbuf);
	free(data.data);

	len = len + 4 + ntohs(data.length);
	
	data.type = 2;
	data.length = 4;
	data.data = (char *)malloc(data.length);
	sg->pid = htonl(sg->pid);
	memcpy(data.data, &sg->pid, data.length);
	pack_data(&data, tmpbuf + len);
	free(data.data);
	
	len = len + 4 + ntohs(data.length);
	
	data.type = 3;
	data.length = 4;
	data.data = (char *)malloc (data.length);
	sg->no = htonl(sg->no);
	memcpy(data.data, &sg->no, data.length);
	pack_data(&data, tmpbuf + len);
	free(data.data);

	len = len + 4 + ntohs(data.length);

	data.type = 1;
	data.length = len;
	data.data = (char *)malloc(data.length);
	memcpy(data.data, tmpbuf, data.length);
	pack_data(&data, buff + 8);
	free(data.data);

	head.length = len + 12;
	head.No = pkt_serial_number;
	pack_head(&head, buff);

	free(sg);
	return len + 12;
}

int pack_sguard_keepalive_msg(char *tmpbuf, unsigned short pkt_serial_number)
{
	if (tmpbuf == NULL || pkt_serial_number < 0)
		return -1;
	DATA tmpdata;
	DATA_HEAD head;
	uint16_t data;
	char buff[16];

	head.cmd = 5;
	head.version = 1;
	head.flag = 0;
	head.length = 8 + 4 + 6;
	head.No = pkt_serial_number;

	tmpdata.type = 1;
	tmpdata.length = 2;
	tmpdata.data = (char *)malloc(tmpdata.length);
	data = htons(1);
	memcpy(tmpdata.data, &data, tmpdata.length);
	pack_data(&tmpdata, tmpbuf + 8);
	free(tmpdata.data);
	memset(buff, 0, 16);
	memcpy(buff, tmpbuf + 8, 6);

	tmpdata.type = 4;
	tmpdata.length = 6;
	tmpdata.data = (char *)malloc(6);
	memcpy(tmpdata.data, buff, 6);
	pack_data(&tmpdata, tmpbuf + 8);
	free(tmpdata.data);

	pack_head(&head, tmpbuf);


	return 18;

}
int pack_data(DATA *data, char *buff)
{
	if (data == NULL || buff == NULL)
		return -1;
	memcpy(buff + 4, data->data, data->length);
	data->type = htons(data->type);
	data->length = htons(data->length);
	memcpy(buff, data, 4);
	
	return 0;
}

int pack_head(DATA_HEAD *head, char *buff)
{
	if (head == NULL || buff == NULL)
		return -1;

	head->No = htons(head->No);
	head->length = htons(head->length);
	head->cmd = htons(head->cmd);
	
	memcpy(buff, head, 8);

	return 0;
}
int cfgmng_get_taskname(char *ac, int len)
{
	if (ac == NULL || len < 0)
		return -1;
    int count = 0;
    int nIndex = 0;
    char chPath[CFGMNG_TASK_NAME_LEN] = {0};
    char cParam[100] = {0};
    char *cTem = chPath;
    int tmp_len;
 
    pid_t pId = getpid();
    sprintf(cParam,"/proc/%d/exe",pId);
/*    printf("cParam = %s.\n", cParam);*/
    count = readlink(cParam, chPath, CFGMNG_TASK_NAME_LEN);
/*    printf("count = %d.\n", count);*/
    if (count < 0 || count >= CFGMNG_TASK_NAME_LEN)
    {
        return -1;
    }
    else
    {
        nIndex = count - 1;
 
        for( ; nIndex >= 0; nIndex--)
        {
            if( chPath[nIndex] == '/' )//筛选出进程名
            {
                nIndex++;
                cTem += nIndex;
                break; 
            }
        }
    }
    tmp_len = strlen(cTem);
    if (0 == tmp_len) {
        return -1;
    }
    
    if (len <= tmp_len +1) {
        return -1;
    }
    
    strcpy(ac, cTem);
    
    return 0;
}
void sig_handler(int signo)
{
	if (signo == SIGINT) {
		exitflag = 1;
	}
}
