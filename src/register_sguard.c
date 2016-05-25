#include "head.h"

extern CONF_T conf_para;
extern int exitflag;
uint16_t pkt_serial_number;
extern uint8_t dms_sguard_reload;

void *thread_register_sguard(void *arg)
{
	if (conf_para.sgno == 0) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "pthread_sguard_register is done ...");
		pthread_exit(NULL);
	}
	int tcp_fd, len;
	struct sockaddr_in serveraddr, clientaddr;
	socklen_t addrlen = sizeof(clientaddr);
	char tmpbuf[BUFF_SIZE];
	int ret, fd_flag, err, code;
	fd_set rset;
	struct timeval tv;
new:

	if (-1 == (tcp_fd = socket(AF_INET, SOCK_STREAM, 0))) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "pthread_sguard_register fail to socket");
		exit(-1);
	}
	

	memset(&serveraddr , 0, sizeof(serveraddr));

	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(conf_para.sguardport);
	serveraddr.sin_addr.s_addr = inet_addr("127.0.0.1");
//	serveraddr.sin_addr.s_addr = inet_addr("192.168.40.168");
	fd_flag = fcntl(tcp_fd, F_GETFL, 0);
	fcntl(tcp_fd, F_SETFL, fd_flag | O_NONBLOCK);

	err = 0;

	ret = connect(tcp_fd, (struct sockaddr *)&serveraddr, addrlen);
	if (exitflag == 1) {
		close(tcp_fd);
		pthread_exit(NULL);
	}
	usleep(1000);
	if (errno != EINPROGRESS && ret < 0) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "pthread_sguard_register fail to connect");
		close(tcp_fd);
		goto new;
	} else if (ret == 0) {
		applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "pthread_sguard_register: connect sguard success.");
		goto ok;
	}
l:
	FD_ZERO(&rset);
	FD_SET(tcp_fd, &rset);
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	ret = select(tcp_fd + 1, NULL, &rset, NULL, &tv);
			
	if (ret <= 0) {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "pthread_sguard_register fail to select");
		goto l;
	}

	if (FD_ISSET(tcp_fd, &rset)) {
		len = sizeof(err);
		code = getsockopt(tcp_fd, SOL_SOCKET, SO_ERROR, &err, (socklen_t *)(&len));

		if (code < 0 || err) {
			if (err)
				errno = err;
			goto up;
		}
	} else {
		applog(APP_LOG_LEVEL_ERR, VDU_LOG_MASK_BASE, "pthread_sguard_register fail to connect");
		exit(0);
	}

ok:
	fcntl(tcp_fd, F_SETFL, fd_flag);

	signal(SIGPIPE,sig_handler);

	len = pack_sguard_msg(tmpbuf, pkt_serial_number ++, &conf_para);

	while (1) {
		sleep(1);
#if 1
		if (dms_sguard_reload) {
			applog(APP_LOG_LEVEL_INFO, VDU_LOG_MASK_BASE, "VDU to recreate the TCP connection with SGUARD");
			dms_sguard_reload = 0;
			break;
		}
#endif
		if (exitflag == 1) {
			close(tcp_fd);
			pthread_exit(NULL);
		}
		int ret = send(tcp_fd, tmpbuf, len, 0);
		len = pack_sguard_keepalive_msg(tmpbuf, pkt_serial_number ++);
		if (ret < 0) {
			close(tcp_fd);
			goto new;
		}
	}
up:
	close(tcp_fd);
	goto new;
}



