/*************************************************************************
	> File Name: test_echo.c
	> Author: 
	> Mail: 
	> Created Time: Tue 05 Dec 2017 04:50:17 AM PST
 ************************************************************************/

#include "common.h"
#include "evco.h"
#include "libsdk/api_net.h"
#include "libsdk/api_tcp.h"

typedef struct proxy_args {
	int srcfd;
	int dstfd;
}proxy_args_t;

void proxy(proxy_args_t *pargs) 
{
	int ret = 0;
#define BUFFER_SIZE 1024*4
	char *buffer = (char *)malloc(BUFFER_SIZE);
	int sended;
	int size;
	LOGN("proxy setup from %d to %d...\n", pargs->srcfd, pargs->dstfd);
	while ( 1 ) {
		size = 0;
		sended = 0;
		ret = evco_recv(pargs->srcfd, buffer, BUFFER_SIZE);
		if ( ret <= 0 ) {
			evco_close(pargs->dstfd);
			break;
		}
		size = ret;
		sended = 0;
AGAIN:
		ret = evco_send(pargs->dstfd, buffer+sended, size-sended);
		if ( ret <= 0 ) {
			evco_close(pargs->dstfd);
			break;
		}
		sended += ret;
		if ( sended < size ) {
			goto AGAIN;
		}
		
	}
	LOGN("proxy from %d to %d exiting, %d bytes left.\n", pargs->srcfd, pargs->dstfd, size-sended);
	FREE_POINTER(buffer);
	FREE_POINTER(pargs);
}


typedef struct on_accept_args
{
	int fd;
	u32 ip;
	u16 port;
} on_accept_args_t;

void on_accept(on_accept_args_t *args)
{
	int fd = args->fd;
	struct sockaddr_in dst_addr = {0};
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = args->ip;
	dst_addr.sin_port = args->port;

	while ( 1 ) {
		int clt_fd = evco_accept(fd);
		if ( clt_fd == -1 ) {
			break;
		}
		LOGN("one client connected...\n");
		int ret = 0;
		int dst_fd = socket(AF_INET, SOCK_STREAM, 0);

		ret = evco_connect(dst_fd, &dst_addr, sizeof(struct sockaddr_in));
		if ( ret != 0 ) {
			LOGW("connect failed...\n");
			evco_close(clt_fd);
			evco_close(dst_fd);
		}
		proxy_args_t *pargs1 = (proxy_args_t *)malloc(sizeof(proxy_args_t));
		pargs1->srcfd = clt_fd;
		pargs1->dstfd = dst_fd;

		proxy_args_t *pargs2 = (proxy_args_t *)malloc(sizeof(proxy_args_t));
		pargs2->srcfd = dst_fd;
		pargs2->dstfd = clt_fd;

		evco_create(evco_get_sc(), STACK_SIZE, (evco_func)proxy, pargs1);
		evco_create(evco_get_sc(), STACK_SIZE, (evco_func)proxy, pargs2);
	}
	evco_close(fd);
	FREE_POINTER(args);
}


int main(int argc, char *argv[])
{
	char *ip = NULL;
	u16 port = 0;

	char *dstaddr = NULL;
	u16 dstport = 0;

	int lfd = 0;
	int ret = 0;

	evsc_t *psc = evsc_alloc();
	if ( argc < 5 ) {
		LOGW("Usage: %s [srcaddr] [srcport] [dstaddr] [dstport]\n", argv[0]);
		goto _E1;
	}
	ip = argv[1];
	port = atoi(argv[2]);
	dstaddr = argv[3];
	dstport = atoi(argv[4]);

	ret = api_tcp_listen_setup(ip_aton(ip), htons(port), &lfd);
	if ( ret != SUCCESS ) {
		LOGW("api_tcp_listen_setup failed...\n");
		return 0;
	}	
	on_accept_args_t *args = (on_accept_args_t *)malloc(sizeof(on_accept_args_t));
	api_set_nonblock(lfd);
	args->fd = lfd;
	args->ip = ip_aton(dstaddr);
	args->port = htons(dstport);
	evco_create(psc, STACK_SIZE, (evco_func)on_accept, args);
	evco_dispatch(psc);
_E1:
	return ret;
}
