/*************************************************************************
	> File Name: test_echo.c
	> Author: 
	> Mail: 
	> Created Time: Tue 05 Dec 2017 04:50:17 AM PST
 ************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <arpa/inet.h>

#include "evco.h"

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
	printf("proxy setup from %d to %d...\n", pargs->srcfd, pargs->dstfd);
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
	printf("proxy from %d to %d exiting, %d bytes left.\n", pargs->srcfd, pargs->dstfd, size-sended);
	free(buffer);
	free(pargs);
}


typedef struct on_accept_args
{
	int fd;
	struct sockaddr_in dst_addr;
} on_accept_args_t;

void on_accept(on_accept_args_t *args)
{
	int fd = args->fd;

	while ( 1 ) {
		int clt_fd = evco_accept(fd);
		if ( clt_fd == -1 ) {
			break;
		}
		printf("one client connected...\n");
		int ret = 0;
		int dst_fd = socket(AF_INET, SOCK_STREAM, 0);

		ret = evco_connect(dst_fd, &args->dst_addr, sizeof(struct sockaddr_in));
		if ( ret != 0 ) {
			printf("connect failed...\n");
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
	free(args);
}


int main(int argc, char *argv[])
{
	char *ip = NULL;
	unsigned short port = 0;

	char *dstip = NULL;
	unsigned short dstport = 0;

	int lfd = 0;
	int ret = 0;

    struct sockaddr_in addr = {0};

	evsc_t *psc = evsc_alloc();

	if ( argc < 5 ) {
		printf("Usage: %s [srcaddr] [srcport] [dstaddr] [dstport]\n", argv[0]);
		goto _E1;
	}

	ip = argv[1];
	port = atoi(argv[2]);
    dstip = argv[3];
    dstport = atoi(argv[4]);

    lfd = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    inet_aton(ip, &addr.sin_addr);
    addr.sin_port = htons(port);

    ret = bind(lfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    if ( ret < 0 ) {
        perror("bind failed...\n");
        return 0;
    }

    ret = listen(lfd, 1024);
    if ( ret < 0 ) {
        printf("listen failed...\n");
        return 0;
    }

	on_accept_args_t *args = (on_accept_args_t *)malloc(sizeof(on_accept_args_t));

	evutil_make_socket_nonblocking(lfd);

	args->fd = lfd;
    args->dst_addr.sin_family = AF_INET;
    args->dst_addr.sin_port = htons(dstport);
    inet_aton(dstip, &args->dst_addr.sin_addr);
	evco_create(psc, STACK_SIZE, (evco_func)on_accept, args);
	evco_dispatch(psc);
_E1:
	return ret;
}
