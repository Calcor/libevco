/*************************************************************************
	> File Name: test_echo.c
	> Author: 
	> Mail: 
	> Created Time: Tue 05 Dec 2017 04:50:17 AM PST
 ************************************************************************/

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <arpa/inet.h>

#include "evco.h"

typedef struct on_read_args
{
	int fd;
} on_read_args_t;

void on_read(on_read_args_t *args)
{
	int fd = args->fd;
	char buffer[128] = {0};
	while ( 1 ) {
		int ret = evco_timed_recv(fd, buffer, sizeof(buffer), 1000);
		if ( ret <= 0 ) {
            if ( errno == ETIMEDOUT ) {
                printf("recv timed out, continue.\n");
                continue;
            }
			break;
		}
		ret = evco_send(fd, buffer, ret);
		if ( ret <= 0 ) {
			break;
		}
	}
	evco_close(fd);
	free(args);
}

typedef struct on_accept_args
{
	int fd;
} on_accept_args_t;

void on_accept(on_accept_args_t *args)
{
	int fd = args->fd;
	while ( 1 ) {
		int clt_fd = evco_accept(fd);
		on_read_args_t *clt_args = NULL;
		if ( clt_fd == -1 ) {
			break;
		}
		printf("one client connected...\n");
		clt_args = (on_read_args_t *)malloc(sizeof(on_read_args_t));
		clt_args->fd = clt_fd;
		evco_create(evco_get_sc(), STACK_SIZE, (evco_func)on_read, clt_args);
	}
	evco_close(fd);
	free(args);
}

typedef struct sleep_args
{
	int x;
}sleep_args_t;

void sleep_and_print(sleep_args_t *args)
{
	while ( 1 ) {
		evco_sleep(1000);
	    printf("%06d, I'm awake...\n", args->x);
	}
}

int main(int argc, char *argv[])
{
	char *ip = NULL;
	unsigned short port = 0;
	int lfd = 0;
	int ret = 0;
	evsc_t *psc = evsc_alloc();
	int x = 0;
    struct sockaddr_in addr = {0};

	on_accept_args_t *args = NULL;
	if ( argc < 3 ) {
		printf("Usage: %s [ipaddr] [port]\n", argv[0]);
		goto _E1;
	}

    lfd = socket(AF_INET, SOCK_STREAM, 0);

	ip = argv[1];
	port = atoi(argv[2]);
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

	args = (on_accept_args_t *)malloc(sizeof(on_accept_args_t));
	evutil_make_socket_nonblocking(lfd);
	args->fd = lfd;
	evco_create(psc, STACK_SIZE, (evco_func)on_accept, args);
	for ( x = 0 ; x < 10; x++ ) {
		sleep_args_t *args = (sleep_args_t *)malloc(sizeof(sleep_args_t));
		args->x = x;
		evco_create(psc, STACK_SIZE, (evco_func)sleep_and_print, args);
	}
	evco_dispatch(psc);
_E1:
	return ret;
}

