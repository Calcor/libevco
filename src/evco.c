/*************************************************************************
	> File Name: evco.c
	> Author: 
	> Mail: 
	> Created Time: Tue 05 Dec 2017 04:50:17 AM PST
 ************************************************************************/

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#ifndef WIN32
#include <ucontext.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include "list.h"
#include "hashtab.h"
#include "event2/event.h"
#include "evco.h"

#ifdef DEBUG
    #define evco_debug(fmt, ...) \
            printf("[%s:%04d]"fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
    #define evco_debug(fmt, ...)
#endif


struct evsc
{
	struct event_base *ev_base;
	hashtab_t *fd_tb;
	struct list_head cond_ready_queue;
};

struct evco
{
#ifdef WIN32
	void *prev;
	void *self;
#else
	ucontext_t prev;
	ucontext_t self;
#endif
	struct event *timer;
	int flag_iotimeout;
	int flag_running;
	evsc_t *psc;
	size_t stack_size;
#ifdef WIN32
	evco_func func;
#else
	char *stack;
#endif
};

typedef struct fd_item
{
	int fd;
	
	struct event *ev_recv;
	struct event *ev_send;

	evco_t *evco_recv;
	evco_t *evco_send;
}fd_item_t;

typedef struct cond_item
{
	struct list_head entry;
	int timeout_msec;	
	evco_t *pco;
}cond_item_t;

struct evco_cond
{
	struct list_head wait_pcos;
};

#ifdef WIN32
__declspec( thread ) evco_t *g_current_pco = NULL;
#else
__thread evco_t *g_current_pco = NULL;
#endif

#define FREE_POINTER(ptr)       \
do {                           \
    if ( ptr != NULL ) {       \
        free(ptr);             \
        ptr = NULL;            \
    }                          \
} while ( 0 )

static void __evsc_fd_dispatch(int sockfd, short events, void *vitem);

static void __evsc_timer_dispatch(int fd, short events, void *vitem);

static void __evco_resume(evco_t *pco);

#define msec2tv(msec, tv) \
do {								\
	tv.tv_sec = msec/1000;			\
	tv.tv_usec = (msec%1000)*1000;	\
} while ( 0 )

int __evco_cond_ready_clear(evsc_t *psc)
{
	cond_item_t *pitem = NULL;
	while ( 1 ) {
		if ( list_empty(&psc->cond_ready_queue) ) {
			return 0;
		}
		pitem = list_entry(psc->cond_ready_queue.next, cond_item_t, entry);
		__evco_resume(pitem->pco);
	}
}

evsc_t *evsc_alloc()
{
	evsc_t *psc = (evsc_t *)malloc(sizeof(evsc_t));
	psc->ev_base = event_base_new();
	psc->fd_tb = hashtab_alloc();
	INIT_LIST_HEAD(&psc->cond_ready_queue);
#ifdef WIN32
	ConvertThreadToFiber(NULL);
#endif
	return psc;
}

#ifdef WIN32
#define __evco_free(pco) \
do {							\
	if ( !pco ) break;			\
	if ( pco->timer ) {			\
		event_del(pco->timer);	\
		event_free(pco->timer); \
	}							\
	DeleteFiber(pco->self);		\
	FREE_POINTER(pco);			\
} while ( 0 )
#else
#define __evco_free(pco) \
do {							\
	if ( !pco ) break;			\
	if ( pco->timer ) {			\
		event_del(pco->timer);	\
		event_free(pco->timer); \
	}							\
	FREE_POINTER(pco->stack);	\
	FREE_POINTER(pco);			\
} while ( 0 )
#endif

#ifdef WIN32
void CALLBACK __evco_entry(void *args)
{
	g_current_pco->func(args);
	g_current_pco->flag_running = 0;
}
#else
void __evco_entry(evco_func func, void *args)
{
	func(args);
	g_current_pco->flag_running = 0;
}
#endif


static fd_item_t *__fd_item_alloc(evsc_t *psc, int fd)
{
	fd_item_t *pitem = (fd_item_t *)malloc(sizeof(fd_item_t));
	pitem->fd = fd;
	pitem->evco_recv = NULL;
	pitem->evco_send = NULL;
	pitem->ev_recv = event_new(psc->ev_base, fd, EV_READ, __evsc_fd_dispatch, &pitem->evco_recv);
	pitem->ev_send = event_new(psc->ev_base, fd, EV_WRITE, __evsc_fd_dispatch, &pitem->evco_send);
	return pitem;
}

static void __evco_resume(evco_t *pco)
{
	int ret = 0;
	evco_t *prev_pco = g_current_pco;
	g_current_pco = pco;
#ifdef WIN32
	pco->prev = GetCurrentFiber();
	if ( pco->prev == NULL ) {
		ret = -1;
	}
	else{
		SwitchToFiber(pco->self);
	}
#else
	ret = swapcontext(&pco->prev, &pco->self);
#endif
	g_current_pco = prev_pco;
	if ( ret != 0 ) {
		evco_debug("swapcontext failed...\n");
		__evco_free(pco);		
	}
	else {
		if ( pco->flag_running == 0 ) {
			__evco_free(pco);
		}
	}
}
static void inline __evco_yield()
{
    g_current_pco->flag_iotimeout = 0;
#ifdef WIN32
	SwitchToFiber(g_current_pco->prev);
#else
	swapcontext(&g_current_pco->self, &g_current_pco->prev);
#endif
}

static void __evco_yield_by_fd(int fd, int flag, unsigned int to_msec)
{
	fd_item_t *pitem = (fd_item_t *)hashtab_query(g_current_pco->psc->fd_tb, fd);
	struct event *pev = NULL;
	int ret = 0;
	if ( pitem == NULL ) {
		pitem = __fd_item_alloc(g_current_pco->psc, fd);
		hashtab_insert(g_current_pco->psc->fd_tb, fd, pitem);
	}
	if ( flag == 0 ) {
		pitem->evco_recv = g_current_pco;
		pev = pitem->ev_recv;
	}
	else {
		pev = pitem->ev_send;
		pitem->evco_send = g_current_pco;
	}
	if ( to_msec == 0 ) {
		ret = event_add(pev, NULL);
	}
	else {
		struct timeval tv;
		msec2tv(to_msec, tv);
		ret = event_add(pev, &tv);	
	}
	if ( ret < 0 ) {
		evco_debug("event_add failed...\n");
	}

	__evco_yield();
}

static void __evsc_fd_dispatch(int sockfd, short events, void *vitem)
{
	evco_t **ppco = (evco_t **)vitem;
	evco_t *pco = *ppco;
	evsc_t *psc = NULL;
	*ppco = NULL;
	if ( pco == NULL ) {
		return;
	}
	psc = pco->psc;
    if ( events & EV_TIMEOUT ) {
        pco->flag_iotimeout = 1;
    } else {
        pco->flag_iotimeout = 0;
    }
	__evco_resume(pco);
	__evco_cond_ready_clear(psc);
}

static void __evsc_timer_dispatch(int fd, short events, void *vitem)
{
	evco_t *pco = (evco_t *)vitem;
	evsc_t *psc = pco->psc;
	pco->flag_iotimeout = 1;
	__evco_resume(pco);
	__evco_cond_ready_clear(psc);
}

void evco_sleep(int msec)
{
	struct timeval tv;
	if ( g_current_pco->timer == NULL ) {
		g_current_pco->timer = evtimer_new(g_current_pco->psc->ev_base, __evsc_timer_dispatch, g_current_pco);
	}
	msec2tv(msec, tv);
	event_add(g_current_pco->timer, &tv);
	__evco_yield();
}
evco_t *evco_create(evsc_t *psc, size_t stack_size, evco_func func, void *args)
{
	evco_t *pco = (evco_t *)malloc(sizeof(evco_t));
#ifdef WIN32
	pco->func = func;
	pco->flag_running = 1;
	pco->stack_size = stack_size;
	pco->psc = psc;
	pco->timer = NULL;
	pco->self = CreateFiber(stack_size, __evco_entry, args);
	if ( pco->self == NULL ) {
		evco_debug("CreateFiber failed...\n");
		goto _E1;
	}
#else
	if ( getcontext(&pco->self) == -1 ) {
		evco_debug("getcontext faild..\n");
		goto _E1;
	}
	pco->flag_running = 1;
	pco->stack = (char *)malloc(stack_size);
	pco->stack_size = stack_size;
	pco->self.uc_stack.ss_sp = pco->stack;
	pco->self.uc_stack.ss_size = stack_size;
	pco->self.uc_link = &pco->prev;
	pco->psc = psc;
	pco->timer = NULL;
	makecontext(&pco->self, (void (*)(void))__evco_entry, 2, func, args);
#endif
	__evco_resume(pco);
	
	return pco;
_E1:
	FREE_POINTER(pco);
	return NULL;
}

int evco_timed_connect(int fd, const struct sockaddr *addr, socklen_t addrlen, int msec)
{
	int ret = 0;
	evutil_make_socket_nonblocking(fd);
	ret = connect(fd, addr, addrlen);
	if ( ret == 0 ) {
		return ret;
	}
#ifdef WIN32 
	if ( WSAEINTR == WSAGetLastError() || WSAEWOULDBLOCK == WSAGetLastError() ) {
#else
	if ( errno == EINPROGRESS || errno == EWOULDBLOCK ) {
#endif
		int err = 0;
		socklen_t len = sizeof(err);
		printf("Connect INPROGREESS, will swap.\n");
		__evco_yield_by_fd(fd, 1, msec);
        if ( g_current_pco->flag_iotimeout ) {
            errno = ETIMEDOUT;
            return -1;
        }
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
		if ( err ) {
			errno = err;
			return -1;
		}
		else {
			return 0;
		}
	}
	else {
		return ret;
	}
	
}

int evco_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    return evco_timed_connect(fd, addr, addrlen, 0);
}

int evco_timed_accept(int fd, int msec)
{
	int clt_fd = 0;
_ACCEPT_START:
	clt_fd = accept(fd, NULL, NULL);
	if ( clt_fd > 0 ) {
		evutil_make_socket_nonblocking(clt_fd);
		return clt_fd;
	}
#ifdef WIN32 
	if ( WSAEINTR == WSAGetLastError() || WSAEWOULDBLOCK == WSAGetLastError() ) {
#else
	if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
#endif
		evco_debug("accept EAGAIN, will swap.\n");
		__evco_yield_by_fd(fd, 0, msec);
        if ( g_current_pco->flag_iotimeout ) {
            errno = ETIMEDOUT;
            return -1;
        }
		goto _ACCEPT_START;	
	}
	else {
		return -1;
	}
}

int evco_accept(int fd)
{
    return evco_timed_accept(fd, 0);
}

int evco_timed_recv(int fd, char *buffer, size_t size, int msec) 
{
	int ret = 0;
_RECV_START:
	ret = recv(fd, buffer, size, 0);
	if ( ret >= 0 ) {
		return ret;
	}
#ifdef WIN32 
	if ( WSAEINTR == WSAGetLastError() || WSAEWOULDBLOCK == WSAGetLastError() ) {
#else
	if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
#endif
		evco_debug("recv EAGAIN, will swap.\n");
		__evco_yield_by_fd(fd, 0, msec);
        if ( g_current_pco->flag_iotimeout ) {
            errno = ETIMEDOUT;
            return -1;
        }
		goto _RECV_START;
	}
	else {
		return -1;
	}
}

int evco_recv(int fd, char *buffer, size_t size) 
{
    return evco_timed_recv(fd, buffer, size, 0);
}


int evco_timed_send(int fd, char *buffer, size_t size, int msec)
{
	int ret = 0;
_SEND_START:
	ret = send(fd, buffer, size, 0);
	if ( ret >= 0 ) {
		return ret;
	}
#ifdef WIN32 
	if ( WSAEINTR == WSAGetLastError() || WSAEWOULDBLOCK == WSAGetLastError() ) {
#else
	if ( errno == EAGAIN || errno == EWOULDBLOCK ) {
#endif
		evco_debug("send EAGAIN, will swap.\n");
		__evco_yield_by_fd(fd, 1, 0);
        if ( g_current_pco->flag_iotimeout ) {
            errno = ETIMEDOUT;
            return -1;
        }
		goto _SEND_START;
	}
	else {
		return -1;
	}
}

int evco_send(int fd, char *buffer, size_t size) 
{
    return evco_timed_send(fd, buffer, size, 0);
}

void __fd_item_free(fd_item_t *pitem)
{
	event_del(pitem->ev_recv);
	event_del(pitem->ev_send);
	event_free(pitem->ev_recv);
	event_free(pitem->ev_send);
	FREE_POINTER(pitem);
}

int evco_close(int fd)
{
	fd_item_t *pitem = hashtab_query(g_current_pco->psc->fd_tb, fd);
	evco_debug("closing fd %d.\n", fd);
#ifdef WIN32
	closesocket(fd);
#else
	close(fd);
#endif
	if ( pitem != NULL ) {
		if ( pitem->evco_recv ) {
			__evco_resume(pitem->evco_recv);
		}
		if ( pitem->evco_send ) {
			__evco_resume(pitem->evco_send);
		}
	}
    __fd_item_free(pitem);
	hashtab_delete(g_current_pco->psc->fd_tb, fd, NULL);
	return 0;
}

evsc_t *evco_get_sc()
{
	return g_current_pco->psc;
}

evco_t *evco_get_co()
{
	return g_current_pco;
}

int evco_dispatch(evsc_t *psc)
{
	return event_base_dispatch(psc->ev_base);
}

evco_cond_t *evco_cond_alloc()
{
	evco_cond_t *pcond = (evco_cond_t *)calloc(1, sizeof(evco_cond_t));
	INIT_LIST_HEAD(&pcond->wait_pcos);
	return pcond;
}

int evco_cond_timedwait(evco_cond_t *pcond, int msec)
{
	cond_item_t item = {0};
	item.pco = g_current_pco;
	item.timeout_msec = msec;
	if ( msec > 0 ) {
		struct timeval tv;
		if ( g_current_pco->timer == NULL ) {
			g_current_pco->timer = evtimer_new(g_current_pco->psc->ev_base, __evsc_timer_dispatch, g_current_pco);
		}
		msec2tv(msec, tv);
		event_add(g_current_pco->timer, &tv);
	}

	list_add_tail(&item.entry, &pcond->wait_pcos);
	g_current_pco->flag_iotimeout = 0;
	__evco_yield();
	list_del(&item.entry);
	if ( g_current_pco->flag_iotimeout == 1 ) {
		g_current_pco->flag_iotimeout = 0;
		return ETIMEDOUT;
	}
	else {
        event_del(g_current_pco->timer);
		return 0;
	}
}

int evco_cond_signal(evco_cond_t *pcond)
{
	cond_item_t *pitem = NULL;
	if ( list_empty(&pcond->wait_pcos)) {
		return 0;
	}
	pitem = list_entry(pcond->wait_pcos.next, cond_item_t, entry);
	list_del(&pitem->entry);
	if ( pitem->timeout_msec > 0 ) {
		event_del(pitem->pco->timer);
	}
	list_add_tail(&pitem->entry, &g_current_pco->psc->cond_ready_queue);
	return 0;
}

int evco_cond_broadcast(evco_cond_t *pcond)
{
	cond_item_t *pitem = NULL;
	while ( 1 ) {
		if ( list_empty(&pcond->wait_pcos)) {
			return 0;
		}
		pitem = list_entry(pcond->wait_pcos.next, cond_item_t, entry);
		list_del(&pitem->entry);
		event_del(pitem->pco->timer);
		list_add_tail(&pitem->entry, &g_current_pco->psc->cond_ready_queue);
	}
	return 0;
}

int evco_cond_free(evco_cond_t *pcond)
{
	evco_cond_broadcast(pcond);
	FREE_POINTER(pcond);
	return 0;
}
