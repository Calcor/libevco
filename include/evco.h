/***************************************************************************************
 *   Copyright (C), 2006-2017, HelloWorld Technology Co., Ltd.
 *   
 *    Filename: evco.h
 * Description: 
 *     Version: 1.0
 *     Created: Miaosu   11/15/17 19:54:16
 *    Revision: none
 *      
 *     History: <author>   <time>    <version >         <desc>
 *              Miaosu   11/15/17                  build this moudle
 ***************************************************************************************/


#ifndef _EVCO_H_
#define _EVCO_H_

#define STACK_SIZE 8192


typedef struct evsc evsc_t;
typedef struct evco evco_t;
typedef struct evco_cond evco_cond_t;

typedef void (*evco_func)(void *);

evco_t *evco_create(evsc_t *psc, size_t stack_size, evco_func func, void *args);

void evco_sleep(int msec);

int evco_accept(int fd);

int evco_close(int fd);

int evco_recv(int fd, char *buffer, size_t size);

int evco_send(int fd, char *buffer, size_t size);

evsc_t *evsc_alloc();

evsc_t *evco_get_sc();

int evco_dispatch(evsc_t *psc);


evco_cond_t *evco_cond_alloc();

int evco_cond_timedwait(evco_cond_t *pcond, int msec);

int evco_cond_signal(evco_cond_t *pcond);

int evco_cond_broadcast(evco_cond_t *pcond);

int evco_cond_free(evco_cond_t *pcond);

#endif 
