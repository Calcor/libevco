/*************************************************************************
	> File Name: hashtab.h
	> Author: 
	> Mail: 
	> Created Time: Tue 05 Dec 2017 04:59:16 AM PST
 ************************************************************************/

#ifndef _HASHTAB_H
#define _HASHTAB_H

typedef struct hashtab hashtab_t;

hashtab_t *hashtab_alloc();

int hashtab_free(hashtab_t *phashtab, void (*cb_free)(void *));

int hashtab_insert(hashtab_t *phashtab, int key, void *pdata);

void *hashtab_query(hashtab_t *phashtab, int key);

int hashtab_delete(hashtab_t *phashtab, int key, void (*cb_free)(void *));

#endif
