/*************************************************************************
	> File Name: hashtab.c
	> Author: 
	> Mail: 
	> Created Time: Tue 05 Dec 2017 04:50:17 AM PST
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "list.h"
#include "hashtab.h"

#define HASHTAB_BUCKET_NUM 1024*128
#define HASHTAB_BUCKET_MASK (HASHTAB_BUCKET_NUM - 1)

struct hashtab_item {
    struct list_head entry;
    int key;
    void *pdata;
};

struct hashtab {
    struct list_head entries[HASHTAB_BUCKET_NUM];
};

hashtab_t *hashtab_alloc()
{
    int ix = 0;
    hashtab_t *phashtab = (hashtab_t *)malloc(sizeof(struct hashtab));
    if ( !phashtab ) {
        return phashtab;
    }

    for ( ix = 0; ix < HASHTAB_BUCKET_NUM; ix++ ) {
        phashtab->entries[ix].next = &phashtab->entries[ix];
        phashtab->entries[ix].prev = &phashtab->entries[ix];
    } 

    return phashtab;
}

struct hashtab_item *__hashtab_query(hashtab_t *phashtab, int key)
{
    struct list_head *pos = NULL;
    struct hashtab_item *pitem = NULL;

    list_for_each(pos, &phashtab->entries[key&HASHTAB_BUCKET_MASK]) {
        pitem = (struct hashtab_item *)pos;
        if ( pitem->key == key ) {
            return pitem;
        }
    }

    return NULL;
}

void *hashtab_query(hashtab_t *phashtab, int key)
{
    struct hashtab_item *pitem = NULL;
    pitem = __hashtab_query(phashtab, key);
    if ( !pitem ) {
        return NULL;
    }

    return pitem->pdata;
}

int hashtab_insert(hashtab_t *phashtab, int key, void *pdata)
{
    struct hashtab_item *pitem = NULL;

    if ( hashtab_query(phashtab, key) ) {
        return -1;
    }

    pitem = (struct hashtab_item *)malloc(sizeof(struct hashtab_item));
    if ( !pitem ) {
        return -1;
    }

    pitem->key = key;
    pitem->pdata = pdata;
    list_add(&pitem->entry, &phashtab->entries[key&HASHTAB_BUCKET_MASK]);
    return 0;
}

int hashtab_delete(hashtab_t *phashtab, int key, void (*cb_free)(void *))
{
    struct hashtab_item *pitem = NULL;

    pitem = __hashtab_query(phashtab, key);
    if ( !pitem ) {
        return -1;
    }

    list_del(&pitem->entry);
    if ( cb_free ) 
        cb_free(pitem->pdata);
    free(pitem);
    return 0;
}
    
int hashtab_free(hashtab_t *phashtab, void (*cb_free)(void *))
{
    int ix = 0;
    struct list_head *pos = NULL;
    struct list_head *next= NULL;
    struct hashtab_item *pitem = NULL;

    for ( ix = 0; ix < HASHTAB_BUCKET_NUM; ix ++ ) {
        list_for_each_safe(pos, next, &phashtab->entries[ix]) {
            list_del(pos);
            pitem = (struct hashtab_item *)pos;
            if ( cb_free )
                cb_free(pitem->pdata);
            free(pitem);
        }
    }
    return 0;
}
