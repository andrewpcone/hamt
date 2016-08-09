/**
 * \file libyasm/hamt.h
 * \brief Hash Array Mapped Trie (HAMT) functions.
 *
 * \license
 *  Copyright (C) 2001-2007  Peter Johnson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND OTHER CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR OTHER CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * \endlicense
 */

#ifndef __HAMT_H__
#define __HAMT_H__

#include <stdlib.h>

/** Hash array mapped trie data structure (opaque type). */
typedef struct HAMT HAMT;
/** Hash array mapped trie entry (opaque type). */
typedef struct HAMTEntry HAMTEntry;

#define PP_CAT(a, b) PP_CAT_I(a, b)
#define PP_CAT_I(a, b) PP_CAT_II(~, a ## b)
#define PP_CAT_II(p, res) res
#define U(base) PP_CAT(base, __LINE__)

typedef struct {HAMTEntry *e; int k;} iterstate_t;

#define HAMT_foreach_value(valexpr, hamt)                               \
    for (iterstate_t U(s) = {HAMT_first(hamt), 1}; U(s).k && U(s).e; U(s).e = HAMT_next(U(s).e), U(s).k = !U(s).k) \
        for (valexpr = HAMTEntry_get_value(U(s).e); U(s).k; U(s).k = !U(s).k)

#define HAMT_foreach(keyexpr, keylenexpr, valexpr, hamt)                   \
    for (iterstate_t U(s) = {HAMT_first(hamt), 1}; U(s).k && U(s).e; U(s).e = HAMT_next(U(s).e), U(s).k = !U(s).k) \
        for (keyexpr = HAMTEntry_get_key(U(s).e); U(s).k; )        \
            for (keylenexpr = HAMTEntry_get_keylen(U(s).e); U(s).k; )         \
                for (valexpr = HAMTEntry_get_value(U(s).e); U(s).k; U(s).k = !U(s).k)

#define HAMT_foreach_entry(e, hamt) \
  for (HAMTEntry *e = HAMT_first(hamt); e; e = HAMT_next(e))


/** 
 * \return New, empty, hash array mapped trie.
 */

HAMT *HAMT_create();

/** Delete HAMT and all data associated with it.  Uses deletefunc() to delete
 * each data item.
 * \param hamt          Hash array mapped trie
 * \param deletefunc    Value deletion function
 */

void HAMT_destroy( HAMT *hamt,
                  void (*deletefunc) ( void *value));

/** Insert key into HAMT, associating it with data.
 * If the key is not present in the HAMT, inserts it, sets *replace to 1, and
 *  returns the data passed in.
 * If the key is already present and *replace is 0, deletes the data passed
 *  in using deletefunc() and returns the data currently associated with the
 *  key.
 * If the key is already present and *replace is 1, deletes the data currently
 *  associated with the key using deletefunc() and replaces it with the data
 *  passed in.
 * \param hamt          Hash array mapped trie
 * \param key           Key
 * \param keylen        Number of bytes in key
 * \param Value         Value to associate with key
 * \param replace       See above description
 * \param deletefunc    Data deletion function if data is replaced
 * \return Data now associated with key.
 */

void *HAMT_insert(HAMT *hamt,
                  const void *key, size_t keylen,
                  void *value, int *replace,
                  void (*deletefunc) ( void *value));

void *HAMT_set(HAMT *hamt, const void *key, size_t keylen,
               void *value, void (*deletefunc) (void *value));

/** Search for the HAMTEntry associated with a key in the HAMT.
 * \param hamt          Hash array mapped trie
 * \param str           Key
 * \return NULL if key/data not present in HAMT, otherwise associated HAMTEntry.
 */

HAMTEntry *HAMT_search(HAMT *hamt, const void *key, size_t keylen);

/** Search for the data associated with a key in the HAMT.
 * \param hamt          Hash array mapped trie
 * \param str           Key
 * \return NULL if key/data not present in HAMT, otherwise associated data.
 */

void *HAMT_get(HAMT *hamt, const void *key, size_t keylen);

/** Traverse over all keys in HAMT, calling function on each data item.
 * \param hamt          Hash array mapped trie
 * \param d             Data to pass to each call to func.
 * \param func          Function to call
 * \return Stops early (and returns func's return value) if func returns a
 *         nonzero value; otherwise 0.
 */

int HAMT_traverse(HAMT *hamt,  void *d,
                  int (*func) (  void *node,
                                void *d));

/** Get the first entry in a HAMT.
 * \param hamt          Hash array mapped trie
 * \return First entry in HAMT, or NULL if HAMT is empty.
 */

HAMTEntry *HAMT_first(HAMT *hamt);

/** Get the next entry in a HAMT.
 * \param prev          Previous entry in HAMT
 * \return Next entry in HAMT, or NULL if no more entries.
 */

HAMTEntry *HAMT_next(HAMTEntry *prev);

/** Get the corresponding data for a HAMT entry.
 * \param entry         HAMT entry (as returned by HAMT_first() and HAMT_next())
 * \return Corresponding data item.
 */

const void *HAMTEntry_get_key(const HAMTEntry *entry);
size_t HAMTEntry_get_keylen(const HAMTEntry *entry);
void* HAMTEntry_get_value(const HAMTEntry *entry);
void HAMTEntry_set_value(HAMTEntry *entry, void *new_value, void (*deletefunc)(void *));

// convenience, for use as deletefunc arg
void HAMT_nothing(void *x);

size_t HAMT_length(const HAMT *hamt);

#endif
