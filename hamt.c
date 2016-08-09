/*
 * Hash Array Mapped Trie (HAMT) implementation
 *
 *  Copyright (C) 2016 Andrew Cone
 *
 *  Based on (https://github.com/yasm/yasm)
 *
 *  Copyright (C) 2001-2007  Peter Johnson
 *
 *  Based on the paper "Ideal Hash Tries" by Phil Bagwell [2000].
 *  One algorithmic change from that described in the paper: we use the LSB's
 *  of the key to index the root table and move upward in the key rather than
 *  use the MSBs as described in the paper.  The LSBs have more entropy.
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
 */

#ifndef HAMT_VERBOSE
#define HAMT_VERBOSE 1
#endif
#ifndef HAMT_USE_XXHASH
#define HAMT_USE_XXHASH 1
#endif

#include <ctype.h>
#include <sys/queue.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if HAMT_USE_XXHASH
#include "xxhash/xxhash.h"
#endif

#if HAMT_VERBOSE
#include <stdio.h>
#endif

#include "hamt.h"

#define BC_TWO(c)       ((uint32_t)0x1 << (c))
#define BC_MSK(c)       (((uint32_t)(-1)) / (BC_TWO(BC_TWO(c)) + (uint32_t)1))
#define BC_COUNT(x,c)   ((x) & BC_MSK(c)) + (((x) >> (BC_TWO(c))) & BC_MSK(c))
#define BitCount(d, s)          do {            \
        d = BC_COUNT(s, 0);                     \
        d = BC_COUNT(d, 1);                     \
        d = BC_COUNT(d, 2);                     \
        d = BC_COUNT(d, 3);                     \
        d = BC_COUNT(d, 4);                     \
    } while (0)

struct HAMTEntry {
    const void *key;
    size_t keylen;
    void *value;
};

typedef struct HAMTNode {
    uint32_t BitMapKey;            /* 32 bits, bitmap or hash key */
    uintptr_t BaseValue;           /* Base of HAMTNode list or value */
} HAMTNode;

struct HAMT {
    HAMTEntry *entries;
    size_t entries_size;
    size_t length;
    HAMTNode *root;
};

/* XXX make a portable version of this.  This depends on the pointer being
 * 4 or 2-byte aligned (as it uses the LSB of the pointer variable to store
 * the subtrie flag!
 */
#define IsSubTrie(n)            ((n)->BaseValue & 1)
#define SetSubTrie(h, n, v)     do {                            \
        if ((uintptr_t)(v) & 1)                                 \
            error_func(__FILE__, __LINE__,                              \
                       "Subtrie is seen as subtrie before flag is set (misaligned?)"); \
        (n)->BaseValue = (uintptr_t)(v) | 1;                            \
    } while (0)
#define GetSubTrie(n)           (HAMTNode *)(((n)->BaseValue | 1) ^ 1)


#define SetEntryForNode(h, n, e)       do {                     \
        if ((uintptr_t)(e) & 1)                                 \
            error_func(__FILE__, __LINE__,                           \
                       "Value is seen as subtrie (misaligned?)");       \
        (n)->BaseValue = ((uintptr_t)((e) - h->entries) + 1) << 1 ;     \
    } while (0)
#define GetEntryForNode(h, n)    ((HAMTEntry *)&h->entries[((n)->BaseValue >> 1) - 1])

void HAMT_nothing(void *x)
{}

static uint32_t
rehash_key(const void *key, size_t keylen, int level)
{
#if HAMT_USE_XXHASH
    return XXH64(key, keylen, level);
#else
    const uint8_t *x = key;
    uint32_t a=31415, b=27183, vHash;
    for (vHash=0; x - (uint8_t *)key < keylen; x++, a*=b)
        vHash = a*vHash*(uint32_t)level + *x;
    return vHash;
#endif
}

static uint32_t
hash_key(const void *key, size_t keylen)
{
    return rehash_key(key, keylen, 1);
}

static int
cmp_key(const void *x, size_t xlen, const void *y, size_t ylen)
{
    if (xlen != ylen) {
        return xlen - ylen;
    } else {
        return memcmp(x, y, xlen);
    }

}

static void
error_func(const char *file, unsigned int line, const char *message)
{
#if HAMT_VERBOSE
    fprintf(stderr, "%s:%u: %s", file, line, message);
#endif
    exit(1);
}


HAMT *
HAMT_create()
{
    HAMT *hamt = malloc(sizeof(HAMT));
    int i;

    hamt->length = 0;
    hamt->entries_size = 4;
    hamt->entries = malloc(hamt->entries_size * sizeof(HAMTEntry));
    hamt->root = malloc(32*sizeof(HAMTNode));

    for (i=0; i<32; i++) {
        hamt->root[i].BitMapKey = 0;
        hamt->root[i].BaseValue = 0;
    }

    return hamt;
}

static void
HAMT_delete_trie(HAMTNode *node)
{
    if (IsSubTrie(node)) {
        uint32_t i, Size;

        /* Count total number of bits in bitmap to determine size */
        BitCount(Size, node->BitMapKey);
        Size &= 0x1F;
        if (Size == 0)
            Size = 32;

        for (i=0; i<Size; i++)
            HAMT_delete_trie(&(GetSubTrie(node))[i]);
        free(GetSubTrie(node));
    }
}

void
HAMT_destroy(HAMT *hamt, void (*deletefunc) (void *))
{
    int i;

    /* delete entries */
    for (size_t i = 0; i < hamt->length; i++) {
        deletefunc(&hamt->entries[i].value);
    }
    free(hamt->entries);

    /* delete trie */
    for (i=0; i<32; i++)
        HAMT_delete_trie(&hamt->root[i]);

    free(hamt->root);
    free(hamt);
}

int
HAMT_traverse(HAMT *hamt, void *d,
              int (*func) (  void *node,
                             void *d))
{
    for (size_t i = 0; i < hamt->length; i++) {
        int retval = func(hamt->entries[i].value, d);
        if (retval != 0)
            return retval;
    }
    return 0;
}

HAMTEntry *
HAMT_first(HAMT *hamt)
{
    return hamt->entries;
}

HAMTEntry *
HAMT_next(HAMTEntry *prev)
{
    return prev + 1;
}


const void *
HAMTEntry_get_key(const HAMTEntry *entry)
{
    return entry->key;
}

size_t
HAMTEntry_get_keylen(const HAMTEntry *entry)
{
    return entry->keylen;
}

void *
HAMTEntry_get_value(const HAMTEntry *entry)
{
    return entry->value;
}

void
HAMTEntry_set_value(HAMTEntry *entry, void *new_value, void (*deletefunc)(void *))
{
    deletefunc(entry->value);
    entry->value = new_value;
}

HAMTEntry*
HAMT_add_entry(HAMT *hamt, const void *key, size_t keylen, void *value)
{
        if (hamt->length == hamt->entries_size) {
            hamt->entries_size *= 2;
            hamt->entries = realloc(hamt->entries, hamt->entries_size * sizeof(HAMTEntry));
        }
        hamt->length++;
        HAMTEntry *e = &hamt->entries[hamt->length - 1];
        e->key = key;
        e->keylen = keylen;
        e->value = value;
        return e;
}

void *
HAMT_insert(HAMT *hamt, const void * const key, size_t keylen, void *value, int *replace,
            void (*deletefunc) ( void *value))
{
    HAMTNode *node, *newnodes;
    HAMTEntry *entry;
    uint32_t key_hash, keypart, Map;
    int keypartbits = 0;
    int level = 0;

    key_hash = hash_key(key, keylen);
    keypart = key_hash & 0x1F;
    node = &hamt->root[keypart];

    if (!node->BaseValue) {
        node->BitMapKey = key_hash;

        entry = HAMT_add_entry(hamt, key, keylen, value);

        SetEntryForNode(hamt, node, entry);
        if (IsSubTrie(node))
            error_func(__FILE__, __LINE__,
                       "Data is seen as subtrie (misaligned?)");
        *replace = 1;
        return value;
    }

    for (;;) {
        if (!(IsSubTrie(node))) {
            if (node->BitMapKey == key_hash
                && cmp_key(GetEntryForNode(hamt, node)->key,
                           GetEntryForNode(hamt, node)->keylen,
                           key,
                           keylen) == 0) {

                if (*replace) {
                    deletefunc(GetEntryForNode(hamt, node)->value);
                    GetEntryForNode(hamt, node)->key = key;
                    GetEntryForNode(hamt, node)->keylen = keylen;
                    GetEntryForNode(hamt, node)->value = value;
                } else
                    deletefunc(value);

                return GetEntryForNode(hamt, node)->value;
            } else {
                uint32_t key_hash2 = node->BitMapKey;
                /* build tree downward until keys differ */
                for (;;) {
                    uint32_t keypart2;

                    /* replace node with subtrie */
                    keypartbits += 5;
                    if (keypartbits > 30) {
                        /* Exceeded 32 bits: rehash */
                        key_hash = rehash_key(key, keylen, level);
                        key_hash2 = rehash_key(GetEntryForNode(hamt, node)->key,
                                               GetEntryForNode(hamt, node)->keylen,
                                               level);
                        keypartbits = 0;
                    }
                    keypart = (key_hash >> keypartbits) & 0x1F;
                    keypart2 = (key_hash2 >> keypartbits) & 0x1F;

                    if (keypart == keypart2) {
                        /* Still equal, build one-node subtrie and continue
                         * downward.
                         */
                        newnodes = malloc(sizeof(HAMTNode));
                        newnodes[0].BitMapKey = key_hash2;
                        newnodes[0].BaseValue = node->BaseValue;
                        node->BitMapKey = 1<<keypart;
                        SetSubTrie(hamt, node, newnodes);
                        node = &newnodes[0];
                        level++;
                    } else {
                        /* partitioned: allocate two-node subtrie */
                        newnodes = malloc(2*sizeof(HAMTNode));

                        entry = HAMT_add_entry(hamt, key, keylen, value);

                        /* Copy nodes into subtrie based on order */
                        if (keypart2 < keypart) {
                            newnodes[0].BitMapKey = key_hash2;
                            newnodes[0].BaseValue = node->BaseValue;
                            newnodes[1].BitMapKey = key_hash;
                            SetEntryForNode(hamt, &newnodes[1], entry);
                        } else {
                            newnodes[0].BitMapKey = key_hash;
                            SetEntryForNode(hamt, &newnodes[0], entry);
                            newnodes[1].BitMapKey = key_hash2;
                            newnodes[1].BaseValue = node->BaseValue;
                        }

                        /* Set bits in bitmap corresponding to keys */
                        node->BitMapKey = (1UL<<keypart) | (1UL<<keypart2);
                        SetSubTrie(hamt, node, newnodes);
                        *replace = 1;
                        return value;
                    }
                }
            }
        }

        /* Subtrie: look up in bitmap */
        keypartbits += 5;
        if (keypartbits > 30) {
            /* Exceeded 32 bits of current key: rehash */
            key_hash = rehash_key(key, keylen, level);
            keypartbits = 0;
        }
        keypart = (key_hash >> keypartbits) & 0x1F;
        if (!(node->BitMapKey & (1<<keypart))) {
            /* bit is 0 in bitmap -> add node to table */
            uint32_t Size;

            /* set bit to 1 */
            node->BitMapKey |= 1<<keypart;

            /* Count total number of bits in bitmap to determine new size */
            BitCount(Size, node->BitMapKey);
            Size &= 0x1F;
            if (Size == 0)
                Size = 32;
            newnodes = malloc(Size*sizeof(HAMTNode));

            /* Count bits below to find where to insert new node at */
            BitCount(Map, node->BitMapKey & ~((~0UL)<<keypart));
            Map &= 0x1F;        /* Clamp to <32 */
            /* Copy existing nodes leaving gap for new node */
            memcpy(newnodes, GetSubTrie(node), Map*sizeof(HAMTNode));
            memcpy(&newnodes[Map+1], &(GetSubTrie(node))[Map],
                   (Size-Map-1)*sizeof(HAMTNode));
            /* Delete old subtrie */
            free(GetSubTrie(node));
            /* Set up new node */
            newnodes[Map].BitMapKey = key_hash;

            entry = HAMT_add_entry(hamt, key, keylen, value);
            SetEntryForNode(hamt, &newnodes[Map], entry);
            SetSubTrie(hamt, node, newnodes);

            *replace = 1;
            return value;
        }

        /* Count bits below */
        BitCount(Map, node->BitMapKey & ~((~0UL)<<keypart));
        Map &= 0x1F;    /* Clamp to <32 */

        /* Go down a level */
        level++;
        node = &(GetSubTrie(node))[Map];
    }
}

void *HAMT_set(HAMT *hamt, const void *key, size_t keylen,
               void *value, void (*deletefunc) (void *value))
{
    int replace = 1;
    return HAMT_insert(hamt, key, keylen, value, &replace, deletefunc);
}

HAMTEntry* HAMT_search(HAMT *hamt, const void *key, size_t keylen)
{
    HAMTNode *node;
    uint32_t key_hash, keypart, Map;
    int keypartbits = 0;
    int level = 0;

    key_hash = hash_key(key, keylen);
    keypart = key_hash & 0x1F;
    node = &hamt->root[keypart];

    if (!node->BaseValue)
        return NULL;

    for (;;) {
        if (!(IsSubTrie(node))) {
            if (node->BitMapKey == key_hash
                && cmp_key(GetEntryForNode(hamt, node)->key,
                           GetEntryForNode(hamt, node)->keylen,
                           key,
                           keylen) == 0)
                return GetEntryForNode(hamt, node);
            else
                return NULL;
        }

        /* Subtree: look up in bitmap */
        keypartbits += 5;
        if (keypartbits > 30) {
            /* Exceeded 32 bits of current key: rehash */
            key_hash = rehash_key(key, keylen, level);
            keypartbits = 0;
        }
        keypart = (key_hash >> keypartbits) & 0x1F;
        if (!(node->BitMapKey & (1<<keypart)))
            return NULL;        /* bit is 0 in bitmap -> no match */

        /* Count bits below */
        BitCount(Map, node->BitMapKey & ~((~0UL)<<keypart));
        Map &= 0x1F;    /* Clamp to <32 */

        /* Go down a level */
        level++;
        node = &(GetSubTrie(node))[Map];
    }
}

void *
HAMT_get(HAMT *hamt, const void *key, size_t keylen)
{
    HAMTEntry *entry = HAMT_search(hamt, key, keylen);
    if (!entry) {
        return NULL;
    }
    return entry->value;
}

size_t
HAMT_length(const HAMT *hamt)
{
    return hamt->length;
}
