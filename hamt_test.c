#include "hamt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void hamt_error_func(const char *file, unsigned int line, const char *message)
{
    fprintf(stderr, "%s:%u: %s", file, line, message);
}

void nothing(void *x) {}

int main() {
    HAMT *h = HAMT_create(1, hamt_error_func);
    char *line = NULL;
    size_t line_cap = 0, line_len;
    ssize_t line_len_or_err;
    while ((line_len_or_err = getline(&line, &line_cap, stdin)) >= 0) {
        line_len = line_len_or_err;
        //        printf("line: %s\n", line);
        if (line[line_len - 1] == '\n') {
            line[line_len - 1] = '\0';
        }
        //        printf("line: %s\n", line);

        char *op = strsep(&line, "\t");
        //        printf("op: %s\n", op);
        char *key = strsep(&line, "\t");
        //        printf("key: %s\n", key);
        
        if (!strcmp(op, "S")) {
            key = strdup(key);
            char *val = strdup(strsep(&line, "\t"));
            //            printf("val: %s\n", val);

            HAMTEntry *e = HAMT_search_entry(h, key);
            if (e) {
                free(key);
                HAMTEntry_set_data(e, val, free);
            } else {
                HAMT_set(h, key, val, nothing);
            }
        } else if (!strcmp(op, "D")) {
                ;
        }
        
    }
}
