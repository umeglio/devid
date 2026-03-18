#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>

#define MAX_DEVNAME_LEN 64
#define MAX_RAW_LINE_LEN 256

typedef struct scan_scope_tag {
    char raw_line[MAX_RAW_LINE_LEN];
    char devname[MAX_DEVNAME_LEN];
    unsigned long anchor_ip;
    unsigned long iface_ip;
    unsigned long mask;
    unsigned long network;
    unsigned long broadcast;
    unsigned long first_host;
    unsigned long last_host;
    unsigned long if_index;
} scan_scope_t;

typedef struct scope_list_tag {
    scan_scope_t *items;
    size_t count;
    size_t capacity;
} scope_list_t;

int load_config(const char *path, scope_list_t *list, char *errbuf, size_t errbuf_size);
void free_scope_list(scope_list_t *list);
const scan_scope_t *find_scope_for_ip(const scope_list_t *list, unsigned long ip, unsigned long if_index);

#endif
