#ifndef PASSIVE_H
#define PASSIVE_H

#include "config.h"

#include <stddef.h>

#define MAX_HOSTNAME_LEN 128
#define MAX_VENDOR_LEN 128
#define MAX_TYPE_LEN 64
#define MAX_SERVICE_LIST_LEN 512
#define MAX_SOURCE_LEN 128
#define MAX_TIMESTAMP_LEN 32
#define MAX_PORT_COUNT 256
#define MAX_PATH_LEN 260

typedef struct oui_entry_tag {
    unsigned long prefix;
    char vendor[MAX_VENDOR_LEN];
} oui_entry_t;

typedef struct oui_db_tag {
    oui_entry_t *items;
    size_t count;
    size_t capacity;
} oui_db_t;

typedef struct scan_options_tag {
    unsigned short tcp_ports[MAX_PORT_COUNT];
    size_t tcp_port_count;
    unsigned short udp_ports[MAX_PORT_COUNT];
    size_t udp_port_count;
    int icmp_timeout_ms;
    int tcp_timeout_ms;
    int udp_timeout_ms;
    int vendor_online;
    char log_path[MAX_PATH_LEN];
} scan_options_t;

typedef struct host_record_tag {
    unsigned long ip;
    unsigned long network;
    unsigned long mask;
    unsigned long anchor_ip;
    unsigned long if_index;
    unsigned long rtt_ms;
    unsigned int ttl;
    unsigned char mac[8];
    unsigned int mac_len;
    int alive;
    char scope_name[MAX_DEVNAME_LEN];
    char hostname[MAX_HOSTNAME_LEN];
    char vendor[MAX_VENDOR_LEN];
    char vendor_source[MAX_SOURCE_LEN];
    char type[MAX_TYPE_LEN];
    char os[MAX_TYPE_LEN];
    char tcp_services[MAX_SERVICE_LIST_LEN];
    char udp_services[MAX_SERVICE_LIST_LEN];
    char reachability[MAX_SOURCE_LEN];
    char timestamp[MAX_TIMESTAMP_LEN];
} host_record_t;

typedef struct host_record_list_tag {
    host_record_t *items;
    size_t count;
    size_t capacity;
} host_record_list_t;

void init_default_scan_options(scan_options_t *options);
int parse_port_spec(const char *spec,
                    unsigned short *ports,
                    size_t *count,
                    size_t max_ports,
                    char *errbuf,
                    size_t errbuf_size);
int load_oui_db(const char *path, oui_db_t *db, char *errbuf, size_t errbuf_size);
void free_oui_db(oui_db_t *db);
int collect_active_hosts(const scope_list_t *scopes,
                         const oui_db_t *oui_db,
                         const scan_options_t *options,
                         host_record_list_t *records,
                         char *errbuf,
                         size_t errbuf_size);
void free_host_record_list(host_record_list_t *records);

#endif
