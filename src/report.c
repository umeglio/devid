#include "report.h"
#include "ipv4.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

static void csv_write_field(FILE *fp, const char *text)
{
    const char *cursor;

    fputc('"', fp);
    if (text != NULL) {
        cursor = text;
        while (*cursor != '\0') {
            if (*cursor == '"') {
                fputc('"', fp);
            }
            fputc(*cursor, fp);
            ++cursor;
        }
    }
    fputc('"', fp);
}

static void csv_write_separator(FILE *fp, int *first)
{
    if (*first) {
        *first = 0;
        return;
    }
    fputc(';', fp);
}

static void csv_write_text(FILE *fp, int *first, const char *text)
{
    csv_write_separator(fp, first);
    csv_write_field(fp, text);
}

int write_csv_report(const char *path,
                     const host_record_list_t *records,
                     char *errbuf,
                     size_t errbuf_size)
{
    FILE *fp;
    size_t i;
    int first;
    char network_text[32];
    char mask_text[32];
    char anchor_text[32];
    char ip_text[32];
    char mac_text[32];
    char rtt_text[32];
    char ttl_text[32];
    char alive_text[8];
    char ifindex_text[32];

    if (path == NULL || records == NULL) {
        safe_copy(errbuf, errbuf_size, "invalid csv arguments");
        return 0;
    }

    fp = fopen(path, "w");
    if (fp == NULL) {
        safe_copy(errbuf, errbuf_size, "cannot open csv output");
        return 0;
    }

    first = 1;
    csv_write_text(fp, &first, "timestamp");
    csv_write_text(fp, &first, "scope");
    csv_write_text(fp, &first, "if_index");
    csv_write_text(fp, &first, "network");
    csv_write_text(fp, &first, "mask");
    csv_write_text(fp, &first, "anchor_ip");
    csv_write_text(fp, &first, "ip");
    csv_write_text(fp, &first, "hostname");
    csv_write_text(fp, &first, "alive");
    csv_write_text(fp, &first, "reachability");
    csv_write_text(fp, &first, "rtt_ms");
    csv_write_text(fp, &first, "ttl");
    csv_write_text(fp, &first, "mac");
    csv_write_text(fp, &first, "vendor");
    csv_write_text(fp, &first, "vendor_source");
    csv_write_text(fp, &first, "type");
    csv_write_text(fp, &first, "os");
    csv_write_text(fp, &first, "tcp_services");
    csv_write_text(fp, &first, "udp_services");
    fputc('\n', fp);

    for (i = 0U; i < records->count; ++i) {
        ipv4_to_string(records->items[i].network, network_text, sizeof(network_text));
        ipv4_to_string(records->items[i].mask, mask_text, sizeof(mask_text));
        ipv4_to_string(records->items[i].anchor_ip, anchor_text, sizeof(anchor_text));
        ipv4_to_string(records->items[i].ip, ip_text, sizeof(ip_text));
        format_mac(records->items[i].mac, records->items[i].mac_len, mac_text, sizeof(mac_text));
        snprintf(rtt_text, sizeof(rtt_text), "%lu", records->items[i].rtt_ms);
        snprintf(ttl_text, sizeof(ttl_text), "%u", records->items[i].ttl);
        snprintf(ifindex_text, sizeof(ifindex_text), "%lu", records->items[i].if_index);
        safe_copy(alive_text, sizeof(alive_text), records->items[i].alive ? "yes" : "no");

        first = 1;
        csv_write_text(fp, &first, records->items[i].timestamp);
        csv_write_text(fp, &first, records->items[i].scope_name);
        csv_write_text(fp, &first, ifindex_text);
        csv_write_text(fp, &first, network_text);
        csv_write_text(fp, &first, mask_text);
        csv_write_text(fp, &first, anchor_text);
        csv_write_text(fp, &first, ip_text);
        csv_write_text(fp, &first, records->items[i].hostname);
        csv_write_text(fp, &first, alive_text);
        csv_write_text(fp, &first, records->items[i].reachability);
        csv_write_text(fp, &first, rtt_text);
        csv_write_text(fp, &first, ttl_text);
        csv_write_text(fp, &first, mac_text);
        csv_write_text(fp, &first, records->items[i].vendor);
        csv_write_text(fp, &first, records->items[i].vendor_source);
        csv_write_text(fp, &first, records->items[i].type);
        csv_write_text(fp, &first, records->items[i].os);
        csv_write_text(fp, &first, records->items[i].tcp_services);
        csv_write_text(fp, &first, records->items[i].udp_services);
        fputc('\n', fp);
    }

    fclose(fp);
    return 1;
}
