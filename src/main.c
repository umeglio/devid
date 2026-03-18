#include "config.h"
#include "passive.h"
#include "report.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s --config <file> [--csv <file>] [--log <file>] [--oui <file>] [--tcp-ports <spec>] [--udp-ports <spec>] [--vendor-online] [--icmp-timeout-ms <n>] [--tcp-timeout-ms <n>] [--udp-timeout-ms <n>]\n",
            program);
}

int main(int argc, char **argv)
{
    const char *config_path;
    const char *csv_path;
    const char *oui_path;
    int i;
    char errbuf[256];
    scope_list_t scopes;
    oui_db_t oui_db;
    host_record_list_t records;
    scan_options_t options;

    config_path = NULL;
    csv_path = "report.csv";
    oui_path = NULL;

    init_default_scan_options(&options);

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if ((strcmp(argv[i], "--csv") == 0 || strcmp(argv[i], "--report") == 0) && i + 1 < argc) {
            csv_path = argv[++i];
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            safe_copy(options.log_path, sizeof(options.log_path), argv[++i]);
        } else if (strcmp(argv[i], "--oui") == 0 && i + 1 < argc) {
            oui_path = argv[++i];
        } else if (strcmp(argv[i], "--vendor-online") == 0) {
            options.vendor_online = 1;
        } else if (strcmp(argv[i], "--tcp-ports") == 0 && i + 1 < argc) {
            if (!parse_port_spec(argv[++i], options.tcp_ports, &options.tcp_port_count, MAX_PORT_COUNT, errbuf, sizeof(errbuf))) {
                fprintf(stderr, "TCP port spec error: %s\n", errbuf);
                return 1;
            }
        } else if (strcmp(argv[i], "--udp-ports") == 0 && i + 1 < argc) {
            if (!parse_port_spec(argv[++i], options.udp_ports, &options.udp_port_count, MAX_PORT_COUNT, errbuf, sizeof(errbuf))) {
                fprintf(stderr, "UDP port spec error: %s\n", errbuf);
                return 1;
            }
        } else if (strcmp(argv[i], "--icmp-timeout-ms") == 0 && i + 1 < argc) {
            options.icmp_timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--tcp-timeout-ms") == 0 && i + 1 < argc) {
            options.tcp_timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--udp-timeout-ms") == 0 && i + 1 < argc) {
            options.udp_timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (config_path == NULL) {
        print_usage(argv[0]);
        return 1;
    }

    memset(&scopes, 0, sizeof(scopes));
    memset(&oui_db, 0, sizeof(oui_db));
    memset(&records, 0, sizeof(records));
    memset(errbuf, 0, sizeof(errbuf));

    if (!load_config(config_path, &scopes, errbuf, sizeof(errbuf))) {
        fprintf(stderr, "Config error: %s\n", errbuf);
        return 1;
    }

    if (!load_oui_db(oui_path, &oui_db, errbuf, sizeof(errbuf))) {
        fprintf(stderr, "OUI error: %s\n", errbuf);
        free_scope_list(&scopes);
        return 1;
    }

    if (!collect_active_hosts(&scopes, &oui_db, &options, &records, errbuf, sizeof(errbuf))) {
        fprintf(stderr, "Scan error: %s\n", errbuf);
        free_oui_db(&oui_db);
        free_scope_list(&scopes);
        return 1;
    }

    if (!write_csv_report(csv_path, &records, errbuf, sizeof(errbuf))) {
        fprintf(stderr, "CSV error: %s\n", errbuf);
        free_host_record_list(&records);
        free_oui_db(&oui_db);
        free_scope_list(&scopes);
        return 1;
    }

    printf("CSV generated : %s\n", csv_path);
    printf("Log generated : %s\n", options.log_path);
    printf("Scopes loaded : %lu\n", (unsigned long) scopes.count);
    printf("Hosts found   : %lu\n", (unsigned long) records.count);

    free_host_record_list(&records);
    free_oui_db(&oui_db);
    free_scope_list(&scopes);
    return 0;
}
