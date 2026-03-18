#define WIN32_LEAN_AND_MEAN

#include "passive.h"
#include "ipv4.h"
#include "util.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

#define QUICK_PORT_COUNT 10

typedef struct logger_tag {
    FILE *fp;
    CRITICAL_SECTION lock;
    int initialized;
} logger_t;

typedef struct scan_context_tag scan_context_t;

typedef struct scope_thread_ctx_tag {
    scan_context_t *scan;
    scan_scope_t scope;
} scope_thread_ctx_t;

struct scan_context_tag {
    const oui_db_t *local_oui;
    oui_db_t vendor_cache;
    scan_options_t options;
    host_record_list_t *records;
    logger_t logger;
    CRITICAL_SECTION records_lock;
    CRITICAL_SECTION vendor_lock;
};

static const unsigned short g_quick_ports[QUICK_PORT_COUNT] = { 22, 53, 80, 135, 139, 443, 445, 3389, 8080, 8443 };

static int ensure_oui_capacity(oui_db_t *db)
{
    oui_entry_t *new_items;
    size_t new_capacity;

    if (db->count < db->capacity) {
        return 1;
    }

    new_capacity = (db->capacity == 0U) ? 32U : (db->capacity * 2U);
    new_items = (oui_entry_t *) realloc(db->items, new_capacity * sizeof(oui_entry_t));
    if (new_items == NULL) {
        return 0;
    }

    db->items = new_items;
    db->capacity = new_capacity;
    return 1;
}

static int ensure_record_capacity(host_record_list_t *records)
{
    host_record_t *new_items;
    size_t new_capacity;

    if (records->count < records->capacity) {
        return 1;
    }

    new_capacity = (records->capacity == 0U) ? 64U : (records->capacity * 2U);
    new_items = (host_record_t *) realloc(records->items, new_capacity * sizeof(host_record_t));
    if (new_items == NULL) {
        return 0;
    }

    records->items = new_items;
    records->capacity = new_capacity;
    return 1;
}

static void set_error(char *errbuf, size_t errbuf_size, const char *message)
{
    safe_copy(errbuf, errbuf_size, message);
}

static int logger_init(logger_t *logger, const char *path)
{
    if (logger == NULL || path == NULL || path[0] == '\0') {
        return 0;
    }

    memset(logger, 0, sizeof(*logger));
    logger->fp = fopen(path, "w");
    if (logger->fp == NULL) {
        return 0;
    }

    InitializeCriticalSection(&logger->lock);
    logger->initialized = 1;
    return 1;
}

static void logger_close(logger_t *logger)
{
    if (logger == NULL) {
        return;
    }

    if (logger->initialized) {
        DeleteCriticalSection(&logger->lock);
        logger->initialized = 0;
    }

    if (logger->fp != NULL) {
        fclose(logger->fp);
        logger->fp = NULL;
    }
}

static void logger_write(scan_context_t *scan, const char *fmt, ...)
{
    char now_text[MAX_TIMESTAMP_LEN];
    char line[1024];
    va_list args;

    if (scan == NULL || scan->logger.fp == NULL) {
        return;
    }

    timestamp_now(now_text, sizeof(now_text));
    va_start(args, fmt);
    vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    EnterCriticalSection(&scan->logger.lock);
    fprintf(scan->logger.fp, "%s %s\n", now_text, line);
    fflush(scan->logger.fp);
    LeaveCriticalSection(&scan->logger.lock);
}

static int port_exists(const unsigned short *ports, size_t count, unsigned short port)
{
    size_t i;

    for (i = 0U; i < count; ++i) {
        if (ports[i] == port) {
            return 1;
        }
    }

    return 0;
}

static int add_port(unsigned short *ports, size_t *count, size_t max_ports, unsigned short port)
{
    if (port == 0U) {
        return 0;
    }

    if (port_exists(ports, *count, port)) {
        return 1;
    }

    if (*count >= max_ports) {
        return 0;
    }

    ports[*count] = port;
    ++(*count);
    return 1;
}

static void trim_leading(char **text)
{
    while (**text == ' ' || **text == '\t') {
        ++(*text);
    }
}

int parse_port_spec(const char *spec,
                    unsigned short *ports,
                    size_t *count,
                    size_t max_ports,
                    char *errbuf,
                    size_t errbuf_size)
{
    char work[1024];
    char *token;
    char *dash;
    char *cursor;
    unsigned long start_port;
    unsigned long end_port;
    unsigned long value;

    if (ports == NULL || count == NULL) {
        set_error(errbuf, errbuf_size, "invalid port parser arguments");
        return 0;
    }

    *count = 0U;
    if (spec == NULL || spec[0] == '\0') {
        return 1;
    }

    safe_copy(work, sizeof(work), spec);
    token = strtok(work, ",");
    while (token != NULL) {
        cursor = token;
        trim_leading(&cursor);
        dash = strchr(cursor, '-');
        if (dash != NULL) {
            *dash = '\0';
            ++dash;
            trim_leading(&dash);
            start_port = strtoul(cursor, NULL, 10);
            end_port = strtoul(dash, NULL, 10);
            if (start_port == 0UL || end_port == 0UL || start_port > 65535UL || end_port > 65535UL || start_port > end_port) {
                set_error(errbuf, errbuf_size, "invalid port range");
                return 0;
            }
            for (value = start_port; value <= end_port; ++value) {
                if (!add_port(ports, count, max_ports, (unsigned short) value)) {
                    set_error(errbuf, errbuf_size, "too many ports in specification");
                    return 0;
                }
            }
        } else {
            value = strtoul(cursor, NULL, 10);
            if (value == 0UL || value > 65535UL) {
                set_error(errbuf, errbuf_size, "invalid port value");
                return 0;
            }
            if (!add_port(ports, count, max_ports, (unsigned short) value)) {
                set_error(errbuf, errbuf_size, "too many ports in specification");
                return 0;
            }
        }
        token = strtok(NULL, ",");
    }

    return 1;
}

void init_default_scan_options(scan_options_t *options)
{
    char errbuf[64];

    if (options == NULL) {
        return;
    }

    memset(options, 0, sizeof(*options));
    options->icmp_timeout_ms = 150;
    options->tcp_timeout_ms = 120;
    options->udp_timeout_ms = 180;
    options->vendor_online = 0;
    safe_copy(options->log_path, sizeof(options->log_path), "scan.log");

    memset(errbuf, 0, sizeof(errbuf));
    parse_port_spec("21,22,23,25,53,80,110,123,135,137,138,139,143,161,389,443,445,3389,5900,8080,8443",
                    options->tcp_ports,
                    &options->tcp_port_count,
                    MAX_PORT_COUNT,
                    errbuf,
                    sizeof(errbuf));
    memset(errbuf, 0, sizeof(errbuf));
    parse_port_spec("53,67,68,69,123,137,138,161,500,514,520,1900,5353",
                    options->udp_ports,
                    &options->udp_port_count,
                    MAX_PORT_COUNT,
                    errbuf,
                    sizeof(errbuf));
}

static int parse_oui_line(const char *line, oui_entry_t *entry)
{
    const char *cursor;
    char prefix_text[32];
    size_t prefix_len;

    if (line == NULL || entry == NULL) {
        return 0;
    }

    cursor = line;
    while (*cursor == ' ' || *cursor == '\t') {
        ++cursor;
    }

    prefix_len = 0U;
    while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' && prefix_len + 1U < sizeof(prefix_text)) {
        prefix_text[prefix_len++] = *cursor++;
    }
    prefix_text[prefix_len] = '\0';

    while (*cursor == ' ' || *cursor == '\t') {
        ++cursor;
    }

    if (prefix_text[0] == '\0' || *cursor == '\0') {
        return 0;
    }

    if (!parse_oui_prefix(prefix_text, &entry->prefix)) {
        return 0;
    }

    safe_copy(entry->vendor, sizeof(entry->vendor), cursor);
    trim_trailing(entry->vendor);
    return entry->vendor[0] != '\0';
}

int load_oui_db(const char *path, oui_db_t *db, char *errbuf, size_t errbuf_size)
{
    FILE *fp;
    char line[256];
    oui_entry_t entry;

    if (db == NULL) {
        set_error(errbuf, errbuf_size, "invalid OUI database pointer");
        return 0;
    }

    memset(db, 0, sizeof(*db));

    if (path == NULL || path[0] == '\0') {
        return 1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        set_error(errbuf, errbuf_size, "cannot open OUI file");
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        trim_trailing(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        if (!parse_oui_line(line, &entry)) {
            continue;
        }

        if (!ensure_oui_capacity(db)) {
            fclose(fp);
            free_oui_db(db);
            set_error(errbuf, errbuf_size, "out of memory while loading OUI file");
            return 0;
        }

        db->items[db->count] = entry;
        ++db->count;
    }

    fclose(fp);
    return 1;
}

void free_oui_db(oui_db_t *db)
{
    if (db == NULL) {
        return;
    }

    free(db->items);
    db->items = NULL;
    db->count = 0U;
    db->capacity = 0U;
}

static const char *lookup_vendor_by_prefix(const oui_db_t *db, unsigned long prefix)
{
    size_t i;

    if (db == NULL) {
        return NULL;
    }

    for (i = 0U; i < db->count; ++i) {
        if (db->items[i].prefix == prefix) {
            return db->items[i].vendor;
        }
    }

    return NULL;
}

static unsigned long mac_prefix_value(const unsigned char *mac, unsigned int mac_len)
{
    if (mac == NULL || mac_len < 3U) {
        return 0UL;
    }

    return ((unsigned long) mac[0] << 16) |
           ((unsigned long) mac[1] << 8) |
           (unsigned long) mac[2];
}

static int store_vendor_cache(oui_db_t *db, unsigned long prefix, const char *vendor)
{
    if (db == NULL || vendor == NULL || vendor[0] == '\0') {
        return 0;
    }

    if (lookup_vendor_by_prefix(db, prefix) != NULL) {
        return 1;
    }

    if (!ensure_oui_capacity(db)) {
        return 0;
    }

    db->items[db->count].prefix = prefix;
    safe_copy(db->items[db->count].vendor, sizeof(db->items[db->count].vendor), vendor);
    ++db->count;
    return 1;
}

static int vendor_lookup_online(const char *mac_text, char *vendor, size_t vendor_size)
{
    HINTERNET session;
    HINTERNET connection;
    HINTERNET request;
    WCHAR path_w[96];
    char path_a[96];
    DWORD status_code;
    DWORD status_size;
    DWORD available;
    DWORD read_count;
    char chunk[128];
    char body[256];
    size_t body_len;
    int wide_result;

    if (mac_text == NULL || vendor == NULL || vendor_size == 0U) {
        return 0;
    }

    vendor[0] = '\0';
    safe_copy(path_a, sizeof(path_a), "/");
    safe_copy(path_a + 1, sizeof(path_a) - 1U, mac_text);
    wide_result = MultiByteToWideChar(CP_ACP, 0, path_a, -1, path_w, (int) (sizeof(path_w) / sizeof(path_w[0])));
    if (wide_result == 0) {
        return 0;
    }

    session = WinHttpOpen(L"dev-id/1.0",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS,
                          0);
    if (session == NULL) {
        return 0;
    }

    WinHttpSetTimeouts(session, 1500, 1500, 1500, 1500);
    connection = WinHttpConnect(session, L"api.macvendors.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (connection == NULL) {
        WinHttpCloseHandle(session);
        return 0;
    }

    request = WinHttpOpenRequest(connection,
                                 L"GET",
                                 path_w,
                                 NULL,
                                 WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 WINHTTP_FLAG_SECURE);
    if (request == NULL) {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return 0;
    }

    if (!WinHttpSendRequest(request,
                            WINHTTP_NO_ADDITIONAL_HEADERS,
                            0,
                            WINHTTP_NO_REQUEST_DATA,
                            0,
                            0,
                            0)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return 0;
    }

    if (!WinHttpReceiveResponse(request, NULL)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return 0;
    }

    status_code = 0UL;
    status_size = sizeof(status_code);
    if (!WinHttpQueryHeaders(request,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &status_code,
                             &status_size,
                             WINHTTP_NO_HEADER_INDEX)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return 0;
    }

    if (status_code != 200UL) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return 0;
    }

    body[0] = '\0';
    body_len = 0U;
    for (;;) {
        available = 0UL;
        if (!WinHttpQueryDataAvailable(request, &available)) {
            break;
        }
        if (available == 0UL) {
            break;
        }
        if (available >= sizeof(chunk)) {
            available = sizeof(chunk) - 1U;
        }
        if (!WinHttpReadData(request, chunk, available, &read_count)) {
            break;
        }
        if (read_count == 0UL) {
            break;
        }
        if (body_len + read_count >= sizeof(body)) {
            read_count = (DWORD) (sizeof(body) - body_len - 1U);
        }
        memcpy(body + body_len, chunk, read_count);
        body_len += read_count;
        body[body_len] = '\0';
        if (body_len + 1U >= sizeof(body)) {
            break;
        }
    }

    trim_trailing(body);
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    if (body[0] == '\0') {
        return 0;
    }

    safe_copy(vendor, vendor_size, body);
    return 1;
}

static void resolve_vendor(scan_context_t *scan,
                           const unsigned char *mac,
                           unsigned int mac_len,
                           char *vendor,
                           size_t vendor_size,
                           char *vendor_source,
                           size_t vendor_source_size)
{
    unsigned long prefix;
    const char *name;
    char mac_text[32];
    char vendor_buf[MAX_VENDOR_LEN];

    if (vendor == NULL || vendor_source == NULL) {
        return;
    }

    safe_copy(vendor, vendor_size, "unknown");
    safe_copy(vendor_source, vendor_source_size, "unresolved");

    prefix = mac_prefix_value(mac, mac_len);
    if (prefix == 0UL) {
        safe_copy(vendor, vendor_size, "n/a");
        safe_copy(vendor_source, vendor_source_size, "no-mac");
        return;
    }

    name = lookup_vendor_by_prefix(scan->local_oui, prefix);
    if (name != NULL) {
        safe_copy(vendor, vendor_size, name);
        safe_copy(vendor_source, vendor_source_size, "local-oui");
        return;
    }

    EnterCriticalSection(&scan->vendor_lock);
    name = lookup_vendor_by_prefix(&scan->vendor_cache, prefix);
    LeaveCriticalSection(&scan->vendor_lock);
    if (name != NULL) {
        safe_copy(vendor, vendor_size, name);
        safe_copy(vendor_source, vendor_source_size, "online-cache");
        return;
    }

    if (!scan->options.vendor_online) {
        return;
    }

    format_mac(mac, mac_len, mac_text, sizeof(mac_text));
    if (vendor_lookup_online(mac_text, vendor_buf, sizeof(vendor_buf))) {
        EnterCriticalSection(&scan->vendor_lock);
        store_vendor_cache(&scan->vendor_cache, prefix, vendor_buf);
        LeaveCriticalSection(&scan->vendor_lock);
        safe_copy(vendor, vendor_size, vendor_buf);
        safe_copy(vendor_source, vendor_source_size, "api.macvendors.com");
    }
}

static void append_text(char *buffer, size_t buffer_size, const char *text)
{
    size_t current_len;
    size_t text_len;

    if (buffer == NULL || buffer_size == 0U || text == NULL || text[0] == '\0') {
        return;
    }

    current_len = strlen(buffer);
    text_len = strlen(text);
    if (current_len + text_len + 1U >= buffer_size) {
        return;
    }

    memcpy(buffer + current_len, text, text_len + 1U);
}

static void append_tag(char *buffer, size_t buffer_size, const char *tag)
{
    if (buffer == NULL || tag == NULL || tag[0] == '\0') {
        return;
    }

    if (strstr(buffer, tag) != NULL) {
        return;
    }

    if (buffer[0] != '\0') {
        append_text(buffer, buffer_size, ",");
    }
    append_text(buffer, buffer_size, tag);
}

static void append_service(char *buffer, size_t buffer_size, unsigned short port, const char *service_name)
{
    char entry[64];

    if (service_name == NULL || service_name[0] == '\0') {
        snprintf(entry, sizeof(entry), "%u", (unsigned int) port);
    } else {
        snprintf(entry, sizeof(entry), "%u/%s", (unsigned int) port, service_name);
    }

    if (strstr(buffer, entry) != NULL) {
        return;
    }

    if (buffer[0] != '\0') {
        append_text(buffer, buffer_size, ", ");
    }
    append_text(buffer, buffer_size, entry);
}

static const char *service_name_for_port(unsigned short port, int is_udp)
{
    if (!is_udp) {
        switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 80: return "http";
        case 110: return "pop3";
        case 123: return "ntp";
        case 135: return "msrpc";
        case 137: return "netbios-ns";
        case 138: return "netbios-dgm";
        case 139: return "netbios-ssn";
        case 143: return "imap";
        case 161: return "snmp";
        case 389: return "ldap";
        case 443: return "https";
        case 445: return "microsoft-ds";
        case 3389: return "rdp";
        case 5900: return "vnc";
        case 8080: return "http-alt";
        case 8443: return "https-alt";
        default: return "tcp";
        }
    }

    switch (port) {
    case 53: return "dns";
    case 67: return "dhcp-server";
    case 68: return "dhcp-client";
    case 69: return "tftp";
    case 123: return "ntp";
    case 137: return "netbios-ns";
    case 138: return "netbios-dgm";
    case 161: return "snmp";
    case 500: return "isakmp";
    case 514: return "syslog";
    case 520: return "rip";
    case 1900: return "ssdp";
    case 5353: return "mdns";
    default: return "udp";
    }
}

static void resolve_hostname(unsigned long ip, char *hostname, size_t hostname_size)
{
    struct sockaddr_in sa;
    char host[NI_MAXHOST];

    if (hostname == NULL || hostname_size == 0U) {
        return;
    }

    safe_copy(hostname, hostname_size, "n/a");
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip);

    if (getnameinfo((const struct sockaddr *) &sa,
                    (socklen_t) sizeof(sa),
                    host,
                    (DWORD) sizeof(host),
                    NULL,
                    0,
                    NI_NAMEREQD) == 0) {
        safe_copy(hostname, hostname_size, host);
    }
}

static int resolve_mac(unsigned long ip, unsigned char *mac, unsigned int *mac_len)
{
    ULONG raw_mac[2];
    ULONG raw_len;
    DWORD status;
    unsigned int copy_len;

    if (mac == NULL || mac_len == NULL) {
        return 0;
    }

    raw_len = 6UL;
    memset(raw_mac, 0, sizeof(raw_mac));
    status = SendARP(htonl(ip), 0UL, raw_mac, &raw_len);
    if (status != NO_ERROR || raw_len == 0UL) {
        return 0;
    }

    copy_len = (unsigned int) raw_len;
    if (copy_len > 8U) {
        copy_len = 8U;
    }

    memcpy(mac, raw_mac, copy_len);
    *mac_len = copy_len;
    return 1;
}

static int probe_icmp(HANDLE icmp_handle,
                      unsigned long ip,
                      int timeout_ms,
                      unsigned long *rtt_ms,
                      unsigned int *ttl)
{
    char send_data[16];
    unsigned char reply_buffer[sizeof(ICMP_ECHO_REPLY) + 32];
    PICMP_ECHO_REPLY reply;
    DWORD result;

    if (icmp_handle == NULL || icmp_handle == INVALID_HANDLE_VALUE) {
        return 0;
    }

    memset(send_data, 0, sizeof(send_data));
    safe_copy(send_data, sizeof(send_data), "dev-id");
    result = IcmpSendEcho(icmp_handle,
                          htonl(ip),
                          send_data,
                          (WORD) strlen(send_data),
                          NULL,
                          reply_buffer,
                          (DWORD) sizeof(reply_buffer),
                          (DWORD) timeout_ms);
    if (result == 0UL) {
        return 0;
    }

    reply = (PICMP_ECHO_REPLY) reply_buffer;
    if (reply->Status != IP_SUCCESS) {
        return 0;
    }

    if (rtt_ms != NULL) {
        *rtt_ms = reply->RoundTripTime;
    }
    if (ttl != NULL) {
        *ttl = reply->Options.Ttl;
    }
    return 1;
}

static int tcp_port_open(unsigned long ip, unsigned short port, int timeout_ms)
{
    SOCKET sock;
    struct sockaddr_in sa;
    u_long mode;
    int result;
    fd_set write_set;
    fd_set error_set;
    struct timeval timeout;
    int so_error;
    int so_len;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return 0;
    }

    mode = 1UL;
    ioctlsocket(sock, FIONBIO, &mode);

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip);
    sa.sin_port = htons(port);

    result = connect(sock, (struct sockaddr *) &sa, sizeof(sa));
    if (result == 0) {
        closesocket(sock);
        return 1;
    }

    result = WSAGetLastError();
    if (result != WSAEWOULDBLOCK && result != WSAEINPROGRESS && result != WSAEINVAL) {
        closesocket(sock);
        return 0;
    }

    FD_ZERO(&write_set);
    FD_ZERO(&error_set);
    FD_SET(sock, &write_set);
    FD_SET(sock, &error_set);
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    result = select(0, NULL, &write_set, &error_set, &timeout);
    if (result <= 0) {
        closesocket(sock);
        return 0;
    }

    so_error = 0;
    so_len = (int) sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *) &so_error, &so_len);
    closesocket(sock);
    return so_error == 0;
}

static int build_udp_probe(unsigned short port, unsigned char *payload, int *payload_len)
{
    static const unsigned char dns_query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a',
        'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm',
        0x00, 0x00, 0x01, 0x00, 0x01
    };
    int i;

    if (payload == NULL || payload_len == NULL) {
        return 0;
    }

    if (port == 53U) {
        for (i = 0; i < (int) sizeof(dns_query); ++i) {
            payload[i] = dns_query[i];
        }
        *payload_len = (int) sizeof(dns_query);
        return 1;
    }

    if (port == 123U) {
        memset(payload, 0, 48U);
        payload[0] = 0x1B;
        *payload_len = 48;
        return 1;
    }

    payload[0] = 'N';
    payload[1] = 'S';
    *payload_len = 2;
    return 1;
}

static int udp_port_responsive(unsigned long ip, unsigned short port, int timeout_ms)
{
    SOCKET sock;
    struct sockaddr_in sa;
    DWORD timeout_value;
    unsigned char payload[64];
    int payload_len;
    int send_result;
    char reply[256];
    int recv_result;
    int error_code;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        return 0;
    }

    timeout_value = (DWORD) timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout_value, sizeof(timeout_value));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *) &timeout_value, sizeof(timeout_value));

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip);
    sa.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *) &sa, sizeof(sa)) == SOCKET_ERROR) {
        closesocket(sock);
        return 0;
    }

    if (!build_udp_probe(port, payload, &payload_len)) {
        closesocket(sock);
        return 0;
    }

    send_result = send(sock, (const char *) payload, payload_len, 0);
    if (send_result == SOCKET_ERROR) {
        closesocket(sock);
        return 0;
    }

    recv_result = recv(sock, reply, sizeof(reply), 0);
    if (recv_result > 0) {
        closesocket(sock);
        return 1;
    }

    error_code = WSAGetLastError();
    closesocket(sock);
    if (error_code == WSAECONNRESET || error_code == WSAECONNREFUSED) {
        return 0;
    }

    return 0;
}

static void scan_tcp_ports(unsigned long ip,
                           const unsigned short *ports,
                           size_t port_count,
                           int timeout_ms,
                           unsigned short *open_ports,
                           size_t *open_count)
{
    size_t i;

    for (i = 0U; i < port_count; ++i) {
        if (port_exists(open_ports, *open_count, ports[i])) {
            continue;
        }
        if (tcp_port_open(ip, ports[i], timeout_ms)) {
            add_port(open_ports, open_count, MAX_PORT_COUNT, ports[i]);
        }
    }
}

static void scan_udp_ports(unsigned long ip,
                           const unsigned short *ports,
                           size_t port_count,
                           int timeout_ms,
                           unsigned short *responsive_ports,
                           size_t *responsive_count)
{
    size_t i;

    for (i = 0U; i < port_count; ++i) {
        if (port_exists(responsive_ports, *responsive_count, ports[i])) {
            continue;
        }
        if (udp_port_responsive(ip, ports[i], timeout_ms)) {
            add_port(responsive_ports, responsive_count, MAX_PORT_COUNT, ports[i]);
        }
    }
}

static void ports_to_service_text(char *buffer,
                                  size_t buffer_size,
                                  const unsigned short *ports,
                                  size_t port_count,
                                  int is_udp)
{
    size_t i;

    if (buffer == NULL || buffer_size == 0U) {
        return;
    }

    buffer[0] = '\0';
    for (i = 0U; i < port_count; ++i) {
        append_service(buffer, buffer_size, ports[i], service_name_for_port(ports[i], is_udp));
    }
    if (buffer[0] == '\0') {
        safe_copy(buffer, buffer_size, "none");
    }
}

static void classify_os(host_record_t *record)
{
    if (record->ttl >= 200U) {
        safe_copy(record->os, sizeof(record->os), "network-device-like");
    } else if (record->ttl >= 100U) {
        safe_copy(record->os, sizeof(record->os), "windows-like");
    } else if (record->ttl > 0U) {
        safe_copy(record->os, sizeof(record->os), "unix-like");
    } else if (strstr(record->tcp_services, "445/microsoft-ds") != NULL || strstr(record->tcp_services, "3389/rdp") != NULL) {
        safe_copy(record->os, sizeof(record->os), "windows-like");
    } else if (strstr(record->tcp_services, "22/ssh") != NULL) {
        safe_copy(record->os, sizeof(record->os), "unix-like");
    } else {
        safe_copy(record->os, sizeof(record->os), "unknown");
    }
}

static void classify_type(host_record_t *record)
{
    if (strstr(record->udp_services, "161/snmp") != NULL || record->ttl >= 200U) {
        safe_copy(record->type, sizeof(record->type), "network-device");
    } else if (strstr(record->tcp_services, "445/microsoft-ds") != NULL || strstr(record->tcp_services, "3389/rdp") != NULL) {
        safe_copy(record->type, sizeof(record->type), "windows-host");
    } else if (strstr(record->tcp_services, "22/ssh") != NULL) {
        safe_copy(record->type, sizeof(record->type), "unix-host");
    } else if (strstr(record->tcp_services, "80/http") != NULL || strstr(record->tcp_services, "443/https") != NULL) {
        safe_copy(record->type, sizeof(record->type), "application-service");
    } else {
        safe_copy(record->type, sizeof(record->type), "host");
    }
}

static int push_record(scan_context_t *scan, const host_record_t *record)
{
    int result;

    result = 0;
    EnterCriticalSection(&scan->records_lock);
    if (ensure_record_capacity(scan->records)) {
        scan->records->items[scan->records->count] = *record;
        ++scan->records->count;
        result = 1;
    }
    LeaveCriticalSection(&scan->records_lock);
    return result;
}

static int is_loopback_scope(const scan_scope_t *scope)
{
    return scope != NULL && scope->network == 0x7F000000UL && scope->mask == 0xFF000000UL;
}

static int scan_host(scan_context_t *scan,
                     const scan_scope_t *scope,
                     HANDLE icmp_handle,
                     unsigned long ip,
                     host_record_t *record)
{
    unsigned short open_tcp[MAX_PORT_COUNT];
    unsigned short open_udp[MAX_PORT_COUNT];
    size_t open_tcp_count;
    size_t open_udp_count;
    unsigned long rtt_ms;
    unsigned int ttl;
    int alive;

    if (scan == NULL || scope == NULL || record == NULL) {
        return 0;
    }

    memset(record, 0, sizeof(*record));
    memset(open_tcp, 0, sizeof(open_tcp));
    memset(open_udp, 0, sizeof(open_udp));
    open_tcp_count = 0U;
    open_udp_count = 0U;
    rtt_ms = 0UL;
    ttl = 0U;
    alive = 0;

    record->ip = ip;
    record->network = scope->network;
    record->mask = scope->mask;
    record->anchor_ip = scope->anchor_ip;
    record->if_index = scope->if_index;
    record->alive = 0;
    safe_copy(record->scope_name, sizeof(record->scope_name), scope->devname);
    safe_copy(record->hostname, sizeof(record->hostname), "n/a");
    safe_copy(record->vendor, sizeof(record->vendor), "unknown");
    safe_copy(record->vendor_source, sizeof(record->vendor_source), "unresolved");
    safe_copy(record->type, sizeof(record->type), "unknown");
    safe_copy(record->os, sizeof(record->os), "unknown");
    safe_copy(record->tcp_services, sizeof(record->tcp_services), "none");
    safe_copy(record->udp_services, sizeof(record->udp_services), "none");
    safe_copy(record->reachability, sizeof(record->reachability), "");
    timestamp_now(record->timestamp, sizeof(record->timestamp));

    if (resolve_mac(ip, record->mac, &record->mac_len)) {
        alive = 1;
        append_tag(record->reachability, sizeof(record->reachability), "arp");
    }

    if (probe_icmp(icmp_handle, ip, scan->options.icmp_timeout_ms, &rtt_ms, &ttl)) {
        alive = 1;
        record->rtt_ms = rtt_ms;
        record->ttl = ttl;
        append_tag(record->reachability, sizeof(record->reachability), "icmp");
    }

    scan_tcp_ports(ip, g_quick_ports, QUICK_PORT_COUNT, scan->options.tcp_timeout_ms, open_tcp, &open_tcp_count);
    if (open_tcp_count > 0U) {
        alive = 1;
        append_tag(record->reachability, sizeof(record->reachability), "tcp");
    }

    if (!alive) {
        return 0;
    }

    record->alive = 1;
    resolve_hostname(ip, record->hostname, sizeof(record->hostname));
    resolve_vendor(scan,
                   record->mac,
                   record->mac_len,
                   record->vendor,
                   sizeof(record->vendor),
                   record->vendor_source,
                   sizeof(record->vendor_source));

    scan_tcp_ports(ip,
                   scan->options.tcp_ports,
                   scan->options.tcp_port_count,
                   scan->options.tcp_timeout_ms,
                   open_tcp,
                   &open_tcp_count);
    scan_udp_ports(ip,
                   scan->options.udp_ports,
                   scan->options.udp_port_count,
                   scan->options.udp_timeout_ms,
                   open_udp,
                   &open_udp_count);

    ports_to_service_text(record->tcp_services, sizeof(record->tcp_services), open_tcp, open_tcp_count, 0);
    ports_to_service_text(record->udp_services, sizeof(record->udp_services), open_udp, open_udp_count, 1);
    classify_os(record);
    classify_type(record);

    if (record->reachability[0] == '\0') {
        safe_copy(record->reachability, sizeof(record->reachability), "detected");
    }

    return 1;
}

static DWORD WINAPI scope_thread_proc(LPVOID param)
{
    scope_thread_ctx_t *thread_ctx;
    scan_context_t *scan;
    HANDLE icmp_handle;
    unsigned long start_ip;
    unsigned long end_ip;
    unsigned long ip;
    unsigned long scanned;
    unsigned long found;
    char network_text[32];
    char mask_text[32];
    char ip_text[32];
    host_record_t record;

    thread_ctx = (scope_thread_ctx_t *) param;
    if (thread_ctx == NULL || thread_ctx->scan == NULL) {
        return 0U;
    }

    scan = thread_ctx->scan;
    icmp_handle = IcmpCreateFile();
    start_ip = thread_ctx->scope.first_host;
    end_ip = thread_ctx->scope.last_host;
    scanned = 0UL;
    found = 0UL;

    if (is_loopback_scope(&thread_ctx->scope)) {
        start_ip = thread_ctx->scope.anchor_ip;
        end_ip = thread_ctx->scope.anchor_ip;
    }

    ipv4_to_string(thread_ctx->scope.network, network_text, sizeof(network_text));
    ipv4_to_string(thread_ctx->scope.mask, mask_text, sizeof(mask_text));
    logger_write(scan,
                 "[scope:%s ifindex=%lu network=%s mask=%s] start first=%lu last=%lu",
                 thread_ctx->scope.devname,
                 thread_ctx->scope.if_index,
                 network_text,
                 mask_text,
                 start_ip,
                 end_ip);

    for (ip = start_ip; ; ++ip) {
        ++scanned;
        if (scan_host(scan, &thread_ctx->scope, icmp_handle, ip, &record)) {
            if (push_record(scan, &record)) {
                ++found;
                ipv4_to_string(record.ip, ip_text, sizeof(ip_text));
                logger_write(scan,
                             "[scope:%s ifindex=%lu] host=%s reachability=%s tcp=%s udp=%s vendor=%s",
                             record.scope_name,
                             record.if_index,
                             ip_text,
                             record.reachability,
                             record.tcp_services,
                             record.udp_services,
                             record.vendor);
            }
        }
        if (ip == end_ip || ip == 0xFFFFFFFFUL) {
            break;
        }
    }

    if (icmp_handle != NULL && icmp_handle != INVALID_HANDLE_VALUE) {
        IcmpCloseHandle(icmp_handle);
    }

    logger_write(scan,
                 "[scope:%s ifindex=%lu network=%s] completed scanned=%lu found=%lu",
                 thread_ctx->scope.devname,
                 thread_ctx->scope.if_index,
                 network_text,
                 scanned,
                 found);
    return 0U;
}

static int scopes_equal(const scan_scope_t *lhs, const scan_scope_t *rhs)
{
    return lhs->network == rhs->network &&
           lhs->mask == rhs->mask &&
           lhs->if_index == rhs->if_index &&
           strcmp(lhs->devname, rhs->devname) == 0;
}

static int build_unique_scopes(const scope_list_t *input, scan_scope_t **items_out, size_t *count_out)
{
    scan_scope_t *unique_items;
    size_t unique_count;
    size_t i;
    size_t j;
    int duplicate;

    if (input == NULL || items_out == NULL || count_out == NULL) {
        return 0;
    }

    *items_out = NULL;
    *count_out = 0U;
    if (input->count == 0U) {
        return 1;
    }

    unique_items = (scan_scope_t *) malloc(input->count * sizeof(scan_scope_t));
    if (unique_items == NULL) {
        return 0;
    }

    unique_count = 0U;
    for (i = 0U; i < input->count; ++i) {
        duplicate = 0;
        for (j = 0U; j < unique_count; ++j) {
            if (scopes_equal(&input->items[i], &unique_items[j])) {
                duplicate = 1;
                break;
            }
        }
        if (!duplicate) {
            unique_items[unique_count] = input->items[i];
            ++unique_count;
        }
    }

    *items_out = unique_items;
    *count_out = unique_count;
    return 1;
}

static int compare_records(const void *lhs, const void *rhs)
{
    const host_record_t *a;
    const host_record_t *b;

    a = (const host_record_t *) lhs;
    b = (const host_record_t *) rhs;

    if (a->network < b->network) {
        return -1;
    }
    if (a->network > b->network) {
        return 1;
    }
    if (a->ip < b->ip) {
        return -1;
    }
    if (a->ip > b->ip) {
        return 1;
    }
    if (a->if_index < b->if_index) {
        return -1;
    }
    if (a->if_index > b->if_index) {
        return 1;
    }
    return 0;
}

int collect_active_hosts(const scope_list_t *scopes,
                         const oui_db_t *oui_db,
                         const scan_options_t *options,
                         host_record_list_t *records,
                         char *errbuf,
                         size_t errbuf_size)
{
    scan_context_t scan;
    scan_scope_t *unique_scopes;
    size_t unique_scope_count;
    scope_thread_ctx_t *thread_ctxs;
    HANDLE *thread_handles;
    size_t created_threads;
    size_t i;
    WSADATA wsa_data;

    if (scopes == NULL || options == NULL || records == NULL) {
        set_error(errbuf, errbuf_size, "invalid scan arguments");
        return 0;
    }

    memset(records, 0, sizeof(*records));
    memset(&scan, 0, sizeof(scan));
    unique_scopes = NULL;
    unique_scope_count = 0U;
    thread_ctxs = NULL;
    thread_handles = NULL;
    created_threads = 0U;

    if (!build_unique_scopes(scopes, &unique_scopes, &unique_scope_count)) {
        set_error(errbuf, errbuf_size, "unable to build unique scope list");
        return 0;
    }

    if (!logger_init(&scan.logger, options->log_path)) {
        free(unique_scopes);
        set_error(errbuf, errbuf_size, "unable to open log file");
        return 0;
    }

    InitializeCriticalSection(&scan.records_lock);
    InitializeCriticalSection(&scan.vendor_lock);
    scan.local_oui = oui_db;
    scan.records = records;
    scan.options = *options;
    memset(&scan.vendor_cache, 0, sizeof(scan.vendor_cache));

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        logger_close(&scan.logger);
        DeleteCriticalSection(&scan.records_lock);
        DeleteCriticalSection(&scan.vendor_lock);
        free(unique_scopes);
        set_error(errbuf, errbuf_size, "WSAStartup failed");
        return 0;
    }

    thread_ctxs = (scope_thread_ctx_t *) calloc(unique_scope_count, sizeof(scope_thread_ctx_t));
    thread_handles = (HANDLE *) calloc(unique_scope_count, sizeof(HANDLE));
    if (thread_ctxs == NULL || thread_handles == NULL) {
        WSACleanup();
        logger_close(&scan.logger);
        DeleteCriticalSection(&scan.records_lock);
        DeleteCriticalSection(&scan.vendor_lock);
        free_oui_db(&scan.vendor_cache);
        free(thread_ctxs);
        free(thread_handles);
        free(unique_scopes);
        set_error(errbuf, errbuf_size, "out of memory while creating scope threads");
        return 0;
    }

    logger_write(&scan,
                 "scan-start scopes=%lu tcp_ports=%lu udp_ports=%lu vendor_online=%d",
                 (unsigned long) unique_scope_count,
                 (unsigned long) options->tcp_port_count,
                 (unsigned long) options->udp_port_count,
                 options->vendor_online);

    for (i = 0U; i < unique_scope_count; ++i) {
        thread_ctxs[i].scan = &scan;
        thread_ctxs[i].scope = unique_scopes[i];
        thread_handles[i] = CreateThread(NULL, 0U, scope_thread_proc, &thread_ctxs[i], 0U, NULL);
        if (thread_handles[i] == NULL) {
            break;
        }
        ++created_threads;
    }

    if (created_threads != unique_scope_count) {
        logger_write(&scan, "thread-creation-warning created=%lu expected=%lu",
                     (unsigned long) created_threads,
                     (unsigned long) unique_scope_count);
    }

    if (created_threads > 0U) {
        WaitForMultipleObjects((DWORD) created_threads, thread_handles, TRUE, INFINITE);
        for (i = 0U; i < created_threads; ++i) {
            CloseHandle(thread_handles[i]);
        }
    }

    qsort(records->items, records->count, sizeof(records->items[0]), compare_records);
    logger_write(&scan, "scan-end discovered=%lu", (unsigned long) records->count);

    free(thread_ctxs);
    free(thread_handles);
    free(unique_scopes);
    free_oui_db(&scan.vendor_cache);
    logger_close(&scan.logger);
    DeleteCriticalSection(&scan.records_lock);
    DeleteCriticalSection(&scan.vendor_lock);
    WSACleanup();
    return 1;
}

void free_host_record_list(host_record_list_t *records)
{
    if (records == NULL) {
        return;
    }

    free(records->items);
    records->items = NULL;
    records->count = 0U;
    records->capacity = 0U;
}
