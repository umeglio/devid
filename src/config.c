#include "config.h"
#include "ipv4.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ensure_scope_capacity(scope_list_t *list)
{
    scan_scope_t *new_items;
    size_t new_capacity;

    if (list->count < list->capacity) {
        return 1;
    }

    new_capacity = (list->capacity == 0U) ? 8U : (list->capacity * 2U);
    new_items = (scan_scope_t *) realloc(list->items, new_capacity * sizeof(scan_scope_t));
    if (new_items == NULL) {
        return 0;
    }

    list->items = new_items;
    list->capacity = new_capacity;
    return 1;
}

static void set_error(char *errbuf, size_t errbuf_size, const char *message, unsigned long line_number)
{
    char line_text[32];

    if (errbuf == NULL || errbuf_size == 0U) {
        return;
    }

    if (line_number == 0UL) {
        safe_copy(errbuf, errbuf_size, message);
        return;
    }

    snprintf(line_text, sizeof(line_text), "line %lu", line_number);
    snprintf(errbuf, errbuf_size, "%s (%s)", message, line_text);
}

static int read_token_until(const char **cursor, char *buffer, size_t buffer_size, const char *delimiter)
{
    const char *start;
    const char *found;
    size_t length;

    if (cursor == NULL || *cursor == NULL || buffer == NULL || delimiter == NULL) {
        return 0;
    }

    start = *cursor;
    found = strstr(start, delimiter);
    if (found == NULL) {
        return 0;
    }

    length = (size_t) (found - start);
    if (length >= buffer_size) {
        return 0;
    }

    memcpy(buffer, start, length);
    buffer[length] = '\0';
    *cursor = found + strlen(delimiter);
    return 1;
}

static int read_token_space(const char **cursor, char *buffer, size_t buffer_size)
{
    const char *start;
    const char *end;
    size_t length;

    if (cursor == NULL || *cursor == NULL || buffer == NULL) {
        return 0;
    }

    start = *cursor;
    while (*start == ' ' || *start == '\t') {
        ++start;
    }

    end = start;
    while (*end != '\0' && *end != ' ' && *end != '\t') {
        ++end;
    }

    length = (size_t) (end - start);
    if (length == 0U || length >= buffer_size) {
        return 0;
    }

    memcpy(buffer, start, length);
    buffer[length] = '\0';
    *cursor = end;
    return 1;
}

static int parse_line(const char *line, scan_scope_t *scope, char *errbuf, size_t errbuf_size)
{
    const char *cursor;
    char anchor_text[32];
    char iface_text[32];
    char mask_text[32];
    char index_text[32];
    char dev_text[MAX_DEVNAME_LEN];

    if (line == NULL || scope == NULL) {
        safe_copy(errbuf, errbuf_size, "internal parser error");
        return 0;
    }

    memset(scope, 0, sizeof(*scope));
    safe_copy(scope->raw_line, sizeof(scope->raw_line), line);

    cursor = line;
    if (strncmp(cursor, "IP=", 3) != 0) {
        safe_copy(errbuf, errbuf_size, "expected IP= prefix");
        return 0;
    }
    cursor += 3;

    if (!read_token_until(&cursor, anchor_text, sizeof(anchor_text), "->")) {
        safe_copy(errbuf, errbuf_size, "missing anchor ip or ->");
        return 0;
    }
    if (!read_token_until(&cursor, iface_text, sizeof(iface_text), "/")) {
        safe_copy(errbuf, errbuf_size, "missing interface ip or /");
        return 0;
    }
    if (!read_token_space(&cursor, mask_text, sizeof(mask_text))) {
        safe_copy(errbuf, errbuf_size, "missing subnet mask");
        return 0;
    }

    while (*cursor == ' ' || *cursor == '\t') {
        ++cursor;
    }
    if (strncmp(cursor, "index=", 6) != 0) {
        safe_copy(errbuf, errbuf_size, "missing index=");
        return 0;
    }
    cursor += 6;
    if (!read_token_space(&cursor, index_text, sizeof(index_text))) {
        safe_copy(errbuf, errbuf_size, "invalid index field");
        return 0;
    }

    while (*cursor == ' ' || *cursor == '\t') {
        ++cursor;
    }
    if (strncmp(cursor, "devname=", 8) != 0) {
        safe_copy(errbuf, errbuf_size, "missing devname=");
        return 0;
    }
    cursor += 8;
    if (!read_token_space(&cursor, dev_text, sizeof(dev_text))) {
        safe_copy(errbuf, errbuf_size, "invalid devname field");
        return 0;
    }

    if (!ipv4_from_string(anchor_text, &scope->anchor_ip)) {
        safe_copy(errbuf, errbuf_size, "invalid anchor ip");
        return 0;
    }
    if (!ipv4_from_string(iface_text, &scope->iface_ip)) {
        safe_copy(errbuf, errbuf_size, "invalid interface ip");
        return 0;
    }
    if (!ipv4_from_string(mask_text, &scope->mask)) {
        safe_copy(errbuf, errbuf_size, "invalid subnet mask");
        return 0;
    }

    scope->if_index = strtoul(index_text, NULL, 10);
    safe_copy(scope->devname, sizeof(scope->devname), dev_text);

    scope->network = ipv4_network(scope->iface_ip, scope->mask);
    scope->broadcast = ipv4_broadcast(scope->iface_ip, scope->mask);

    if (scope->broadcast > scope->network + 1UL) {
        scope->first_host = scope->network + 1UL;
        scope->last_host = scope->broadcast - 1UL;
    } else {
        scope->first_host = scope->iface_ip;
        scope->last_host = scope->iface_ip;
    }

    return 1;
}

int load_config(const char *path, scope_list_t *list, char *errbuf, size_t errbuf_size)
{
    FILE *fp;
    char line[MAX_RAW_LINE_LEN];
    unsigned long line_number;
    scan_scope_t scope;

    if (path == NULL || list == NULL) {
        safe_copy(errbuf, errbuf_size, "invalid arguments");
        return 0;
    }

    memset(list, 0, sizeof(*list));
    fp = fopen(path, "r");
    if (fp == NULL) {
        safe_copy(errbuf, errbuf_size, "cannot open config file");
        return 0;
    }

    line_number = 0UL;
    while (fgets(line, sizeof(line), fp) != NULL) {
        ++line_number;
        trim_trailing(line);

        if (line[0] == '\0') {
            continue;
        }

        if (!parse_line(line, &scope, errbuf, errbuf_size)) {
            set_error(errbuf, errbuf_size, errbuf, line_number);
            fclose(fp);
            free_scope_list(list);
            return 0;
        }

        if (!ensure_scope_capacity(list)) {
            fclose(fp);
            free_scope_list(list);
            safe_copy(errbuf, errbuf_size, "out of memory while loading config");
            return 0;
        }

        list->items[list->count] = scope;
        ++list->count;
    }

    fclose(fp);

    if (list->count == 0U) {
        safe_copy(errbuf, errbuf_size, "config file is empty");
        return 0;
    }

    return 1;
}

void free_scope_list(scope_list_t *list)
{
    if (list == NULL) {
        return;
    }

    free(list->items);
    list->items = NULL;
    list->count = 0U;
    list->capacity = 0U;
}

const scan_scope_t *find_scope_for_ip(const scope_list_t *list, unsigned long ip, unsigned long if_index)
{
    size_t i;
    const scan_scope_t *fallback;

    if (list == NULL) {
        return NULL;
    }

    fallback = NULL;
    for (i = 0U; i < list->count; ++i) {
        if (ipv4_in_subnet(ip, list->items[i].network, list->items[i].mask)) {
            if (list->items[i].if_index == if_index) {
                return &list->items[i];
            }
            if (fallback == NULL) {
                fallback = &list->items[i];
            }
        }
    }

    return fallback;
}
