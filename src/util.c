#include "util.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

void safe_copy(char *dst, size_t dst_size, const char *src)
{
    size_t len;

    if (dst == NULL || dst_size == 0U) {
        return;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    len = strlen(src);
    if (len >= dst_size) {
        len = dst_size - 1U;
    }

    memcpy(dst, src, len);
    dst[len] = '\0';
}

void trim_trailing(char *text)
{
    size_t len;

    if (text == NULL) {
        return;
    }

    len = strlen(text);
    while (len > 0U) {
        if (text[len - 1U] == '\r' || text[len - 1U] == '\n' ||
            text[len - 1U] == ' ' || text[len - 1U] == '\t') {
            text[len - 1U] = '\0';
            --len;
        } else {
            break;
        }
    }
}

void timestamp_now(char *buffer, size_t buffer_size)
{
    time_t now;
    struct tm *info;

    if (buffer == NULL || buffer_size == 0U) {
        return;
    }

    now = time(NULL);
    info = localtime(&now);
    if (info == NULL) {
        safe_copy(buffer, buffer_size, "unknown");
        return;
    }

    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", info);
}

void format_mac(const unsigned char *mac, unsigned int mac_len, char *buffer, size_t buffer_size)
{
    unsigned int i;
    size_t offset;
    int written;

    if (buffer == NULL || buffer_size == 0U) {
        return;
    }

    if (mac == NULL || mac_len == 0U) {
        safe_copy(buffer, buffer_size, "n/a");
        return;
    }

    buffer[0] = '\0';
    offset = 0U;

    for (i = 0U; i < mac_len; ++i) {
        written = snprintf(buffer + offset, buffer_size - offset,
                           (i == 0U) ? "%02X" : ":%02X", mac[i]);
        if (written < 0) {
            safe_copy(buffer, buffer_size, "n/a");
            return;
        }
        if ((size_t) written >= buffer_size - offset) {
            break;
        }
        offset += (size_t) written;
    }
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return (int) (c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (int) (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (int) (c - 'A');
    }
    return -1;
}

int parse_oui_prefix(const char *text, unsigned long *prefix_out)
{
    unsigned long result;
    int nibble_count;
    int value;

    if (text == NULL || prefix_out == NULL) {
        return 0;
    }

    result = 0UL;
    nibble_count = 0;

    while (*text != '\0' && nibble_count < 6) {
        if (*text == ':' || *text == '-' || *text == ' ' || *text == '\t') {
            ++text;
            continue;
        }

        value = hex_value(*text);
        if (value < 0) {
            return 0;
        }

        result = (result << 4) | (unsigned long) value;
        ++nibble_count;
        ++text;
    }

    if (nibble_count != 6) {
        return 0;
    }

    *prefix_out = result;
    return 1;
}
