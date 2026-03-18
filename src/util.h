#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>

void safe_copy(char *dst, size_t dst_size, const char *src);
void trim_trailing(char *text);
void timestamp_now(char *buffer, size_t buffer_size);
void format_mac(const unsigned char *mac, unsigned int mac_len, char *buffer, size_t buffer_size);
int parse_oui_prefix(const char *text, unsigned long *prefix_out);

#endif
