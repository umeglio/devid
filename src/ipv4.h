#ifndef IPV4_H
#define IPV4_H

#include <stddef.h>

int ipv4_from_string(const char *text, unsigned long *out);
void ipv4_to_string(unsigned long ip, char *buffer, size_t buffer_size);
unsigned long ipv4_network(unsigned long ip, unsigned long mask);
unsigned long ipv4_broadcast(unsigned long ip, unsigned long mask);
int ipv4_in_subnet(unsigned long ip, unsigned long network, unsigned long mask);

#endif
