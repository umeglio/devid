#include "ipv4.h"

#include <winsock2.h>
#include <ws2tcpip.h>

int ipv4_from_string(const char *text, unsigned long *out)
{
    struct in_addr addr;

    if (text == NULL || out == NULL) {
        return 0;
    }

    if (InetPtonA(AF_INET, text, &addr) != 1) {
        return 0;
    }

    *out = ntohl(addr.s_addr);
    return 1;
}

void ipv4_to_string(unsigned long ip, char *buffer, size_t buffer_size)
{
    struct in_addr addr;
    const char *result;

    if (buffer == NULL || buffer_size == 0U) {
        return;
    }

    addr.s_addr = htonl(ip);
    result = InetNtopA(AF_INET, &addr, buffer, (DWORD) buffer_size);
    if (result == NULL && buffer_size > 0U) {
        buffer[0] = '\0';
    }
}

unsigned long ipv4_network(unsigned long ip, unsigned long mask)
{
    return ip & mask;
}

unsigned long ipv4_broadcast(unsigned long ip, unsigned long mask)
{
    return (ip & mask) | (~mask);
}

int ipv4_in_subnet(unsigned long ip, unsigned long network, unsigned long mask)
{
    return (ip & mask) == (network & mask);
}
