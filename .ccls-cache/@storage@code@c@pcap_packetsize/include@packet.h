#ifndef PACKET_GUARD_H
#define PACKET_GUARD_H

#include <stdint.h>

#define UNUSED(X) (void)(X);

enum ip_version
{
	IPv4,
	IPv6,
	IP_ALL
};

typedef enum ip_version IpVersion;
typedef struct filter *Filter;

Filter filter_create(char * interface, uint32_t seconds, IpVersion ip_ver);
void filter_destroy(Filter *filter);

void start_capture(Filter filter);
void print_stats(void);

#endif
