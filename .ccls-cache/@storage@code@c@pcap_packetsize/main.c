#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "packet.h"

int main(int argc, char **argv)
{
	uint32_t time;
	Filter filter;

	if (argc < 3)
	{
		if (argc > 0)
			printf("usage: %s <interface> <seconds>",argv[0]);
		else
			printf("usage: pcap_packetsize <interface> <seconds>");
		return EXIT_FAILURE;
	}
	else
	{
		time = (uint32_t)strtol(argv[2],NULL,10);
		if (errno != 0)
			time = 10;
		filter = filter_create(argv[1],time,IPv4);
		start_capture(filter);
		print_stats();
		filter_destroy(&filter);
	}
	return EXIT_SUCCESS;
}
