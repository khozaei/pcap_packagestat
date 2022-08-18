#include "packet.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"
#define ETHER_HDRLEN 14

enum protocol
{
	TCP,
	UDP,
	OTHER
};

typedef enum protocol Protocol;

struct filter
{
	IpVersion ip_ver;
	uint32_t filter_time;
	char interface[64];
};

struct packet
{
	struct in_addr ip_src;
	struct in_addr ip_dst;
	Protocol protocol;
	uint32_t count;
	uint32_t size;
};

pcap_t *__pcap_handler;
struct packet *packet_array = NULL;

void packet_received(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void timeout_handler(int sig);
void append_packet(struct packet packet);
const char *proto_str(Protocol);
const char *human_readable(uint32_t bytes);

Filter filter_create(char *interface, uint32_t seconds, IpVersion ip_ver)
{
	struct ifaddrs *addrs,*tmp;
	struct filter *filter;
	bool find;

	filter = malloc(sizeof(struct filter));
	filter->ip_ver = ip_ver;
	filter->filter_time = seconds;
	find = false;
	getifaddrs(&addrs);
	tmp = addrs;

	while (tmp)
	{
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
		{
			if (strncmp(interface,tmp->ifa_name,64) == 0)
			{
				strncpy(filter->interface,interface,64);
				find = true;
				break;
			}
		}

		tmp = tmp->ifa_next;
	}
	freeifaddrs(addrs);
	if (find)
		return filter;
	return NULL;
}

void filter_destroy(Filter *filter)
{
	if (*filter)
	{
		free((*filter));
	}
}

void start_capture(Filter filter)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 subnet;
	bpf_u_int32 ip;
	u_char args[16];
	
	snprintf((char *)args,16,"pcap_packetsize");
	if (filter)
	{
		if (filter->ip_ver == IPv4)
			pcap_lookupnet(filter->interface,&ip,&subnet,errbuf);
		else
		{
			//not implemented yet
		}
		__pcap_handler = pcap_open_live(filter->interface,BUFSIZ,0,filter->filter_time,errbuf);
		if (!__pcap_handler)
		{
			printf("pcap_open_live(): %s\n",errbuf); 
			return;
		}
		alarm(filter->filter_time);
		signal(SIGALRM,timeout_handler);
		pcap_loop(__pcap_handler,-1,packet_received,args);
	}
}

void packet_received(u_char *user, const struct pcap_pkthdr *packet, const u_char *bytes)
{
	struct ether_header *ether;
	u_short ether_type;
	u_char protocol;
	u_char ip_ver;
	struct packet local_packet;
	struct in_addr *ip;
	char ip_src_str[16];
	char ip_dst_str[16];

	if (packet->caplen < ETHER_HDRLEN)
	{
		printf("Packet length less than ethernet header length\n");
		return;
	}
	ether = (struct ether_header*)bytes;
	ether_type = ntohs(ether->ether_type);
	if (ether_type == ETHERTYPE_IP)
	{
		ip_ver = (((*(bytes + sizeof(struct ether_header))) & 0xf0) >> 4);
		if (ip_ver != 4)
			return;//only IPv4
		local_packet.size = packet->len;
		protocol = *(bytes + sizeof(struct ether_header) + 9);
		if (protocol == IPPROTO_TCP)
		{
			local_packet.protocol = TCP;
		}
		else if (protocol == IPPROTO_UDP)
		{
			local_packet.protocol = UDP;
		}
		else
		{
			local_packet.protocol = OTHER;
			return;//only UDP & TCP
		}
		ip = malloc(sizeof(struct in_addr));
		memset(ip,0,sizeof(struct in_addr));
		memcpy(ip,(bytes + sizeof(struct ether_header) + 12),sizeof(struct in_addr));
		if (ip)
			memcpy(&local_packet.ip_src,ip,sizeof(struct in_addr));
		memset(ip,0,sizeof(struct in_addr));
		memcpy(ip,(bytes + sizeof(struct ether_header) + 12 + sizeof(struct in_addr)),sizeof(struct in_addr));
		if (ip)
			memcpy(&local_packet.ip_dst,ip,sizeof(struct in_addr));
		memcpy(&local_packet.ip_dst,ip,sizeof(struct in_addr));
		free(ip);
		strncpy(ip_src_str,inet_ntoa(local_packet.ip_src),16);
		strncpy(ip_dst_str,inet_ntoa(local_packet.ip_dst),16);
		append_packet(local_packet);
	}
}

void timeout_handler(int sig)
{
	UNUSED(sig)
	if (__pcap_handler)
	{
		pcap_breakloop(__pcap_handler);
		pcap_close(__pcap_handler);
	}
}

void append_packet(struct packet packet)
{
	for (int i = 0; i < arrlenu(packet_array); i++)
	{
		if (packet_array[i].ip_src.s_addr == packet.ip_src.s_addr &&
			packet_array[i].ip_dst.s_addr == packet.ip_dst.s_addr &&
			packet_array[i].protocol == packet.protocol)
		{
				packet_array[i].count++;
				packet_array[i].size += packet.size;
				return;
		}
	}
	packet.count = 1;
	arrput(packet_array,packet);
}

const char *proto_str(Protocol p)
{
	static const char *enum_str[] = {"TCP","UDP","OTHER",};
	
	if (p >= 0 && p < 3)
		return enum_str[p];
	return "";
}

void print_stats()
{
	char ip_dst_str[16];
	char ip_src_str[16];

	printf("%-15s\t\t%-15s\t\tprotocol\tpacket_count\tpacket_size\n","ip_src","ip_dst");
	for (int i = 0; i < arrlenu(packet_array); i++)
	{
		strncpy(ip_src_str,inet_ntoa(packet_array[i].ip_src),16);
		strncpy(ip_dst_str,inet_ntoa(packet_array[i].ip_dst),16);
		printf("%-15s\t\t%-15s\t\t%s\t\t%u\t\t%u(%s)\n",ip_src_str
			,ip_dst_str,proto_str(packet_array[i].protocol)
		    ,packet_array[i].count,packet_array[i].size
			,human_readable(packet_array[i].size));
	}

}

const char *human_readable(uint32_t bytes)
{
	static char output[200];
	double double_bytes;
	uint8_t index;
	const char *suffix[] = {"B","KB","MB","GB",};

	double_bytes = bytes;
	index = 0;
	if (bytes > 1024)
	{
		for (index = 0; (bytes / 1024 > 0) && (index < 4); index++)
		{
			double_bytes = bytes / 1024.0;
			bytes /= 1024;
		}
	}
	snprintf(output,200,"%.02lf%s",double_bytes,suffix[index]);
	return output;
}
