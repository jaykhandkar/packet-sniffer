#ifndef SNIFFER
#define SNIFFER

#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#define SIZE_ETHHDR sizeof(struct ethhdr)
#define SIZE_IPHDR sizeof(struct iphdr)

void sig_handler(int c);
void pr_pack(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet);
void print_timestamp(struct timeval t);
void print_ip(const u_char *packet);
void print_tcp(const u_char *packet);
void print_udp(const u_char *packet);
void print_icmp(const u_char *packet);

int num_packets;

#endif
