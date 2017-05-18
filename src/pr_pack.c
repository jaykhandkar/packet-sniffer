#include "sniffer.h"

void pr_pack(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet)
{
    struct iphdr *ip = (struct iphdr *)(packet + SIZE_ETHHDR);

    ++num_packets;

    print_timestamp(hdr->ts);						/* print timestamp */
    print_ip(packet);
    switch(ip->protocol)
    {
    case IPPROTO_TCP:
        print_tcp(packet);
        break;
    case IPPROTO_UDP:
        print_udp(packet);
        break;
    case IPPROTO_ICMP:
        print_icmp(packet);
        break;
    default:
        printf("\n");
    }
}

void print_timestamp(struct timeval ts)
{
    char s[50];
    struct tm *tm_struct = localtime(&ts.tv_sec);
    strftime(s, sizeof(s), "%T", tm_struct);

    printf("%s ", s);
}

void print_ip(const u_char *packet)
{
    struct iphdr *ip = (struct iphdr *)(packet + SIZE_ETHHDR);

    printf("IP(tos 0x%x, ttl %u, id %u, off %u, proto %u, length %u)", ip->tos, ip->ttl, ntohs(ip->id),
           ntohs(ip->frag_off), ip->protocol, ntohs(ip->tot_len));
}

void print_tcp(const u_char *packet)
{
    struct iphdr *ip = (struct  iphdr *)(packet + SIZE_ETHHDR);
    struct tcphdr *tcp = (struct tcphdr *)(packet + SIZE_ETHHDR + SIZE_IPHDR);
    struct in_addr src_addr, dest_addr;

    src_addr.s_addr = ip->saddr;
    dest_addr.s_addr = ip->daddr;

    printf(" TCP ");
    printf("%s:%u  >  %s:%u:\n", inet_ntoa(src_addr), ntohs(tcp->source), inet_ntoa(dest_addr), ntohs(tcp->dest));
    printf("\tcksum 0x%x seq %u ack %u win %u\n", ntohs(tcp->check), ntohs(tcp->seq), ntohs(tcp->ack_seq), ntohs(tcp->window));
}

void print_icmp(const u_char *packet)
{
    struct iphdr *ip = (struct iphdr *)(packet + SIZE_ETHHDR);
    struct icmphdr *icmp = (struct icmphdr *)(packet + SIZE_ETHHDR + SIZE_IPHDR);
    struct in_addr src_addr, dest_addr;

    src_addr.s_addr = ip->saddr;
    dest_addr.s_addr = ip->daddr;

    printf("%s  >  %s:\n", inet_ntoa(src_addr), inet_ntoa(dest_addr));

    switch(icmp->type)
    {
    case ICMP_ECHOREPLY:
        printf("ICMP echo reply, ");
        printf("id %u, seq %u\n", ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
        break;
    case ICMP_ECHO:
        printf("ICMP echo request, ");
        printf("id %u, seq %u\n", ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
        break;
    default:
        printf("\n");
    }
}

void print_udp(const u_char *packet)
{
    struct iphdr *ip = (struct iphdr *)(packet + SIZE_ETHHDR);
    struct udphdr * udp = (struct udphdr *)(packet + SIZE_ETHHDR + SIZE_IPHDR);
    struct in_addr src_addr, dest_addr;

    src_addr.s_addr = ip->saddr;
    dest_addr.s_addr = ip->daddr;

    printf(" UDP ");
    printf("%s:%u  >  %s:%u:\n", inet_ntoa(src_addr), ntohs(udp->source), inet_ntoa(dest_addr), ntohs(udp->dest));
    printf("\tcksum 0x%x len %u\n", ntohs(udp->check), ntohs(udp->len));
}
