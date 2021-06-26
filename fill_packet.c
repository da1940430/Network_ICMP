#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>


void 
fill_iphdr ( struct ip *ip_hdr , const char* dst_ip, const char* dev_name)
{
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;      //unit is "4 bytes"
    ip_hdr->ip_tos = 0x00;
    ip_hdr->ip_len = htons(PACKET_SIZE);
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = 1;
    ip_hdr->ip_p = IPPROTO_ICMP;
}

void
fill_icmphdr (struct icmphdr *icmp_hdr)
{
    icmp_hdr->type=ICMP_ECHO;   //echo request
    icmp_hdr->un.echo.id=htons(0x256);
    int seq = ntohs(icmp_hdr->un.echo.sequence);
    seq++;
    icmp_hdr->un.echo.sequence = htons(seq);   //sequence add 1
    icmp_hdr->checksum=0;
    icmp_hdr->checksum=fill_cksum(((unsigned short *)icmp_hdr), ICMP_PACKET_SIZE);
}

u16
fill_cksum(unsigned short *buf, int bufsz)
{
    unsigned long sum = 0xffff;

    while(bufsz > 1){
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if(bufsz == 1)
        sum += *(unsigned char*)buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;

}