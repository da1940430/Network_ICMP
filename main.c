#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <strings.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <time.h>

#include "fill_packet.h"

int mask_zero_count(char *);
int str2bin(char *);

pid_t pid;

int main(int argc, char* argv[])
{
	char *device;
	int t;

	if(argc<5 || strcmp(argv[1], "-i") != 0 || strcmp(argv[3],"-t") != 0){
		perror("Usage: sudo ./ipscanner -i \"device\" -t \"time\"");
		exit(EXIT_FAILURE);
	}else{
		device = argv[2];
		t = atoi(argv[4]);
	}

	int sockfd;
	int on = 1;
	
	pid = getpid();
	
	if((sockfd = socket(PF_INET, SOCK_RAW , IPPROTO_ICMP)) < 0)
	{
		perror("socket");
		exit(1);
	}

	if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}
	//set time out 
	struct timeval timeout;
	if(t>=1000){
		timeout.tv_sec=t/1000;
		timeout.tv_usec=t%1000*1000;
	}else{
		timeout.tv_sec=0;
		timeout.tv_usec=t*1000;
	}

	if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval)) < 0){
		perror("setsockopt");
		exit(1);
	}

	struct ifreq req_ip, req_mask;
	strcpy(req_ip.ifr_name, device);	//put internet card device name into req
	strcpy(req_mask.ifr_name, device);	

	if(ioctl(sockfd,SIOCGIFADDR,&req_ip) == -1){	//get ip address
		perror("ioctl error!");
		exit(-1);
	}

	if(ioctl(sockfd,SIOCGIFNETMASK,&req_mask) == -1){	//get mask
		perror("ioctl error!");
		exit(-1);
	}

	struct in_addr my_ip, my_mask;
	struct sockaddr_in *addr = (struct sockaddr_in *)&(req_ip.ifr_addr);
	struct sockaddr_in *mask= (struct sockaddr_in *)&(req_mask.ifr_netmask);
	memcpy(&my_ip, &(addr->sin_addr), sizeof(my_ip));	//store local ip
	memcpy(&my_mask, &(mask->sin_addr), sizeof(my_mask));	//store local mask

	myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
	bzero(packet, PACKET_SIZE);
	//fill ip header
	memcpy(&(packet->ip_hdr.ip_src), &(addr->sin_addr),sizeof(struct in_addr));
	fill_iphdr(&(packet->ip_hdr), NULL, NULL);
	//get subnet ip address
	struct in_addr subnet;
	subnet.s_addr=my_ip.s_addr & my_mask.s_addr;	//get subnet (ip AND mask)
	subnet.s_addr =ntohl(subnet.s_addr);
	subnet.s_addr++;	//first subnet ip can't use
	//compute that how much subnet ip address
	int num_of_zero = mask_zero_count(inet_ntoa(my_mask));
	int num_of_subnet_ip = 1;
	while(num_of_zero--)
		num_of_subnet_ip*=2;	//pow(2,num_of_zero)
	num_of_subnet_ip-=2;	//first ip and last ip can't use
	//fill icmp header
	packet->icmp_hdr.un.echo.sequence=0;	//init sequence
	packet->icmp_hdr.un.echo.id=htons(((uint16_t)pid));

	/*
	 *   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
		 or use the standard socket like the one in the ARP homework
 	 *   to get the "ICMP echo response" packets 
	 *	 You should reset the timer every time before you send a packet.
	 */
	//create sendto dst struct
	struct sockaddr_in dst;
	bzero(&dst, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = IPPROTO_ICMP;
	//recv variable
	struct sockaddr sa;
	myicmp *icmp_pack=(myicmp *)malloc(PACKET_SIZE);
	socklen_t len = sizeof(sa);
	//send icmp packet
	while(num_of_subnet_ip--){
		//fill student ID and send time
		char data[50]="M083040019/";
		char send_time_str[50];
		struct timespec time_start={0, 0};
		clock_gettime(CLOCK_MONOTONIC, &time_start);
		sprintf(send_time_str, "%ld", time_start.tv_nsec);
		strcat(send_time_str, "/");
		strcat(data, send_time_str);
		strcpy(packet->data, data);		

		fill_icmphdr(&(packet->icmp_hdr));
		uint32_t dst_ip=htonl(subnet.s_addr);
		dst.sin_addr.s_addr = dst_ip;

		//check whether the dst ip is local ip or not
		char *myip_str=malloc(sizeof(in_addr_t)), *dstip_str=malloc(sizeof(in_addr_t));
		strcpy(myip_str, inet_ntoa(my_ip));
		strcpy(dstip_str, inet_ntoa(dst.sin_addr));
		if(strcmp(myip_str, dstip_str)==0){
			subnet.s_addr++;
			continue;
		}else{
			memcpy(&(packet->ip_hdr.ip_dst), &dst_ip, sizeof(struct in_addr));
			// printf("send icmp request to: ");
			// puts(inet_ntoa(dst.sin_addr));
			if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0){
				perror("sendto");
				exit(1);
			}
			subnet.s_addr++;
		}

		ssize_t bytes=recvfrom(sockfd, icmp_pack, PACKET_SIZE, 0, &sa, &len);
		if(bytes == -1){
			printf("PING %s, data size= %ld, seq = %d, timesout = %d ms, ", inet_ntoa(packet->ip_hdr.ip_dst), strlen(packet->data), ntohs(packet->icmp_hdr.un.echo.sequence), t);
			puts("Destination unreachable");
		}else if(icmp_pack->icmp_hdr.type == ICMP_ECHOREPLY){
			struct sockaddr_in *recv=(struct sockaddr_in *) &sa;
			char data[strlen(icmp_pack->data)], *tok;
			strcpy(data, icmp_pack->data);
			if(sizeof(data)!=0){
				tok=strtok(data, "/");
				tok=strtok(NULL, "/");
				long time_start = atol(tok);
				struct timespec time_end={0, 0};
				clock_gettime(CLOCK_MONOTONIC, &time_end);
				printf("PING %s, data size= %ld, seq = %d, timesout = %d ms, ", inet_ntoa(icmp_pack->ip_hdr.ip_src), strlen(icmp_pack->data), ntohs(icmp_pack->icmp_hdr.un.echo.sequence), t);
				printf("Reply from: %s, time: %lf ms\n", inet_ntoa(recv->sin_addr), (((double)time_end.tv_nsec-time_start)/1000000));
			}
		}
	}

	// pthread_join(recv_pth, NULL);
	free(packet);

	return 0;
}


int mask_zero_count(char *mask_str){
	char *token;
	int num_of_zero = 0;
	token=strtok(mask_str,".");
	do{
		num_of_zero+=str2bin(token);
		token=strtok(NULL, ".");
	}while(token!=NULL);

	return num_of_zero;
}

int str2bin(char *str){
	int num = atoi(str);
	int count = 0, mod=0, bits=8;
	while(bits--){
		mod = num % 2;
		if(mod==0)
			count++;
		num/=2;
	}
	return count;
}