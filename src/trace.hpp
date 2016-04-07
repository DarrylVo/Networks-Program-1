/*
 * trace.hpp
 *
 *  Created on: Apr 1, 2016
 *      Author: darryl
 */

#ifndef SRC_TRACE_HPP_
#define SRC_TRACE_HPP_



#define ARP_TYPE 0xe
#define IP_TYPE 0x8
#define ICMP_TYPE 0x1
#define TCP_TYPE 0x6
#define HTTP_TYPE 80
#define UDP_TYPE 0x11
#define DNS_TYPE 53

struct ethernet {
	ether_addr src;
	ether_addr dest;
	unsigned char type[2];
};

struct arp {
	unsigned char op[2];
	ether_addr sendermac;
	in_addr senderip;
	ether_addr targetmac;
	in_addr targetip;
};

struct ip {
	unsigned char version;
	unsigned char hlen;
	unsigned char dserv;
	unsigned char ecn;
	unsigned char ttl;
	unsigned char prot;
	unsigned char checksum[2];
	in_addr srcip;
	in_addr destip;
};

struct tcp {
	unsigned short srcport;
	unsigned short destport;
	unsigned int seq;
	unsigned int ack;
	unsigned char offset;
	unsigned char synf;
	unsigned char rstf;
	unsigned char finf;
	unsigned char ackf;
	unsigned short window;
	unsigned char checksum[2];
};

struct udp {
	unsigned short srcport;
	unsigned short destport;
};




void getethernet(const u_char *pktdata, ethernet *e);

int printethernet(ethernet *eheader);

void getarp(const u_char *pktdata, arp *aheader );

void printarp(arp *aheader);

void getip(const u_char *pktdata, ip *iheader);

int check_ipchecksum(const u_char *pktdata);

int printip(ip *iheader, const u_char *pktdata);

void printicmp(const u_char *pktdata,unsigned char ihlen);

void gettcp(const u_char *pktdata, tcp *tcpheader, unsigned char ihlen);

void printtcp(tcp *tcpheader);

void check_tcpheader(const u_char *pktdata, ip *ipheader, unsigned short packsize);

void analyze(pcap_t *cap);

void getudp(const u_char *pktdata,udp *udpheader);

void printudp(udp *udpheader);



#endif /* SRC_TRACE_HPP_ */
