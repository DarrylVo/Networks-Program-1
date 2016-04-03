/*
 * trace.hpp
 *
 *  Created on: Apr 1, 2016
 *      Author: darryl
 */

#ifndef SRC_TRACE_HPP_
#define SRC_TRACE_HPP_



#define ARP_TYPE 0xe

typedef struct ethernet {
	ether_addr src;
	ether_addr dest;
	unsigned char type[2];
};

typedef struct arp {
	unsigned char op[2];
	ether_addr sendermac;
	in_addr senderip;
	ether_addr targetmac;
	in_addr targetip;
};

void getethernet(const u_char *pktdata, ethernet *e);

int printethernet(ethernet *eheader);

void getarp(const u_char *pktdata, arp *aheader );

void printarp(arp *aheader);

void analyze(pcap_t *cap);



#endif /* SRC_TRACE_HPP_ */
