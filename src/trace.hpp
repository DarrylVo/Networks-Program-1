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
	unsigned char src[6];
	unsigned char dest[6];
	unsigned char type[2];
};

typedef struct arp {
	unsigned char op[2];
	unsigned char sendermac[6];
	unsigned char senderip[4];
	unsigned char targetmac[6];
	unsigned char targetip[4];
};

void getethernet(const u_char *pktdata, ethernet *e);

int printethernet(ethernet *e);

void analyze(pcap_t *cap);



#endif /* SRC_TRACE_HPP_ */
