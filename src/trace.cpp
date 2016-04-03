#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include "checksum.h"
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "trace.hpp"
using namespace std;



int printethernet(ethernet *eheader) {
	int type;

	type = eheader->type[0]+eheader->type[1];
	cout<< "\tEthernet Header"<<endl;
	printf("\t\tDest MAC: %s\n",ether_ntoa(&eheader->dest));
	printf("\t\tSource MAC: %s\n",ether_ntoa(&eheader->src));
	switch (type) {
		case ARP_TYPE: 	printf("\t\tType: ARP\n\n");
		return ARP_TYPE;
		break;
	}
	return -1;
}

void printarp(arp *aheader) {
	printf("\tARP header\n");
	if( aheader->op[1]==2)
		printf("\t\tOpcode: Reply\n");
	else
		printf("\t\tOpcode: Request\n");
	printf("\t\tSender MAC: %s\n",ether_ntoa(&aheader->sendermac));
	printf("\t\tSender IP: %s\n",inet_ntoa(aheader->senderip));
	printf("\t\tTarget MAC: %s\n",ether_ntoa(&aheader->targetmac));
	printf("\t\tTarget IP: %s\n",inet_ntoa(aheader->targetip));

}

void getarp(const u_char *pktdata, arp *aheader ) {
	memcpy(aheader->op,pktdata+20,2);
	memcpy(aheader->sendermac.ether_addr_octet,pktdata+22,6);
	memcpy(&(aheader->senderip.s_addr),pktdata+28,4);
	memcpy(aheader->targetmac.ether_addr_octet,pktdata+32,6);
	memcpy(&(aheader->targetip),pktdata+38,4);

}

void getethernet(const u_char *pktdata, ethernet *eheader) {
	memcpy(eheader->dest.ether_addr_octet,pktdata,6);
	memcpy(eheader->src.ether_addr_octet,pktdata+6,6);
	memcpy(eheader->type,pktdata+12,2);
}

void analyze(pcap_t *cap) {
	pcap_pkthdr *genericheader;
	const u_char *pktdata;
	ethernet eheader;
	arp aheader;
	int i = 1;
	int type;

	//while there are packets left, extract data and print
	while(pcap_next_ex(cap,&genericheader, &pktdata )==1) {
		printf("\nPacket number: %d  Packet Len: %d\n\n",i++,genericheader->len);
		getethernet(pktdata,&eheader);
		type = printethernet(&eheader);
		switch(type) {
			case ARP_TYPE:
				getarp(pktdata,&aheader);
				printarp(&aheader);
			break;
		}
	}


}

int main(int argc, char **argv) {
	pcap_t *cap;
	char errbuff[PCAP_ERRBUF_SIZE];

	//check arg number
	if(argc!=2) {
		cerr<< "error, please give one argument for the .pcap file " <<endl;
		return -1;
	}

	//open pcap file
	cap = pcap_open_offline(argv[1],errbuff);
	if(cap == NULL) {
		cerr<<errbuff <<endl;
		return -1;
	}
	analyze(cap);
	pcap_close(cap);

	return 0;
}
