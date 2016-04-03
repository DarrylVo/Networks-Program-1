#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include "checksum.h"
#include <netinet/ether.h>
#include "trace.hpp"
using namespace std;

int printethernet(ethernet *eheader) {
	ether_addr dest;
	ether_addr src;
	int type;

	memcpy(dest.ether_addr_octet,eheader->dest,6);
	memcpy(src.ether_addr_octet,eheader->src,6);
	type = eheader->type[0]+eheader->type[1];
	cout<< "\tEthernet Header:"<<endl;
	printf("\t\tDest MAC: %s\n",ether_ntoa(&dest));
	printf("\t\tSource Mac: %s\n",ether_ntoa(&src));
	switch (type) {
		case ARP_TYPE: 	printf("\t\tType: ARP\n\n");
		return ARP_TYPE;
		break;
	}
}

void getethernet(const u_char *pktdata, ethernet *eheader) {
	memcpy(eheader->dest,pktdata,6);
	memcpy(eheader->src,pktdata+6,6);
	memcpy(eheader->type,pktdata+12,2);
}

void analyze(pcap_t *cap) {
	pcap_pkthdr *genericheader;
	const u_char *pktdata;
	ethernet eheader;
	int i = 1;
	int type;

	//while there are packets left, extract data and print
	while(pcap_next_ex(cap,&genericheader, &pktdata )==1) {
		printf("\nPacket number: %d Packet Len: %d\n\n",i++,genericheader->len);
		getethernet(pktdata,&eheader);
		type = printethernet(&eheader);
		switch(type) {
			case ARP_TYPE:

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
