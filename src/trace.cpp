#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include "checksum.h"
#include "trace.hpp"
using namespace std;

void printethernet(ethernet *eheader) {
	cout<< "\tEthernet Header:"<<endl;
	printf("\t\tDestination MAC: ");
	for(int i = 0; i < 5; i ++) {
		printf("%x:",*(eheader->dest+i));
	}
	printf("%x\n",*(eheader->dest+5));
	printf("")
	cout <<"/t/tType:"<<endl;
}

void getethernet(const u_char *pktdata, ethernet *eheader) {
	memcpy(eheader->dest,pktdata,6);

}


int main(int argc, char **argv) {
	if(argc!=2) {
		cerr<< "error, please give one argument for the .pcap file " <<endl;
		return -1;
	}
	pcap_t *cap;
	char errbuff[PCAP_ERRBUF_SIZE];



	cap = pcap_open_offline(argv[1],errbuff);
	if(cap == NULL)
		cerr<<errbuff <<endl;

	pcap_pkthdr *genericheader;
	const u_char *pktdata;
	ethernet eheader;

	int err = pcap_next_ex(cap,&genericheader, &pktdata );

	getethernet(pktdata,&eheader);
	printethernet(&eheader);




	pcap_close(cap);


	return 0;
}
