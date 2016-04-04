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
		case ARP_TYPE:
			printf("\t\tType: ARP\n\n");
			return ARP_TYPE;
			break;
		case IP_TYPE :
			printf("\t\tType: IP\n\n");
			return IP_TYPE;
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
	memcpy(&(aheader->targetip.s_addr),pktdata+38,4);

}

void getethernet(const u_char *pktdata, ethernet *eheader) {
	memcpy(eheader->dest.ether_addr_octet,pktdata,6);
	memcpy(eheader->src.ether_addr_octet,pktdata+6,6);
	memcpy(eheader->type,pktdata+12,2);
}

void getip(const u_char *pktdata, ip *iheader) {
	memcpy(&iheader->version,pktdata+14,1);
	iheader->version = iheader->version >> 4;
	memcpy(&iheader->hlen,pktdata+14,1);
	iheader->hlen = iheader->hlen & 0x0F;
	memcpy(&iheader->dserv,pktdata+15,1);
	iheader->dserv = iheader->dserv>> 2;
	memcpy(&iheader->ecn,pktdata+15,1);
	iheader->ecn = iheader->ecn & 0x3;
	memcpy(&iheader->ttl,pktdata+22,1);
	memcpy(&iheader->prot,pktdata+23,1);
	memcpy(&iheader->destip.s_addr,pktdata+30,4);
	memcpy(&iheader->srcip.s_addr,pktdata+26,4);
	memcpy(iheader->checksum,pktdata+24,2);
}

int check_ipchecksum(const u_char *pktdata) {
	unsigned short data[10];
	unsigned short *temp = data;
	for(int i = 0; i < 10; i ++) {

			memcpy(temp++,pktdata+14+i*2,2);
			data[i] = ntohs(data[i]);
			//printf("moving:%x\n",data[i]);

	}

	return !in_cksum(data,20);
}

int printip(ip *iheader, const u_char *pktdata) {
	printf("\tIP Header\n");
	printf("\t\tIP Version: %d\n",iheader->version);
	printf("\t\tHeader Len (bytes) : %d\n",iheader->hlen*4);
	printf("\t\tTOS subfields:\n");
	printf("\t\t\tDiffserv bits: %d\n",iheader->dserv);
	printf("\t\t\tECN bits: %d\n",iheader->ecn);
	printf("\t\tTTL: %d\n",iheader->ttl);
	switch(iheader->prot) {
		case ICMP_TYPE:
			printf("\t\tProtocol: ICMP\n");
			break;
		default:
			printf("\t\tProtocol: Unknown\n");
			break;
	}

	if(check_ipchecksum(pktdata))
		printf("\t\tChecksum: Correct (0x%02x%02x)\n",iheader->checksum[0],iheader->checksum[1]);
	else
		printf("\t\tChecksum: Incorrect (0x%02x%02x)\n",iheader->checksum[0],iheader->checksum[1]);
	printf("\t\tSender IP: %s\n",inet_ntoa(iheader->srcip));
	printf("\t\tDest IP: %s\n",inet_ntoa(iheader->destip));
	return iheader->prot;
}

void printicmp(const u_char *pktdata,unsigned char ihlen) {
	printf("\tICMP Header\n");
	unsigned char pro;
	memcpy(&pro,pktdata+14+ihlen*4,1);
	if(pro == 0x08) {

		printf("\t\tType: Request\n");
	}
	else if(pro == 0)
		printf("\t\tType: Reply\n");
	else
		printf("\t\tType: %d\n",pro);

}

void printtcp(tcp *tcpheader) {
	printf("\tTCP Header\n");
	printf("\t\tSource Port: %hu\n",tcpheader->srcport);
	printf("\t\tDest Port: %hu\n",tcpheader->destport);
	printf("\t\tSequence Number: %d\n",tcpheader->seq);
	printf("\t\tACK Number: %d\n",tcpheader->ack);
	printf("\t\tData Offset (bytes) : %d",tcpheader->offset);
}

void gettcp(const u_char *pktdata, tcp *tcpheader, unsigned char ihlen) {
	ihlen*=4;
	memcpy(&tcpheader->srcport,pktdata+ihlen+14,2);
	tcpheader->srcport = ntohs(tcpheader->srcport);
	memcpy(&tcpheader->destport,pktdata+ihlen+16,2);
	tcpheader->destport = ntohs(tcpheader->destport);
	memcpy(&tcpheader->seq,pktdata+ihlen+18,4);
	tcpheader->seq = ntohl(tcpheader->seq);
	memcpy(&tcpheader->ack,pktdata+ihlen+22,4);
	tcpheader->ack = ntohl(tcpheader->ack);
	memcpy(&tcpheader->offset,pktdata+ihlen+26,1);
	tcpheader->offset = tcpheader->offset >>4;
	tcpheader->offset = tcpheader->offset>>2 | ((tcpheader->offset << 2)&0xc);

}

void analyze(pcap_t *cap) {
	pcap_pkthdr *genericheader;
	const u_char *pktdata;
	ethernet eheader;
	arp aheader;
	ip iheader;
	tcp tcpheader;
	int i = 1;
	int type;
	int iptype;

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
			case IP_TYPE:
				getip(pktdata,&iheader);
				iptype = printip(&iheader, pktdata);
				switch(iptype) {
					case ICMP_TYPE:
						printicmp(pktdata,iheader.hlen);
						break;
					case TCP_TYPE:
						gettcp(pktdata, &tcpheader,iheader.hlen);
						printtcp(&tcpheader);
						break;
				}
				break;
		}
		break;

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
