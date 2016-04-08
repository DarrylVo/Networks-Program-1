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
	unsigned short ipheader[10];
	unsigned short *temp = ipheader;
	for(int i = 0; i < 10; i ++) {
		memcpy(temp++,pktdata+14+i*2,2);
		ipheader[i] = ntohs(ipheader[i]);
	}
	return !in_cksum(ipheader,20);
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
		case TCP_TYPE:
			printf("\t\tProtocol: TCP\n");
			break;

		case UDP_TYPE:
			printf("\t\tProtocol: UDP\n");
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
	printf("\t\tDest IP: %s\n\n",inet_ntoa(iheader->destip));
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
	switch(tcpheader->srcport) {
		case HTTP_TYPE:
			printf("\t\tSource Port: HTTP\n");
			break;
		default:
			printf("\t\tSource Port: %hu\n",tcpheader->srcport);
			break;
	}

	switch (tcpheader->destport) {
		case HTTP_TYPE:
			printf("\t\tDest Port: HTTP\n");
			break;
		default:
			printf("\t\tDest Port: %hu\n",tcpheader->destport);
			break;
	}
	printf("\t\tSequence Number: %u\n",tcpheader->seq);
	printf("\t\tACK Number: %u\n",tcpheader->ack);
	printf("\t\tData Offset (bytes) : %d\n",tcpheader->offset*4);
	if(tcpheader->synf)
		printf("\t\tSYN Flag: Yes\n");
	else
		printf("\t\tSYN Flag: No\n");

	if(tcpheader->rstf)
		printf("\t\tRST Flag: Yes\n");
	else
		printf("\t\tRST Flag: No\n");
	if(tcpheader->finf)
		printf("\t\tFIN Flag: Yes\n");
	else
		printf("\t\tFIN Flag: No\n");
	if(tcpheader->ackf)
		printf("\t\tACK Flag: Yes\n");
	else
		printf("\t\tACK Flag: No\n");
	printf("\t\tWindow Size: %hu\n",tcpheader->window);

}

void check_tcpheader(const u_char *pktdata, ip *ipheader,tcp *tcpheader, unsigned short packsize) {
	unsigned short ip_total;
	memcpy(&ip_total,pktdata+16,2);
	ip_total = ntohs(ip_total);

	unsigned short tcp_payload_size = ip_total - ipheader->hlen*4 - tcpheader->offset*4;

	unsigned short tcp_total_size = tcp_payload_size+tcpheader->offset*4;

	unsigned short header_buff[(tcp_total_size+12)/2];

	unsigned short cons = 6;
	cons = htons(cons);
	unsigned short n_total = htons(tcp_total_size);

	memcpy(header_buff,&ipheader->srcip,4);
	memcpy(header_buff+2,&ipheader->destip,4);
	memcpy(header_buff+4,&cons,2);
	memcpy(header_buff+5,&n_total,2);
	memcpy(header_buff+6,pktdata+14+ipheader->hlen*4,tcp_total_size);
	if(in_cksum( header_buff,tcp_total_size+12)==0)
		printf("\t\tChecksum: Correct (0x%02x%02x)\n",tcpheader->checksum[0],tcpheader->checksum[1]);
	else
		printf("\t\tChecksum: Incorrect (0x%02x%02x)\n",tcpheader->checksum[0],tcpheader->checksum[1]);
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
	memcpy(&tcpheader->synf,pktdata+ihlen+27,1);
	tcpheader->synf = tcpheader->synf>>1 &0x1;

	memcpy(&tcpheader->rstf,pktdata+ihlen+27,1);
	tcpheader->rstf = tcpheader->rstf>>2 &0x1;

	memcpy(&tcpheader->finf,pktdata+ihlen+27,1);
	tcpheader->finf = tcpheader->finf>>0 &0x1;

	memcpy(&tcpheader->ackf,pktdata+ihlen+27,1);
	tcpheader->ackf = tcpheader->ackf>>4 &0x1;

	memcpy(&tcpheader->window,pktdata+ihlen+28,2);
	tcpheader->window = ntohs(tcpheader->window);

	memcpy(&tcpheader->checksum,pktdata+ihlen+30,2);
}

void getudp(const u_char *pktdata, udp *udpheader, unsigned char hlen) {
	hlen*=4;
	memcpy(&udpheader->srcport,pktdata+14+hlen,2);
	udpheader->srcport = ntohs(udpheader->srcport);
	memcpy(&udpheader->destport,pktdata+14+hlen+2,2);
	udpheader->destport = ntohs(udpheader->destport);

}

void printudp(udp * udpheader) {
	printf("\tUDP Header\n");
	switch(udpheader->srcport) {
		case DNS_TYPE:
			printf("\t\tSource Port:  DNS\n");
			break;
		default:
			printf("\t\tSource Port:  %hu\n",udpheader->srcport);
			break;
	}

	switch (udpheader->destport) {
		case DNS_TYPE:
			printf("\t\tDest Port:  DNS\n");
			break;
		default:
			printf("\t\tDest Port:  %hu\n",udpheader->destport);
			break;
	}


}

void analyze(pcap_t *cap) {
	pcap_pkthdr *genericheader;
	const u_char *pktdata;
	ethernet eheader;
	arp aheader;
	ip iheader;
	tcp tcpheader;
	udp udpheader;
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
						check_tcpheader(pktdata,&iheader,&tcpheader, genericheader->len);
						break;
					case UDP_TYPE:
						getudp(pktdata, &udpheader,iheader.hlen);
						printudp(&udpheader);
				}
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
