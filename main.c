#include "pcap_test.h"

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	struct ether_header *eptr;
	struct ip *iptr;
	struct tcphdr *tptr;
	const u_char *dptr;

	if(argc != 2 ) {
		printf("Usage : ./pcap_test <device>\n");
		return -1;
	}
	
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL) {
		fprintf(stderr, "Couldn't open device %s : %s \n", dev, errbuf);
		return -1;
	}

	while (1) {	/* Grab a packet */
		pcap_next_ex(handle, &header, &packet);
		eptr = (struct eptr_header *) packet;
		printf("-----------------------------------\n");
		printf("Jacked a packet with length of [%d]\n", header->len);
		printf("ether type : 0x%04x\n", ntohs(eptr->ether_type));
		printf("eth.smac : ");
		p_colon(eptr->ether_shost);
		printf("eth.dmac : ");
		p_colon(eptr->ether_dhost);
		if(eptr->ether_type == IPTYPE) {
			iptr = (struct ip *) (packet + 14);
			printf("ip protocol : %d\n", iptr->ip_p);
			printf("ip.sip : %s\n", inet_ntoa(iptr->ip_src));
			printf("ip.dip : %s\n", inet_ntoa(iptr->ip_dst));
			if(iptr->ip_p == TCPTYPE) {
				tptr = (struct tcphdr *) (packet + 14 + (iptr->ip_hl * 4));
				dptr = packet + 14 + (iptr->ip_hl * 4) + (tptr->th_off * 4);
				printf("tcp.sport : %d\n", ntohs(tptr->th_sport));
				printf("tcp.dport : %d\n", ntohs(tptr->th_dport));
				printf("data\n");
				p_data(dptr, ntohs(iptr->ip_len) - iptr->ip_hl * 4 - tptr->th_off * 4);
			}
		}
		printf("\n");
	}		/* And close the session */
	pcap_close(handle);
	return(0);
}
