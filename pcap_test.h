#include <pcap.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define IPTYPE 8
#define TCPTYPE 6

void p_colon(u_char *str);
void p_data(u_char *str, int len);
