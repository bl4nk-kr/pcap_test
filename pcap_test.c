#include "pcap_test.h"

void p_colon(u_char *str) {
	int i;

	for(i=0;i<6;i++) {
		printf("%02X", str[i]);
		if(i != 5) printf(":");
	}
	printf("\n");
}

void p_data(u_char *str, int len) {
	int i;
	
	if(len == 0) {
		printf("(empty)\n");
		return;
	}
	else if(len > 16)
		len = 16;

	printf("First %d bytes : ", len);
	for(i=0;i<len;i++) {
		printf("%02x", *(str+i++));
		printf("%02x ", *(str+i));
	}
	printf("    ");
	for(i=0;i<len;i++) {
		if(0x1f < *(str+i) && *(str+i) < 0x7f) printf("%c", *(str+i));
		else printf(".");
	}
	printf("\n\n");
}
