all : pcap_test

pcap_test : pcap_test.o main.o
	gcc -o pcap_test pcap_test.o main.o -lpcap

pcap_test.o : pcap_test.c pcap_test.h
	gcc -c -o pcap_test.o pcap_test.c -lpcap

main.o : main.c pcap_test.h
	gcc -c -o main.o main.c

clean :
	rm *.o pcap_test
