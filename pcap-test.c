#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#define ETHERTYPE_IP 0x0800


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
        struct pcap_pkthdr* header; //timestamp, length
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet); //read
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        // add here!!!!!!!!!
        struct ether_header *ethr;
        struct ip *iphdr;
        struct tcphdr *tcph;

        ethr = (struct ether_header *)packet;
        packet += sizeof(struct ether_header); //eth+offset

        if (ntohs(ethr->ether_type) == ETHERTYPE_IP){
            iphdr = (struct ip *)packet;
            if (iphdr -> ip_p == IPPROTO_TCP){
                tcph = (struct tcphdr *)(packet + iphdr->ip_hl * 4);
                printf("%u bytes captured\n", header->caplen); //capture length

                //1. Ethernet Header의 src mac / dst mac
                printf("Src Mac : %s\n",ether_ntoa((struct ether_addr *)ethr->ether_shost));
                printf("Dst Mac : %s\n",ether_ntoa((struct ether_addr *)ethr->ether_dhost));

                //2. IP Header의 src ip / dst ip
                printf("Src IP  : %s \n",inet_ntoa(iphdr->ip_src));
                printf("Dst IP  : %s \n",inet_ntoa(iphdr->ip_dst));

                //3. TCP Header의 src port / dst port
                printf("Src Port: %d\n" , ntohs(tcph->th_sport));
                printf("Dst Port: %d\n" , ntohs(tcph->th_dport));

                //4. Payload(Data)의 hexadecimal value(최대 20바이트까지만)
                printf("TCP Payload : ");
                int length = header->len - sizeof (* ethr); // length: Total Packet Size - Ethernet Header Size

                // (IP header size + TCP header size + TCP data size)
                int i=(iphdr->ip_hl*4)+(tcph->doff*4); // i: IP header's size + TCP header's size

                if (length-i>=20) length=i+20;// length-i: TCP data size, data size is maximum 20
                if (length-i==0){
                    printf("Data size is zero.");
                    }
                else{
                    for(; i<length; i++){
                        printf("%02x ", *(packet+i));
                    }
                }
                printf("\n\n");
            }
        }
	}
	pcap_close(pcap);
}
