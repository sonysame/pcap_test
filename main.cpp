#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ethernet{
	char destination_address[6];
	char source_address[6];
	char ethernet_type[2];
};
struct ip{
	char version_IHL[1];
	char tos[1];
	char total_length[2];
	char identification[2];
	char flags_fragmentoffset[2];
	char ttl[1];
	char protocol[1];
	char headerchecksum[2];
	char source_address[4];
	char destination_address[4];
};
struct tcp{
	char source_port[2];
	char destination_port[2];
	char sequence_number[4];
	char acknowledgment_number[4];
	char header_length_reserved_codebits[2];
	char window[2];
	char checksum[2];
	char urgent[2];
};
void dump(u_char * p, int len){
	for(int i=0;i<len;i++){
		printf("%02x ",*p);
		p++;
		if((i&0x0f)==0x0f)
			printf("\n");
	}
}

void dump2(char * p, int len){
	int i;
	struct ethernet a;
	struct ethernet * a_ptr=&a;
	a_ptr=(struct ethernet *)p;
	printf("dst mac: ");
	for(i=0;i<sizeof(a.destination_address)-1;i++)printf("%02x:", (u_char)*(a_ptr->destination_address+i));
	printf("%02x\n",(u_char)*(a_ptr->destination_address+i));
	printf("src mac: ");
	for(i=0;i<sizeof(a.source_address)-1;i++)printf("%02x:",(u_char)*(a_ptr->source_address+i));
	printf("%02x\n",(u_char)*(a_ptr->source_address+i));
	if(*(a_ptr->ethernet_type)==8&&*(a_ptr->ethernet_type+1)==0){
		printf("\nipv4\n");
		struct ip b;
		struct ip * b_ptr=&b;
		b_ptr=(struct ip *)(p+sizeof(a));
		printf("dst ip: ");
		for(i=0;i<sizeof(b.destination_address)-1;i++)printf("%d.", (u_char)*(b_ptr->destination_address+i));
		printf("%d\n",(u_char)*(b_ptr->destination_address+i));
		printf("src ip: ");
		for(i=0;i<sizeof(b.source_address)-1;i++)printf("%d.",(u_char)*(b_ptr->source_address+i));
		printf("%d\n",(u_char)*(b_ptr->source_address+i));
		unsigned char m=b_ptr->version_IHL[0];
		m&=0xf;
		m*=4;
		if(*(b_ptr->protocol)==6){
			printf("\nTCP\n");
			struct tcp c;
			struct tcp * c_ptr=&c;
			c_ptr=(struct tcp *)(p+sizeof(a)+m);
			printf("src port: ");
			printf("%d\n",((u_char)*(c_ptr->source_port))*256+(u_char)*(c_ptr->source_port+1));
			printf("dst port: ");
			printf("%d\n",((u_char)*(c_ptr->destination_port))*256+(u_char)*(c_ptr->destination_port+1));
			unsigned char n=c_ptr->header_length_reserved_codebits[0];
			n=n>>4;
			n*=4;
			if(sizeof(a)+m+n!=len){
				printf("\nData:\n");
				for(i=0;i<32;i++){
					if(i+sizeof(a)+m+n==len)break;
					printf("%02x ",(u_char)*(p+sizeof(a)+m+n+i));
					if((i&0xf)==0xf)printf("\n");
				}
			}
			printf("\n=========================================================\n");
			return;
		}
		if(sizeof(a)+m!=len){
			printf("\nData:\n");
			for(i=0;i<32;i++){
				if(i+sizeof(a)+m==len)break;
            	printf("%02x ",(u_char)*(p+sizeof(a)+m+i));                 
            	if((i&0xf)==0xf)printf("\n");
        	}
		}
        printf("\n=========================================================\n");
        return;
	}
	if(sizeof(a)!=len){
		printf("\nData:\n");
		for(i=0;i<32;i++){
			if(i+sizeof(a)==len)break;
			printf("%02x ",(u_char)*(p+sizeof(a)+i));
			if((i&0xf)==0xf)printf("\n");
		}
	}
	printf("\n=========================================================\n");
	return;
}


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
 
  while (1) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n%u bytes captured\n", header->caplen);
	//dump((u_char *)packet, header->caplen);
	printf("\n\n");
	dump2((char *)packet, header->caplen);
	printf("\n");
  }

  pcap_close(handle);
  return 0;
}
