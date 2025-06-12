#include <stdio.h>
#include <pcap.h>
#include <string.h>

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, 
                    const unsigned char *packet);

int main(int argc, char* argv[]) {

    pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "ip";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const unsigned char *packet;		/* The actual packet */
    
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
    }
    
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open default device: %s\n", errbuf);
		return(2);
    }

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
    }

    pcap_loop(handle, 10, packet_handler, NULL);

    pcap_close(handle);
    
    return 0;

}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, 
                    const unsigned char *packet) {
    
    printf("Jacked a packet with length of [%d]\n", header->len);
}
                    