#include "sniffer.h"

pcap_t *handle;

int main(int argc, char *argv[])
{
    int c;										/* for getopt */
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    num_packets = 0;

    bpf_u_int32 netp, maskp;					/* IP, netmask of our device */

    char *interface = NULL;						/* device to sniff on */
    char *filter_expr = NULL;					/* filter expression */

    while((c = getopt(argc, argv, "i:f:")) > 0)
        switch(c) {
        case 'i':
            interface = optarg;
            break;
        case 'f':
            filter_expr = optarg;
            break;
        default:
            return 1;
        }

    if (optind < argc) {
        fprintf(stderr, "non-option argument: %s\n", argv[optind]);
    }

    if (interface == NULL) {					  /* interface not specified */
        if ((interface = pcap_lookupdev(errbuf)) == NULL) {
            fprintf(stderr, "couldnt find default device: %s\n", errbuf);
            return 1;
        }
    }

    if (pcap_lookupnet(interface, &netp, &maskp, errbuf) < 0) {
        fprintf(stderr, "couldn't lookup netmask: %s\n", errbuf);
        return 1;
    }

    if ((handle = pcap_open_live(interface, BUFSIZ, 1, 0, errbuf)) == NULL) {
        fprintf(stderr, "couldn't open device %s for sniffing: %s\n", interface, errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_expr, 0, netp) < 0) {
        fprintf(stderr, "couldn't compile expression %s: %s\n", filter_expr, pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "couldn't apply expression %s: %s", filter_expr, pcap_geterr(handle));
        return 1;
    }

    signal(SIGINT, sig_handler);				/* let user stop */

    printf("listening on %s filter expression = \"%s\"\n", interface, filter_expr == NULL ? "(none)": filter_expr);

    pcap_loop(handle, -1, pr_pack, NULL);
    /* NOT REACHED */
}

void sig_handler(int c)
{
    printf("\n%d packets sniffed\n", num_packets);
    pcap_close(handle);
    exit(0);
}
