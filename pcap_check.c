#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
            
            uint16_t src_port = ntohs(tcp_header->th_sport);
            uint16_t dst_port = ntohs(tcp_header->th_dport);
            int tcp_data_length = pkthdr->len - (sizeof(struct ether_header) + ip_header->ip_hl * 4 + tcp_header->th_off * 4);

            printf("Ethernet Header\n");
            printf("  Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
            printf("  Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));
            printf("IP Header\n");
            printf("  Source IP: %s\n", src_ip);
            printf("  Destination IP: %s\n", dst_ip);
            printf("TCP Header\n");
            printf("  Source Port: %u\n", src_port);
            printf("  Destination Port: %u\n", dst_port);
            printf("TCP Data\n");
            for (int i = 0; i < tcp_data_length; i++) {
                printf("%c", packet[sizeof(struct ether_header) + ip_header->ip_hl * 4 + tcp_header->th_off * 4 + i]);
            }
            printf("\n\n");
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter expression\n");
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        return 1;
    }
    
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
