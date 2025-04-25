#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/time.h>

#define BUFFER_SIZE 65536

// Global variables for performance metrics
struct timeval prev_time = {0, 0};
int total_packets = 0, tcp_count = 0, udp_count = 0, icmp_count = 0;

// Function prototypes
void process_packet(unsigned char *buffer, int size, pcap_dumper_t *dumper);
void print_ip_header(struct iphdr *ip);
void print_tcp_header(struct tcphdr *tcp);
void print_udp_header(struct udphdr *udp);
void print_icmp_header(struct icmphdr *icmp);
double calculate_jitter(struct timeval *curr_time);

int main() {
    int sock_raw;
    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);

    // Create a raw socket
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        return 1;
    }

    // Open PCAP file for writing
    pcap_t *pcap_handle = pcap_open_dead(DLT_EN10MB, BUFFER_SIZE);
    pcap_dumper_t *dumper = pcap_dump_open(pcap_handle, "capture.pcap");

    printf("Packet sniffer started...\n");

    // Capture packets in a loop
    while (1) {
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, (socklen_t *)&saddr_size);
        if (data_size < 0) {
            perror("Recvfrom Error");
            break;
        }
        process_packet(buffer, data_size, dumper);
    }

    // Cleanup
    close(sock_raw);
    free(buffer);
    pcap_dump_close(dumper);
    pcap_close(pcap_handle);

    return 0;
}

// Process captured packet
void process_packet(unsigned char *buffer, int size, pcap_dumper_t *dumper) {
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct timeval curr_time;
    gettimeofday(&curr_time, NULL);

    total_packets++;
    printf("\nPacket %d Captured\n", total_packets);

    print_ip_header(ip);

    // Process different protocols
    switch (ip->protocol) {
        case IPPROTO_TCP:
            tcp_count++;
            print_tcp_header((struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4));
            break;
        case IPPROTO_UDP:
            udp_count++;
            print_udp_header((struct udphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4));
            break;
        case IPPROTO_ICMP:
            icmp_count++;
            print_icmp_header((struct icmphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4));
            break;
        default:
            printf("Unknown Protocol\n");
    }

    // Calculate jitter
    double jitter = calculate_jitter(&curr_time);
    printf("Jitter: %.2f ms\n", jitter);

    // Write to PCAP file
    struct pcap_pkthdr header;
    header.ts.tv_sec = curr_time.tv_sec;
    header.ts.tv_usec = curr_time.tv_usec;
    header.caplen = size;
    header.len = size;
    pcap_dump((u_char *)dumper, &header, buffer);
}

// Print IP header details
void print_ip_header(struct iphdr *ip) {
    struct sockaddr_in src, dest;
    src.sin_addr.s_addr = ip->saddr;
    dest.sin_addr.s_addr = ip->daddr;

    printf("IP Header:\n");
    printf(" - Source IP: %s\n", inet_ntoa(src.sin_addr));
    printf(" - Destination IP: %s\n", inet_ntoa(dest.sin_addr));
    printf(" - TTL: %d\n", ip->ttl);
}

// Print TCP header details
void print_tcp_header(struct tcphdr *tcp) {
    printf("TCP Header:\n");
    printf(" - Source Port: %u\n", ntohs(tcp->source));
    printf(" - Destination Port: %u\n", ntohs(tcp->dest));
    printf(" - Sequence Number: %u\n", ntohl(tcp->seq));
}

// Print UDP header details
void print_udp_header(struct udphdr *udp) {
    printf("UDP Header:\n");
    printf(" - Source Port: %u\n", ntohs(udp->source));
    printf(" - Destination Port: %u\n", ntohs(udp->dest));
}

// Print ICMP header details
void print_icmp_header(struct icmphdr *icmp) {
    printf("ICMP Header:\n");
    printf(" - Type: %d\n", icmp->type);
    printf(" - Code: %d\n", icmp->code);
}

// Calculate jitter (variation in packet delay)
double calculate_jitter(struct timeval *curr_time) {
    if (prev_time.tv_sec == 0 && prev_time.tv_usec == 0) {
        prev_time = *curr_time;
        return 0;
    }

    double time_diff = (curr_time->tv_sec - prev_time.tv_sec) * 1000.0 +
                       (curr_time->tv_usec - prev_time.tv_usec) / 1000.0;
    prev_time = *curr_time;
    return time_diff;
}
