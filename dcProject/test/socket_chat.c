#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

#define PORT 8080
#define MAX_BUFFER 1024

// Packet analysis function
void analyze_packet(const u_char *packet, struct pcap_pkthdr *header) {
    // Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    // IP header
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    
    printf("\n--- Packet Analysis ---\n");
    printf("Packet Length: %d bytes\n", header->len);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           eth_header->ether_shost[0], eth_header->ether_shost[1],
           eth_header->ether_shost[2], eth_header->ether_shost[3],
           eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           eth_header->ether_dhost[0], eth_header->ether_dhost[1],
           eth_header->ether_dhost[2], eth_header->ether_dhost[3],
           eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    
    // IP protocol analysis
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
    printf("Protocol: ");
    switch(ip_header->ip_p) {
        case IPPROTO_TCP:
            printf("TCP\n");
            break;
        case IPPROTO_UDP:
            printf("UDP\n");
            break;
        default:
            printf("Other\n");
    }
}

// Server function
void start_server() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[MAX_BUFFER] = {0};
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Bind
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Server listening on port %d\n", PORT);
    
    // Accept connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }
    
    // Packet capture setup
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    // Open device for packet capture
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return;
    }
    
    // Open pcap file for writing
    pcap_dumper_t *dumper = pcap_dump_open(handle, "chat_packets.pcap");
    if (dumper == NULL) {
        fprintf(stderr, "Error opening pcap file\n");
        return;
    }
    
    // Chat and packet capture loop
    fd_set readfds;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(new_socket, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        int activity = select(new_socket + 1, &readfds, NULL, NULL, NULL);
        
        if (FD_ISSET(new_socket, &readfds)) {
            int valread = read(new_socket, buffer, MAX_BUFFER);
            if (valread <= 0) break;
            printf("Client: %s", buffer);
            memset(buffer, 0, MAX_BUFFER);
        }
        
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            fgets(buffer, MAX_BUFFER, stdin);
            send(new_socket, buffer, strlen(buffer), 0);
        }
        
        // Capture packets
        struct pcap_pkthdr *header;
        const u_char *packet;
        int result = pcap_next_ex(handle, &header, &packet);
        if (result > 0) {
            // Write packet to pcap file
            pcap_dump((u_char *)dumper, header, packet);
            
            // Analyze packet
            analyze_packet(packet, header);
        }
    }
    
    // Cleanup
    pcap_dump_close(dumper);
    pcap_close(handle);
    close(new_socket);
    close(server_fd);
}

// Client function
void start_client() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[MAX_BUFFER] = {0};
    
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }
    
    // Connect
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        exit(EXIT_FAILURE);
    }
    
    // Packet capture setup
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    // Open device for packet capture
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return;
    }
    
    // Open pcap file for writing
    pcap_dumper_t *dumper = pcap_dump_open(handle, "chat_packets.pcap");
    if (dumper == NULL) {
        fprintf(stderr, "Error opening pcap file\n");
        return;
    }
    
    // Chat and packet capture loop
    fd_set readfds;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        int activity = select(sock + 1, &readfds, NULL, NULL, NULL);
        
        if (FD_ISSET(sock, &readfds)) {
            int valread = read(sock, buffer, MAX_BUFFER);
            if (valread <= 0) break;
            printf("Server: %s", buffer);
            memset(buffer, 0, MAX_BUFFER);
        }
        
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            fgets(buffer, MAX_BUFFER, stdin);
            send(sock, buffer, strlen(buffer), 0);
        }
        
        // Capture packets
        struct pcap_pkthdr *header;
        const u_char *packet;
        int result = pcap_next_ex(handle, &header, &packet);
        if (result > 0) {
            // Write packet to pcap file
            pcap_dump((u_char *)dumper, header, packet);
            
            // Analyze packet
            analyze_packet(packet, header);
        }
    }
    
    // Cleanup
    pcap_dump_close(dumper);
    pcap_close(handle);
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s [server|client]\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "server") == 0) {
        start_server();
    } else if (strcmp(argv[1], "client") == 0) {
        start_client();
    } else {
        printf("Invalid argument. Use 'server' or 'client'\n");
        return 1;
    }
    
    return 0;
}