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
#include <sys/select.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <time.h>
#include <math.h>

#define PORT 8080
#define MAX_BUFFER 1024
#define MAX_CLIENTS 10
#define MAX_PACKET_HISTORY 1000

struct PacketStats {
    int total_packets;
    int tcp_packets;
    int udp_packets;
    int icmp_packets;
    int other_packets;
    
    // Jitter calculation
    struct {
        struct timeval timestamps[MAX_PACKET_HISTORY];
        int timestamp_count;
        double jitter_ms;
    } jitter_data;
    
    struct {
        uint32_t expected_sequence;
        uint32_t last_sequence;
        int total_packets_received;
        int packets_lost;
        double packet_loss_rate;
    } packet_loss;
};

struct PacketStats global_stats = {0};

// Function to calculate jitter
void calculate_jitter(struct timeval *new_timestamp) {
    struct PacketStats *stats = &global_stats;
    
    if (stats->jitter_data.timestamp_count > 0) {
        // Calculate time difference between consecutive packets
        struct timeval *last_ts = &stats->jitter_data.timestamps[stats->jitter_data.timestamp_count - 1];
        long time_diff_us = (new_timestamp->tv_sec - last_ts->tv_sec) * 1000000 + 
                            (new_timestamp->tv_usec - last_ts->tv_usec);
        
        // Update jitter calculation (using simple moving average)
        if (stats->jitter_data.timestamp_count > 1) {
            double time_diff_ms = time_diff_us / 1000.0;
            stats->jitter_data.jitter_ms = 
                (0.9 * stats->jitter_data.jitter_ms) + (0.1 * fabs(time_diff_ms));
        }
    }
    
    // Store timestamp
    if (stats->jitter_data.timestamp_count < MAX_PACKET_HISTORY) {
        stats->jitter_data.timestamps[stats->jitter_data.timestamp_count] = *new_timestamp;
        stats->jitter_data.timestamp_count++;
    } else {
        // Shift timestamps if history is full
        memmove(&stats->jitter_data.timestamps[0], 
                &stats->jitter_data.timestamps[1], 
                sizeof(struct timeval) * (MAX_PACKET_HISTORY - 1));
        stats->jitter_data.timestamps[MAX_PACKET_HISTORY - 1] = *new_timestamp;
    }
}

// Packet analysis function
void analyze_packet(const u_char *packet, struct pcap_pkthdr *header) {
    struct PacketStats *stats = &global_stats;
    
    // Increment total packet count
    stats->total_packets++;
    
    // Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    // IP header
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    
    // Analyze protocol
    switch(ip_header->ip_p) {
        case IPPROTO_TCP:
            stats->tcp_packets++;
            break;
        case IPPROTO_UDP:
            stats->udp_packets++;
            break;
        case IPPROTO_ICMP:
            stats->icmp_packets++;
            break;
        default:
            stats->other_packets++;
    }
    
    // Packet loss estimation (simulated with sequence number)
    // Note: Real sequence number tracking would require protocol-specific parsing
    stats->packet_loss.total_packets_received++;
    if (stats->packet_loss.total_packets_received > 1) {
        if (stats->packet_loss.last_sequence + 1 != stats->packet_loss.expected_sequence) {
            stats->packet_loss.packets_lost++;
        }
        stats->packet_loss.expected_sequence++;
    }
    stats->packet_loss.last_sequence = stats->packet_loss.expected_sequence;
    
    // Calculate packet loss rate
    if (stats->packet_loss.total_packets_received > 0) {
        stats->packet_loss.packet_loss_rate = 
            (double)stats->packet_loss.packets_lost / 
            stats->packet_loss.total_packets_received * 100.0;
    }
    
    // Calculate jitter
    calculate_jitter(&header->ts);
    
    // Print detailed packet information
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
        case IPPROTO_ICMP:
            printf("ICMP\n");
            break;
        default:
            printf("Other\n");
    }
}

// Function to print packet statistics periodically
void print_packet_statistics() {
    struct PacketStats *stats = &global_stats;
    
    printf("\n--- Packet Statistics ---\n");
    printf("Total Packets: %d\n", stats->total_packets);
    printf("TCP Packets: %d (%.2f%%)\n", 
           stats->tcp_packets, 
           (stats->total_packets > 0) ? 
           ((double)stats->tcp_packets / stats->total_packets * 100.0) : 0);
    printf("UDP Packets: %d (%.2f%%)\n", 
           stats->udp_packets, 
           (stats->total_packets > 0) ? 
           ((double)stats->udp_packets / stats->total_packets * 100.0) : 0);
    printf("ICMP Packets: %d (%.2f%%)\n", 
           stats->icmp_packets, 
           (stats->total_packets > 0) ? 
           ((double)stats->icmp_packets / stats->total_packets * 100.0) : 0);
    printf("Other Packets: %d (%.2f%%)\n", 
           stats->other_packets, 
           (stats->total_packets > 0) ? 
           ((double)stats->other_packets / stats->total_packets * 100.0) : 0);
    
    // Jitter statistics
    printf("Network Jitter: %.2f ms\n", stats->jitter_data.jitter_ms);
    
    // Packet loss statistics
    printf("Packet Loss: %.2f%%\n", stats->packet_loss.packet_loss_rate);
}

// Function to get local IP address
void get_local_ip(char *ip_address) {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;

    if (getifaddrs(&ifap) == -1) {
        perror("getifaddrs");
        strcpy(ip_address, "Unknown");
        return;
    }

    // Iterate through available interfaces
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            
            // Skip loopback address
            if (strcmp(addr, "127.0.0.1") != 0) {
                strcpy(ip_address, addr);
                freeifaddrs(ifap);
                return;
            }
        }
    }

    freeifaddrs(ifap);
    strcpy(ip_address, "127.0.0.1");
}

// Server function with multiple client support
void start_server() {
    int server_fd, new_socket, client_sockets[MAX_CLIENTS] = {0};
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[MAX_BUFFER] = {0};
    fd_set readfds;
    int max_sd, sd, activity;
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Allow socket to be reusable
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
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
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    // Print local IP address for connection
    char local_ip[INET_ADDRSTRLEN];
    get_local_ip(local_ip);
    printf("Server is running on IP: %s, Port: %d\n", local_ip, PORT);
    printf("Waiting for connections...\n");
    
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
    
    time_t last_stats_print = time(NULL);
    
    while (1) {
        // Clear socket set
        FD_ZERO(&readfds);
        
        // Add server socket to set
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;
        
        // Add child sockets to set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_sockets[i];
            
            if (sd > 0)
                FD_SET(sd, &readfds);
            
            if (sd > max_sd)
                max_sd = sd;
        }
        
        // Wait for activity on sockets
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        
        if (activity < 0) {
            perror("select error");
            exit(EXIT_FAILURE);
        }
        
        // New connection
        if (FD_ISSET(server_fd, &readfds)) {
            if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                perror("Accept failed");
                exit(EXIT_FAILURE);
            }
            
            // Add new socket to array of sockets
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    printf("New client connected. Socket fd is %d, IP is : %s, port : %d\n", 
                           new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                    break;
                }
            }
        }
        
        // Handle client messages
        for (int i = 0; i < MAX_CLIENTS; i++) {
            sd = client_sockets[i];
            
            if (FD_ISSET(sd, &readfds)) {
                // Clear buffer before reading
                memset(buffer, 0, MAX_BUFFER);
                
                // Check if it was for closing
                int valread = read(sd, buffer, MAX_BUFFER);
                if (valread <= 0) {
                    // Somebody disconnected
                    getpeername(sd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                    printf("Client disconnected, IP %s, port %d\n", 
                           inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                    
                    // Close the socket and mark as 0
                    close(sd);
                    client_sockets[i] = 0;
                } else {
                    // Null-terminate the buffer to ensure it's a proper string
                    buffer[valread] = '\0';
                    
                    // Print the received message on the server side
                    printf("Client %d: %s", sd, buffer);
                    
                    // Broadcast message to other clients
                    for (int j = 0; j < MAX_CLIENTS; j++) {
                        if (client_sockets[j] != 0 && client_sockets[j] != sd) {
                            send(client_sockets[j], buffer, strlen(buffer), 0);
                        }
                    }
                }
            }
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
        
        // Periodically print statistics
        time_t current_time = time(NULL);
        if (current_time - last_stats_print >= 10) {
            print_packet_statistics();
            last_stats_print = current_time;
        }
    }
    
    // Cleanup
    pcap_dump_close(dumper);
    pcap_close(handle);
}

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
    char local_ip[INET_ADDRSTRLEN];
    get_local_ip(local_ip);
    
    if (inet_pton(AF_INET, local_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        exit(EXIT_FAILURE);
    }
    
    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Connected to server at %s:%d\n", local_ip, PORT);
    
    // Create file descriptors for select()
    fd_set readfds;
    int max_sd;
    
    while (1) {
        // Clear socket set
        FD_ZERO(&readfds);
        
        // Add standard input and socket to set
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);
        max_sd = (STDIN_FILENO > sock) ? STDIN_FILENO : sock;
        
        // Wait for activity on sockets
        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        
        if (activity < 0) {
            perror("select error");
            break;
        }
        
        // Input from user
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            memset(buffer, 0, MAX_BUFFER);
            if (fgets(buffer, MAX_BUFFER, stdin) == NULL) {
                break;
            }
            
            // Send message to server
            send(sock, buffer, strlen(buffer), 0);
        }
        
        // Message from server
        if (FD_ISSET(sock, &readfds)) {
            memset(buffer, 0, MAX_BUFFER);
            int valread = read(sock, buffer, MAX_BUFFER);
            if (valread <= 0) {
                printf("Server disconnected\n");
                break;
            }
            
            // Null-terminate the buffer
            buffer[valread] = '\0';
            printf("Server: %s", buffer);
        }
    }
    
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