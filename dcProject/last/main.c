#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#define PORT 8080
#define MAX_BUFFER 1024
#define MAX_CLIENTS 30
#define CSV_FILE ".network.csv"
#define PCAP_FILE ".capture.pcap"

// Statistics structure
typedef struct {
    unsigned long total_packets;
    unsigned long tcp_packets;
    unsigned long udp_packets;
    unsigned long icmp_packets;
    unsigned long other_packets;
    unsigned long bytes_received;
    unsigned long packets_lost;
    double avg_jitter;
    double min_jitter;
    double max_jitter;
    double avg_packet_size;
    unsigned long max_packet_size;
    unsigned long min_packet_size;
    struct timeval last_packet_time;
    struct timeval first_packet_time;
    unsigned long total_sequence_expected;
    unsigned long total_sequence_received;
    int first_packet;
    // TCP specific stats
    unsigned long syn_packets;
    unsigned long fin_packets;
    unsigned long rst_packets;
    unsigned long ack_packets;
    unsigned long psh_packets;
    // Port statistics
    unsigned long src_port_counts[65536];
    unsigned long dst_port_counts[65536];
} PacketStats;

PacketStats stats;
pcap_t *handle;
pcap_dumper_t *dumper;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
int running = 1;
int client_sockets[MAX_CLIENTS];
int client_count = 0;
char *interface_name;

// Function to get formatted timestamp
void get_timestamp(char* buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *timeinfo = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", timeinfo);
}

// Function to initialize stats
void init_stats() {
    pthread_mutex_lock(&stats_mutex);
    stats.total_packets = 0;
    stats.tcp_packets = 0;
    stats.udp_packets = 0;
    stats.icmp_packets = 0;
    stats.other_packets = 0;
    stats.bytes_received = 0;
    stats.packets_lost = 0;
    stats.avg_jitter = 0.0;
    stats.min_jitter = 0.0;
    stats.max_jitter = 0.0;
    stats.avg_packet_size = 0.0;
    stats.max_packet_size = 0;
    stats.min_packet_size = 0;
    stats.first_packet = 1;
    stats.syn_packets = 0;
    stats.fin_packets = 0;
    stats.rst_packets = 0;
    stats.ack_packets = 0;
    stats.psh_packets = 0;
    stats.total_sequence_expected = 0;
    stats.total_sequence_received = 0;
    
    memset(stats.src_port_counts, 0, sizeof(stats.src_port_counts));
    memset(stats.dst_port_counts, 0, sizeof(stats.dst_port_counts));
    
    gettimeofday(&stats.first_packet_time, NULL);
    gettimeofday(&stats.last_packet_time, NULL);
    pthread_mutex_unlock(&stats_mutex);
}

// Calculate session duration in seconds
double get_session_duration() {
    struct timeval now;
    gettimeofday(&now, NULL);
    
    return (now.tv_sec - stats.first_packet_time.tv_sec) + 
           (now.tv_usec - stats.first_packet_time.tv_usec) / 1000000.0;
}

// Function to save stats to CSV
void save_stats_to_csv() {
    FILE *csv_file = fopen(CSV_FILE, "w");
    if (!csv_file) {
        perror("Failed to open CSV file");
        return;
    }
    
    // Get current timestamp
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    // Write CSV header
    fprintf(csv_file, "Timestamp,%s\n", timestamp);
    fprintf(csv_file, "Metric,Value\n");
    
    pthread_mutex_lock(&stats_mutex);
    fprintf(csv_file, "Total Packets,%lu\n", stats.total_packets);
    fprintf(csv_file, "TCP Packets,%lu\n", stats.tcp_packets);
    fprintf(csv_file, "UDP Packets,%lu\n", stats.udp_packets);
    fprintf(csv_file, "ICMP Packets,%lu\n", stats.icmp_packets);
    fprintf(csv_file, "Other Protocol Packets,%lu\n", stats.other_packets);
    fprintf(csv_file, "Total Bytes,%lu\n", stats.bytes_received);
    fprintf(csv_file, "Packets Lost,%lu\n", stats.packets_lost);
    fprintf(csv_file, "Packet Loss Rate,%.2f%%\n", stats.total_packets > 0 ? 
            (double)stats.packets_lost / (stats.packets_lost + stats.total_packets) * 100.0 : 0.0);
    fprintf(csv_file, "Average Jitter (ms),%.2f\n", stats.avg_jitter);
    fprintf(csv_file, "Minimum Jitter (ms),%.2f\n", stats.min_jitter);
    fprintf(csv_file, "Maximum Jitter (ms),%.2f\n", stats.max_jitter);
    fprintf(csv_file, "Average Packet Size (bytes),%.2f\n", stats.avg_packet_size);
    fprintf(csv_file, "Minimum Packet Size (bytes),%lu\n", stats.min_packet_size);
    fprintf(csv_file, "Maximum Packet Size (bytes),%lu\n", stats.max_packet_size);
    fprintf(csv_file, "Session Duration (seconds),%.2f\n", get_session_duration());
    
    // TCP flag statistics
    fprintf(csv_file, "SYN Packets,%lu\n", stats.syn_packets);
    fprintf(csv_file, "FIN Packets,%lu\n", stats.fin_packets);
    fprintf(csv_file, "RST Packets,%lu\n", stats.rst_packets);
    fprintf(csv_file, "ACK Packets,%lu\n", stats.ack_packets);
    fprintf(csv_file, "PSH Packets,%lu\n", stats.psh_packets);
    
    // Top 5 source ports
    fprintf(csv_file, "\nTop Source Ports\n");
    fprintf(csv_file, "Port,Count\n");
    
    // Find top ports (simple bubble sort for top 5)
    unsigned long top_ports[5] = {0};
    unsigned long top_counts[5] = {0};
    
    for (int i = 0; i < 65536; i++) {
        for (int j = 0; j < 5; j++) {
            if (stats.src_port_counts[i] > top_counts[j]) {
                // Shift everything down
                for (int k = 4; k > j; k--) {
                    top_ports[k] = top_ports[k-1];
                    top_counts[k] = top_counts[k-1];
                }
                top_ports[j] = i;
                top_counts[j] = stats.src_port_counts[i];
                break;
            }
        }
    }
    
    // Write top source ports
    for (int i = 0; i < 5; i++) {
        if (top_counts[i] > 0) {
            fprintf(csv_file, "%lu,%lu\n", top_ports[i], top_counts[i]);
        }
    }
    
    // Top 5 destination ports
    fprintf(csv_file, "\nTop Destination Ports\n");
    fprintf(csv_file, "Port,Count\n");
    
    // Reset for destination ports
    memset(top_ports, 0, sizeof(top_ports));
    memset(top_counts, 0, sizeof(top_counts));
    
    for (int i = 0; i < 65536; i++) {
        for (int j = 0; j < 5; j++) {
            if (stats.dst_port_counts[i] > top_counts[j]) {
                // Shift everything down
                for (int k = 4; k > j; k--) {
                    top_ports[k] = top_ports[k-1];
                    top_counts[k] = top_counts[k-1];
                }
                top_ports[j] = i;
                top_counts[j] = stats.dst_port_counts[i];
                break;
            }
        }
    }
    
    // Write top destination ports
    for (int i = 0; i < 5; i++) {
        if (top_counts[i] > 0) {
            fprintf(csv_file, "%lu,%lu\n", top_ports[i], top_counts[i]);
        }
    }
    
    pthread_mutex_unlock(&stats_mutex);
    
    fclose(csv_file);
    printf("Statistics saved to %s at %s\n", CSV_FILE, timestamp);
}

// Signal handler for graceful exit
void signal_handler(int sig) {
    printf("\nShutting down...\n");
    running = 0;
    
    // Close all client connections
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_sockets[i] > 0) {
            close(client_sockets[i]);
        }
    }
    
    // Save statistics and cleanup
    save_stats_to_csv();
    
    if (dumper) pcap_dump_close(dumper);
    if (handle) pcap_close(handle);
    
    exit(0);
}

// Print packet details to console (for debugging)
void print_packet_info(const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    unsigned short src_port, dst_port;
    
    printf("\n=== Packet Received ===\n");
    printf("Length: %d bytes\n", header->len);
    printf("Ethernet type: 0x%04x\n", ntohs(eth_header->ether_type));
    
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
        
        // Get IP addresses
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        
        printf("Protocol: ");
        switch(ip_header->ip_p) {
            case IPPROTO_TCP:
                printf("TCP\n");
                tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
                src_port = ntohs(tcp_header->th_sport);
                dst_port = ntohs(tcp_header->th_dport);
                printf("TCP Flags: ");
                if (tcp_header->th_flags & TH_SYN) printf("SYN ");
                if (tcp_header->th_flags & TH_ACK) printf("ACK ");
                if (tcp_header->th_flags & TH_FIN) printf("FIN ");
                if (tcp_header->th_flags & TH_RST) printf("RST ");
                if (tcp_header->th_flags & TH_PUSH) printf("PSH ");
                if (tcp_header->th_flags & TH_URG) printf("URG ");
                printf("\n");
                break;
            case IPPROTO_UDP:
                printf("UDP\n");
                udp_header = (struct udphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
                src_port = ntohs(udp_header->uh_sport);
                dst_port = ntohs(udp_header->uh_dport);
                break;
            case IPPROTO_ICMP:
                printf("ICMP\n");
                src_port = 0;
                dst_port = 0;
                break;
            default:
                printf("Other (%d)\n", ip_header->ip_p);
                src_port = 0;
                dst_port = 0;
        }
        
        printf("Source: %s:%d\n", src_ip, src_port);
        printf("Destination: %s:%d\n", dst_ip, dst_port);
    }
    printf("=======================\n");
}

// Packet analysis callback function
void packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Extract Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    // Check if it's an IP packet
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }
    
    // For debugging/verification
    // print_packet_info(header, packet);
    
    // Extract IP header
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    int ip_header_len = ip_header->ip_hl * 4;
    
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    
    pthread_mutex_lock(&stats_mutex);
    
    // Update packet counts
    stats.total_packets++;
    stats.bytes_received += header->len;
    
    // Update packet size statistics
    if (stats.total_packets == 1) {
        stats.min_packet_size = header->len;
        stats.max_packet_size = header->len;
        stats.avg_packet_size = (double)header->len;
    } else {
        if (header->len < stats.min_packet_size) stats.min_packet_size = header->len;
        if (header->len > stats.max_packet_size) stats.max_packet_size = header->len;
        stats.avg_packet_size = ((stats.total_packets - 1) * stats.avg_packet_size + header->len) / stats.total_packets;
    }
    
    // Calculate jitter (inter-packet arrival time variance)
    if (!stats.first_packet) {
        // Time difference in milliseconds
        double diff = (current_time.tv_sec - stats.last_packet_time.tv_sec) * 1000.0 + 
                     (current_time.tv_usec - stats.last_packet_time.tv_usec) / 1000.0;
        
        // Update jitter stats
        if (stats.total_packets == 2) {
            stats.avg_jitter = diff;
            stats.min_jitter = diff;
            stats.max_jitter = diff;
        } else {
            stats.avg_jitter = ((stats.total_packets - 2) * stats.avg_jitter + diff) / (stats.total_packets - 1);
            if (diff < stats.min_jitter) stats.min_jitter = diff;
            if (diff > stats.max_jitter) stats.max_jitter = diff;
        }
    } else {
        stats.first_packet = 0;
    }
    
    // Save current packet time
    stats.last_packet_time = current_time;
    
    // Protocol analysis
    switch (ip_header->ip_p) {
        case IPPROTO_TCP: {
            stats.tcp_packets++;
            
            // Extract TCP header
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
            
            // Update port statistics
            unsigned short src_port = ntohs(tcp_header->th_sport);
            unsigned short dst_port = ntohs(tcp_header->th_dport);
            
            stats.src_port_counts[src_port]++;
            stats.dst_port_counts[dst_port]++;
            
            // TCP flags analysis
            if (tcp_header->th_flags & TH_SYN) stats.syn_packets++;
            if (tcp_header->th_flags & TH_FIN) stats.fin_packets++;
            if (tcp_header->th_flags & TH_RST) stats.rst_packets++;
            if (tcp_header->th_flags & TH_ACK) stats.ack_packets++;
            if (tcp_header->th_flags & TH_PUSH) stats.psh_packets++;
            
            // Sequence number analysis for potential packet loss
            static uint32_t last_seq = 0;
            uint32_t current_seq = ntohl(tcp_header->th_seq);
            
            if (last_seq != 0 && current_seq > last_seq) {
                stats.total_sequence_expected += (current_seq - last_seq);
                stats.total_sequence_received++;
                
                // Very simple packet loss estimation
                if ((current_seq - last_seq) > 1) {
                    stats.packets_lost += (current_seq - last_seq - 1);
                }
            }
            
            last_seq = current_seq;
            break;
        }
        case IPPROTO_UDP: {
            stats.udp_packets++;
            
            // Extract UDP header
            struct udphdr *udp_header = (struct udphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
            
            // Update port statistics
            unsigned short src_port = ntohs(udp_header->uh_sport);
            unsigned short dst_port = ntohs(udp_header->uh_dport);
            
            stats.src_port_counts[src_port]++;
            stats.dst_port_counts[dst_port]++;
            break;
        }
        case IPPROTO_ICMP:
            stats.icmp_packets++;
            break;
        default:
            stats.other_packets++;
    }
    
    pthread_mutex_unlock(&stats_mutex);
    
    // Write packet to pcap file - Make sure to flush frequently
    pcap_dump((u_char *)dumper, header, packet);
    pcap_dump_flush(dumper);  // This is crucial to ensure data is written to disk
    
    // Periodically save stats to CSV
    if (stats.total_packets % 100 == 0) {
        save_stats_to_csv();
    }
}

// Function to start packet capture in a separate thread
void *packet_capture_thread(void *arg) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[100];
    bpf_u_int32 net, mask;
    
    // Get network information
    if (pcap_lookupnet(interface_name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s: %s\n", interface_name, errbuf);
        net = 0;
        mask = 0;
    }
    
    // Open device for packet capture
    handle = pcap_open_live(interface_name, BUFSIZ, 1, 100, errbuf);  // Reduced timeout for faster packet processing
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface_name, errbuf);
        return NULL;
    }
    
    // Create filter expression for port - include both UDP and TCP on our port
    sprintf(filter_exp, "tcp port %d or udp port %d", PORT, PORT);
    
    // Compile and set filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return NULL;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return NULL;
    }
    
    // Open pcap file for writing
    dumper = pcap_dump_open(handle, PCAP_FILE);
    if (dumper == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", pcap_geterr(handle));
        return NULL;
    }
    
    printf("Packet capture started on interface %s (filter: %s)\n", interface_name, filter_exp);
    printf("Saving captured packets to %s\n", PCAP_FILE);
    
    // Start packet capture loop
    pcap_loop(handle, -1, packet_callback, NULL);
    
    return NULL;
}

// Server function
void start_server() {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    fd_set readfds;
    char buffer[MAX_BUFFER];
    
    // Initialize client socket array
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_sockets[i] = 0;
    }
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
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
    if (listen(server_fd, 5) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Server listening on port %d\n", PORT);
    
    // Initialize stats before starting capture
    init_stats();
    
    // Start packet capture in a separate thread
    pthread_t capture_thread;
    if (pthread_create(&capture_thread, NULL, packet_capture_thread, NULL) != 0) {
        perror("Failed to create packet capture thread");
        exit(EXIT_FAILURE);
    }
    
    // Main server loop
    while (running) {
        // Clear the socket set
        FD_ZERO(&readfds);
        
        // Add server socket to set
        FD_SET(server_fd, &readfds);
        int max_sd = server_fd;
        
        // Add child sockets to set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_sockets[i];
            
            if (sd > 0) {
                FD_SET(sd, &readfds);
            }
            
            if (sd > max_sd) {
                max_sd = sd;
            }
        }
        
        // Wait for activity on any socket with timeout
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(max_sd + 1, &readfds, NULL, NULL, &timeout);
        
        if ((activity < 0) && (errno != EINTR)) {
            perror("Select error");
        }
        
        // Check for connection requests
        if (FD_ISSET(server_fd, &readfds)) {
            int new_socket;
            if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                perror("Accept failed");
                exit(EXIT_FAILURE);
            }
            
            // Get client info
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(address.sin_addr), client_ip, INET_ADDRSTRLEN);
            printf("New connection from %s:%d\n", client_ip, ntohs(address.sin_port));
            
            // Add new socket to array of sockets
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    client_count++;
                    printf("Client #%d added to list\n", i);
                    break;
                }
            }
            
            // Welcome message
            char welcome_msg[100];
            sprintf(welcome_msg, "Welcome to the chat server! You are client #%d\n", client_count);
            send(new_socket, welcome_msg, strlen(welcome_msg), 0);
        }
        
        // Check for data from clients
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_sockets[i];
            
            if (FD_ISSET(sd, &readfds)) {
                // Read message
                int valread = read(sd, buffer, MAX_BUFFER);
                
                if (valread == 0) {
                    // Client disconnected
                    getpeername(sd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(address.sin_addr), client_ip, INET_ADDRSTRLEN);
                    printf("Client disconnected: %s:%d\n", client_ip, ntohs(address.sin_port));
                    
                    // Close socket and mark as available
                    close(sd);
                    client_sockets[i] = 0;
                    client_count--;
                } else {
                    // Process message
                    buffer[valread] = '\0';
                    
                    // Get sender info
                    getpeername(sd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(address.sin_addr), client_ip, INET_ADDRSTRLEN);
                    
                    // Format message with sender info and timestamp
                    char timestamp[32];
                    get_timestamp(timestamp, sizeof(timestamp));
                    
                    char formatted_msg[MAX_BUFFER + 100];
                    sprintf(formatted_msg, "[%s] Client #%d (%s): %s", timestamp, i, client_ip, buffer);
                    printf("%s", formatted_msg);
                    
                    // Forward message to all other clients
                    for (int j = 0; j < MAX_CLIENTS; j++) {
                        if (client_sockets[j] > 0 && j != i) {
                            send(client_sockets[j], formatted_msg, strlen(formatted_msg), 0);
                        }
                    }
                }
            }
        }
    }
}

// Client function
void start_client(const char *server_ip) {
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
    
    // Convert IPv4 address from text to binary form
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid server address");
        exit(EXIT_FAILURE);
    }
    
    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Connected to server at %s:%d\n", server_ip, PORT);
    printf("Type your message and press Enter. Type 'exit' to quit.\n");
    
    // Chat loop
    fd_set readfds;
    while (running) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);
        
        // Set timeout for select
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(sock + 1, &readfds, NULL, NULL, &timeout);
        
        if ((activity < 0) && (errno != EINTR)) {
            perror("Select error");
        }
        
        // Check for messages from server
        if (FD_ISSET(sock, &readfds)) {
            memset(buffer, 0, MAX_BUFFER);
            int valread = read(sock, buffer, MAX_BUFFER);
            
            if (valread == 0) {
                printf("Server disconnected\n");
                break;
            } else {
                printf("%s", buffer);
            }
        }
        
        // Check for user input
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            memset(buffer, 0, MAX_BUFFER);
            fgets(buffer, MAX_BUFFER, stdin);
            
            // Check for exit command
            if (strcmp(buffer, "exit\n") == 0) {
                printf("Exiting...\n");
                break;
            }
            
            // Send message to server
            send(sock, buffer, strlen(buffer), 0);
            // Send message to server
            send(sock, buffer, strlen(buffer), 0);
        }
    }
    
    // Close socket
    close(sock);
}

int main(int argc, char *argv[]) {
    // Register signal handler
    signal(SIGINT, signal_handler);
    
    if (argc < 2) {
        printf("Usage: %s -s <interface> (for server) or %s -c <server_ip> (for client)\n", argv[0], argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "-s") == 0) {
        if (argc < 3) {
            printf("Server mode requires an interface name\n");
            printf("Usage: %s -s <interface>\n", argv[0]);
            return 1;
        }
        interface_name = argv[2];
        start_server();
    } else if (strcmp(argv[1], "-c") == 0) {
        if (argc < 3) {
            printf("Client mode requires a server IP address\n");
            printf("Usage: %s -c <server_ip>\n", argv[0]);
            return 1;
        }
        start_client(argv[2]);
    } else {
        printf("Invalid option. Use -s for server or -c for client\n");
        return 1;
    }
    
    return 0;
}