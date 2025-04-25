#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <time.h>
#include <sys/time.h>

#define MAX_CLIENTS 10
#define PORT 8080
#define MAX_BUFFER 1024

// Packet Analysis Structures
typedef struct {
    int total_packets;
    int lost_packets;
    int tcp_packets;
    int udp_packets;
    int icmp_packets;
    double total_bytes;
    double jitter_sum;
    double last_timestamp;
    pthread_mutex_t mutex;
} PacketStats;

// Client Connection Structure
typedef struct {
    int socket;
    struct sockaddr_in address;
    int addr_len;
} ClientConnection;

// Global Variables
PacketStats global_packet_stats = {0};
ClientConnection client_list[MAX_CLIENTS] = {0};
pthread_t client_threads[MAX_CLIENTS] = {0};
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// Advanced Packet Analysis Function
void analyze_packet_advanced(const u_char *packet, struct pcap_pkthdr *header) {
    struct timeval current_time = header->ts;
    
    pthread_mutex_lock(&global_packet_stats.mutex);
    
    // Increment total packets
    global_packet_stats.total_packets++;
    
    // Calculate total bytes
    global_packet_stats.total_bytes += header->len;
    
    // Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    // IP header
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    
    // Protocol-specific counting
    switch(ip_header->ip_p) {
        case IPPROTO_TCP:
            global_packet_stats.tcp_packets++;
            break;
        case IPPROTO_UDP:
            global_packet_stats.udp_packets++;
            break;
        case IPPROTO_ICMP:
            global_packet_stats.icmp_packets++;
            break;
    }
    
    // Jitter calculation
    if (global_packet_stats.last_timestamp > 0) {
        double current_ts = current_time.tv_sec + (current_time.tv_usec / 1000000.0);
        double last_ts = global_packet_stats.last_timestamp;
        double jitter = fabs(current_ts - last_ts);
        
        global_packet_stats.jitter_sum += jitter;
    }
    
    global_packet_stats.last_timestamp = current_time.tv_sec + (current_time.tv_usec / 1000000.0);
    
    pthread_mutex_unlock(&global_packet_stats.mutex);
    
    // Detailed Packet Logging
    printf("\n--- Detailed Packet Analysis ---\n");
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

// Packet Capture Thread
void* packet_capture_thread(void *arg) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    // Open device for packet capture
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return NULL;
    }
    
    // Open pcap file for writing
    pcap_dumper_t *dumper = pcap_dump_open(handle, "advanced_chat_packets.pcap");
    if (dumper == NULL) {
        fprintf(stderr, "Error opening pcap file\n");
        pcap_close(handle);
        return NULL;
    }
    
    // Continuous packet capture
    struct pcap_pkthdr *header;
    const u_char *packet;
    while (1) {
        int result = pcap_next_ex(handle, &header, &packet);
        if (result > 0) {
            // Write packet to pcap file
            pcap_dump((u_char *)dumper, header, packet);
            
            // Analyze packet
            analyze_packet_advanced(packet, header);
        }
    }
    
    // Cleanup (unreachable in this implementation)
    pcap_dump_close(dumper);
    pcap_close(handle);
    
    return NULL;
}

// Client Handler Thread
void* handle_client(void *arg) {
    ClientConnection *client_conn = (ClientConnection *)arg;
    int client_socket = client_conn->socket;
    char buffer[MAX_BUFFER] = {0};
    
    while (1) {
        // Clear buffer
        memset(buffer, 0, MAX_BUFFER);
        
        // Receive message
        int read_status = read(client_socket, buffer, MAX_BUFFER);
        if (read_status <= 0) {
            printf("Client disconnected\n");
            break;
        }
        
        // Broadcast message to all clients
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < client_count; i++) {
            if (client_list[i].socket != client_socket) {
                send(client_list[i].socket, buffer, strlen(buffer), 0);
            }
        }
        pthread_mutex_unlock(&clients_mutex);
        
        // Print received message
        printf("Received: %s", buffer);
    }
    
    // Remove client from list
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (client_list[i].socket == client_socket) {
            // Remove this client by shifting the array
            for (int j = i; j < client_count - 1; j++) {
                client_list[j] = client_list[j + 1];
            }
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    
    // Close socket
    close(client_socket);
    
    return NULL;
}

// Server Function
void start_server() {
    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    // Initialize packet stats mutex
    pthread_mutex_init(&global_packet_stats.mutex, NULL);
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Socket options
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
    
    // Start packet capture thread
    pthread_t packet_capture;
    if (pthread_create(&packet_capture, NULL, packet_capture_thread, NULL) != 0) {
        perror("Packet capture thread creation failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Server listening on port %d\n", PORT);
    
    // Accept connections
    while (1) {
        // Check if we've reached max clients
        if (client_count >= MAX_CLIENTS) {
            printf("Maximum clients reached\n");
            sleep(1);
            continue;
        }
        
        // Accept new connection
        ClientConnection *new_client = &client_list[client_count];
        new_client->addr_len = addrlen;
        
        new_client->socket = accept(server_fd, 
                                    (struct sockaddr *)&new_client->address, 
                                    (socklen_t*)&new_client->addr_len);
        
        if (new_client->socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        // Create thread for this client
        if (pthread_create(&client_threads[client_count], NULL, handle_client, new_client) != 0) {
            perror("Client thread creation failed");
            close(new_client->socket);
            continue;
        }
        
        // Detach thread so it cleans up automatically
        pthread_detach(client_threads[client_count]);
        
        // Increment client count
        client_count++;
        
        printf("New client connected. Total clients: %d\n", client_count);
    }
    
    // Close server socket
    close(server_fd);
}

// Print Packet Statistics Periodically
void* stats_printer(void *arg) {
    while (1) {
        sleep(10);  // Print stats every 10 seconds
        
        pthread_mutex_lock(&global_packet_stats.mutex);
        
        printf("\n--- Network Statistics ---\n");
        printf("Total Packets: %d\n", global_packet_stats.total_packets);
        printf("Total Bytes Transferred: %.2f\n", global_packet_stats.total_bytes);
        printf("TCP Packets: %d\n", global_packet_stats.tcp_packets);
        printf("UDP Packets: %d\n", global_packet_stats.udp_packets);
        printf("ICMP Packets: %d\n", global_packet_stats.icmp_packets);
        printf("Average Jitter: %f seconds\n", 
               global_packet_stats.total_packets > 1 ? 
               (global_packet_stats.jitter_sum / (global_packet_stats.total_packets - 1)) : 0);
        
        pthread_mutex_unlock(&global_packet_stats.mutex);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    // Start stats printer thread
    pthread_t stats_thread;
    if (pthread_create(&stats_thread, NULL, stats_printer, NULL) != 0) {
        perror("Stats thread creation failed");
        return 1;
    }
    
    // Start server
    start_server();
    
    return 0;
}