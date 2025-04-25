#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>  // Added for ioctl() function
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <pcap/pcap.h>

// Global definitions
#define PACKET_BUFFER_SIZE 65536
#define MAX_PCAP_FILE_SIZE 100000000  // 100 MB
#define DEFAULT_INTERFACE "eth0"
#define SAMPLE_INTERVAL 1000          // in milliseconds
#define MAX_PACKETS 10000

// Global variables
volatile int running = 1;
char *interface = DEFAULT_INTERFACE;
pcap_dumper_t *pcap_dumper = NULL;
pcap_t *pcap_handle = NULL;
FILE *metrics_file = NULL;

// Metrics storage
struct {
    unsigned long packets_received;
    unsigned long packets_dropped;
    unsigned long bytes_received;
    double jitter_sum;
    double jitter_count;
    struct timespec last_packet_time;
    unsigned long packet_count_per_interval[MAX_PACKETS];
    unsigned int interval_count;
} metrics = {0};

// Function prototypes
void setup_raw_socket(int *sock_fd);
void process_packet(unsigned char *buffer, int size);
void signal_handler(int signum);
void setup_pcap_dumper();
void close_pcap_dumper();
void write_metrics_to_file();
void calculate_metrics(struct timespec *current_time);
void print_usage();
void analyze_packet_loss();
void analyze_jitter();
void start_wireshark_analysis();

// Main function
int main(int argc, char *argv[]) {
    int sock_raw;
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    unsigned char *buffer = (unsigned char *)malloc(PACKET_BUFFER_SIZE);
    int option;
    
    // Parse command line arguments
    while ((option = getopt(argc, argv, "i:h")) != -1) {
        switch (option) {
            case 'i':
                interface = optarg;
                break;
            case 'h':
                print_usage();
                return 0;
            default:
                print_usage();
                return 1;
        }
    }

    printf("Starting network monitoring on interface %s\n", interface);
    
    // Setup signal handling for graceful termination
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Setup raw socket
    setup_raw_socket(&sock_raw);
    
    // Setup pcap dumper for Wireshark integration
    setup_pcap_dumper();
    
    // Open metrics file
    metrics_file = fopen("network_metrics.csv", "w");
    if (metrics_file == NULL) {
        perror("Failed to open metrics file");
        exit(1);
    }
    
    // Write CSV header
    fprintf(metrics_file, "Timestamp,Packets Received,Packets Dropped,Bytes Received,Packet Loss %%,Jitter (ms)\n");
    
    // Initialize timing metrics
    clock_gettime(CLOCK_MONOTONIC, &metrics.last_packet_time);
    
    // Main packet capture loop
    while (running) {
        int packet_size = recvfrom(sock_raw, buffer, PACKET_BUFFER_SIZE, 0, &saddr, (socklen_t *)&saddr_len);
        
        if (packet_size < 0) {
            printf("Failed to receive packet\n");
            continue;
        }
        
        process_packet(buffer, packet_size);
    }
    
    // Cleanup
    close(sock_raw);
    free(buffer);
    close_pcap_dumper();
    
    if (metrics_file) {
        fclose(metrics_file);
    }
    
    // Final analysis
    printf("\nPerforming final analysis...\n");
    analyze_packet_loss();
    analyze_jitter();
    
    // Start Wireshark for deeper analysis
    start_wireshark_analysis();
    
    return 0;
}

// Setup raw socket for packet capture
void setup_raw_socket(int *sock_fd) {
    struct sockaddr_ll sll;
    struct ifreq ifr;
    
    // Create raw socket
    *sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (*sock_fd < 0) {
        perror("Socket creation failed");
        exit(1);
    }
    
    // Get interface index
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(*sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Failed to get interface index");
        exit(1);
    }
    
    // Bind to interface
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(*sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Socket bind failed");
        exit(1);
    }
    
    // Set promiscuous mode
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(*sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("Failed to get interface flags");
        exit(1);
    }
    
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(*sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("Failed to set promiscuous mode");
        exit(1);
    }
    
    printf("Raw socket setup complete on interface %s (index: %d)\n", interface, ifr.ifr_ifindex);
}

// Process captured packets
void process_packet(unsigned char *buffer, int size) {
    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);
    
    // Update metrics
    metrics.packets_received++;
    metrics.bytes_received += size;
    
    // Calculate jitter
    if (metrics.packets_received > 1) {
        double time_diff = (current_time.tv_sec - metrics.last_packet_time.tv_sec) * 1000.0 +
                          (current_time.tv_nsec - metrics.last_packet_time.tv_nsec) / 1000000.0;
        metrics.jitter_sum += time_diff;
        metrics.jitter_count++;
    }
    
    // Save packet timestamp
    metrics.last_packet_time = current_time;
    
    // Add to pcap file for Wireshark analysis
    if (pcap_dumper) {
        struct pcap_pkthdr pcap_header;
        pcap_header.ts.tv_sec = current_time.tv_sec;
        pcap_header.ts.tv_usec = current_time.tv_nsec / 1000;
        pcap_header.caplen = size;
        pcap_header.len = size;
        pcap_dump((u_char *)pcap_dumper, &pcap_header, buffer);
    }
    
    // Calculate and log metrics periodically
    static struct timespec last_metrics_time = {0, 0};
    double elapsed = (current_time.tv_sec - last_metrics_time.tv_sec) * 1000.0 +
                    (current_time.tv_nsec - last_metrics_time.tv_nsec) / 1000000.0;
    
    if (elapsed >= SAMPLE_INTERVAL || last_metrics_time.tv_sec == 0) {
        calculate_metrics(&current_time);
        last_metrics_time = current_time;
        
        // Track packets per interval for loss detection
        if (metrics.interval_count < MAX_PACKETS) {
            metrics.packet_count_per_interval[metrics.interval_count++] = metrics.packets_received;
        }
    }
    
    // Parse Ethernet header
    struct ethhdr *eth = (struct ethhdr *)buffer;
    
    // Print basic packet info (for debugging)
    if (metrics.packets_received % 1000 == 0) {
        printf("Packet #%lu: Size = %d bytes, Protocol = 0x%x\n", 
            metrics.packets_received, size, ntohs(eth->h_proto));
    }
    
    // Parse IP header if it's an IP packet
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        
        // Parse TCP/UDP headers for more detailed analysis
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
            
            if (metrics.packets_received % 1000 == 0) {
                printf("  TCP Packet - Source: %s:%d, Destination: %s:%d\n", 
                    inet_ntoa(*(struct in_addr *)&ip->saddr), ntohs(tcp->source),
                    inet_ntoa(*(struct in_addr *)&ip->daddr), ntohs(tcp->dest));
            }
        } 
        else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
            
            if (metrics.packets_received % 1000 == 0) {
                printf("  UDP Packet - Source: %s:%d, Destination: %s:%d\n", 
                    inet_ntoa(*(struct in_addr *)&ip->saddr), ntohs(udp->source),
                    inet_ntoa(*(struct in_addr *)&ip->daddr), ntohs(udp->dest));
            }
        }
    }
}

// Setup pcap dumper for writing captured packets to a file
void setup_pcap_dumper() {
    char pcap_filename[100];
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Generate timestamped filename
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(pcap_filename, sizeof(pcap_filename), "capture_%Y%m%d_%H%M%S.pcap", t);
    
    // Initialize pcap
    pcap_handle = pcap_open_dead(DLT_EN10MB, PACKET_BUFFER_SIZE);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Failed to initialize pcap\n");
        return;
    }
    
    // Open pcap file for writing
    pcap_dumper = pcap_dump_open(pcap_handle, pcap_filename);
    if (pcap_dumper == NULL) {
        fprintf(stderr, "Failed to open pcap file: %s\n", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        pcap_handle = NULL;
        return;
    }
    
    printf("Capturing packets to file: %s\n", pcap_filename);
}

// Close the pcap dumper
void close_pcap_dumper() {
    if (pcap_dumper) {
        pcap_dump_close(pcap_dumper);
        pcap_dumper = NULL;
    }
    
    if (pcap_handle) {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }
}

// Calculate and record metrics
void calculate_metrics(struct timespec *current_time) {
    // Calculate packet loss
    // This is a simplistic approximation - real packet loss would require sequence numbers
    static unsigned long last_packets_received = 0;
    static unsigned long last_bytes_received = 0;
    
    unsigned long packets_in_interval = metrics.packets_received - last_packets_received;
    unsigned long bytes_in_interval = metrics.bytes_received - last_bytes_received;
    
    // Estimate packet loss based on expected packet rate
    // This is just a placeholder - real implementation would use better heuristics
    static double expected_packets_per_interval = 0;
    if (expected_packets_per_interval == 0 && metrics.interval_count > 3) {
        // Initialize expectation after a few intervals
        expected_packets_per_interval = (double)metrics.packets_received / metrics.interval_count;
    }
    
    double packet_loss = 0.0;
    if (expected_packets_per_interval > 0) {
        double expected = expected_packets_per_interval;
        packet_loss = expected > packets_in_interval ? 
                      (expected - packets_in_interval) / expected * 100.0 : 0.0;
        
        // Update expected rate with a weighted average
        expected_packets_per_interval = expected_packets_per_interval * 0.8 + packets_in_interval * 0.2;
    }
    
    // Calculate average jitter in milliseconds
    double avg_jitter = metrics.jitter_count > 0 ? metrics.jitter_sum / metrics.jitter_count : 0;
    
    // Write metrics to file
    time_t current_time_t = current_time->tv_sec;
    struct tm *timeinfo = localtime(&current_time_t);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    fprintf(metrics_file, "%s,%lu,%lu,%lu,%.2f,%.2f\n", 
            timestamp, metrics.packets_received, metrics.packets_dropped, 
            metrics.bytes_received, packet_loss, avg_jitter);
    fflush(metrics_file);
    
    // Display current metrics
    printf("\n--- Network Metrics at %s ---\n", timestamp);
    printf("Packets: %lu (%.2f pkts/sec)\n", 
           metrics.packets_received, 
           packets_in_interval / (SAMPLE_INTERVAL / 1000.0));
    printf("Bandwidth: %.2f KB/sec\n", 
           bytes_in_interval / (SAMPLE_INTERVAL / 1000.0) / 1024.0);
    printf("Estimated Packet Loss: %.2f%%\n", packet_loss);
    printf("Average Jitter: %.2f ms\n", avg_jitter);
    printf("-----------------------------------\n");
    
    // Update last values
    last_packets_received = metrics.packets_received;
    last_bytes_received = metrics.bytes_received;
}

// Handle signals for graceful termination
void signal_handler(int signum) {
    printf("\nReceived signal %d, terminating...\n", signum);
    running = 0;
}

// Print usage instructions
void print_usage() {
    printf("Usage: network_monitor [-i interface]\n");
    printf("Options:\n");
    printf("  -i <interface>  Network interface to monitor (default: %s)\n", DEFAULT_INTERFACE);
    printf("  -h              Display this help message\n");
}

// Analyze packet loss patterns
void analyze_packet_loss() {
    printf("\n=== Packet Loss Analysis ===\n");
    
    if (metrics.interval_count < 2) {
        printf("Not enough data collected for analysis.\n");
        return;
    }
    
    // Find periods of significant packet loss
    int loss_count = 0;
    int max_loss_period = 0;
    int current_loss_period = 0;
    unsigned long avg_packets = 0;
    
    // Calculate average packets per interval
    for (int i = 0; i < metrics.interval_count; i++) {
        avg_packets += metrics.packet_count_per_interval[i];
    }
    avg_packets /= metrics.interval_count;
    
    // Analyze loss patterns
    for (int i = 1; i < metrics.interval_count; i++) {
        unsigned long prev = metrics.packet_count_per_interval[i-1];
        unsigned long curr = metrics.packet_count_per_interval[i];
        unsigned long diff = prev > curr ? prev - curr : 0;
        
        // If packet count dropped by more than 20% of average, consider it loss
        if (diff > avg_packets * 0.2) {
            loss_count++;
            current_loss_period++;
            
            if (current_loss_period > max_loss_period) {
                max_loss_period = current_loss_period;
            }
        } else {
            current_loss_period = 0;
        }
    }
    
    printf("Total intervals with significant packet loss: %d of %d (%.1f%%)\n", 
           loss_count, metrics.interval_count, 
           (double)loss_count / metrics.interval_count * 100);
    printf("Longest continuous period of packet loss: %d intervals (%.1f seconds)\n", 
           max_loss_period, max_loss_period * (SAMPLE_INTERVAL / 1000.0));
    
    if (loss_count > metrics.interval_count * 0.1) {
        printf("ALERT: Network experiencing significant packet loss!\n");
    } else {
        printf("Network packet loss is within acceptable limits.\n");
    }
}

// Analyze jitter patterns
void analyze_jitter() {
    printf("\n=== Jitter Analysis ===\n");
    
    if (metrics.jitter_count < 10) {
        printf("Not enough data collected for jitter analysis.\n");
        return;
    }
    
    double avg_jitter = metrics.jitter_sum / metrics.jitter_count;
    
    printf("Average jitter: %.2f ms\n", avg_jitter);
    
    if (avg_jitter > 50) {
        printf("ALERT: High jitter detected! This may affect real-time applications.\n");
    } else if (avg_jitter > 20) {
        printf("WARNING: Moderate jitter detected. Monitor for impact on real-time applications.\n");
    } else {
        printf("Jitter levels are acceptable for most applications.\n");
    }
    
    // In a real implementation, would analyze jitter variance and patterns
    printf("For detailed jitter analysis, examine the captured pcap file in Wireshark.\n");
}

// Start Wireshark for deeper analysis
void start_wireshark_analysis() {
    printf("\n=== Starting Wireshark Analysis ===\n");
    
    // Get the most recent capture file
    FILE *fp = popen("ls -t capture_*.pcap | head -1", "r");
    if (fp == NULL) {
        printf("Failed to find capture files.\n");
        return;
    }
    
    char latest_file[256];
    if (fgets(latest_file, sizeof(latest_file), fp) == NULL) {
        printf("No capture files found.\n");
        pclose(fp);
        return;
    }
    
    // Remove newline
    latest_file[strcspn(latest_file, "\n")] = 0;
    
    printf("Opening %s in Wireshark for detailed analysis...\n", latest_file);
    
    // Prepare Wireshark command
    char command[512];
    snprintf(command, sizeof(command), "wireshark %s &", latest_file);
    
    // Execute command
    int ret = system(command);
    if (ret != 0) {
        printf("Failed to start Wireshark. Make sure it's installed.\n");
        printf("You can manually open the capture file: %s\n", latest_file);
    }
    
    pclose(fp);
}