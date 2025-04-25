#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <readline/readline.h>
#include <readline/history.h>

// Global definitions
#define PACKET_BUFFER_SIZE 65536
#define MAX_PCAP_FILE_SIZE 100000000  // 100 MB
#define DEFAULT_INTERFACE "eth0"
#define SAMPLE_INTERVAL 1000          // in milliseconds
#define MAX_PACKETS 10000
#define WARNING_THRESHOLD_LOSS 5.0    // 5% packet loss threshold for warning
#define WARNING_THRESHOLD_JITTER 20.0 // 20ms jitter threshold for warning
#define CRITICAL_THRESHOLD_LOSS 10.0  // 10% packet loss threshold for critical
#define CRITICAL_THRESHOLD_JITTER 50.0 // 50ms jitter threshold for critical

// Network traffic classification types
typedef enum {
    TRAFFIC_UNKNOWN,
    TRAFFIC_WEB,
    TRAFFIC_VIDEO_STREAMING,
    TRAFFIC_GAMING,
    TRAFFIC_VOIP,
    TRAFFIC_FILE_TRANSFER,
    TRAFFIC_DATABASE,
    TRAFFIC_TYPES_COUNT
} TrafficType;

// Traffic classification thresholds
struct {
    const char *name;
    int common_ports[5];
    double typical_jitter;
    double max_acceptable_loss;
} traffic_profiles[] = {
    { "Unknown", {0}, 0.0, 0.0 },
    { "Web Traffic", {80, 443, 8080, 8443, 0}, 50.0, 1.0 },
    { "Video Streaming", {554, 1935, 5000, 5001, 0}, 30.0, 2.0 },
    { "Gaming", {3074, 3478, 3658, 27015, 0}, 10.0, 0.5 },
    { "VoIP", {5060, 5061, 16384, 16397, 0}, 15.0, 1.0 },
    { "File Transfer", {20, 21, 22, 989, 990}, 100.0, 5.0 },
    { "Database", {1433, 1521, 3306, 5432, 0}, 20.0, 0.1 }
};

// Global variables
volatile int running = 1;
char *interface = DEFAULT_INTERFACE;
pcap_dumper_t *pcap_dumper = NULL;
pcap_t *pcap_handle = NULL;
FILE *metrics_file = NULL;
pthread_t cli_thread;
pthread_mutex_t metrics_mutex = PTHREAD_MUTEX_INITIALIZER;
int verbose_output = 0;
int classification_enabled = 1;
int warning_enabled = 1;
TrafficType detected_traffic_type = TRAFFIC_UNKNOWN;

// Traffic statistics per type
struct {
    unsigned long packets;
    unsigned long bytes;
} traffic_stats[TRAFFIC_TYPES_COUNT] = {0};

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
    double current_packet_loss;
    double current_jitter;
    unsigned long tcp_packets;
    unsigned long udp_packets;
    unsigned long icmp_packets;
    unsigned long other_packets;
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
void *cli_handler(void *arg);
void classify_network_traffic();
void check_network_health();
void print_help_command();
void generate_traffic_report();
TrafficType identify_traffic_type(int port, int protocol);
void classify_packet(struct iphdr *ip, int protocol, int size);

// Main function
int main(int argc, char *argv[]) {
    int sock_raw;
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    unsigned char *buffer = (unsigned char *)malloc(PACKET_BUFFER_SIZE);
    int option;
    
    // Parse command line arguments
    while ((option = getopt(argc, argv, "i:hvdw")) != -1) {
        switch (option) {
            case 'i':
                interface = optarg;
                break;
            case 'h':
                print_usage();
                return 0;
            case 'v':
                verbose_output = 1;
                break;
            case 'd':
                classification_enabled = 0;
                break;
            case 'w':
                warning_enabled = 0;
                break;
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
    fprintf(metrics_file, "Timestamp,Packets Received,Packets Dropped,Bytes Received,Packet Loss %%,Jitter (ms),Traffic Type\n");
    
    // Initialize timing metrics
    clock_gettime(CLOCK_MONOTONIC, &metrics.last_packet_time);
    
    // Start CLI thread
    if (pthread_create(&cli_thread, NULL, cli_handler, NULL) != 0) {
        perror("Failed to create CLI thread");
        exit(1);
    }
    
    printf("Network monitoring started. Type 'help' for available commands.\n");
    
    // Main packet capture loop
    while (running) {
        int packet_size = recvfrom(sock_raw, buffer, PACKET_BUFFER_SIZE, 0, &saddr, (socklen_t *)&saddr_len);
        
        if (packet_size < 0) {
            if (verbose_output) printf("Failed to receive packet\n");
            continue;
        }
        
        process_packet(buffer, packet_size);
    }
    
    // Wait for CLI thread to finish
    pthread_cancel(cli_thread);
    pthread_join(cli_thread, NULL);
    
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
    generate_traffic_report();
    
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
    
    pthread_mutex_lock(&metrics_mutex);
    
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
    
    pthread_mutex_unlock(&metrics_mutex);
    
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
        
        pthread_mutex_lock(&metrics_mutex);
        // Track packets per interval for loss detection
        if (metrics.interval_count < MAX_PACKETS) {
            metrics.packet_count_per_interval[metrics.interval_count++] = metrics.packets_received;
        }
        pthread_mutex_unlock(&metrics_mutex);
        
        // Check network health
        if (warning_enabled) {
            check_network_health();
        }
    }
    
    // Parse Ethernet header
    struct ethhdr *eth = (struct ethhdr *)buffer;
    
    // Print basic packet info (for debugging)
    if (verbose_output && metrics.packets_received % 1000 == 0) {
        printf("Packet #%lu: Size = %d bytes, Protocol = 0x%x\n", 
            metrics.packets_received, size, ntohs(eth->h_proto));
    }
    
    // Parse IP header if it's an IP packet
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        
        pthread_mutex_lock(&metrics_mutex);
        // Update protocol-specific counters
        if (ip->protocol == IPPROTO_TCP) {
            metrics.tcp_packets++;
            struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
            
            if (classification_enabled) {
                classify_packet(ip, IPPROTO_TCP, size);
            }
            
            if (verbose_output && metrics.packets_received % 1000 == 0) {
                printf("  TCP Packet - Source: %s:%d, Destination: %s:%d\n", 
                    inet_ntoa(*(struct in_addr *)&ip->saddr), ntohs(tcp->source),
                    inet_ntoa(*(struct in_addr *)&ip->daddr), ntohs(tcp->dest));
            }
        } 
        else if (ip->protocol == IPPROTO_UDP) {
            metrics.udp_packets++;
            struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
            
            if (classification_enabled) {
                classify_packet(ip, IPPROTO_UDP, size);
            }
            
            if (verbose_output && metrics.packets_received % 1000 == 0) {
                printf("  UDP Packet - Source: %s:%d, Destination: %s:%d\n", 
                    inet_ntoa(*(struct in_addr *)&ip->saddr), ntohs(udp->source),
                    inet_ntoa(*(struct in_addr *)&ip->daddr), ntohs(udp->dest));
            }
        }
        else if (ip->protocol == IPPROTO_ICMP) {
            metrics.icmp_packets++;
        }
        else {
            metrics.other_packets++;
        }
        pthread_mutex_unlock(&metrics_mutex);
    }
}

// Classify a packet based on protocol and port
void classify_packet(struct iphdr *ip, int protocol, int size) {
    int src_port = 0, dst_port = 0;
    
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)ip + (ip->ihl * 4));
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
    }
    else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((unsigned char *)ip + (ip->ihl * 4));
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    }
    
    // Identify traffic type based on port
    TrafficType src_type = identify_traffic_type(src_port, protocol);
    TrafficType dst_type = identify_traffic_type(dst_port, protocol);
    
    // Choose the more specific type (not UNKNOWN)
    TrafficType type = (src_type != TRAFFIC_UNKNOWN) ? src_type : dst_type;
    
    // Update traffic statistics
    traffic_stats[type].packets++;
    traffic_stats[type].bytes += size;
    
    // Update most frequent traffic type
    static unsigned long max_packets = 0;
    if (traffic_stats[type].packets > max_packets) {
        max_packets = traffic_stats[type].packets;
        detected_traffic_type = type;
    }
}

// Identify traffic type based on port and protocol
TrafficType identify_traffic_type(int port, int protocol) {
    for (int i = 1; i < TRAFFIC_TYPES_COUNT; i++) {
        for (int j = 0; j < 5; j++) {
            if (traffic_profiles[i].common_ports[j] == 0) {
                break;
            }
            if (port == traffic_profiles[i].common_ports[j]) {
                return i;
            }
        }
    }
    
    // Some special cases based on port ranges
    if (port >= 16384 && port <= 16482) {
        return TRAFFIC_VOIP; // RTP/RTCP port range
    }
    if (port >= 27000 && port <= 27050) {
        return TRAFFIC_GAMING; // Steam and other game servers
    }
    if (port >= 49152 && port <= 65535) {
        // Ephemeral ports, can't determine accurately
        return TRAFFIC_UNKNOWN;
    }
    
    return TRAFFIC_UNKNOWN;
}

// Check network health and issue warnings
void check_network_health() {
    pthread_mutex_lock(&metrics_mutex);
    double packet_loss = metrics.current_packet_loss;
    double jitter = metrics.current_jitter;
    TrafficType traffic_type = detected_traffic_type;
    pthread_mutex_unlock(&metrics_mutex);
    
    // Get traffic profile for detected traffic
    double acceptable_loss = traffic_profiles[traffic_type].max_acceptable_loss;
    double acceptable_jitter = traffic_profiles[traffic_type].typical_jitter;
    
    // Use default thresholds if traffic type is unknown
    if (traffic_type == TRAFFIC_UNKNOWN) {
        acceptable_loss = WARNING_THRESHOLD_LOSS;
        acceptable_jitter = WARNING_THRESHOLD_JITTER;
    }
    
    // Check for warnings and critical issues
    if (packet_loss > CRITICAL_THRESHOLD_LOSS || 
        (traffic_type != TRAFFIC_UNKNOWN && packet_loss > acceptable_loss * 2)) {
        printf("\033[1;31m[CRITICAL] Severe packet loss detected: %.2f%% (Acceptable: %.2f%%)\033[0m\n", 
               packet_loss, acceptable_loss);
    } 
    else if (packet_loss > WARNING_THRESHOLD_LOSS || 
             (traffic_type != TRAFFIC_UNKNOWN && packet_loss > acceptable_loss)) {
        printf("\033[1;33m[WARNING] Packet loss detected: %.2f%% (Acceptable: %.2f%%)\033[0m\n", 
               packet_loss, acceptable_loss);
    }
    
    if (jitter > CRITICAL_THRESHOLD_JITTER || 
        (traffic_type != TRAFFIC_UNKNOWN && jitter > acceptable_jitter * 2)) {
        printf("\033[1;31m[CRITICAL] High jitter detected: %.2f ms (Acceptable: %.2f ms)\033[0m\n", 
               jitter, acceptable_jitter);
    } 
    else if (jitter > WARNING_THRESHOLD_JITTER || 
             (traffic_type != TRAFFIC_UNKNOWN && jitter > acceptable_jitter)) {
        printf("\033[1;33m[WARNING] Elevated jitter detected: %.2f ms (Acceptable: %.2f ms)\033[0m\n", 
               jitter, acceptable_jitter);
    }
    
    // Issue traffic-specific warnings
    if (traffic_type != TRAFFIC_UNKNOWN) {
        printf("Detected primary traffic type: %s\n", traffic_profiles[traffic_type].name);
        
        // Specific recommendations based on traffic type
        if (traffic_type == TRAFFIC_GAMING && jitter > acceptable_jitter) {
            printf("\033[1;33m[WARNING] High jitter may cause lag in games\033[0m\n");
        } 
        else if (traffic_type == TRAFFIC_VOIP && (packet_loss > acceptable_loss || jitter > acceptable_jitter)) {
            printf("\033[1;33m[WARNING] Network conditions may cause poor call quality\033[0m\n");
        }
        else if (traffic_type == TRAFFIC_VIDEO_STREAMING && packet_loss > acceptable_loss) {
            printf("\033[1;33m[WARNING] Packet loss may cause video buffering or quality reduction\033[0m\n");
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
    pthread_mutex_lock(&metrics_mutex);
    
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
    
    // Store current packet loss for warning system
    metrics.current_packet_loss = packet_loss;
    
    // Calculate average jitter in milliseconds
    double avg_jitter = metrics.jitter_count > 0 ? metrics.jitter_sum / metrics.jitter_count : 0;
    metrics.current_jitter = avg_jitter;
    
    pthread_mutex_unlock(&metrics_mutex);
    
    // Write metrics to file
    time_t current_time_t = current_time->tv_sec;
    struct tm *timeinfo = localtime(&current_time_t);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    fprintf(metrics_file, "%s,%lu,%lu,%lu,%.2f,%.2f,%s\n", 
            timestamp, metrics.packets_received, metrics.packets_dropped, 
            metrics.bytes_received, packet_loss, avg_jitter,
            traffic_profiles[detected_traffic_type].name);
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
    
    // Display protocol distribution
    pthread_mutex_lock(&metrics_mutex);
    unsigned long total = metrics.tcp_packets + metrics.udp_packets + 
                         metrics.icmp_packets + metrics.other_packets;
    
    if (total > 0) {
        printf("Protocol Distribution: TCP: %.1f%%, UDP: %.1f%%, ICMP: %.1f%%, Other: %.1f%%\n",
            (double)metrics.tcp_packets / total * 100.0,
            (double)metrics.udp_packets / total * 100.0,
            (double)metrics.icmp_packets / total * 100.0,
            (double)metrics.other_packets / total * 100.0);
    }
    pthread_mutex_unlock(&metrics_mutex);
    
    printf("Primary Traffic Type: %s\n", traffic_profiles[detected_traffic_type].name);
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
    printf("Usage: network_monitor [-i interface] [-v] [-d] [-w]\n");
    printf("Options:\n");
    printf("  -i <interface>  Network interface to monitor (default: %s)\n", DEFAULT_INTERFACE);
    printf("  -v              Enable verbose output\n");
    printf("  -d              Disable traffic classification\n");
    printf("  -w              Disable warnings\n");
    printf("  -h              Display this help message\n");
    printf("\n");
    printf("In the interactive CLI, type 'help' for available commands.\n");
}

// Analyze packet loss patterns
void analyze_packet_loss() {
    printf("\n=== Packet Loss Analysis ===\n");
    
    pthread_mutex_lock(&metrics_mutex);
    if (metrics.interval_count < 2) {
        printf("Not enough data collected for analysis.\n");
        pthread_mutex_unlock(&metrics_mutex);
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
    
    int interval_count = metrics.interval_count;
    pthread_mutex_unlock(&metrics_mutex);
    
    printf("Total intervals with significant packet loss: %d of %d (%.1f%%)\n", 
           loss_count, interval_count, 
           (double)loss_count / interval_count * 100);
    printf("Longest continuous period of packet loss: %d intervals (%.1f seconds)\n", 
           max_loss_period, max_loss_period * (SAMPLE_INTERVAL / 1000.0));
    
    if (loss_count > interval_count * 0.1) {
        printf("\033[1;31mALERT: Network experiencing significant packet loss!\033[0m\n");
    } else {
        printf("\033[1;32mNetwork packet loss is within acceptable limits.\033[0m\n");
    }
}

// Analyze jitter patterns
void analyze_jitter() {
    printf("\n=== Jitter Analysis ===\n");
    
    pthread_mutex_lock(&metrics_mutex);
    if (metrics.jitter_count < 10) {
        printf("Not enough data collected for jitter analysis.\n");
        pthread_mutex_unlock(&metrics_mutex);
        return;
    }
    
    double avg_jitter = metrics.jitter_sum / metrics.jitter_count;
    pthread_mutex_unlock(&metrics_mutex);
    
    printf("Average jitter: %.2f ms\n", avg_jitter);
    
    if (avg_jitter > 50) {
        printf("\033[1;31mALERT: High jitter detected! This may affect real-time applications.\033[0m\n");
    } else if (avg_jitter > 20) {
        printf("\033[1;33mWARNING: Moderate jitter detected. Monitor for impact on real-time applications.\033[0m\n");
    } else {
        printf("\033[1;32mJitter levels are acceptable for most applications.\033[0m\n");
    }
    
    // In a real implementation, would analyze jitter variance and patterns
    printf("For detailed jitter analysis, examine the captured pcap");
}

// Start Wireshark for deeper analysis
void start_wireshark_analysis() {
    printf("Starting Wireshark for deeper packet analysis...\n");
    
    // Get the pcap file name (assuming it's the most recent one)
    system("ls -t capture_*.pcap | head -1 > /tmp/pcap_file.txt");
    
    FILE *file = fopen("/tmp/pcap_file.txt", "r");
    if (!file) {
        printf("Error: Could not find capture file.\n");
        return;
    }
    
    char pcap_file[256];
    if (fgets(pcap_file, sizeof(pcap_file), file) == NULL) {
        printf("Error: Could not read capture file name.\n");
        fclose(file);
        return;
    }
    fclose(file);
    
    // Remove newline character
    pcap_file[strcspn(pcap_file, "\n")] = 0;
    
    // Check if Wireshark is available
    if (system("which wireshark > /dev/null 2>&1") != 0) {
        printf("Wireshark is not installed. Please install it to view the captured packets.\n");
        printf("You can open the pcap file '%s' later with Wireshark.\n", pcap_file);
        return;
    }
    
    // Build command to open Wireshark with the capture file
    char command[512];
    snprintf(command, sizeof(command), "wireshark '%s' &", pcap_file);
    
    // Execute the command
    if (system(command) != 0) {
        printf("Failed to start Wireshark. You can open the pcap file '%s' manually.\n", pcap_file);
    }
}

// Generate traffic report
void generate_traffic_report() {
    printf("\n=== Traffic Analysis Report ===\n");
    
    pthread_mutex_lock(&metrics_mutex);
    
    // Calculate total packets and bytes
    unsigned long total_packets = 0;
    unsigned long total_bytes = 0;
    for (int i = 0; i < TRAFFIC_TYPES_COUNT; i++) {
        total_packets += traffic_stats[i].packets;
        total_bytes += traffic_stats[i].bytes;
    }
    
    // Skip report if no packets classified
    if (total_packets == 0) {
        printf("No traffic classified yet. Enable classification for detailed reports.\n");
        pthread_mutex_unlock(&metrics_mutex);
        return;
    }
    
    // Print traffic distribution
    printf("Traffic Type Distribution:\n");
    printf("-------------------------\n");
    printf("%-15s | %-10s | %-10s | %-8s\n", "Type", "Packets", "Bytes", "% Total");
    printf("-------------------------\n");
    
    for (int i = 0; i < TRAFFIC_TYPES_COUNT; i++) {
        if (traffic_stats[i].packets > 0) {
            double percentage = (double)traffic_stats[i].packets / total_packets * 100.0;
            printf("%-15s | %-10lu | %-10lu | %6.2f%%\n", 
                   traffic_profiles[i].name,
                   traffic_stats[i].packets,
                   traffic_stats[i].bytes,
                   percentage);
        }
    }
    
    // Identify dominant traffic type
    printf("\nDominant Traffic: %s (%.2f%% of packets)\n", 
           traffic_profiles[detected_traffic_type].name,
           (double)traffic_stats[detected_traffic_type].packets / total_packets * 100.0);
    
    // Network health evaluation based on traffic type
    double packet_loss = metrics.current_packet_loss;
    double jitter = metrics.current_jitter;
    
    printf("\nNetwork Quality for %s traffic:\n", traffic_profiles[detected_traffic_type].name);
    
    // Evaluate packet loss
    double acceptable_loss = traffic_profiles[detected_traffic_type].max_acceptable_loss;
    if (detected_traffic_type == TRAFFIC_UNKNOWN) {
        acceptable_loss = 1.0; // Default threshold
    }
    
    if (packet_loss <= acceptable_loss) {
        printf("Packet Loss: %.2f%% - \033[1;32mGOOD\033[0m (Threshold: %.2f%%)\n", 
               packet_loss, acceptable_loss);
    } else if (packet_loss <= acceptable_loss * 2) {
        printf("Packet Loss: %.2f%% - \033[1;33mFAIR\033[0m (Threshold: %.2f%%)\n", 
               packet_loss, acceptable_loss);
    } else {
        printf("Packet Loss: %.2f%% - \033[1;31mPOOR\033[0m (Threshold: %.2f%%)\n", 
               packet_loss, acceptable_loss);
    }
    
    // Evaluate jitter
    double acceptable_jitter = traffic_profiles[detected_traffic_type].typical_jitter;
    if (detected_traffic_type == TRAFFIC_UNKNOWN) {
        acceptable_jitter = 20.0; // Default threshold
    }
    
    if (jitter <= acceptable_jitter) {
        printf("Jitter: %.2f ms - \033[1;32mGOOD\033[0m (Threshold: %.2f ms)\n", 
               jitter, acceptable_jitter);
    } else if (jitter <= acceptable_jitter * 1.5) {
        printf("Jitter: %.2f ms - \033[1;33mFAIR\033[0m (Threshold: %.2f ms)\n", 
               jitter, acceptable_jitter);
    } else {
        printf("Jitter: %.2f ms - \033[1;31mPOOR\033[0m (Threshold: %.2f ms)\n", 
               jitter, acceptable_jitter);
    }
    
    pthread_mutex_unlock(&metrics_mutex);
    
    // Recommendations based on traffic type and quality
    printf("\nRecommendations:\n");
    if (detected_traffic_type == TRAFFIC_GAMING) {
        if (jitter > acceptable_jitter || packet_loss > acceptable_loss) {
            printf("- For gaming, try a wired connection instead of Wi-Fi\n");
            printf("- Check for background downloads affecting game performance\n");
            printf("- Consider QoS settings on your router to prioritize gaming traffic\n");
        }
    } else if (detected_traffic_type == TRAFFIC_VOIP) {
        if (jitter > acceptable_jitter || packet_loss > acceptable_loss) {
            printf("- For VoIP, ensure sufficient bandwidth (100+ Kbps per call)\n");
            printf("- Enable QoS for voice traffic on your router\n");
            printf("- Minimize network congestion during important calls\n");
        }
    } else if (detected_traffic_type == TRAFFIC_VIDEO_STREAMING) {
        if (packet_loss > acceptable_loss) {
            printf("- For video streaming, increase buffer size in your streaming apps\n");
            printf("- Consider reducing video quality to match available bandwidth\n");
            printf("- Check for bandwidth competition from other devices\n");
        }
    }
    
    printf("\nSee the network_metrics.csv file for detailed historical data.\n");
}

// CLI command handler thread
void *cli_handler(void *arg) {
    char *input;
    
    // Set up readline
    using_history();
    
    printf("CLI ready. Type 'help' for available commands.\n");
    
    while (running) {
        input = readline("network> ");
        if (input == NULL) {
            break;
        }
        
        // Skip empty lines
        if (*input) {
            add_history(input);
            
            // Process commands
            if (strcmp(input, "help") == 0) {
                print_help_command();
            }
            else if (strcmp(input, "stats") == 0) {
                pthread_mutex_lock(&metrics_mutex);
                printf("Packets captured: %lu\n", metrics.packets_received);
                printf("Bytes captured: %lu\n", metrics.bytes_received);
                printf("TCP packets: %lu\n", metrics.tcp_packets);
                printf("UDP packets: %lu\n", metrics.udp_packets);
                printf("ICMP packets: %lu\n", metrics.icmp_packets);
                printf("Other packets: %lu\n", metrics.other_packets);
                printf("Current packet loss: %.2f%%\n", metrics.current_packet_loss);
                printf("Current jitter: %.2f ms\n", metrics.current_jitter);
                printf("Detected traffic type: %s\n", traffic_profiles[detected_traffic_type].name);
                pthread_mutex_unlock(&metrics_mutex);
            }
            else if (strcmp(input, "analyze") == 0) {
                analyze_packet_loss();
                analyze_jitter();
            }
            else if (strcmp(input, "report") == 0) {
                generate_traffic_report();
            }
            else if (strcmp(input, "wireshark") == 0) {
                start_wireshark_analysis();
            }
            else if (strcmp(input, "verbose") == 0) {
                verbose_output = !verbose_output;
                printf("Verbose output: %s\n", verbose_output ? "enabled" : "disabled");
            }
            else if (strcmp(input, "classify") == 0) {
                classification_enabled = !classification_enabled;
                printf("Traffic classification: %s\n", classification_enabled ? "enabled" : "disabled");
            }
            else if (strcmp(input, "warnings") == 0) {
                warning_enabled = !warning_enabled;
                printf("Network warnings: %s\n", warning_enabled ? "enabled" : "disabled");
            }
            else if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0) {
                running = 0;
            }
            else {
                printf("Unknown command: %s\n", input);
                printf("Type 'help' for available commands.\n");
            }
        }
        
        free(input);
    }
    
    return NULL;
}

// Print help for CLI commands
void print_help_command() {
    printf("\nAvailable commands:\n");
    printf("  help      - Display this help message\n");
    printf("  stats     - Show current network statistics\n");
    printf("  analyze   - Run packet loss and jitter analysis\n");
    printf("  report    - Generate traffic analysis report\n");
    printf("  wireshark - Open captured packets in Wireshark\n");
    printf("  verbose   - Toggle verbose output\n");
    printf("  classify  - Toggle traffic classification\n");
    printf("  warnings  - Toggle network warnings\n");
    printf("  quit      - Exit the program\n");
    printf("\n");
}