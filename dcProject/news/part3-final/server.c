// server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>  // Added for struct hostent and gethostbyname()
#include <ifaddrs.h> // Added for getifaddrs()

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

typedef struct {
    int socket;
    int id;
    struct sockaddr_in address;
} client_t;

client_t *clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
int client_count = 0;

void add_client(client_t *client) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] == NULL) {
            clients[i] = client;
            break;
        }
    }
    client_count++;
    pthread_mutex_unlock(&clients_mutex);
}

void remove_client(int id) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->id == id) {
            clients[i] = NULL;
            break;
        }
    }
    client_count--;
    pthread_mutex_unlock(&clients_mutex);
}

void send_message_to_all(char *message, int sender_id) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->id != sender_id) {
            if (send(clients[i]->socket, message, strlen(message), 0) < 0) {
                perror("Send failed");
                break;
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

void *handle_client(void *arg) {
    client_t *client = (client_t *)arg;
    char buffer[BUFFER_SIZE];
    char message[BUFFER_SIZE + 30];
    int read_size;

    // Notify all clients about the new connection
    sprintf(message, "Client %d (%s:%d) has joined\n", 
            client->id, 
            inet_ntoa(client->address.sin_addr), 
            ntohs(client->address.sin_port));
    printf("%s", message);
    send_message_to_all(message, client->id);

    // Receive messages from client
    while ((read_size = recv(client->socket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[read_size] = '\0';
        
        // Format message with client identifier
        sprintf(message, "Client %d: %s", client->id, buffer);
        printf("%s", message);
        
        // Send message to all other clients
        send_message_to_all(message, client->id);
    }

    // Client disconnected
    if (read_size == 0) {
        sprintf(message, "Client %d disconnected\n", client->id);
        printf("%s", message);
        send_message_to_all(message, client->id);
    } else if (read_size == -1) {
        perror("recv failed");
    }

    // Remove client and free memory
    close(client->socket);
    remove_client(client->id);
    free(client);
    
    return NULL;
}

void *server_input(void *arg) {
    char buffer[BUFFER_SIZE];
    char message[BUFFER_SIZE + 20];
    
    while (1) {
        fgets(buffer, BUFFER_SIZE, stdin);
        sprintf(message, "Server: %s", buffer);
        send_message_to_all(message, -1); // -1 as server ID
        printf("%s", message);
    }
    
    return NULL;
}

// Alternative function to print IP addresses using getifaddrs
void print_server_ip() {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }
    
    printf("Server IP addresses for clients to connect to:\n");
    
    // Walk through linked list
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
            
        family = ifa->ifa_addr->sa_family;
        
        // Only consider IPv4 addresses
        if (family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                           host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                continue;
            }
            
            // Skip loopback addresses
            if (strcmp(host, "127.0.0.1") != 0) {
                printf("- %s (interface: %s)\n", host, ifa->ifa_name);
            }
        }
    }
    
    freeifaddrs(ifaddr);
    printf("Port: %d\n", PORT);
}

int main() {
    int server_fd;
    struct sockaddr_in server_addr;
    pthread_t thread_id, input_thread;

    // Ignore SIGPIPE signal to prevent termination when a client disconnects
    signal(SIGPIPE, SIG_IGN);

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Prepare the server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind the socket to the network address and port
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server started. Waiting for connections...\n");
    
    // Display server IP addresses
    print_server_ip();

    // Create thread for server input
    if (pthread_create(&input_thread, NULL, server_input, NULL) < 0) {
        perror("Thread creation failed");
        exit(EXIT_FAILURE);
    }

    // Accept incoming connections
    int client_id = 1;
    while (1) {
        client_t *client = (client_t *)malloc(sizeof(client_t));
        int addr_len = sizeof(client->address);
        
        // Accept connection
        if ((client->socket = accept(server_fd, (struct sockaddr *)&client->address, (socklen_t*)&addr_len)) < 0) {
            perror("Accept failed");
            free(client);
            continue;
        }
        
        // Set client ID and add to list
        client->id = client_id++;
        add_client(client);
        
        printf("New connection: Client %d from %s:%d\n", 
               client->id, 
               inet_ntoa(client->address.sin_addr), 
               ntohs(client->address.sin_port));
        
        // Create thread to handle client
        if (pthread_create(&thread_id, NULL, handle_client, (void*)client) < 0) {
            perror("Thread creation failed");
            remove_client(client->id);
            free(client);
            continue;
        }
        
        // Detach thread to auto-cleanup
        pthread_detach(thread_id);
    }

    // Close server socket
    close(server_fd);
    return 0;
}