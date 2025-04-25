// client.c
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

#define BUFFER_SIZE 1024
#define NAME_LENGTH 32

char name[NAME_LENGTH];
int sock = 0;
volatile int connected = 0;

void *receive_messages(void *arg) {
    char buffer[BUFFER_SIZE];
    int read_size;

    while ((read_size = recv(sock, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[read_size] = '\0';
        printf("%s", buffer);
    }
    
    if (read_size == 0) {
        printf("Server disconnected\n");
    } else if (read_size == -1) {
        perror("recv failed");
    }
    
    connected = 0;
    
    return NULL;
}

void cleanup() {
    if (connected) {
        close(sock);
        connected = 0;
    }
    printf("Client terminated\n");
}

int main(int argc, char *argv[]) {
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];
    pthread_t thread_id;
    char server_ip[16];
    int server_port;
    
    // Register cleanup function
    atexit(cleanup);
    signal(SIGINT, exit);

    // Check command line arguments
    if (argc < 3) {
        printf("Usage: %s <server_ip> <port>\n", argv[0]);
        printf("Example: %s 192.168.1.100 8080\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    // Parse command line arguments
    strncpy(server_ip, argv[1], 15);
    server_ip[15] = '\0';
    server_port = atoi(argv[2]);
    
    // Get user name
    printf("Enter your name: ");
    fgets(name, NAME_LENGTH, stdin);
    // Remove newline
    name[strcspn(name, "\n")] = '\0';

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Prepare the server address structure
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);
    
    if(inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    printf("Connecting to server at %s:%d...\n", server_ip, server_port);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    connected = 1;
    printf("Connected to server\n");

    // Create thread to receive messages
    if (pthread_create(&thread_id, NULL, receive_messages, NULL) < 0) {
        perror("Thread creation failed");
        exit(EXIT_FAILURE);
    }

    // Send initial message with user's name
    sprintf(buffer, "%s has joined the chat\n", name);
    if (send(sock, buffer, strlen(buffer), 0) < 0) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }

    // Send messages
    printf("Start typing messages (press Enter to send):\n");
    while(connected) {
        fgets(buffer, BUFFER_SIZE, stdin);
        
        // Add name to message
        char message[BUFFER_SIZE + NAME_LENGTH + 3];
        sprintf(message, "%s: %s", name, buffer);
        
        if (send(sock, message, strlen(message), 0) < 0) {
            perror("Send failed");
            break;
        }
    }

    exit(0);
}