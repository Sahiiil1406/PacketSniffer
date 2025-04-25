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

#define PORT 8080
#define BUFFER_SIZE 1024
#define SERVER_IP "127.0.0.1"

void *receive_messages(void *socket_desc) {
    int sock = *(int*)socket_desc;
    char buffer[BUFFER_SIZE];
    int read_size;

    while((read_size = recv(sock, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[read_size] = '\0';
        printf("Server: %s", buffer);
    }
    
    if(read_size == 0) {
        printf("Server disconnected\n");
    } else if(read_size == -1) {
        perror("recv failed");
    }
    
    return NULL;
}

int main() {
    int sock = 0, *new_sock;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];
    pthread_t thread_id;

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Prepare the server address structure
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server\n");

    // Create thread to receive messages
    new_sock = malloc(sizeof(int));
    *new_sock = sock;
    if (pthread_create(&thread_id, NULL, receive_messages, (void*) new_sock) < 0) {
        perror("Thread creation failed");
        exit(EXIT_FAILURE);
    }

    // Send messages
    while(1) {
        fgets(buffer, BUFFER_SIZE, stdin);
        if (send(sock, buffer, strlen(buffer), 0) < 0) {
            perror("Send failed");
            break;
        }
    }

    // Close the socket
    close(sock);
    return 0;
}