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

#define PORT 8080
#define BUFFER_SIZE 1024

void *receive_messages(void *socket_desc) {
    int sock = *(int*)socket_desc;
    char buffer[BUFFER_SIZE];
    int read_size;

    while((read_size = recv(sock, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[read_size] = '\0';
        printf("Client: %s", buffer);
    }
    
    if(read_size == 0) {
        printf("Client disconnected\n");
    } else if(read_size == -1) {
        perror("recv failed");
    }
    
    return NULL;
}

int main() {
    int server_fd, client_sock, *new_sock;
    struct sockaddr_in server_addr, client_addr;
    int addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    pthread_t thread_id;

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
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server started. Waiting for connections...\n");

    // Accept an incoming connection
    if ((client_sock = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t*)&addr_len)) < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    printf("Connection accepted from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // Create thread to receive messages
    new_sock = malloc(sizeof(int));
    *new_sock = client_sock;
    if (pthread_create(&thread_id, NULL, receive_messages, (void*) new_sock) < 0) {
        perror("Thread creation failed");
        exit(EXIT_FAILURE);
    }

    // Send messages
    while(1) {
        fgets(buffer, BUFFER_SIZE, stdin);
        if (send(client_sock, buffer, strlen(buffer), 0) < 0) {
            perror("Send failed");
            break;
        }
    }

    // Close the socket
    close(client_sock);
    close(server_fd);
    return 0;
}