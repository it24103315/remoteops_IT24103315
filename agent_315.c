#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 9410
#define BUFFER_SIZE 1024

int main() {

    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // 1. Create TCP socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    // 2. Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // 3. Bind socket to port 9410
    if (bind(server_fd,
             (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {

        perror("bind");
        close(server_fd);
        return 1;
    }

    // 4. Start listening
    if (listen(server_fd, 5) < 0) {

        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("=================================\n");
    printf("       RemoteOps Agent\n");
    printf("=================================\n");
    printf("Registration : IT24103315\n");
    printf("TCP Port     : 9410\n");
    printf("SID          : 5133\n");
    printf("Agent listening on port 9410...\n");

    // 5. Accept one client
    client_fd = accept(server_fd,
                       (struct sockaddr *)&client_addr,
                       &client_len);

    if (client_fd < 0) {
        perror("accept");
        close(server_fd);
        return 1;
    }

    printf("Controller connected!\n");

    // 6. Receive data
    memset(buffer, 0, BUFFER_SIZE);

    int bytes_received = recv(client_fd,
                              buffer,
                              BUFFER_SIZE - 1,
                              0);

    if (bytes_received > 0) {

        printf("Received: %s\n", buffer);

        // 7. Send response
        char response[] = "RemoteOps Agent received your message\n";

        send(client_fd,
             response,
             strlen(response),
             0);
    }

    // 8. Close connection
    close(client_fd);
    close(server_fd);

    return 0;
}
