#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    char *server_ip = "127.0.0.1";
    int port = 9410;

    if (argc >= 2) server_ip = argv[1];
    if (argc >= 3) port = atoi(argv[2]);

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid server address");
        close(sock_fd);
        return 1;
    }

    printf("Connecting to RemoteOps Agent at %s:%d...\n", server_ip, port);
    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock_fd);
        return 1;
    }

    printf("Connected! Type commands (e.g., AUTH OPS-3315, QUIT)\n");
    printf("----------------------------------------------------\n");

    char input[BUFFER_SIZE];
    char recv_buf[BUFFER_SIZE];

    while (1) {
        printf("RemoteOps> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }

        // Send command to Agent (includes \n)
        if (send(sock_fd, input, strlen(input), 0) < 0) {
            perror("Send failed");
            break;
        }

        // Receive response line from Agent
        memset(recv_buf, 0, sizeof(recv_buf));
        int bytes = recv(sock_fd, recv_buf, sizeof(recv_buf) - 1, 0);
        if (bytes <= 0) {
            printf("[!] Server closed connection.\n");
            break;
        }

        printf("%s", recv_buf);

        // If user typed QUIT and server replied OK BYE
        if (strncmp(input, "QUIT", 4) == 0) {
            break;
        }
    }

    close(sock_fd);
    printf("Disconnected from Agent.\n");
    return 0;
}
