#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 9410
#define SID_TAG "SID:5133"
#define AUTH_TOKEN "OPS-3315"
#define LOG_FILE "remoteops_IT24103315.log"
#define BUFFER_SIZE 1024

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Logger Function (Thread-Safe)
void write_log(const char *client_ip, int client_port, const char *action, const char *details) {
    pthread_mutex_lock(&log_mutex);
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        time_t now = time(NULL);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(f, "[%s] [%s:%d] %s: %s\n", time_str, client_ip, client_port, action, details);
        fclose(f);
    }
    pthread_mutex_unlock(&log_mutex);
}

// Client Connection Info Structure
typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
} client_info_t;

// Per-Client Thread Handler
void *handle_client(void *arg) {
    client_info_t *info = (client_info_t *)arg;
    int client_fd = info->client_fd;
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->client_addr.sin_addr, client_ip, sizeof(client_ip));
    int client_port = ntohs(info->client_addr.sin_port);
    free(info);

    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), "Connected to Agent on port %d", PORT);
    write_log(client_ip, client_port, "CONNECT", log_buf);
    printf("[+] Client connected from %s:%d\n", client_ip, client_port);

    int is_authenticated = 0;
    char recv_buf[BUFFER_SIZE];
    char line_buf[BUFFER_SIZE];
    int line_len = 0;

    while (1) {
        memset(recv_buf, 0, sizeof(recv_buf));
        int bytes = recv(client_fd, recv_buf, sizeof(recv_buf) - 1, 0);
        if (bytes <= 0) {
            // Client disconnected or error
            break;
        }

        // Line-based Framing (accumulate until '\n')
        for (int i = 0; i < bytes; i++) {
            char c = recv_buf[i];
            if (c == '\r') continue; // Ignore carriage return
            if (c == '\n') {
                line_buf[line_len] = '\0';
                
                // Trim trailing spaces
                while (line_len > 0 && line_buf[line_len - 1] == ' ') {
                    line_buf[--line_len] = '\0';
                }

                if (line_len > 0) {
                    write_log(client_ip, client_port, "COMMAND", line_buf);
                    printf("[%s:%d] Command received: %s\n", client_ip, client_port, line_buf);

                    char response[BUFFER_SIZE];
                    memset(response, 0, sizeof(response));

                    // Command Dispatching
                    if (strncmp(line_buf, "AUTH ", 5) == 0) {
                        char *token = line_buf + 5;
                        if (strcmp(token, AUTH_TOKEN) == 0) {
                            is_authenticated = 1;
                            snprintf(response, sizeof(response), "OK AUTHENTICATED %s\n", SID_TAG);
                            write_log(client_ip, client_port, "AUTH", "Success");
                        } else {
                            snprintf(response, sizeof(response), "ERR 001 AUTH_FAILED %s\n", SID_TAG);
                            write_log(client_ip, client_port, "AUTH", "Failed token");
                        }
                    } else if (strcmp(line_buf, "QUIT") == 0) {
                        snprintf(response, sizeof(response), "OK BYE %s\n", SID_TAG);
                        send(client_fd, response, strlen(response), 0);
                        write_log(client_ip, client_port, "DISCONNECT", "Graceful QUIT");
                        goto cleanup;
                    } else if (!is_authenticated) {
                        snprintf(response, sizeof(response), "ERR 001 AUTH_REQUIRED %s\n", SID_TAG);
                        write_log(client_ip, client_port, "ERROR", "Command rejected: Not authenticated");
                    } else {
                        // Placeholders for next features (SYSINFO, LISTPROC, EXEC, etc.)
                        snprintf(response, sizeof(response), "ERR 999 NOT_IMPLEMENTED_YET %s\n", SID_TAG);
                    }

                    send(client_fd, response, strlen(response), 0);
                }
                line_len = 0;
            } else {
                if (line_len < BUFFER_SIZE - 1) {
                    line_buf[line_len++] = c;
                }
            }
        }
    }

cleanup:
    write_log(client_ip, client_port, "DISCONNECT", "Connection closed");
    printf("[-] Client disconnected %s:%d\n", client_ip, client_port);
    close(client_fd);
    return NULL;
}

int main() {
    int server_fd;
    struct sockaddr_in server_addr;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("====================================================\n");
    printf("   RemoteOps Agent Started (Multi-threaded)\n");
    printf("   Registration Number : IT24103315\n");
    printf("   Listening Port      : %d\n", PORT);
    printf("   Session ID Tag      : %s\n", SID_TAG);
    printf("   Auth Token          : %s\n", AUTH_TOKEN);
    printf("   Log File            : %s\n", LOG_FILE);
    printf("====================================================\n");
    printf("Agent is ready and listening for connections...\n");

    while (1) {
        client_info_t *info = malloc(sizeof(client_info_t));
        socklen_t addr_len = sizeof(info->client_addr);
        info->client_fd = accept(server_fd, (struct sockaddr *)&info->client_addr, &addr_len);

        if (info->client_fd < 0) {
            free(info);
            continue;
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, info) != 0) {
            perror("Failed to create thread");
            close(info->client_fd);
            free(info);
        } else {
            pthread_detach(tid); // Automatically reclaim thread resources
        }
    }

    close(server_fd);
    return 0;
}
