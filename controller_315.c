#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFFER_SIZE 4096

int recv_line(int sock, char *buf, int max_len) {
    int idx = 0;
    while (idx < max_len - 1) {
        char c;
        int n = recv(sock, &c, 1, 0);
        if (n <= 0) return -1;
        if (c == '\r') continue;
        if (c == '\n') break;
        buf[idx++] = c;
    }
    buf[idx] = '\0';
    return idx;
}

// Background thread listening for UDP Telemetry datagrams
typedef struct {
    int udp_port;
    volatile int running;
} udp_listener_t;

void *udp_listener_thread(void *arg) {
    udp_listener_t *listener = (udp_listener_t *)arg;
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) return NULL;

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons(listener->udp_port);

    if (bind(udp_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        close(udp_sock);
        return NULL;
    }

    char buf[512];
    while (listener->running) {
        struct sockaddr_in sender;
        socklen_t slen = sizeof(sender);
        int r = recvfrom(udp_sock, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&sender, &slen);
        if (r > 0) {
            buf[r] = '\0';
            printf("\n[UDP TELEMETRY] %s", buf);
            printf("RemoteOps> ");
            fflush(stdout);
        }
    }
    close(udp_sock);
    return NULL;
}

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

    printf("Connected! Available commands: AUTH, SYSINFO, LISTPROC, EXEC, PUT, GET, MONITOR START <port>, MONITOR STOP, QUIT\n");
    printf("--------------------------------------------------------------------------------------------------------\n");

    char input[BUFFER_SIZE];
    char recv_buf[BUFFER_SIZE];

    udp_listener_t ulistener;
    ulistener.running = 0;
    pthread_t utid = 0;

    while (1) {
        printf("RemoteOps> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin)) break;

        char cmd[BUFFER_SIZE];
        strcpy(cmd, input);
        size_t len = strlen(cmd);
        if (len > 0 && cmd[len - 1] == '\n') cmd[len - 1] = '\0';

        // === MONITOR START HANDLING ===
        if (strncmp(cmd, "MONITOR START ", 14) == 0) {
            int uport = atoi(cmd + 14);
            if (uport > 0) {
                if (ulistener.running) {
                    ulistener.running = 0;
                    pthread_cancel(utid);
                }
                ulistener.udp_port = uport;
                ulistener.running = 1;
                pthread_create(&utid, NULL, udp_listener_thread, &ulistener);
            }
        } else if (strcmp(cmd, "MONITOR STOP") == 0) {
            if (ulistener.running) {
                ulistener.running = 0;
                pthread_cancel(utid);
                utid = 0;
            }
        }
        // === PUT HANDLING ===
        else if (strncmp(cmd, "PUT ", 4) == 0) {
            char fname[256];
            if (sscanf(cmd + 4, "%255s", fname) == 1) {
                FILE *fp = fopen(fname, "rb");
                if (!fp) {
                    printf("[!] Local file not found: %s\n", fname);
                    continue;
                }
                fseek(fp, 0, SEEK_END);
                long fsize = ftell(fp);
                fseek(fp, 0, SEEK_SET);

                char put_cmd[512];
                snprintf(put_cmd, sizeof(put_cmd), "PUT %s %ld\n", fname, fsize);
                send(sock_fd, put_cmd, strlen(put_cmd), 0);

                char file_buf[BUFFER_SIZE];
                size_t r;
                while ((r = fread(file_buf, 1, sizeof(file_buf), fp)) > 0) {
                    send(sock_fd, file_buf, r, 0);
                }
                fclose(fp);

                if (recv_line(sock_fd, recv_buf, sizeof(recv_buf)) > 0) {
                    printf("%s\n", recv_buf);
                }
                continue;
            }
        }
        // === GET HANDLING ===
        else if (strncmp(cmd, "GET ", 4) == 0) {
            char fname[256];
            if (sscanf(cmd + 4, "%255s", fname) == 1) {
                send(sock_fd, input, strlen(input), 0);

                if (recv_line(sock_fd, recv_buf, sizeof(recv_buf)) > 0) {
                    printf("%s\n", recv_buf);

                    if (strncmp(recv_buf, "OK FILE_SEND ", 13) == 0) {
                        char resp_fname[256];
                        long fsize = 0;
                        sscanf(recv_buf + 13, "%255s %ld", resp_fname, &fsize);

                        char save_as[512];
                        snprintf(save_as, sizeof(save_as), "downloaded_%s", fname);
                        FILE *fp = fopen(save_as, "wb");
                        if (fp) {
                            long remaining = fsize;
                            char file_buf[BUFFER_SIZE];
                            while (remaining > 0) {
                                int to_read = remaining > BUFFER_SIZE ? BUFFER_SIZE : (int)remaining;
                                int n = recv(sock_fd, file_buf, to_read, 0);
                                if (n <= 0) break;
                                fwrite(file_buf, 1, n, fp);
                                remaining -= n;
                            }
                            fclose(fp);
                            printf("[+] Successfully saved downloaded file as '%s' (%ld bytes)\n", save_as, fsize);
                        }
                    }
                }
                continue;
            }
        }

        // Send normal command
        if (send(sock_fd, input, strlen(input), 0) < 0) break;

        if (recv_line(sock_fd, recv_buf, sizeof(recv_buf)) <= 0) {
            printf("[!] Server closed connection.\n");
            break;
        }
        printf("%s\n", recv_buf);

        if (strncmp(input, "QUIT", 4) == 0) break;
    }

    if (ulistener.running) {
        ulistener.running = 0;
        pthread_cancel(utid);
    }

    close(sock_fd);
    printf("Disconnected from Agent.\n");
    return 0;
}
