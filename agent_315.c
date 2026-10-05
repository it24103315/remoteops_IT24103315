#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 9410
#define SID_TAG "SID:5133"
#define AUTH_TOKEN "OPS-3315"
#define LOG_FILE "remoteops_IT24103315.log"
#define STORAGE_DIR "./agentfiles/IT24103315"
#define BUFFER_SIZE 4096
#define MAX_FILE_SIZE (10 * 1024 * 1024)

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

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

void get_sysinfo(char *output, size_t max_len) {
    double load = 0.0;
    FILE *f_load = fopen("/proc/loadavg", "r");
    if (f_load) {
        fscanf(f_load, "%lf", &load);
        fclose(f_load);
    }

    long total_mem = 0, free_mem = 0;
    FILE *f_mem = fopen("/proc/meminfo", "r");
    if (f_mem) {
        char line[128];
        while (fgets(line, sizeof(line), f_mem)) {
            if (strncmp(line, "MemTotal:", 9) == 0) sscanf(line + 9, "%ld", &total_mem);
            if (strncmp(line, "MemAvailable:", 13) == 0) sscanf(line + 13, "%ld", &free_mem);
        }
        fclose(f_mem);
    }
    long used_mem_mb = (total_mem - free_mem) / 1024;
    if (used_mem_mb < 0) used_mem_mb = 0;

    long uptime_sec = 0;
    FILE *f_up = fopen("/proc/uptime", "r");
    if (f_up) {
        double up_val = 0;
        fscanf(f_up, "%lf", &up_val);
        uptime_sec = (long)up_val;
        fclose(f_up);
    }

    snprintf(output, max_len, "OK SYSINFO %.2f %ld %ld %s\n", load, used_mem_mb, uptime_sec, SID_TAG);
}

void get_listproc(char *output, size_t max_len) {
    FILE *fp = popen("ps -eo comm,pid --no-headers | head -n 25", "r");
    if (!fp) {
        snprintf(output, max_len, "ERR 003 PROC_ERROR %s\n", SID_TAG);
        return;
    }

    char line[128];
    char list_buf[3500] = "";
    int first = 1;

    while (fgets(line, sizeof(line), fp)) {
        char comm[64];
        int pid;
        if (sscanf(line, "%63s %d", comm, &pid) == 2) {
            char entry[128];
            snprintf(entry, sizeof(entry), "%s[%d]", comm, pid);
            if (!first) strncat(list_buf, ",", sizeof(list_buf) - strlen(list_buf) - 1);
            strncat(list_buf, entry, sizeof(list_buf) - strlen(list_buf) - 1);
            first = 0;
        }
    }
    pclose(fp);
    snprintf(output, max_len, "OK PROCS %s %s\n", list_buf, SID_TAG);
}

void execute_whitelisted(const char *cmd_name, char *output, size_t max_len) {
    const char *shell_cmd = NULL;

    if (strcmp(cmd_name, "DATE") == 0) shell_cmd = "date";
    else if (strcmp(cmd_name, "UPTIME") == 0) shell_cmd = "uptime";
    else if (strcmp(cmd_name, "DISKFREE") == 0) shell_cmd = "df -h / | tail -n 1";
    else if (strcmp(cmd_name, "HOSTNAME") == 0) shell_cmd = "hostname";
    else if (strcmp(cmd_name, "WHOAMI") == 0) shell_cmd = "whoami";

    if (!shell_cmd) {
        snprintf(output, max_len, "ERR 002 COMMAND_NOT_ALLOWED %s\n", SID_TAG);
        return;
    }

    FILE *fp = popen(shell_cmd, "r");
    if (!fp) {
        snprintf(output, max_len, "ERR 003 EXEC_FAILED %s\n", SID_TAG);
        return;
    }

    char result[512] = "";
    if (fgets(result, sizeof(result), fp)) {
        size_t len = strlen(result);
        if (len > 0 && result[len - 1] == '\n') result[len - 1] = '\0';
    }
    pclose(fp);
    snprintf(output, max_len, "OK EXEC_RESULT %s %s\n", result, SID_TAG);
}

int read_line(int fd, char *buf, int max_len) {
    int idx = 0;
    while (idx < max_len - 1) {
        char c;
        int r = recv(fd, &c, 1, 0);
        if (r <= 0) return -1;
        if (c == '\r') continue;
        if (c == '\n') break;
        buf[idx++] = c;
    }
    buf[idx] = '\0';
    return idx;
}

// UDP Telemetry Worker Thread Context
typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    int target_port;
    volatile int running;
} udp_monitor_ctx_t;

void *udp_monitor_thread(void *arg) {
    udp_monitor_ctx_t *ctx = (udp_monitor_ctx_t *)arg;
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket creation failed");
        return NULL;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(ctx->target_port);
    inet_pton(AF_INET, ctx->target_ip, &dest_addr.sin_addr);

    printf("[UDP] Started telemetry stream to %s:%d\n", ctx->target_ip, ctx->target_port);

    while (ctx->running) {
        // Collect telemetry
        double load = 0.0;
        FILE *f_load = fopen("/proc/loadavg", "r");
        if (f_load) { fscanf(f_load, "%lf", &load); fclose(f_load); }

        long total_mem = 0, free_mem = 0;
        FILE *f_mem = fopen("/proc/meminfo", "r");
        if (f_mem) {
            char line[128];
            while (fgets(line, sizeof(line), f_mem)) {
                if (strncmp(line, "MemTotal:", 9) == 0) sscanf(line + 9, "%ld", &total_mem);
                if (strncmp(line, "MemAvailable:", 13) == 0) sscanf(line + 13, "%ld", &free_mem);
            }
            fclose(f_mem);
        }
        long used_mem_mb = (total_mem - free_mem) / 1024;
        if (used_mem_mb < 0) used_mem_mb = 0;

        long uptime_sec = 0;
        FILE *f_up = fopen("/proc/uptime", "r");
        if (f_up) { double up_val = 0; fscanf(f_up, "%lf", &up_val); uptime_sec = (long)up_val; fclose(f_up); }

        char packet[256];
        snprintf(packet, sizeof(packet), "SYSINFO %.2f %ld %ld %s\n", load, used_mem_mb, uptime_sec, SID_TAG);

        sendto(udp_sock, packet, strlen(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        // Sleep 2 seconds between datagrams
        for (int i = 0; i < 20 && ctx->running; i++) {
            usleep(100000); // 100ms chunks to allow quick cancellation
        }
    }

    close(udp_sock);
    printf("[UDP] Stopped telemetry stream to %s:%d\n", ctx->target_ip, ctx->target_port);
    return NULL;
}

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
} client_info_t;

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
    char line_buf[BUFFER_SIZE];

    // UDP context per client session
    udp_monitor_ctx_t udp_ctx;
    memset(&udp_ctx, 0, sizeof(udp_ctx));
    pthread_t udp_tid = 0;

    mkdir(STORAGE_DIR, 0755);

    while (1) {
        int len = read_line(client_fd, line_buf, sizeof(line_buf));
        if (len < 0) {
            write_log(client_ip, client_port, "DISCONNECT", "Ungraceful disconnect or socket dropped");
            printf("[!] Client ungracefully disconnected: %s:%d\n", client_ip, client_port);
            break;
        }

        while (len > 0 && (line_buf[len - 1] == ' ' || line_buf[len - 1] == '\t')) line_buf[--len] = '\0';
        if (len == 0) continue;

        write_log(client_ip, client_port, "COMMAND", line_buf);
        printf("[%s:%d] Command: %s\n", client_ip, client_port, line_buf);

        char response[BUFFER_SIZE];
        memset(response, 0, sizeof(response));

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
            send(client_fd, response, strlen(response), MSG_NOSIGNAL);
        } else if (strcmp(line_buf, "AUTH") == 0) {
            snprintf(response, sizeof(response), "ERR 001 TOKEN_REQUIRED %s\n", SID_TAG);
            send(client_fd, response, strlen(response), MSG_NOSIGNAL);
        } else if (strcmp(line_buf, "QUIT") == 0) {
            snprintf(response, sizeof(response), "OK BYE %s\n", SID_TAG);
            send(client_fd, response, strlen(response), MSG_NOSIGNAL);
            write_log(client_ip, client_port, "DISCONNECT", "Graceful QUIT");
            break;
        } else if (!is_authenticated) {
            snprintf(response, sizeof(response), "ERR 001 AUTH_REQUIRED %s\n", SID_TAG);
            write_log(client_ip, client_port, "ERROR", "Command rejected: Not authenticated");
            send(client_fd, response, strlen(response), MSG_NOSIGNAL);
        } else if (strcmp(line_buf, "SYSINFO") == 0) {
            get_sysinfo(response, sizeof(response));
            send(client_fd, response, strlen(response), MSG_NOSIGNAL);
        } else if (strcmp(line_buf, "LISTPROC") == 0) {
            get_listproc(response, sizeof(response));
            send(client_fd, response, strlen(response), MSG_NOSIGNAL);
        } else if (strncmp(line_buf, "EXEC ", 5) == 0) {
            char *exec_cmd = line_buf + 5;
            execute_whitelisted(exec_cmd, response, sizeof(response));
            send(client_fd, response, strlen(response), MSG_NOSIGNAL);
        } else if (strcmp(line_buf, "EXEC") == 0) {
            snprintf(response, sizeof(response), "ERR 002 COMMAND_MISSING %s\n", SID_TAG);
            send(client_fd, response, strlen(response), MSG_NOSIGNAL);
        } 
        // === MONITOR START <udp_port> ===
        else if (strncmp(line_buf, "MONITOR START", 13) == 0) {
            int target_uport = 0;
            if (sscanf(line_buf + 13, "%d", &target_uport) == 1 && target_uport > 0 && target_uport <= 65535) {
                if (udp_ctx.running) {
                    udp_ctx.running = 0;
                    pthread_join(udp_tid, NULL);
                }
                strncpy(udp_ctx.target_ip, client_ip, sizeof(udp_ctx.target_ip));
                udp_ctx.target_port = target_uport;
                udp_ctx.running = 1;
                pthread_create(&udp_tid, NULL, udp_monitor_thread, &udp_ctx);

                snprintf(response, sizeof(response), "OK MONITOR_STARTED %s\n", SID_TAG);
                write_log(client_ip, client_port, "MONITOR", "Started UDP stream");
            } else {
                snprintf(response, sizeof(response), "ERR 009 INVALID_UDP_PORT %s\n", SID_TAG);
            }
            send(client_fd, response, strlen(response), MSG_NOSIGNAL);
        }
        // === MONITOR STOP ===
        else if (strcmp(line_buf, "MONITOR STOP") == 0) {
            if (udp_ctx.running) {
                udp_ctx.running = 0;
                pthread_join(udp_tid, NULL);
                udp_tid = 0;
                snprintf(response, sizeof(response), "OK MONITOR_STOPPED %s\n", SID_TAG);
                write_log(client_ip, client_port, "MONITOR", "Stopped UDP stream");
            } else {
                snprintf(response, sizeof(response), "OK MONITOR_STOPPED %s\n", SID_TAG);
            }
            send(client_fd, response, strlen(response), MSG_NOSIGNAL);
        }
        // === PUT Handler ===
        else if (strncmp(line_buf, "PUT ", 4) == 0) {
            char fname[256];
            long fsize = 0;
            if (sscanf(line_buf + 4, "%255s %ld", fname, &fsize) == 2) {
                if (fsize > MAX_FILE_SIZE) {
                    snprintf(response, sizeof(response), "ERR 004 FILE_TOO_LARGE %s\n", SID_TAG);
                    send(client_fd, response, strlen(response), MSG_NOSIGNAL);
                } else {
                    char filepath[512];
                    snprintf(filepath, sizeof(filepath), "%s/%s", STORAGE_DIR, fname);
                    FILE *fp = fopen(filepath, "wb");
                    if (!fp) {
                        snprintf(response, sizeof(response), "ERR 006 FILE_WRITE_FAILED %s\n", SID_TAG);
                        send(client_fd, response, strlen(response), MSG_NOSIGNAL);
                    } else {
                        long remaining = fsize;
                        char file_buf[BUFFER_SIZE];
                        while (remaining > 0) {
                            int to_read = remaining > BUFFER_SIZE ? BUFFER_SIZE : (int)remaining;
                            int r = recv(client_fd, file_buf, to_read, 0);
                            if (r <= 0) break;
                            fwrite(file_buf, 1, r, fp);
                            remaining -= r;
                        }
                        fclose(fp);

                        if (remaining == 0) {
                            snprintf(response, sizeof(response), "OK FILE_RECEIVED %s %s\n", fname, SID_TAG);
                            char log_det[256];
                            snprintf(log_det, sizeof(log_det), "Uploaded %s (%ld bytes)", fname, fsize);
                            write_log(client_ip, client_port, "PUT", log_det);
                        } else {
                            snprintf(response, sizeof(response), "ERR 007 INCOMPLETE_TRANSFER %s\n", SID_TAG);
                        }
                        send(client_fd, response, strlen(response), MSG_NOSIGNAL);
                    }
                }
            } else {
                snprintf(response, sizeof(response), "ERR 008 MALFORMED_PUT_CMD %s\n", SID_TAG);
                send(client_fd, response, strlen(response), MSG_NOSIGNAL);
            }
        }
        // === GET Handler ===
        else if (strncmp(line_buf, "GET ", 4) == 0) {
            char fname[256];
            if (sscanf(line_buf + 4, "%255s", fname) == 1) {
                char filepath[512];
                snprintf(filepath, sizeof(filepath), "%s/%s", STORAGE_DIR, fname);
                FILE *fp = fopen(filepath, "rb");
                if (!fp) {
                    snprintf(response, sizeof(response), "ERR 005 FILE_NOT_FOUND %s\n", SID_TAG);
                    send(client_fd, response, strlen(response), MSG_NOSIGNAL);
                    write_log(client_ip, client_port, "GET", "File not found");
                } else {
                    fseek(fp, 0, SEEK_END);
                    long fsize = ftell(fp);
                    fseek(fp, 0, SEEK_SET);

                    snprintf(response, sizeof(response), "OK FILE_SEND %s %ld %s\n", fname, fsize, SID_TAG);
                    send(client_fd, response, strlen(response), MSG_NOSIGNAL);

                    char file_buf[BUFFER_SIZE];
                    size_t bytes_read;
                    while ((bytes_read = fread(file_buf, 1, sizeof(file_buf), fp)) > 0) {
                        send(client_fd, file_buf, bytes_read, MSG_NOSIGNAL);
                    }
                    fclose(fp);

                    char log_det[256];
                    snprintf(log_det, sizeof(log_det), "Downloaded %s (%ld bytes)", fname, fsize);
                    write_log(client_ip, client_port, "GET", log_det);
                }
            } else {
                snprintf(response, sizeof(response), "ERR 008 MALFORMED_GET_CMD %s\n", SID_TAG);
                send(client_fd, response, strlen(response), MSG_NOSIGNAL);
            }
        } else {
            snprintf(response, sizeof(response), "ERR 002 COMMAND_NOT_ALLOWED %s\n", SID_TAG);
            send(client_fd, response, strlen(response), MSG_NOSIGNAL);
        }
    }

    // Cleanup active UDP stream upon disconnect
    if (udp_ctx.running) {
        udp_ctx.running = 0;
        pthread_join(udp_tid, NULL);
    }

    close(client_fd);
    return NULL;
}

int main() {
    signal(SIGPIPE, SIG_IGN);

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
    printf("   RemoteOps Agent (Full Protocol & UDP Telemetry)\n");
    printf("   Registration Number : IT24103315\n");
    printf("   TCP Listening Port  : %d\n", PORT);
    printf("   Session ID Tag      : %s\n", SID_TAG);
    printf("   Storage Directory   : %s\n", STORAGE_DIR);
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
            pthread_detach(tid);
        }
    }

    close(server_fd);
    return 0;
}
