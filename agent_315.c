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
#define BUFFER_SIZE 4096

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Thread-safe logger
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

// 1. SYSINFO Helper: Read Linux /proc stats
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

// 2. LISTPROC Helper: Snapshot processes
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
            if (!first) {
                strncat(list_buf, ",", sizeof(list_buf) - strlen(list_buf) - 1);
            }
            strncat(list_buf, entry, sizeof(list_buf) - strlen(list_buf) - 1);
            first = 0;
        }
    }
    pclose(fp);

    snprintf(output, max_len, "OK PROCS %s %s\n", list_buf, SID_TAG);
}

// 3. EXEC Whitelist Handler
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
    char recv_buf[BUFFER_SIZE];
    char line_buf[BUFFER_SIZE];
    int line_len = 0;

    while (1) {
        memset(recv_buf, 0, sizeof(recv_buf));
        int bytes = recv(client_fd, recv_buf, sizeof(recv_buf) - 1, 0);
        if (bytes <= 0) break;

        for (int i = 0; i < bytes; i++) {
            char c = recv_buf[i];
            if (c == '\r') continue;
            if (c == '\n') {
                line_buf[line_len] = '\0';
                while (line_len > 0 && line_buf[line_len - 1] == ' ') {
                    line_buf[--line_len] = '\0';
                }

                if (line_len > 0) {
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
                    } else if (strcmp(line_buf, "QUIT") == 0) {
                        snprintf(response, sizeof(response), "OK BYE %s\n", SID_TAG);
                        send(client_fd, response, strlen(response), 0);
                        write_log(client_ip, client_port, "DISCONNECT", "Graceful QUIT");
                        goto cleanup;
                    } else if (!is_authenticated) {
                        snprintf(response, sizeof(response), "ERR 001 AUTH_REQUIRED %s\n", SID_TAG);
                        write_log(client_ip, client_port, "ERROR", "Command rejected: Not authenticated");
                    } else if (strcmp(line_buf, "SYSINFO") == 0) {
                        get_sysinfo(response, sizeof(response));
                    } else if (strcmp(line_buf, "LISTPROC") == 0) {
                        get_listproc(response, sizeof(response));
                    } else if (strncmp(line_buf, "EXEC ", 5) == 0) {
                        char *exec_cmd = line_buf + 5;
                        execute_whitelisted(exec_cmd, response, sizeof(response));
                    } else {
                        snprintf(response, sizeof(response), "ERR 002 COMMAND_NOT_ALLOWED %s\n", SID_TAG);
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
    printf("Agent is ready and listening on port %d...\n", PORT);

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
