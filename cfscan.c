/*
 * cfscan.c - Lightweight C23 Subnet Reachability Scanner (IPv4/IPv6 + OpenSSL HTTPS + SOCKS5)
 *
 * Features:
 *   - Standalone single-file C23 (ISO/IEC 9899:2024) using system OpenSSL (-lssl -lcrypto)
 *   - Cross-platform: Linux, macOS, FreeBSD, Windows (WinSock2)
 *   - Resumable incremental scanning:
 *       * Automatically resumes from non-empty underscan-ips-v{4,6}.txt if present,
 *         otherwise reads ips-v{4,6}.txt (or -in=<file> / -reset).
 *       * Merges, deduplicates, and numerically sorts reachable subnets into
 *         scan-ips-v{4,6}.txt atomically without overwriting prior hits.
 *       * Writes remaining unreachable subnets into underscan-ips-v{4,6}.txt.
 *   - Probe modes:
 *       * -code=0 (default): Lightweight TLS ClientHello (SNI) -> checks ServerHello (port 443)
 *       * -code=N (>0): Full HTTPS (OpenSSL, port 443 default) or HTTP (port 80) HEAD/GET status check
 *   - Optional RFC 1928 SOCKS5 proxy (-proxy=socks5://host:port) for IPv4 & IPv6 targets
 *   - CI-friendly & TTY-friendly real-time progress reporting + HTTP status distribution summary
 */

#ifndef _WIN32
#  ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#  endif
#  ifndef _DEFAULT_SOURCE
#    define _DEFAULT_SOURCE
#  endif
#endif

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#  define CFSCAN_NULL nullptr
#else
#  define CFSCAN_NULL NULL
#endif

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <io.h>
#  include <process.h>
   typedef SOCKET sock_t;
#  define INVALID_SOCK INVALID_SOCKET
#  define close_sock(s) closesocket(s)
#  define isatty_stdout() _isatty(_fileno(stdout))
#else
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
#  include <pthread.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>
   typedef int sock_t;
#  define INVALID_SOCK (-1)
#  define close_sock(s) close(s)
#  define isatty_stdout() isatty(STDOUT_FILENO)
#endif

/* ---------------- Configuration & Data Structures ---------------- */

typedef struct {
    int ip_ver;              /* 4 or 6 */
    int num;                 /* max random IP samples per subnet (early-exit on 1st hit) */
    int task;                /* concurrent worker threads */
    int delay_ms;            /* per-attempt timeout in ms */
    int expected_code;       /* 0 = raw TLS handshake, >0 = HTTP/HTTPS status code */
    int port;                /* target port (default 443) */
    int tls_mode;            /* -1 = auto by port, 0 = plain HTTP, 1 = HTTPS (OpenSSL) */
    bool use_https;          /* resolved HTTPS flag when expected_code > 0 */
    bool reset;              /* ignore existing underscan file and scan from base */
    bool has_proxy;
    char proxy_host[256];
    int proxy_port;
    char domain[256];
    char host[256];
    char path[256];
    char in_file[512];
    char scan_file[512];
    char underscan_file[512];
} Config;

typedef struct {
    uint8_t addr[16];        /* IPv4 uses first 4 bytes; IPv6 uses 16 bytes (network order) */
    uint8_t prefix;          /* 0..32 or 0..128 */
    uint8_t is_v6;           /* 0 = v4, 1 = v6 */
    char text[64];           /* canonical representation e.g. 104.16.0.0/13 */
    bool ok;                 /* probe result */
} Subnet;

typedef struct {
    Subnet *items;
    size_t len;
    size_t cap;
} SubnetList;

/* ---------------- Time & PRNG Helpers ---------------- */

static int64_t now_ms(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq = {0};
    static LARGE_INTEGER start = {0};
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
    }
    LARGE_INTEGER cur;
    QueryPerformanceCounter(&cur);
    return (int64_t)(((cur.QuadPart - start.QuadPart) * 1000LL) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000LL + (int64_t)(ts.tv_nsec / 1000000L);
#endif
}

static void sleep_ms(int ms) {
    if (ms <= 0) return;
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, CFSCAN_NULL);
#endif
}

/* SplitMix64 + xoshiro256** (thread-local, lock-free) */
typedef struct {
    uint64_t s[4];
} RngState;

static uint64_t splitmix64(uint64_t *x) {
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void rng_seed(RngState *r, uint64_t seed) {
    for (int i = 0; i < 4; i++) r->s[i] = splitmix64(&seed);
}

static inline uint64_t rotl64(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static uint64_t rng_next(RngState *r) {
    const uint64_t result = rotl64(r->s[1] * 5ULL, 7) * 9ULL;
    const uint64_t t = r->s[1] << 17;
    r->s[2] ^= r->s[0];
    r->s[3] ^= r->s[1];
    r->s[1] ^= r->s[2];
    r->s[0] ^= r->s[3];
    r->s[2] ^= t;
    r->s[3] = rotl64(r->s[3], 45);
    return result;
}

static void format_wall_time(char buf[16]) {
    time_t t = time(CFSCAN_NULL);
    struct tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    snprintf(buf, 16, "%02d:%02d:%02d", tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
}

/* ---------------- Subnet Parsing, Sorting & File I/O ---------------- */

static void subnet_list_push(SubnetList *list, const Subnet *s) {
    if (list->len == list->cap) {
        size_t ncap = list->cap ? list->cap * 2 : 256;
        Subnet *ni = (Subnet *)realloc(list->items, ncap * sizeof(Subnet));
        if (!ni) {
            fprintf(stderr, "Out of memory\n");
            exit(1);
        }
        list->items = ni;
        list->cap = ncap;
    }
    list->items[list->len++] = *s;
}

static void apply_cidr_mask(uint8_t *addr, int bytes, int prefix) {
    int full = prefix / 8;
    int rem = prefix % 8;
    if (full < bytes) {
        if (rem > 0) {
            uint8_t mask = (uint8_t)(0xFFU << (8 - rem));
            addr[full] &= mask;
            full++;
        }
        for (int i = full; i < bytes; i++) addr[i] = 0;
    }
}

/* Sanitizes a raw line (BOM, comments, CSV, [v6]:port, ip:port#remark) and parses into Subnet */
static bool parse_subnet_line(const char *raw, int expected_ver, Subnet *out) {
    char buf[256];
    const unsigned char *u = (const unsigned char *)raw;
    if (u[0] == 0xEF && u[1] == 0xBB && u[2] == 0xBF) raw += 3; /* UTF-8 BOM */

    while (*raw == ' ' || *raw == '\t' || *raw == '\r' || *raw == '\n') raw++;
    if (*raw == '\0' || *raw == '#' || *raw == ';' || (*raw == '/' && raw[1] == '/')) return false;

    size_t len = 0;
    while (raw[len] && raw[len] != '\r' && raw[len] != '\n' &&
           raw[len] != '#' && raw[len] != ',' && raw[len] != ' ' && raw[len] != '\t') {
        if (len + 1 < sizeof(buf)) buf[len] = raw[len];
        len++;
    }
    if (len == 0 || len >= sizeof(buf)) return false;
    buf[len] = '\0';

    char *p = buf;
    if (*p == '[') {
        p++;
        char *rb = strchr(p, ']');
        if (!rb) return false;
        *rb = '\0';
    }

    int prefix = -1;
    char *slash = strchr(p, '/');
    if (slash) {
        *slash = '\0';
        char *endp = CFSCAN_NULL;
        long v = strtol(slash + 1, &endp, 10);
        if (!endp || *endp != '\0' || v < 0 || v > 128) return false;
        prefix = (int)v;
    } else if (expected_ver == 4) {
        char *colon = strchr(p, ':');
        if (colon) *colon = '\0';
    }

    memset(out, 0, sizeof(*out));
    if (expected_ver == 4) {
        struct in_addr in4;
        if (inet_pton(AF_INET, p, &in4) != 1) return false;
        if (prefix < 0) prefix = 32;
        if (prefix > 32) return false;
        memcpy(out->addr, &in4, 4);
        apply_cidr_mask(out->addr, 4, prefix);
        out->prefix = (uint8_t)prefix;
        out->is_v6 = 0;

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, out->addr, ip_str, sizeof(ip_str));
        if (prefix == 32 && !slash) {
            snprintf(out->text, sizeof(out->text), "%s", ip_str);
        } else {
            snprintf(out->text, sizeof(out->text), "%s/%d", ip_str, prefix);
        }
        return true;
    } else {
        struct in6_addr in6;
        if (inet_pton(AF_INET6, p, &in6) != 1) return false;
        if (prefix < 0) prefix = 128;
        if (prefix > 128) return false;
        memcpy(out->addr, &in6, 16);
        apply_cidr_mask(out->addr, 16, prefix);
        out->prefix = (uint8_t)prefix;
        out->is_v6 = 1;

        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, out->addr, ip_str, sizeof(ip_str));
        if (prefix == 128 && !slash) {
            snprintf(out->text, sizeof(out->text), "%s", ip_str);
        } else {
            snprintf(out->text, sizeof(out->text), "%s/%d", ip_str, prefix);
        }
        return true;
    }
}

static int subnet_cmp(const void *a, const void *b) {
    const Subnet *sa = (const Subnet *)a;
    const Subnet *sb = (const Subnet *)b;
    if (sa->is_v6 != sb->is_v6) return (int)sa->is_v6 - (int)sb->is_v6;
    int bytes = sa->is_v6 ? 16 : 4;
    int c = memcmp(sa->addr, sb->addr, (size_t)bytes);
    if (c != 0) return c;
    return (int)sa->prefix - (int)sb->prefix;
}

static void subnet_list_sort_dedup(SubnetList *list) {
    if (list->len <= 1) return;
    qsort(list->items, list->len, sizeof(Subnet), subnet_cmp);
    size_t w = 1;
    for (size_t i = 1; i < list->len; i++) {
        if (subnet_cmp(&list->items[w - 1], &list->items[i]) != 0) {
            list->items[w++] = list->items[i];
        }
    }
    list->len = w;
}

static size_t load_subnets_file(const char *path, int expected_ver, SubnetList *out) {
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    size_t before = out->len;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        Subnet s;
        if (parse_subnet_line(line, expected_ver, &s)) {
            subnet_list_push(out, &s);
        }
    }
    fclose(fp);
    return out->len - before;
}

static bool write_subnets_atomic(const char *path, const SubnetList *list) {
    char tmp_path[600];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing: %s\n", tmp_path, strerror(errno));
        return false;
    }
    for (size_t i = 0; i < list->len; i++) {
        fprintf(fp, "%s\n", list->items[i].text);
    }
    if (fflush(fp) != 0) {
        fclose(fp);
        remove(tmp_path);
        return false;
    }
#ifdef _WIN32
    _commit(_fileno(fp));
#else
    fsync(fileno(fp));
#endif
    fclose(fp);

#ifdef _WIN32
    if (!MoveFileExA(tmp_path, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        remove(path);
        if (rename(tmp_path, path) != 0) {
            remove(tmp_path);
            return false;
        }
    }
#else
    if (rename(tmp_path, path) != 0) {
        remove(tmp_path);
        return false;
    }
#endif
    return true;
}

static void sample_random_ip(const Subnet *s, RngState *rng, uint8_t out_addr[16]) {
    if (!s->is_v6) {
        uint32_t net = ((uint32_t)s->addr[0] << 24) | ((uint32_t)s->addr[1] << 16) |
                       ((uint32_t)s->addr[2] << 8)  | (uint32_t)s->addr[3];
        uint32_t ip = net;
        if (s->prefix < 32) {
            int host_bits = 32 - s->prefix;
            uint32_t mask = (host_bits == 32) ? 0xFFFFFFFFU : ((1U << host_bits) - 1U);
            uint32_t r = (uint32_t)rng_next(rng) & mask;
            if (host_bits >= 2) {
                if (r == 0) r = 1;
                else if (r == mask) r = mask - 1;
            }
            ip = (net & ~mask) | r;
        }
        out_addr[0] = (uint8_t)(ip >> 24);
        out_addr[1] = (uint8_t)(ip >> 16);
        out_addr[2] = (uint8_t)(ip >> 8);
        out_addr[3] = (uint8_t)(ip);
    } else {
        memcpy(out_addr, s->addr, 16);
        if (s->prefix < 128) {
            uint64_t r1 = rng_next(rng);
            uint64_t r2 = rng_next(rng);
            uint8_t rnd[16];
            memcpy(rnd, &r1, 8);
            memcpy(rnd + 8, &r2, 8);
            int full = s->prefix / 8;
            int rem = s->prefix % 8;
            if (rem > 0 && full < 16) {
                uint8_t keep = (uint8_t)(0xFFU << (8 - rem));
                out_addr[full] = (uint8_t)((out_addr[full] & keep) | (rnd[full] & ~keep));
                full++;
            }
            for (int i = full; i < 16; i++) out_addr[i] = rnd[i];
        }
    }
}

/* ---------------- Non-blocking Socket, SOCKS5, OpenSSL & Probe Logic ---------------- */

static bool set_nonblocking(sock_t fd) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

static bool last_err_in_progress(void) {
#ifdef _WIN32
    int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS;
#else
    return errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

static int poll_fd(sock_t fd, short events, int timeout_ms) {
    if (timeout_ms <= 0) return 0;
#ifdef _WIN32
    WSAPOLLFD pfd = { .fd = fd, .events = events, .revents = 0 };
    return WSAPoll(&pfd, 1, timeout_ms);
#else
    struct pollfd pfd = { .fd = fd, .events = events, .revents = 0 };
    int rc;
    do {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);
    return rc;
#endif
}

static bool send_all_deadline(sock_t fd, const uint8_t *buf, size_t len, int64_t deadline) {
    size_t sent = 0;
    while (sent < len) {
        int rem = (int)(deadline - now_ms());
        if (rem <= 0) return false;
        if (poll_fd(fd, POLLOUT, rem) <= 0) return false;
#ifdef _WIN32
        int n = send(fd, (const char *)(buf + sent), (int)(len - sent), 0);
#else
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
#endif
        if (n > 0) {
            sent += (size_t)n;
        } else if (n < 0 && last_err_in_progress()) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

static ssize_t recv_exact_deadline(sock_t fd, uint8_t *buf, size_t len, int64_t deadline) {
    size_t got = 0;
    while (got < len) {
        int rem = (int)(deadline - now_ms());
        if (rem <= 0) return -1;
        if (poll_fd(fd, POLLIN, rem) <= 0) return -1;
#ifdef _WIN32
        int n = recv(fd, (char *)(buf + got), (int)(len - got), 0);
#else
        ssize_t n = recv(fd, buf + got, len - got, 0);
#endif
        if (n > 0) {
            got += (size_t)n;
        } else if (n < 0 && last_err_in_progress()) {
            continue;
        } else {
            return (ssize_t)got;
        }
    }
    return (ssize_t)got;
}

static ssize_t recv_some_deadline(sock_t fd, uint8_t *buf, size_t cap, int64_t deadline) {
    while (true) {
        int rem = (int)(deadline - now_ms());
        if (rem <= 0) return -1;
        if (poll_fd(fd, POLLIN, rem) <= 0) return -1;
#ifdef _WIN32
        int n = recv(fd, (char *)buf, (int)cap, 0);
#else
        ssize_t n = recv(fd, buf, cap, 0);
#endif
        if (n > 0) return (ssize_t)n;
        if (n < 0 && last_err_in_progress()) continue;
        return n;
    }
}

static sock_t connect_sa_deadline(const struct sockaddr *sa, socklen_t salen, int64_t deadline) {
    sock_t fd = socket(sa->sa_family, SOCK_STREAM, 0);
    if (fd == INVALID_SOCK) return INVALID_SOCK;
    if (!set_nonblocking(fd)) {
        close_sock(fd);
        return INVALID_SOCK;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));

    int rc = connect(fd, sa, salen);
    if (rc != 0) {
        if (!last_err_in_progress()) {
            close_sock(fd);
            return INVALID_SOCK;
        }
        int rem = (int)(deadline - now_ms());
        if (rem <= 0 || poll_fd(fd, POLLOUT, rem) <= 0) {
            close_sock(fd);
            return INVALID_SOCK;
        }
        int err = 0;
        socklen_t errlen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen) != 0 || err != 0) {
            close_sock(fd);
            return INVALID_SOCK;
        }
    }
    return fd;
}

/* Connect directly or through RFC 1928 SOCKS5 proxy */
static sock_t dial_target(const Config *cfg, const struct sockaddr_storage *proxy_sa, socklen_t proxy_salen,
                          const uint8_t target_ip[16], bool is_v6, uint16_t port, int64_t deadline) {
    if (!cfg->has_proxy) {
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));
        socklen_t salen = 0;
        if (!is_v6) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
            sin->sin_family = AF_INET;
            sin->sin_port = htons(port);
            memcpy(&sin->sin_addr, target_ip, 4);
            salen = sizeof(*sin);
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons(port);
            memcpy(&sin6->sin6_addr, target_ip, 16);
            salen = sizeof(*sin6);
        }
        return connect_sa_deadline((const struct sockaddr *)&ss, salen, deadline);
    }

    sock_t fd = connect_sa_deadline((const struct sockaddr *)proxy_sa, proxy_salen, deadline);
    if (fd == INVALID_SOCK) return INVALID_SOCK;

    const uint8_t greet[3] = { 0x05, 0x01, 0x00 };
    uint8_t rep[2];
    if (!send_all_deadline(fd, greet, sizeof(greet), deadline) ||
        recv_exact_deadline(fd, rep, 2, deadline) != 2 ||
        rep[0] != 0x05 || rep[1] != 0x00) {
        close_sock(fd);
        return INVALID_SOCK;
    }

    uint8_t req[22];
    size_t req_len = 0;
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    if (!is_v6) {
        req[3] = 0x01;
        memcpy(req + 4, target_ip, 4);
        req[8] = (uint8_t)(port >> 8);
        req[9] = (uint8_t)(port & 0xFF);
        req_len = 10;
    } else {
        req[3] = 0x04;
        memcpy(req + 4, target_ip, 16);
        req[20] = (uint8_t)(port >> 8);
        req[21] = (uint8_t)(port & 0xFF);
        req_len = 22;
    }

    if (!send_all_deadline(fd, req, req_len, deadline)) {
        close_sock(fd);
        return INVALID_SOCK;
    }

    uint8_t hdr[4];
    if (recv_exact_deadline(fd, hdr, 4, deadline) != 4 || hdr[0] != 0x05 || hdr[1] != 0x00) {
        close_sock(fd);
        return INVALID_SOCK;
    }

    size_t skip = 0;
    if (hdr[3] == 0x01) skip = 4 + 2;
    else if (hdr[3] == 0x04) skip = 16 + 2;
    else if (hdr[3] == 0x03) {
        uint8_t dlen = 0;
        if (recv_exact_deadline(fd, &dlen, 1, deadline) != 1) {
            close_sock(fd);
            return INVALID_SOCK;
        }
        skip = (size_t)dlen + 2;
    } else {
        close_sock(fd);
        return INVALID_SOCK;
    }

    uint8_t drain[260];
    if (skip > sizeof(drain) || recv_exact_deadline(fd, drain, skip, deadline) != (ssize_t)skip) {
        close_sock(fd);
        return INVALID_SOCK;
    }
    return fd;
}

/* Lightweight raw TLS ClientHello probe (used when -code=0) */
static size_t build_tls_client_hello(uint8_t *buf, size_t cap, const char *sni, RngState *rng) {
    size_t sni_len = strlen(sni);
    if (sni_len > 250 || cap < 128 + sni_len) return 0;

    uint8_t *p = buf;
    p[0] = 0x16; p[1] = 0x03; p[2] = 0x01;
    uint8_t *rec_len_ptr = p + 3;
    p += 5;

    *p++ = 0x01;
    uint8_t *hs_len_ptr = p;
    p += 3;

    *p++ = 0x03; *p++ = 0x03;

    for (int i = 0; i < 4; i++) {
        uint64_t r = rng_next(rng);
        memcpy(p, &r, 8);
        p += 8;
    }
    *p++ = 0x00;

    static const uint8_t suites[] = {
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
        0xC0, 0x2F, 0xC0, 0x2B, 0xCC, 0xA9, 0xCC, 0xA8
    };
    *p++ = 0x00; *p++ = (uint8_t)sizeof(suites);
    memcpy(p, suites, sizeof(suites));
    p += sizeof(suites);

    *p++ = 0x01; *p++ = 0x00;

    uint8_t *ext_len_ptr = p;
    p += 2;
    uint8_t *ext_start = p;

    if (sni_len > 0) {
        uint16_t list_len = (uint16_t)(sni_len + 3);
        uint16_t ext_len = (uint16_t)(list_len + 2);
        *p++ = 0x00; *p++ = 0x00;
        *p++ = (uint8_t)(ext_len >> 8);  *p++ = (uint8_t)(ext_len & 0xFF);
        *p++ = (uint8_t)(list_len >> 8); *p++ = (uint8_t)(list_len & 0xFF);
        *p++ = 0x00;
        *p++ = (uint8_t)(sni_len >> 8);  *p++ = (uint8_t)(sni_len & 0xFF);
        memcpy(p, sni, sni_len);
        p += sni_len;
    }

    static const uint8_t groups[] = { 0x00, 0x0A, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1D, 0x00, 0x17 };
    memcpy(p, groups, sizeof(groups)); p += sizeof(groups);

    static const uint8_t sigs[] = {
        0x00, 0x0D, 0x00, 0x0C, 0x00, 0x0A,
        0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x02, 0x01
    };
    memcpy(p, sigs, sizeof(sigs)); p += sizeof(sigs);

    static const uint8_t vers[] = { 0x00, 0x2B, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03 };
    memcpy(p, vers, sizeof(vers)); p += sizeof(vers);

    size_t ext_total = (size_t)(p - ext_start);
    ext_len_ptr[0] = (uint8_t)(ext_total >> 8);
    ext_len_ptr[1] = (uint8_t)(ext_total & 0xFF);

    size_t hs_total = (size_t)(p - (hs_len_ptr + 3));
    hs_len_ptr[0] = (uint8_t)(hs_total >> 16);
    hs_len_ptr[1] = (uint8_t)(hs_total >> 8);
    hs_len_ptr[2] = (uint8_t)(hs_total & 0xFF);

    size_t rec_total = (size_t)(p - (buf + 5));
    rec_len_ptr[0] = (uint8_t)(rec_total >> 8);
    rec_len_ptr[1] = (uint8_t)(rec_total & 0xFF);

    return (size_t)(p - buf);
}

static bool probe_tls_hello(const Config *cfg, const struct sockaddr_storage *proxy_sa, socklen_t proxy_salen,
                            const uint8_t ip[16], bool is_v6, RngState *rng) {
    int64_t deadline = now_ms() + cfg->delay_ms;
    sock_t fd = dial_target(cfg, proxy_sa, proxy_salen, ip, is_v6, (uint16_t)cfg->port, deadline);
    if (fd == INVALID_SOCK) return false;

    uint8_t ch[512];
    size_t ch_len = build_tls_client_hello(ch, sizeof(ch), cfg->host, rng);
    bool ok = false;
    if (ch_len > 0 && send_all_deadline(fd, ch, ch_len, deadline)) {
        uint8_t resp[5];
        if (recv_exact_deadline(fd, resp, 5, deadline) == 5) {
            if (resp[0] == 0x16 && resp[1] == 0x03) ok = true;
        }
    }
    close_sock(fd);
    return ok;
}

static int parse_http_status(const char *buf, size_t len) {
    if (len < 12 || strncmp(buf, "HTTP/", 5) != 0) return -1;
    const char *sp = memchr(buf, ' ', len);
    if (!sp || (size_t)(sp - buf) + 4 > len) return -1;
    while ((size_t)(sp - buf) < len && *sp == ' ') sp++;
    if ((size_t)(sp - buf) + 3 > len) return -1;
    if (sp[0] < '0' || sp[0] > '9' || sp[1] < '0' || sp[1] > '9' || sp[2] < '0' || sp[2] > '9') return -1;
    return (sp[0] - '0') * 100 + (sp[1] - '0') * 10 + (sp[2] - '0');
}

/* OpenSSL non-blocking helpers */
static bool ssl_wait_io(SSL *ssl, sock_t fd, int rc, int64_t deadline) {
    int err = SSL_get_error(ssl, rc);
    int rem = (int)(deadline - now_ms());
    if (rem <= 0) return false;
    if (err == SSL_ERROR_WANT_READ) return poll_fd(fd, POLLIN, rem) > 0;
    if (err == SSL_ERROR_WANT_WRITE) return poll_fd(fd, POLLOUT, rem) > 0;
    return false;
}

static bool ssl_connect_deadline(SSL *ssl, sock_t fd, int64_t deadline) {
    while (true) {
        if (now_ms() >= deadline) return false;
        int rc = SSL_connect(ssl);
        if (rc == 1) return true;
        if (!ssl_wait_io(ssl, fd, rc, deadline)) return false;
    }
}

static bool ssl_write_all_deadline(SSL *ssl, sock_t fd, const uint8_t *buf, size_t len, int64_t deadline) {
    size_t sent = 0;
    while (sent < len) {
        if (now_ms() >= deadline) return false;
        int rc = SSL_write(ssl, buf + sent, (int)(len - sent));
        if (rc > 0) {
            sent += (size_t)rc;
        } else {
            if (!ssl_wait_io(ssl, fd, rc, deadline)) return false;
        }
    }
    return true;
}

static ssize_t ssl_read_some_deadline(SSL *ssl, sock_t fd, uint8_t *buf, size_t cap, int64_t deadline) {
    while (true) {
        if (now_ms() >= deadline) return -1;
        int rc = SSL_read(ssl, buf, (int)cap);
        if (rc > 0) return (ssize_t)rc;
        int err = SSL_get_error(ssl, rc);
        if (err == SSL_ERROR_ZERO_RETURN) return 0;
        if (!ssl_wait_io(ssl, fd, rc, deadline)) return -1;
    }
}

static int probe_http_or_https_once(const Config *cfg, SSL_CTX *ssl_ctx,
                                    const struct sockaddr_storage *proxy_sa, socklen_t proxy_salen,
                                    const uint8_t ip[16], bool is_v6, const char *method) {
    int64_t deadline = now_ms() + cfg->delay_ms;
    sock_t fd = dial_target(cfg, proxy_sa, proxy_salen, ip, is_v6, (uint16_t)cfg->port, deadline);
    if (fd == INVALID_SOCK) return -1;

    char req[768];
    int n = snprintf(req, sizeof(req),
                     "%s %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: cfscan/1.0\r\n"
                     "Connection: close\r\n\r\n",
                     method, cfg->path, cfg->host);
    if (n <= 0 || (size_t)n >= sizeof(req)) {
        close_sock(fd);
        return -1;
    }

    int code = -1;
    if (cfg->use_https) {
        SSL *ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            close_sock(fd);
            return -1;
        }
        SSL_set_fd(ssl, (int)fd);
        if (cfg->host[0] != '\0') SSL_set_tlsext_host_name(ssl, cfg->host);
        SSL_set_connect_state(ssl);

        if (ssl_connect_deadline(ssl, fd, deadline) &&
            ssl_write_all_deadline(ssl, fd, (const uint8_t *)req, (size_t)n, deadline)) {
            uint8_t resp[512];
            ssize_t r = ssl_read_some_deadline(ssl, fd, resp, sizeof(resp) - 1, deadline);
            if (r > 0) {
                resp[r] = '\0';
                code = parse_http_status((const char *)resp, (size_t)r);
            }
        }
        SSL_free(ssl);
    } else {
        if (send_all_deadline(fd, (const uint8_t *)req, (size_t)n, deadline)) {
            uint8_t resp[512];
            ssize_t r = recv_some_deadline(fd, resp, sizeof(resp) - 1, deadline);
            if (r > 0) {
                resp[r] = '\0';
                code = parse_http_status((const char *)resp, (size_t)r);
            }
        }
    }

    close_sock(fd);
    return code;
}

typedef struct {
    const Config *cfg;
    SSL_CTX *ssl_ctx;
    SubnetList *work;
    struct sockaddr_storage proxy_sa;
    socklen_t proxy_salen;
    atomic_size_t next_idx;
    atomic_size_t done_cnt;
    atomic_size_t ok_cnt;
    atomic_size_t http_code_cnt[600];
    atomic_size_t http_err_cnt;
} ScanCtx;

static bool probe_subnet(ScanCtx *ctx, const Subnet *s, RngState *rng) {
    const Config *cfg = ctx->cfg;
    for (int i = 0; i < cfg->num; i++) {
        uint8_t ip[16];
        sample_random_ip(s, rng, ip);
        if (cfg->expected_code == 0) {
            if (probe_tls_hello(cfg, &ctx->proxy_sa, ctx->proxy_salen, ip, s->is_v6 != 0, rng)) return true;
        } else {
            int code = probe_http_or_https_once(cfg, ctx->ssl_ctx, &ctx->proxy_sa, ctx->proxy_salen,
                                                ip, s->is_v6 != 0, "HEAD");
            if (code == 405 && cfg->expected_code != 405) {
                code = probe_http_or_https_once(cfg, ctx->ssl_ctx, &ctx->proxy_sa, ctx->proxy_salen,
                                                ip, s->is_v6 != 0, "GET");
            }
            if (code >= 100 && code < 600) {
                atomic_fetch_add_explicit(&ctx->http_code_cnt[code], 1, memory_order_relaxed);
            } else {
                atomic_fetch_add_explicit(&ctx->http_err_cnt, 1, memory_order_relaxed);
            }
            if (code == cfg->expected_code) return true;
        }
    }
    return false;
}

/* ---------------- Worker Pool & Progress Reporting ---------------- */

typedef struct {
    ScanCtx *ctx;
    int tid;
} WorkerArg;

#ifdef _WIN32
static unsigned __stdcall worker_main(void *arg) {
#else
static void *worker_main(void *arg) {
#endif
    WorkerArg *wa = (WorkerArg *)arg;
    ScanCtx *ctx = wa->ctx;
    RngState rng;
    rng_seed(&rng, (uint64_t)time(CFSCAN_NULL) ^ ((uint64_t)now_ms() << 16) ^ ((uint64_t)(wa->tid + 1) * 0x9e3779b97f4a7c15ULL));

    size_t total = ctx->work->len;
    while (true) {
        size_t idx = atomic_fetch_add_explicit(&ctx->next_idx, 1, memory_order_relaxed);
        if (idx >= total) break;
        bool hit = probe_subnet(ctx, &ctx->work->items[idx], &rng);
        ctx->work->items[idx].ok = hit;
        if (hit) atomic_fetch_add_explicit(&ctx->ok_cnt, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&ctx->done_cnt, 1, memory_order_relaxed);
    }
#ifdef _WIN32
    return 0;
#else
    return CFSCAN_NULL;
#endif
}

/* ---------------- Argument Parsing Helpers ---------------- */

static void parse_domain(Config *cfg, const char *val) {
    if (strncmp(val, "https://", 8) == 0) val += 8;
    else if (strncmp(val, "http://", 7) == 0) val += 7;
    snprintf(cfg->domain, sizeof(cfg->domain), "%s", val);

    const char *slash = strchr(val, '/');
    if (slash) {
        size_t hlen = (size_t)(slash - val);
        if (hlen >= sizeof(cfg->host)) hlen = sizeof(cfg->host) - 1;
        memcpy(cfg->host, val, hlen);
        cfg->host[hlen] = '\0';
        snprintf(cfg->path, sizeof(cfg->path), "%s", slash);
    } else {
        snprintf(cfg->host, sizeof(cfg->host), "%s", val);
        snprintf(cfg->path, sizeof(cfg->path), "/");
    }
}

static bool parse_proxy(Config *cfg, const char *val) {
    if (!val || !*val) return true;
    if (strncmp(val, "socks5://", 9) == 0) val += 9;
    else if (strncmp(val, "socks5h://", 10) == 0) val += 10;

    const char *colon = strrchr(val, ':');
    if (!colon || colon == val) return false;
    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) return false;

    const char *hstart = val;
    size_t hlen = (size_t)(colon - val);
    if (hlen >= 2 && hstart[0] == '[' && hstart[hlen - 1] == ']') {
        hstart++;
        hlen -= 2;
    }
    if (hlen == 0 || hlen >= sizeof(cfg->proxy_host)) return false;
    memcpy(cfg->proxy_host, hstart, hlen);
    cfg->proxy_host[hlen] = '\0';
    cfg->proxy_port = port;
    cfg->has_proxy = true;
    return true;
}

static bool is_https_port(int port) {
    return port == 443 || port == 8443 || port == 2053 || port == 2083 || port == 2087 || port == 2096;
}

static void print_usage(const char *prog) {
    printf(
        "Usage: %s [options]\n"
        "  -ips=4|6              IP version to scan (alias: -4, -6, -scan=4|6) [default: 4]\n"
        "  -domain=HOST[/PATH]   Target domain for TLS SNI / HTTP Host [default: cloudflaremirrors.com/debian]\n"
        "  -code=N               0 = lightweight TLS handshake; >0 = HTTP/HTTPS status check [default: 0]\n"
        "  -port=N               Target port (e.g. 443 for HTTPS or 80 for HTTP) [default: 443]\n"
        "  -tls=auto|0|1         Force HTTPS (1) or plain HTTP (0) when -code>0 [default: auto by port]\n"
        "  -num=N                Max random IP samples per subnet (early-exit on hit) [default: 1]\n"
        "  -task=N               Concurrent worker threads [default: 200]\n"
        "  -delay=MS             Per-attempt timeout in milliseconds [default: 1500]\n"
        "  -proxy=socks5://H:P   Optional SOCKS5 proxy (supports IPv4 & IPv6 targets)\n"
        "  -in=FILE              Explicit input subnet file (overrides auto-resume)\n"
        "  -reset                Ignore existing underscan-ips-v*.txt and scan from ips-v*.txt\n"
        "  -h, -help             Show this help message\n",
        prog
    );
}

static bool match_arg(const char *arg, const char *name, const char **out_val) {
    if (*arg == '-') arg++;
    if (*arg == '-') arg++;
    size_t nlen = strlen(name);
    if (strncmp(arg, name, nlen) == 0 && arg[nlen] == '=') {
        *out_val = arg + nlen + 1;
        return true;
    }
    return false;
}

int main(int argc, char **argv) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.ip_ver = 4;
    cfg.num = 1;
    cfg.task = 200;
    cfg.delay_ms = 1500;
    cfg.expected_code = 0;
    cfg.port = 443;
    cfg.tls_mode = -1;
    parse_domain(&cfg, "cloudflaremirrors.com/debian");

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = CFSCAN_NULL;
        if (strcmp(a, "-h") == 0 || strcmp(a, "-help") == 0 || strcmp(a, "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(a, "-4") == 0) {
            cfg.ip_ver = 4;
        } else if (strcmp(a, "-6") == 0) {
            cfg.ip_ver = 6;
        } else if (strcmp(a, "-https") == 0) {
            cfg.tls_mode = 1;
        } else if (strcmp(a, "-http") == 0) {
            cfg.tls_mode = 0;
        } else if (strcmp(a, "-reset") == 0 || strcmp(a, "--reset") == 0) {
            cfg.reset = true;
        } else if (match_arg(a, "ips", &v) || match_arg(a, "scan", &v)) {
            cfg.ip_ver = atoi(v);
        } else if (match_arg(a, "domain", &v)) {
            parse_domain(&cfg, v);
        } else if (match_arg(a, "code", &v)) {
            cfg.expected_code = atoi(v);
        } else if (match_arg(a, "port", &v)) {
            cfg.port = atoi(v);
        } else if (match_arg(a, "tls", &v)) {
            if (strcmp(v, "auto") == 0) cfg.tls_mode = -1;
            else if (strcmp(v, "1") == 0 || strcmp(v, "true") == 0) cfg.tls_mode = 1;
            else cfg.tls_mode = 0;
        } else if (match_arg(a, "num", &v)) {
            cfg.num = atoi(v);
        } else if (match_arg(a, "task", &v)) {
            cfg.task = atoi(v);
        } else if (match_arg(a, "delay", &v)) {
            cfg.delay_ms = atoi(v);
        } else if (match_arg(a, "proxy", &v)) {
            if (!parse_proxy(&cfg, v)) {
                fprintf(stderr, "Invalid -proxy format: %s (expected socks5://host:port)\n", v);
                return 1;
            }
        } else if (match_arg(a, "in", &v)) {
            snprintf(cfg.in_file, sizeof(cfg.in_file), "%s", v);
        } else {
            fprintf(stderr, "Unknown argument: %s\n", a);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (cfg.ip_ver != 4 && cfg.ip_ver != 6) {
        fprintf(stderr, "Invalid -ips value: %d (must be 4 or 6)\n", cfg.ip_ver);
        return 1;
    }
    if (cfg.num < 1) cfg.num = 1;
    if (cfg.task < 1) cfg.task = 1;
    if (cfg.task > 2000) cfg.task = 2000;
    if (cfg.delay_ms < 100) cfg.delay_ms = 100;
    if (cfg.port <= 0 || cfg.port > 65535) cfg.port = 443;

    if (cfg.expected_code > 0) {
        if (cfg.tls_mode == 1) cfg.use_https = true;
        else if (cfg.tls_mode == 0) cfg.use_https = false;
        else cfg.use_https = is_https_port(cfg.port);
    }

    snprintf(cfg.scan_file, sizeof(cfg.scan_file), "scan-ips-v%d.txt", cfg.ip_ver);
    snprintf(cfg.underscan_file, sizeof(cfg.underscan_file), "underscan-ips-v%d.txt", cfg.ip_ver);

    ScanCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.cfg = &cfg;

    if (cfg.expected_code > 0 && cfg.use_https) {
        ctx.ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx.ssl_ctx) {
            fprintf(stderr, "Failed to create OpenSSL SSL_CTX\n");
            return 1;
        }
        SSL_CTX_set_verify(ctx.ssl_ctx, SSL_VERIFY_NONE, CFSCAN_NULL);
    }

    if (cfg.has_proxy) {
        struct addrinfo hints, *res = CFSCAN_NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        char pbuf[16];
        snprintf(pbuf, sizeof(pbuf), "%d", cfg.proxy_port);
        if (getaddrinfo(cfg.proxy_host, pbuf, &hints, &res) != 0 || !res) {
            fprintf(stderr, "Failed to resolve SOCKS5 proxy %s:%d\n", cfg.proxy_host, cfg.proxy_port);
            if (ctx.ssl_ctx) SSL_CTX_free(ctx.ssl_ctx);
            return 1;
        }
        memcpy(&ctx.proxy_sa, res->ai_addr, res->ai_addrlen);
        ctx.proxy_salen = (socklen_t)res->ai_addrlen;
        freeaddrinfo(res);
    }

    SubnetList work = {0};
    char chosen_src[540];
    if (cfg.in_file[0] != '\0') {
        snprintf(chosen_src, sizeof(chosen_src), "%s", cfg.in_file);
        load_subnets_file(chosen_src, cfg.ip_ver, &work);
    } else {
        if (!cfg.reset && load_subnets_file(cfg.underscan_file, cfg.ip_ver, &work) > 0) {
            snprintf(chosen_src, sizeof(chosen_src), "%s (resume)", cfg.underscan_file);
        } else {
            snprintf(chosen_src, sizeof(chosen_src), "ips-v%d.txt", cfg.ip_ver);
            load_subnets_file(chosen_src, cfg.ip_ver, &work);
        }
    }

    subnet_list_sort_dedup(&work);
    if (work.len == 0) {
        fprintf(stderr, "No valid IPv%d subnets found in %s\n", cfg.ip_ver, chosen_src);
        free(work.items);
        if (ctx.ssl_ctx) SSL_CTX_free(ctx.ssl_ctx);
        return 1;
    }

    SubnetList existing_ok = {0};
    load_subnets_file(cfg.scan_file, cfg.ip_ver, &existing_ok);
    subnet_list_sort_dedup(&existing_ok);

    if (existing_ok.len > 0) {
        size_t w = 0;
        for (size_t i = 0; i < work.len; i++) {
            if (!bsearch(&work.items[i], existing_ok.items, existing_ok.len, sizeof(Subnet), subnet_cmp)) {
                work.items[w++] = work.items[i];
            }
        }
        work.len = w;
        if (work.len == 0) {
            printf("[cfscan] All subnets in %s are already present in %s (%zu total). Nothing to scan.\n",
                   chosen_src, cfg.scan_file, existing_ok.len);
            write_subnets_atomic(cfg.underscan_file, &work);
            free(work.items);
            free(existing_ok.items);
            if (ctx.ssl_ctx) SSL_CTX_free(ctx.ssl_ctx);
#ifdef _WIN32
            WSACleanup();
#endif
            return 0;
        }
    }

    RngState shuf_rng;
    rng_seed(&shuf_rng, (uint64_t)time(CFSCAN_NULL) ^ ((uint64_t)now_ms() << 20));
    for (size_t i = work.len - 1; i > 0; i--) {
        size_t j = (size_t)(rng_next(&shuf_rng) % (uint64_t)(i + 1));
        Subnet tmp = work.items[i];
        work.items[i] = work.items[j];
        work.items[j] = tmp;
    }

    int workers = cfg.task;
    if ((size_t)workers > work.len) workers = (int)work.len;

    const char *mode_str = (cfg.expected_code == 0) ? "TLS-Hello" : (cfg.use_https ? "HTTPS" : "HTTP");
    printf("[cfscan] IPv%d | Source: %s (%zu subnets) | Mode: %s (port %d) | Domain: %s | Samples/subnet: %d | Workers: %d | Timeout: %dms",
           cfg.ip_ver, chosen_src, work.len, mode_str, cfg.port,
           cfg.domain, cfg.num, workers, cfg.delay_ms);
    if (cfg.expected_code > 0) printf(" | Expect %d", cfg.expected_code);
    if (cfg.has_proxy) printf(" | Proxy: socks5://%s:%d", cfg.proxy_host, cfg.proxy_port);
    printf("\n");
    fflush(stdout);

    ctx.work = &work;
    atomic_init(&ctx.next_idx, 0);
    atomic_init(&ctx.done_cnt, 0);
    atomic_init(&ctx.ok_cnt, 0);
    atomic_init(&ctx.http_err_cnt, 0);
    for (int i = 0; i < 600; i++) atomic_init(&ctx.http_code_cnt[i], 0);

    WorkerArg *wargs = (WorkerArg *)calloc((size_t)workers, sizeof(WorkerArg));
#ifdef _WIN32
    HANDLE *threads = (HANDLE *)calloc((size_t)workers, sizeof(HANDLE));
#else
    pthread_t *threads = (pthread_t *)calloc((size_t)workers, sizeof(pthread_t));
#endif
    if (!wargs || !threads) {
        fprintf(stderr, "Out of memory\n");
        if (ctx.ssl_ctx) SSL_CTX_free(ctx.ssl_ctx);
        return 1;
    }

    int64_t t_start = now_ms();
    for (int i = 0; i < workers; i++) {
        wargs[i].ctx = &ctx;
        wargs[i].tid = i;
#ifdef _WIN32
        threads[i] = (HANDLE)_beginthreadex(CFSCAN_NULL, 256 * 1024, worker_main, &wargs[i], 0, CFSCAN_NULL);
#else
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        size_t stksz = 256 * 1024;
#  ifdef PTHREAD_STACK_MIN
        if (stksz < (size_t)PTHREAD_STACK_MIN) stksz = (size_t)PTHREAD_STACK_MIN;
#  endif
        pthread_attr_setstacksize(&attr, stksz);
        pthread_create(&threads[i], &attr, worker_main, &wargs[i]);
        pthread_attr_destroy(&attr);
#endif
    }

    bool is_ci = (getenv("CI") != CFSCAN_NULL || getenv("GITHUB_ACTIONS") != CFSCAN_NULL || !isatty_stdout());
    int last_pct_bucket = -1;
    int64_t last_log_ms = t_start;
    while (true) {
        size_t done = atomic_load_explicit(&ctx.done_cnt, memory_order_relaxed);
        size_t ok = atomic_load_explicit(&ctx.ok_cnt, memory_order_relaxed);
        size_t miss = done - ok;
        int64_t elapsed_ms = now_ms() - t_start;
        double sec = elapsed_ms > 0 ? (double)elapsed_ms / 1000.0 : 0.001;
        double pct = (double)done * 100.0 / (double)work.len;

        if (is_ci) {
            int bucket = (int)(pct / 5.0);
            if (done == work.len || bucket > last_pct_bucket || (now_ms() - last_log_ms) >= 5000) {
                char ts[16];
                format_wall_time(ts);
                printf("[%s] Progress: %zu/%zu (%.1f%%) | OK: %zu | Miss: %zu | %.1f/s\n",
                       ts, done, work.len, pct, ok, miss, (double)done / sec);
                fflush(stdout);
                last_pct_bucket = bucket;
                last_log_ms = now_ms();
            }
        } else {
            printf("\r[cfscan] %zu/%zu (%.1f%%) | OK: %zu | Miss: %zu | %.1f/s   ",
                   done, work.len, pct, ok, miss, (double)done / sec);
            fflush(stdout);
        }

        if (done >= work.len) break;
        sleep_ms(200);
    }
    if (!is_ci) printf("\n");

    for (int i = 0; i < workers; i++) {
#ifdef _WIN32
        if (threads[i]) {
            WaitForSingleObject(threads[i], INFINITE);
            CloseHandle(threads[i]);
        }
#else
        pthread_join(threads[i], CFSCAN_NULL);
#endif
    }
    free(threads);
    free(wargs);

    SubnetList new_under = {0};
    size_t newly_ok = 0;
    for (size_t i = 0; i < work.len; i++) {
        if (work.items[i].ok) {
            subnet_list_push(&existing_ok, &work.items[i]);
            newly_ok++;
        } else {
            subnet_list_push(&new_under, &work.items[i]);
        }
    }

    size_t prev_ok_cnt = existing_ok.len - newly_ok;
    subnet_list_sort_dedup(&existing_ok);
    subnet_list_sort_dedup(&new_under);

    if (!write_subnets_atomic(cfg.scan_file, &existing_ok)) {
        fprintf(stderr, "Error writing %s\n", cfg.scan_file);
        if (ctx.ssl_ctx) SSL_CTX_free(ctx.ssl_ctx);
        return 1;
    }
    if (!write_subnets_atomic(cfg.underscan_file, &new_under)) {
        fprintf(stderr, "Error writing %s\n", cfg.underscan_file);
        if (ctx.ssl_ctx) SSL_CTX_free(ctx.ssl_ctx);
        return 1;
    }

    double total_sec = (double)(now_ms() - t_start) / 1000.0;
    printf("[cfscan] Done in %.2fs | This run: %zu OK, %zu miss | Saved %s: %zu total (prev %zu) | Remaining %s: %zu\n",
           total_sec, newly_ok, new_under.len,
           cfg.scan_file, existing_ok.len, prev_ok_cnt,
           cfg.underscan_file, new_under.len);

    if (cfg.expected_code > 0) {
        printf("[cfscan] Status distribution:");
        bool any = false;
        for (int c = 100; c < 600; c++) {
            size_t cnt = atomic_load_explicit(&ctx.http_code_cnt[c], memory_order_relaxed);
            if (cnt > 0) {
                printf(" %d=%zu", c, cnt);
                any = true;
            }
        }
        size_t err_cnt = atomic_load_explicit(&ctx.http_err_cnt, memory_order_relaxed);
        if (err_cnt > 0 || !any) printf(" err/timeout=%zu", err_cnt);
        printf("\n");
    }

    free(work.items);
    free(existing_ok.items);
    free(new_under.items);
    if (ctx.ssl_ctx) SSL_CTX_free(ctx.ssl_ctx);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
