#define CFNAT_VERSION "0.0.14"

/* =========================================================================
 * C23 (ISO/IEC 9899:2024) Standard Compatibility & Polyfill Layer
 * ========================================================================= */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#define CFNAT_IS_C23 1
#else
#define CFNAT_IS_C23 0
#endif

#if CFNAT_IS_C23
  #define CFNAT_NODISCARD [[nodiscard]]
  #define CFNAT_UNUSED    [[maybe_unused]]
  #define CFNAT_NORETURN  [[noreturn]]
#elif defined(__GNUC__) || defined(__clang__)
  #define CFNAT_NODISCARD __attribute__((warn_unused_result))
  #define CFNAT_UNUSED    __attribute__((unused))
  #define CFNAT_NORETURN  __attribute__((noreturn))
#else
  #define CFNAT_NODISCARD
  #define CFNAT_UNUSED
  #define CFNAT_NORETURN
#endif

#if !CFNAT_IS_C23
  #ifndef nullptr
    #define nullptr NULL
  #endif
  #include <stdbool.h>
#endif

/* C23 constexpr object support (Clang 18+, GCC 14+, or standard conforming C23 compiler) */
#if defined(__has_extension)
  #if __has_extension(c_constexpr)
    #define CFNAT_CONSTEXPR constexpr
  #else
    #define CFNAT_CONSTEXPR static const
  #endif
#elif defined(__GNUC__) && (__GNUC__ >= 14)
  #define CFNAT_CONSTEXPR constexpr
#elif CFNAT_IS_C23 && !defined(__clang__)
  #define CFNAT_CONSTEXPR constexpr
#else
  #define CFNAT_CONSTEXPR static const
#endif

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <wininet.h>
#include <io.h>
#include <locale.h>
#else
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>
#ifdef __linux__
#include <sys/epoll.h>
#endif
#ifdef __APPLE__
#include <sys/event.h>
#include <sys/types.h>
#endif
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#define close closesocket
#ifndef SHUT_RD
#define SHUT_RD SD_RECEIVE
#endif
#ifndef SHUT_WR
#define SHUT_WR SD_SEND
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
typedef SOCKET socket_t;
CFNAT_NODISCARD static inline int cfnat_socket_valid(socket_t s) { return s != INVALID_SOCKET; }
CFNAT_NODISCARD static inline int cfnat_socket_invalid(socket_t s) { return s == INVALID_SOCKET; }
#else
typedef int socket_t;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif
CFNAT_NODISCARD static inline int cfnat_socket_valid(socket_t s) { return s >= 0; }
CFNAT_NODISCARD static inline int cfnat_socket_invalid(socket_t s) { return s < 0; }
#endif

/* 跨平台单套接字超时轮询（替代 select，突破 FD_SETSIZE 1024 限制）
 * poll_type: 1 = POLLIN (可读), 2 = POLLOUT (可写), 3 = 读写
 * 返回值: >0 表示就绪, 0 表示超时, <0 表示出错 */
#ifdef _WIN32
CFNAT_NODISCARD static int cfnat_poll_single(socket_t fd, int poll_type, int timeout_ms) {
    if (cfnat_socket_invalid(fd)) return -1;
    WSAPOLLFD pfd;
    pfd.fd = fd;
    pfd.events = 0;
    if (poll_type & 1) pfd.events |= POLLIN;
    if (poll_type & 2) pfd.events |= POLLOUT;
    pfd.revents = 0;
    int rc = WSAPoll(&pfd, 1, timeout_ms);
    if (rc <= 0) return rc;
    if ((poll_type & 2) && (pfd.revents & (POLLOUT | POLLERR | POLLHUP))) return 1;
    if ((poll_type & 1) && (pfd.revents & POLLIN)) return 1;
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
    return 1;
}
#else
CFNAT_NODISCARD static int cfnat_poll_single(socket_t fd, int poll_type, int timeout_ms) {
    if (cfnat_socket_invalid(fd)) return -1;
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = 0;
    if (poll_type & 1) pfd.events |= POLLIN;
    if (poll_type & 2) pfd.events |= POLLOUT;
    pfd.revents = 0;
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return rc;
    if ((poll_type & 2) && (pfd.revents & (POLLOUT | POLLERR | POLLHUP))) return 1;
    if ((poll_type & 1) && (pfd.revents & POLLIN)) return 1;
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
    return 1;
}
#endif

#define MAX_IP_LEN 64
#define MAX_COLO_LEN 8
#define MAX_REGION_LEN 64
#define MAX_CITY_LEN 64
#define MAX_LINE 512
#if CFNAT_IS_C23
#define COPY_BUF_SIZE 16'384
#else
#define COPY_BUF_SIZE 16384
#endif
#define MAX_ADDR_LEN 128
#define MAX_NAME_LEN 64
#define MAX_DOMAIN_LEN 256
#define MAX_PATH_LEN 256
#define MAX_RESOLVER_LEN 64
#define MAX_RESOLVER_SPEC_LEN 256


static const char *DEFAULT_BAIDU_DOMAIN = "cloudnproxy.baidu.com";
CFNAT_CONSTEXPR int DEFAULT_BAIDU_PORT = 443;
CFNAT_CONSTEXPR int DEFAULT_BAIDU_IPNUM = 12;
static const char *DEFAULT_BAIDU_SCAN_TARGET = "myip.ipip.net:80";
typedef struct {
    const char *label;
    const char *host;
    const char *ip;
    const char *path;
} DohResolver;

typedef struct {
    char host[MAX_DOMAIN_LEN];
    char ip[MAX_RESOLVER_LEN];
    char path[MAX_RESOLVER_SPEC_LEN];
} CustomDohStorage;

static const DohResolver BAIDU_DOH_RESOLVERS[] = {
    { "AliDNS DoH", "dns.alidns.com", "223.5.5.5", "/resolve" },
    { "Cloudflare DoH", "cloudflare-dns.com", "1.1.1.1", "/dns-query" },
    { nullptr, nullptr, nullptr, nullptr }
};
static const char *BAIDU_DNS_RESOLVERS[] = {
    "223.5.5.5",
    "119.29.29.29",
    "1.1.1.1",
    "8.8.8.8",
    nullptr
};
static const char *BAIDU_PROXY_FALLBACK_IPS[] = {
    "110.242.70.68",
    "110.242.70.69",
    "180.101.50.249",
    "183.240.98.84",
    "220.181.7.1",
    "220.181.33.174",
    "220.181.111.189",
    "14.215.182.75",
    "36.155.169.188",
    "153.3.237.117",
    "157.0.146.158",
    "163.177.17.6",
    "163.177.17.189",
    "180.101.50.208",
    nullptr
};
static const char *IPS_V4_URLS[] = {
    "https://cdn.jsdelivr.net/gh/fscarmen/cfnat@main/ips-v4.txt",
    "https://raw.githubusercontent.com/fscarmen/cfnat/main/ips-v4.txt",
    nullptr
};

static const char *IPS_V6_URLS[] = {
    "https://cdn.jsdelivr.net/gh/fscarmen/cfnat@main/ips-v6.txt",
    "https://raw.githubusercontent.com/fscarmen/cfnat/main/ips-v6.txt",
    nullptr
};

static const char *LOC_URLS[] = {
    "https://cdn.jsdelivr.net/gh/fscarmen/cfnat@main/locations.json",
    "https://raw.githubusercontent.com/fscarmen/cfnat/main/locations.json",
    nullptr
};


#if CFNAT_IS_C23
typedef enum : uint8_t {
    LOG_SILENT = 0,
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
} LogLevel;
#else
typedef enum {
    LOG_SILENT = 0,
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
} LogLevel;
#endif

typedef struct {
    int enabled;
    int ips_type;             /* 4 或 6 */
    char name[32];            /* "v4", "v6", "baidu" */
    char listen_addr[MAX_ADDR_LEN]; /* 本地监听地址 */
    int port;                 /* TLS 转发目标端口 */
    int http_port;            /* HTTP 转发目标端口 */
    int delay_ms;             /* 延迟上限 (ms) */
    int task;                 /* 并发扫描线程数 */
    int ipnum;                /* 提取有效 IP 数量 */
    int num;                  /* 单 IP 探测次数 */
    int random_mode;          /* 是否随机抽样 */
    int v6_split;             /* IPv6 细分抽样子网前缀，默认 54 (切分 /54 产生 64 个样本) */
    int code;                 /* HTTP 期望状态码 (0 表示不检测，仅测连通性) */
    char domain[MAX_DOMAIN_LEN]; /* 状态码检查域名/路径 */
    char colo[256];           /* 数据中心筛选规则 (含排除) */
    int use_baidu_proxy;      /* 0: 直连, 1: 百度前置, 2: 混合 */
} ProfileConfig;

typedef struct {
    char colo[256], domain[256], log_name[16];
    char baidu_domain[MAX_DOMAIN_LEN], baidu_scan_target[MAX_ADDR_LEN];
    char direct_listen[MAX_ADDR_LEN], baidu_listen[MAX_ADDR_LEN];
    char v4_listen[MAX_ADDR_LEN], v6_listen[MAX_ADDR_LEN];
    char bind_if[MAX_NAME_LEN], baidu_resolver[MAX_RESOLVER_SPEC_LEN];
    int code, delay_ms, ipnum, ips_type, num, port, http_port, random_mode, task, health_log;
    int v6_split;             /* 全局 IPv6 细分子网前缀 (默认 54) */
    int use_baidu_proxy, baidu_port, baidu_ipnum;
    int cli_mode;             /* 显式单次 CLI 测速模式 (-cli / -scan-only) */
    LogLevel log_level;
    ProfileConfig prof_v4;
    ProfileConfig prof_v6;
    ProfileConfig prof_baidu;
} Config;

typedef struct {
    char iata[MAX_COLO_LEN], region[MAX_REGION_LEN], city[MAX_CITY_LEN];
} Location;

typedef struct {
    char ip[MAX_IP_LEN], data_center[MAX_COLO_LEN], region[MAX_REGION_LEN], city[MAX_CITY_LEN];
    int latency_ms, loss_rate, probe_count, success_count;
    /* P0-EWMA: 指数加权移动平均延迟、抖动、连续失败次数 */
    int ewma_latency;
    int jitter_ms;
    int consecutive_fail;
    struct sockaddr_storage addr; /* 二进制地址预解析，热路径免重复 inet_pton */
    socklen_t addr_len;
} Result;

static inline void result_init_addr(Result *r) {
    if (!r || !r->ip[0]) return;
    memset(&r->addr, 0, sizeof(r->addr));
    if (strchr(r->ip, ':')) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&r->addr;
        s6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, r->ip, &s6->sin6_addr) == 1) {
            r->addr_len = sizeof(struct sockaddr_in6);
        }
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&r->addr;
        s4->sin_family = AF_INET;
        if (inet_pton(AF_INET, r->ip, &s4->sin_addr) == 1) {
            r->addr_len = sizeof(struct sockaddr_in);
        }
    }
}

typedef struct {
    Result *items;
    size_t len, cap;
} ResultList;

typedef struct StringChunk {
    struct StringChunk *next;
    size_t used;
    size_t cap;
    char data[];
} StringChunk;

typedef struct {
    char **items;
    size_t len, cap;
    StringChunk *chunks;
} StringList;

typedef struct BaiduProxyPool BaiduProxyPool;
typedef struct CarrierRuntime CarrierRuntime;

/* ── CidrList 惰性展开 ─────────────────────────────────────── */
/* 只存 CIDR 范围，不展开具体 IP，支持前缀和 + 二分查找 */
typedef struct {
    uint32_t base;      /* 网络号（主机字节序） */
    uint32_t count;     /* 该 CIDR 包含的 IP 数量 */
    int prefix;         /* 前缀长度 */
} CidrEntry;

typedef struct {
    CidrEntry *entries;
    uint64_t *prefix_sum;  /* 前缀和数组，prefix_sum[i] = sum(entries[0..i].count) */
    size_t len, cap;
    uint64_t total_ips;    /* 所有 CIDR 的 IP 总数 */
    int random_mode;       /* 是否随机抽样 */
} CidrList;

typedef struct {
    char **ips;
    CidrList *cidrs;    /* v0.0.11: CIDR 惰性展开，nullptr 时回退到 ips */
    size_t total;
    atomic_size_t index;
    atomic_size_t completed;
    atomic_size_t connect_fail;
    atomic_size_t header_fail;
    atomic_size_t cfray_miss;
    atomic_size_t colo_skip;
    atomic_size_t http_code_mismatch;
    long scan_start_ms;
    ResultList *results;
    pthread_mutex_t results_mu;
    Config *cfg;
    BaiduProxyPool *proxy_pool;
    char head_req[1024];
    int head_req_len;
    char get_req[1024];
    int get_req_len;
    int probe_port;
    int hdr_timeout;
} ScanCtx;



static long now_ms(void);
static void log_msg(const char *fmt, ...);
static void trim_line(char *s);
static uint32_t ipv4_to_u32(const char *s);
static void u32_to_ipv4(uint32_t v, char *out, size_t sz);
/* ── CidrList 函数实现 ──────────────────────────────────────── */

/* 添加 CIDR 条目 */
static int cidrlist_add(CidrList *cl, uint32_t base, uint32_t count, int prefix) {
    if (!cl) return -1;
    if (cl->len == cl->cap) {
        size_t nc = cl->cap ? cl->cap * 2 : 64;
        CidrEntry *ne = realloc(cl->entries, nc * sizeof(CidrEntry));
        if (!ne) return -1;
        cl->entries = ne;
        uint64_t *np = realloc(cl->prefix_sum, nc * sizeof(uint64_t));
        if (!np) return -1;
        cl->prefix_sum = np;
        cl->cap = nc;
    }
    cl->entries[cl->len].base = base;
    cl->entries[cl->len].count = count;
    cl->entries[cl->len].prefix = prefix;
    cl->total_ips += count;
    cl->prefix_sum[cl->len] = cl->total_ips;  /* 前缀和 */
    cl->len++;
    return 0;
}

/* 获取总 IP 数 */
static uint64_t cidrlist_total(CidrList *cl) {
    return cl ? cl->total_ips : 0;
}

/* 按全局索引惰性生成 IP（二分查找定位 CIDR 条目） */
static int cidrlist_get_ip(CidrList *cl, size_t global_idx, char *out, size_t outsz) {
    if (!cl || !out || outsz == 0 || global_idx >= cl->total_ips) return -1;
    /* 二分查找定位 CIDR 条目 */
    size_t lo = 0, hi = cl->len;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (cl->prefix_sum[mid] <= global_idx)
            lo = mid + 1;
        else
            hi = mid;
    }
    /* lo 即为目标条目索引 */
    uint64_t prev = lo > 0 ? cl->prefix_sum[lo - 1] : 0;
    uint32_t offset = (uint32_t)(global_idx - prev);
    u32_to_ipv4(cl->entries[lo].base + offset, out, outsz);
    return 0;
}

/* 释放 CIDR 列表 */
static void cidrlist_destroy(CidrList *cl) {
    if (!cl) return;
    free(cl->entries);
    free(cl->prefix_sum);
    memset(cl, 0, sizeof(*cl));
}

/* 从文件加载 CIDR 列表（惰性遍历） */
static CidrList load_cidr_list(const char *filename, int random_mode) {
    CidrList cl = {0};
    cl.random_mode = random_mode;
    FILE *f = fopen(filename, "r");
    if (!f) return cl;
    log_msg("正在读取 %s，模式：%s", filename, random_mode ? "CIDR随机抽样" : "惰性展开CIDR");
    char line[MAX_LINE];
    long start_ms = now_ms();
    size_t cidr_count = 0;
    (void)cidr_count;
    while (fgets(line, sizeof(line), f)) {
        trim_line(line);
        if (!line[0]) continue;
        char *slash = strchr(line, '/');
        if (!slash) {
            /* 单个 IP，当作 /32 处理 */
            uint32_t ip = ipv4_to_u32(line);
            if (ip == 0) continue;
            cidrlist_add(&cl, ip, 1, 32);
            cidr_count++;
            continue;
        }
        *slash = 0;
        int prefix = atoi(slash + 1);
        uint32_t base = ipv4_to_u32(line);
        if (base == 0 || prefix < 0 || prefix > 32) continue;
        uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
        uint32_t start = base & mask;
        uint32_t count = prefix == 32 ? 1u : (1u << (32 - prefix));
        cidrlist_add(&cl, start, count, prefix);
        cidr_count++;
    }
    fclose(f);
    log_msg("CIDR 列表加载完成: %zu 个 CIDR 条目，共 %llu 个候选 IP，耗时 %ld 秒",
            cl.len, (unsigned long long)cl.total_ips, (now_ms() - start_ms) / 1000);
    return cl;
}

/* ── CidrList 结束 ──────────────────────────────────────────── */

typedef struct {
    char mode[MAX_NAME_LEN];
    char addr[MAX_ADDR_LEN];
    int use_baidu_proxy;
    ProfileConfig prof;
} CarrierListenSpec;

typedef struct {
    char addr[MAX_ADDR_LEN];
    atomic_int active;
    atomic_int failures;
    atomic_long ewma_ms;
} BaiduProxyNode;

struct BaiduProxyPool {
    char name[MAX_NAME_LEN];
    BaiduProxyNode *nodes;
    size_t len;
    size_t cap;
    /* P0-CACHE: 缓存最优节点索引，5 秒有效期，原子无锁并发安全 */
    atomic_int cached_best_idx;
    atomic_long cached_at_ms;
};

typedef struct {
    Result *items;
    size_t len;
    size_t current_index;
    char current_ip[MAX_IP_LEN];
    struct sockaddr_storage current_addr;
    socklen_t current_addr_len;
    atomic_int fast_fail_count;
    pthread_mutex_t mu;
    atomic_int cache_valid;  /* P0-1: 1=当前 IP 可直接使用，0=需要重新选择 */
} CandidatePool;

typedef struct {
    socket_t client_fd;
    int tls_port, http_port, num, delay_ms;
    char ip[MAX_IP_LEN];
    struct sockaddr_storage ip_addr;
    socklen_t ip_addr_len;
    char client_addr[64];
    BaiduProxyPool *proxy_pool;
    CarrierRuntime *runtime;
    int use_mixed; // 1 表示混合模式
    unsigned long long conn_id;
} ConnCtx;

typedef struct {
    socket_t from, to;
    uint64_t bytes;
} PipeCtx;

typedef struct UdpSession UdpSession;

struct CarrierRuntime {
    socket_t listen_fd;
    socket_t udp_listen_fd;
    CarrierListenSpec spec;
    CandidatePool candidates;      /* TCP 候选池 (供 H2 / TCP 转发使用) */
    CandidatePool udp_candidates;  /* UDP 候选池 (供 H3 / QUIC 转发使用) */
    BaiduProxyPool *proxy_pool;
    pthread_t health_tid;          /* TCP 渐进式健康检查线程 */
    pthread_t udp_health_tid;      /* UDP QUIC 健康检查线程 */
    pthread_t accept_tid;
    pthread_t udp_tid;
    UdpSession *udp_sessions;
    UdpSession *last_udp_sess;     /* P0-MRU: 单级热点会话缓存 (为 H3 多路复用提供 O(1) 检索) */
    pthread_mutex_t udp_mu;
    atomic_int rescanning_lock;    /* 实例独享的自愈扫描互斥锁 (防跨协议阻塞) */
};

static Config g_cfg;
static Location *g_locations = nullptr;
static size_t g_location_count = 0;
static atomic_int g_running = 1;
static atomic_int g_active_tcp_conns = 0;
static atomic_ullong g_tcp_conn_seq = 0;
static atomic_int g_active_udp_sessions = 0;
static atomic_ullong g_udp_sess_seq = 0;

static BaiduProxyPool g_default_proxy_pool = {0};

static CarrierRuntime *g_carrier_runtimes = nullptr;
static size_t g_carrier_runtime_count = 0;
static pthread_mutex_t g_log_mu = PTHREAD_MUTEX_INITIALIZER;

static int parse_addr(const char *addr, char *host, size_t hostsz, int *port);
static socket_t accept_interruptible(socket_t listen_fd, struct sockaddr *addr,
#ifdef _WIN32
        int *addrlen
#else
        socklen_t *addrlen
#endif
);

#ifdef _WIN32
static int cfnat_get_console_handle(FILE *stream, HANDLE *out) {
    int fd = _fileno(stream);
    if (fd < 0) return 0;

    intptr_t os_handle = _get_osfhandle(fd);
    if (os_handle == -1) return 0;

    HANDLE handle = (HANDLE)os_handle;
    DWORD mode = 0;
    if (!GetConsoleMode(handle, &mode)) return 0;

    if (out) *out = handle;
    return 1;
}

static int cfnat_write_utf8(FILE *stream, const char *text, size_t len) {
    if (!text || len == 0) return 0;

    HANDLE handle = nullptr;
    if (!cfnat_get_console_handle(stream, &handle)) {
        return (int)fwrite(text, 1, len, stream);
    }

    int wlen = MultiByteToWideChar(CP_UTF8, 0, text, (int)len, nullptr, 0);
    if (wlen <= 0) {
        return (int)fwrite(text, 1, len, stream);
    }

    wchar_t *wide = (wchar_t *)malloc(((size_t)wlen + 1) * sizeof(wchar_t));
    if (!wide) {
        return (int)fwrite(text, 1, len, stream);
    }

    MultiByteToWideChar(CP_UTF8, 0, text, (int)len, wide, wlen);
    wide[wlen] = L'\0';

    DWORD written = 0;
    BOOL ok = WriteConsoleW(handle, wide, (DWORD)wlen, &written, nullptr);
    free(wide);

    if (!ok) {
        return (int)fwrite(text, 1, len, stream);
    }
    return (int)len;
}

static int cfnat_vfprintf(FILE *stream, const char *fmt, va_list ap) {
    char stack_buf[8192];
    va_list ap_copy;
    va_copy(ap_copy, ap);
    int needed = vsnprintf(stack_buf, sizeof(stack_buf), fmt, ap_copy);
    va_end(ap_copy);

    if (needed < 0) return needed;
    if ((size_t)needed < sizeof(stack_buf)) {
        cfnat_write_utf8(stream, stack_buf, (size_t)needed);
        return needed;
    }

    char *buf = (char *)malloc((size_t)needed + 1);
    if (!buf) {
        cfnat_write_utf8(stream, stack_buf, strlen(stack_buf));
        return needed;
    }

    va_copy(ap_copy, ap);
    vsnprintf(buf, (size_t)needed + 1, fmt, ap_copy);
    va_end(ap_copy);

    cfnat_write_utf8(stream, buf, (size_t)needed);
    free(buf);
    return needed;
}

static int cfnat_fprintf(FILE *stream, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = cfnat_vfprintf(stream, fmt, ap);
    va_end(ap);
    return rc;
}

static int cfnat_printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int rc = cfnat_vfprintf(stdout, fmt, ap);
    va_end(ap);
    return rc;
}

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

static void init_windows_console_utf8(void) {
    setlocale(LC_ALL, "");
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE && hOut != nullptr) {
        DWORD mode = 0;
        if (GetConsoleMode(hOut, &mode)) {
            SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
    HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
    if (hErr != INVALID_HANDLE_VALUE && hErr != nullptr) {
        DWORD mode = 0;
        if (GetConsoleMode(hErr, &mode)) {
            SetConsoleMode(hErr, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

#define printf cfnat_printf
#define fprintf cfnat_fprintf
#define vfprintf cfnat_vfprintf

#else

static inline int cfnat_write_utf8(FILE *stream, const char *text, size_t len) {
    if (!text || len == 0) return 0;
    return (int)fwrite(text, 1, len, stream);
}

#endif

#ifdef _WIN32
#ifndef isatty
#define isatty _isatty
#endif
#ifndef fileno
#define fileno _fileno
#endif
#endif

#define ANSI_RESET   "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_DIM     "\033[2m"
#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_WHITE   "\033[37m"
#define ANSI_GRAY    "\033[90m"

static int terminal_has_color(FILE *stream) {
    if (!stream) return 0;
    int fd = fileno(stream);
    if (fd < 0) return 0;
    return isatty(fd);
}

static void print_results_table_stream(FILE *stream, const Result *items, size_t count, long duration_sec) {
    if (!items || count == 0 || !stream) return;
    pthread_mutex_lock(&g_log_mu);
    int use_color = terminal_has_color(stream);
    const char *c_ip = use_color ? (ANSI_CYAN ANSI_BOLD) : "";
    const char *c_colo = use_color ? (ANSI_YELLOW ANSI_BOLD) : "";
    const char *c_reg = use_color ? (ANSI_MAGENTA ANSI_BOLD) : "";
    const char *c_city = use_color ? (ANSI_WHITE ANSI_BOLD) : "";
    const char *c_lat = use_color ? (ANSI_GREEN ANSI_BOLD) : "";
    const char *c_val_green = use_color ? ANSI_GREEN : "";
    const char *c_val_yellow = use_color ? ANSI_YELLOW : "";
    const char *c_val_red = use_color ? ANSI_RED : "";
    const char *c_bold = use_color ? ANSI_BOLD : "";
    const char *reset = use_color ? ANSI_RESET : "";

    fprintf(stream, "\n%sIP 地址%s          | %s数据中心%s | %s地区%s          | %s城市%s        | %s延迟%s\n",
            c_ip, reset, c_colo, reset, c_reg, reset, c_city, reset, c_lat, reset);
    fprintf(stream, "-----------------+----------+---------------+---------------+---------\n");
    for (size_t i = 0; i < count; i++) {
        const Result *r = &items[i];
        const char *lat_color = c_val_green;
        if (r->latency_ms > 250) lat_color = c_val_red;
        else if (r->latency_ms > 150) lat_color = c_val_yellow;

        fprintf(stream, "%-16s | %-8s | %-13s | %-13s | %s%3d ms%s\n",
                r->ip,
                r->data_center[0] ? r->data_center : "UNK",
                r->region[0] ? r->region : "-",
                r->city[0] ? r->city : "-",
                lat_color, r->latency_ms, reset);
    }
    fprintf(stream, "\n%s%s成功提取 %zu 个有效IP，耗时 %ld秒%s\n\n",
            c_bold, c_val_green, count, duration_sec, reset);
    fflush(stream);
    pthread_mutex_unlock(&g_log_mu);
}

static void print_results_table(const Result *items, size_t count, long duration_sec) {
    print_results_table_stream(stderr, items, count, duration_sec);
}

static long now_ms(void) {
#ifdef _WIN32
    return (long)GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (long)tv.tv_sec * 1000L + tv.tv_usec / 1000L;
#endif
}

static const char *log_level_name(LogLevel level) {
    switch (level) {
    case LOG_SILENT:
        return "silent";
    case LOG_ERROR:
        return "error";
    case LOG_WARN:
        return "warn";
    case LOG_INFO:
        return "info";
    case LOG_DEBUG:
    default:
        return "debug";
    }
}

static int parse_log_level(const char *v, LogLevel *out) {
    if (!v || !*v) return -1;
    if (!strcasecmp(v, "silent") || !strcasecmp(v, "off")) {
        *out = LOG_SILENT;
        return 0;
    }
    if (!strcasecmp(v, "error")) {
        *out = LOG_ERROR;
        return 0;
    }
    if (!strcasecmp(v, "warn") || !strcasecmp(v, "warning")) {
        *out = LOG_WARN;
        return 0;
    }
    if (!strcasecmp(v, "info")) {
        *out = LOG_INFO;
        return 0;
    }
    if (!strcasecmp(v, "debug")) {
        *out = LOG_DEBUG;
        return 0;
    }
    return -1;
}

static void vlog_line(const char *tag, const char *fmt, va_list ap) {
    time_t t = time(nullptr);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char ts[32];
    strftime(ts, sizeof(ts), "%Y/%m/%d %H:%M:%S", &tmv);

    int use_color = terminal_has_color(stderr);
    const char *tag_color = "";
    const char *time_color = use_color ? ANSI_GRAY : "";
    const char *reset = use_color ? ANSI_RESET : "";

    if (use_color) {
        if (!strcmp(tag, "ERROR")) tag_color = ANSI_RED ANSI_BOLD;
        else if (!strcmp(tag, "WARN")) tag_color = ANSI_YELLOW ANSI_BOLD;
        else if (!strcmp(tag, "INFO")) tag_color = ANSI_GREEN;
        else if (!strcmp(tag, "DEBUG")) tag_color = ANSI_MAGENTA;
        else if (!strcmp(tag, "CONN")) tag_color = ANSI_BLUE;
        else tag_color = ANSI_CYAN;
    }

    /* 紧凑栈帧：常规日志行长 < 200 字节，1KB/2KB 缓冲比原 12KB 栈帧缩减 75% 消耗 */
    char raw_msg[1024];
    int n = vsnprintf(raw_msg, sizeof(raw_msg), fmt, ap);
    if (n < 0) return;

    /* 单一完整行缓冲输出，彻底杜绝并发日志交错与字符截断 */
    char line_buf[2048];
    size_t out_len = 0;

    int prefix_len = snprintf(line_buf, sizeof(line_buf), "%s%s%s [%s%s%s] ",
                              time_color, ts, reset, tag_color, tag, reset);
    if (prefix_len > 0) out_len = (size_t)prefix_len;

    /* 视觉可读性与色彩差异化：[TCP/H2] 为高亮青色，[UDP/H3] 为高亮洋红 */
    if (use_color) {
        const char *p = raw_msg;
        while (*p && out_len + 64 < sizeof(line_buf)) {
            if (*p == '\n') {
                line_buf[out_len++] = '\n';
                p++;
                int plen = snprintf(line_buf + out_len, sizeof(line_buf) - out_len, "%s%s%s [%s%s%s] ",
                                    time_color, ts, reset, tag_color, tag, reset);
                if (plen > 0) out_len += (size_t)plen;
            } else if (strncmp(p, "[TCP/H2]", 8) == 0) {
                const char *tcp_colored = ANSI_CYAN ANSI_BOLD "[TCP/H2]" ANSI_RESET;
                size_t clen = strlen(tcp_colored);
                if (out_len + clen < sizeof(line_buf) - 2) {
                    memcpy(line_buf + out_len, tcp_colored, clen);
                    out_len += clen;
                }
                p += 8;
            } else if (strncmp(p, "[UDP/H3]", 8) == 0) {
                const char *udp_colored = ANSI_MAGENTA ANSI_BOLD "[UDP/H3]" ANSI_RESET;
                size_t clen = strlen(udp_colored);
                if (out_len + clen < sizeof(line_buf) - 2) {
                    memcpy(line_buf + out_len, udp_colored, clen);
                    out_len += clen;
                }
                p += 8;
            } else {
                line_buf[out_len++] = *p++;
            }
        }
    } else {
        const char *p = raw_msg;
        while (*p && out_len + 64 < sizeof(line_buf)) {
            if (*p == '\n') {
                line_buf[out_len++] = '\n';
                p++;
                int plen = snprintf(line_buf + out_len, sizeof(line_buf) - out_len, "%s [%s] ", ts, tag);
                if (plen > 0) out_len += (size_t)plen;
            } else {
                line_buf[out_len++] = *p++;
            }
        }
    }

    if (out_len + 2 < sizeof(line_buf)) {
        line_buf[out_len++] = '\n';
        line_buf[out_len] = '\0';
    }

    pthread_mutex_lock(&g_log_mu);
    cfnat_write_utf8(stderr, line_buf, out_len);
    fflush(stderr);
    pthread_mutex_unlock(&g_log_mu);
}

static void log_msg(const char *fmt, ...) {
    if (g_cfg.log_level < LOG_INFO) return;
    va_list ap;
    va_start(ap, fmt);
    vlog_line("INFO", fmt, ap);
    va_end(ap);
}

static void warn_msg(const char *fmt, ...) {
    if (g_cfg.log_level < LOG_WARN) return;
    va_list ap;
    va_start(ap, fmt);
    vlog_line("WARN", fmt, ap);
    va_end(ap);
}

static void debug_msg(const char *fmt, ...) {
    if (g_cfg.log_level < LOG_DEBUG) return;
    va_list ap;
    va_start(ap, fmt);
    vlog_line("DEBUG", fmt, ap);
    va_end(ap);
}

static void conn_msg(const char *fmt, ...) {
    if (g_cfg.log_level < LOG_DEBUG) return; /* P1: 仅在 DEBUG 级别输出连接日志，杜绝日常刷屏 */
    va_list ap;
    va_start(ap, fmt);
    vlog_line("CONN", fmt, ap);
    va_end(ap);
}

static int sleep_interruptible_ms(int ms) {
    int left = ms;
    while (left > 0 && atomic_load(&g_running)) {
        int chunk = left > 200 ? 200 : left;
#ifdef _WIN32
        Sleep((DWORD)chunk);
#else
        struct timespec ts;
        ts.tv_sec = chunk / 1000;
        ts.tv_nsec = (long)(chunk % 1000) * 1000000L;
        nanosleep(&ts, nullptr);
#endif
        left -= chunk;
    }
    return atomic_load(&g_running) ? 0 : -1;
}

static void sleep_ms_raw(int ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, nullptr);
#endif
}

static int bind_socket_to_interface(socket_t fd, int family) {
    if (!g_cfg.bind_if[0]) return 0;
#ifdef _WIN32
    (void)fd;
    (void)family;
    errno = ENOTSUP;
    return -1;
#elif defined(__APPLE__)
    unsigned int ifindex = if_nametoindex(g_cfg.bind_if);
    if (ifindex == 0) {
        errno = ENODEV;
        return -1;
    }
    int idx = (int)ifindex;
    int level = family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
    int opt = family == AF_INET6 ? IPV6_BOUND_IF : IP_BOUND_IF;
    return setsockopt(fd, level, opt, &idx, sizeof(idx));
#elif defined(__linux__)
    (void)family;
    return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, g_cfg.bind_if, strlen(g_cfg.bind_if) + 1);
#else
    (void)fd;
    (void)family;
    errno = ENOTSUP;
    return -1;
#endif
}

static int validate_bind_interface(const Config *c) {
    if (!c || !c->bind_if[0]) return 0;
#ifdef _WIN32
    fprintf(stderr, "-bind-if 当前不支持 Windows\n");
    return -1;
#elif defined(__APPLE__) || defined(__linux__)
    if (if_nametoindex(c->bind_if) == 0) {
        fprintf(stderr, "找不到网络接口: %s\n", c->bind_if);
        return -1;
    }
    return 0;
#else
    fprintf(stderr, "-bind-if 当前平台不支持\n");
    return -1;
#endif
}

static void usage(const char *p) {
    printf("cfnat v%s - Cloudflare NAT 优选工具 (C 版)\n", CFNAT_VERSION);
    printf("Usage of %s:\n", p);
    printf("  -V, -version              显示版本号\n");
    printf("  -bind-if=value            绑定出站物理网卡，例如 macOS: en0，Linux: eth0\n");
    printf("  -v4-listen[=addr]         开启 IPv4 本地监听地址 (默认 0.0.0.0:4443)\n");
    printf("  -v6-listen[=addr]         开启 IPv6 本地监听地址 (默认 0.0.0.0:6443)\n");
    printf("  -baidu-listen[=addr]      开启百度前置本地监听地址 (默认 0.0.0.0:5444)\n");
    printf("  -direct-listen=value      兼容旧参数: 直连优选监听地址 (默认 IPv4: 4443，指定 -ips=6 为 6443)\n");
    printf("  -baidu-resolver=value     Fake-IP 时百度域名解析器: auto | udp://IP | doh://IP/path?host=HOST\n");
    printf("  -colo=value               数据中心筛选 (支持反选: -HKG, ^HKG, !HKG)\n");
    printf("  -exclude-colo=value       显式排除的数据中心，例如 HKG,SJC\n");
    printf("  -delay=value              有效延迟毫秒上限 (default 300)\n");
    printf("  -ipnum=value              提取的有效 IP 数量 (default 20)\n");
    printf("  -num=value                单 IP 探测尝试次数 (default 5)\n");
    printf("  -port=value               TLS 转发目标端口 (default 443)\n");
    printf("  -http-port=value          非 TLS/HTTP 转发目标端口 (default 80)\n");
    printf("  -code=value               期望响应 HTTP 状态码 (默认缺省 0: 仅测连通性; 显式指定如 200 则做二次状态检测)\n");
    printf("  -domain=value             状态码检查域名地址 (default cloudflaremirrors.com/debian)\n");
    printf("  -random=value             是否随机生成 IP (default true)\n");
    printf("  -v6-split=value           IPv6 /48 细分抽样子网前缀，例如 54 (产生 64 个样本, default 54)\n");
    printf("  -task=value               并发扫描线程数 (default 200)\n");
    printf("  -cli, -scan-only          仅单次 CLI 测速并打印结果表格，不启动本地端口监听\n");
    printf("  -log=value                日志级别: silent,error,warn,info,debug (default info)\n");
    printf("  注: 以上参数均支持 -v4- 或 -v6- 前缀实现精细化覆盖，如 -v6-code=200 -v4-delay=150\n");
}

static int parse_bool(const char *v) {
    return !v || strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0 || strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0;
}

static void format_listen_endpoint(const char *in, int default_port, char *out, size_t outsz) {
    if (!out || outsz == 0) return;
    if (!in || !*in) {
        snprintf(out, outsz, "0.0.0.0:%d", default_port);
        return;
    }
    /* 如果输入是纯数字（端口），自动拼上 0.0.0.0: */
    int is_all_digit = 1;
    for (const char *p = in; *p; p++) {
        if (!isdigit((unsigned char)*p)) { is_all_digit = 0; break; }
    }
    if (is_all_digit) {
        snprintf(out, outsz, "0.0.0.0:%s", in);
    } else {
        snprintf(out, outsz, "%s", in);
    }
}

static void cfg_defaults(Config *c) {
    memset(c, 0, sizeof(*c));
    strcpy(c->domain, "cloudflaremirrors.com/debian");
    strcpy(c->log_name, "info");
    strcpy(c->baidu_domain, DEFAULT_BAIDU_DOMAIN);
    strcpy(c->baidu_scan_target, DEFAULT_BAIDU_SCAN_TARGET);
    strcpy(c->baidu_resolver, "auto");
    c->code = 0;  /* 默认缺省 0: 仅测连通性 */
    c->delay_ms = 300;
    c->ipnum = 20;
    c->ips_type = 4;
    c->num = 5;
    c->port = 443;
    c->http_port = 80;
    c->random_mode = 1;
    c->v6_split = 54;
    c->task = 200;
    c->health_log = 60;
    c->use_baidu_proxy = 0;
    c->baidu_port = DEFAULT_BAIDU_PORT;
    c->baidu_ipnum = DEFAULT_BAIDU_IPNUM;
    c->cli_mode = 0;
    c->log_level = LOG_INFO;
}

static void parse_args(Config *c, int argc, char **argv) {
    cfg_defaults(c);
    char exclude_colo_buf[256] = {0};
    char v4_exclude_colo_buf[256] = {0};
    char v6_exclude_colo_buf[256] = {0};

    /* 标记哪些专属参数被显式指定了 */
    int has_v4_listen = 0, has_v6_listen = 0, has_baidu_listen = 0;
    char v4_listen_val[MAX_ADDR_LEN] = {0};
    char v6_listen_val[MAX_ADDR_LEN] = {0};
    char baidu_listen_val[MAX_ADDR_LEN] = {0};

    int v4_port = 0, v6_port = 0;
    int v4_http_port = 0, v6_http_port = 0;
    int v4_delay = 0, v6_delay = 0;
    int v4_task = 0, v6_task = 0;
    int v4_ipnum = 0, v6_ipnum = 0;
    int v4_num = 0, v6_num = 0;
    int v4_code = -1, v6_code = -1; /* -1 表示未指定专属 */
    int v4_random = -1, v6_random = -1;
    int v6_split_val = -1;
    char v4_colo[256] = {0}, v6_colo[256] = {0};
    char v4_domain[MAX_DOMAIN_LEN] = {0}, v6_domain[MAX_DOMAIN_LEN] = {0};

    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            usage(argv[0]);
            exit(0);
        }
        if (!strcmp(arg, "-V") || !strcmp(arg, "-version") || !strcmp(arg, "--version")) {
            printf("cfnat version %s\n", CFNAT_VERSION);
            exit(0);
        }
        if (arg[0] != '-') continue;
        char *key = arg + 1;
        if (*key == '-') key++;
        char *eq = strchr(key, '=');
        char *val = nullptr;
        if (eq) {
            *eq = 0;
            val = eq + 1;
        } else if (i + 1 < argc) {
            if (argv[i + 1][0] != '-') {
                val = argv[++i];
            } else if ((!strcmp(key, "colo") || !strcmp(key, "v4-colo") || !strcmp(key, "v6-colo") ||
                        !strcmp(key, "exclude-colo") || !strcmp(key, "v4-exclude-colo") || !strcmp(key, "v6-exclude-colo") ||
                        !strcmp(key, "ex-colo") || !strcmp(key, "v4-ex-colo") || !strcmp(key, "v6-ex-colo")) &&
                       argv[i + 1][1] != '\0' && !strchr(argv[i + 1], '=')) {
                /* 支持数据中心筛选反选传参，如 -colo -HKG */
                val = argv[++i];
            }
        }

        /* 本地监听参数解析: 支持 -v4-listen, -v6-listen, -baidu-listen, -direct-listen */
        if (!strcmp(key, "v4-listen")) {
            has_v4_listen = 1;
            format_listen_endpoint(val, 4443, v4_listen_val, sizeof(v4_listen_val));
        } else if (!strcmp(key, "v6-listen")) {
            has_v6_listen = 1;
            format_listen_endpoint(val, 6443, v6_listen_val, sizeof(v6_listen_val));
        } else if (!strcmp(key, "baidu-listen")) {
            has_baidu_listen = 1;
            format_listen_endpoint(val, 5444, baidu_listen_val, sizeof(baidu_listen_val));
        } else if (!strcmp(key, "direct-listen") && val) {
            snprintf(c->direct_listen, sizeof(c->direct_listen), "%s", val);
        }
        /* v4 专属覆盖参数 */
        else if (!strcmp(key, "v4-port") && val) v4_port = atoi(val);
        else if (!strcmp(key, "v4-http-port") && val) v4_http_port = atoi(val);
        else if (!strcmp(key, "v4-delay") && val) v4_delay = atoi(val);
        else if (!strcmp(key, "v4-task") && val) v4_task = atoi(val);
        else if (!strcmp(key, "v4-ipnum") && val) v4_ipnum = atoi(val);
        else if (!strcmp(key, "v4-num") && val) v4_num = atoi(val);
        else if (!strcmp(key, "v4-code") && val) v4_code = atoi(val);
        else if (!strcmp(key, "v4-domain") && val) snprintf(v4_domain, sizeof(v4_domain), "%s", val);
        else if (!strcmp(key, "v4-colo") && val) snprintf(v4_colo, sizeof(v4_colo), "%s", val);
        else if ((!strcmp(key, "v4-exclude-colo") || !strcmp(key, "v4-ex-colo")) && val) {
            if (v4_exclude_colo_buf[0]) snprintf(v4_exclude_colo_buf + strlen(v4_exclude_colo_buf), sizeof(v4_exclude_colo_buf) - strlen(v4_exclude_colo_buf), ",%s", val);
            else snprintf(v4_exclude_colo_buf, sizeof(v4_exclude_colo_buf), "%s", val);
        } else if (!strcmp(key, "v4-random")) v4_random = parse_bool(val);

        /* v6 专属覆盖参数 */
        else if (!strcmp(key, "v6-port") && val) v6_port = atoi(val);
        else if (!strcmp(key, "v6-http-port") && val) v6_http_port = atoi(val);
        else if (!strcmp(key, "v6-delay") && val) v6_delay = atoi(val);
        else if (!strcmp(key, "v6-task") && val) v6_task = atoi(val);
        else if (!strcmp(key, "v6-ipnum") && val) v6_ipnum = atoi(val);
        else if (!strcmp(key, "v6-num") && val) v6_num = atoi(val);
        else if (!strcmp(key, "v6-code") && val) v6_code = atoi(val);
        else if (!strcmp(key, "v6-domain") && val) snprintf(v6_domain, sizeof(v6_domain), "%s", val);
        else if (!strcmp(key, "v6-colo") && val) snprintf(v6_colo, sizeof(v6_colo), "%s", val);
        else if ((!strcmp(key, "v6-exclude-colo") || !strcmp(key, "v6-ex-colo")) && val) {
            if (v6_exclude_colo_buf[0]) snprintf(v6_exclude_colo_buf + strlen(v6_exclude_colo_buf), sizeof(v6_exclude_colo_buf) - strlen(v6_exclude_colo_buf), ",%s", val);
            else snprintf(v6_exclude_colo_buf, sizeof(v6_exclude_colo_buf), "%s", val);
        } else if (!strcmp(key, "v6-random")) v6_random = parse_bool(val);
        else if (!strcmp(key, "v6-split") && val) {
            int v = atoi(val);
            if (v >= 48 && v <= 64) {
                v6_split_val = v;
                c->v6_split = v;
            } else {
                warn_msg("参数 -v6-split=%s 超出有效范围 [48, 64]，默认使用 54", val);
                v6_split_val = 54;
                c->v6_split = 54;
            }
        }

        /* 全局通用参数 */
        else if (!strcmp(key, "baidu-resolver") && val) snprintf(c->baidu_resolver, sizeof(c->baidu_resolver), "%s", val);
        else if (!strcmp(key, "bind-if") && val) snprintf(c->bind_if, sizeof(c->bind_if), "%s", val);
        else if (!strcmp(key, "code") && val) c->code = atoi(val);
        else if (!strcmp(key, "colo") && val) snprintf(c->colo, sizeof(c->colo), "%s", val);
        else if ((!strcmp(key, "exclude-colo") || !strcmp(key, "ex-colo")) && val) {
            if (exclude_colo_buf[0]) snprintf(exclude_colo_buf + strlen(exclude_colo_buf), sizeof(exclude_colo_buf) - strlen(exclude_colo_buf), ",%s", val);
            else snprintf(exclude_colo_buf, sizeof(exclude_colo_buf), "%s", val);
        }
        else if (!strcmp(key, "delay") && val) c->delay_ms = atoi(val);
        else if (!strcmp(key, "domain") && val) snprintf(c->domain, sizeof(c->domain), "%s", val);
        else if (!strcmp(key, "ipnum") && val) c->ipnum = atoi(val);
        else if (!strcmp(key, "ips") && val) c->ips_type = atoi(val);
        else if ((!strcmp(key, "log") || !strcmp(key, "log-level")) && val) {
            if (parse_log_level(val, &c->log_level) != 0) {
                fprintf(stderr, "非法 -log=%s，可选值: silent, error, warn, info, debug\n", val);
                exit(1);
            }
            snprintf(c->log_name, sizeof(c->log_name), "%s", log_level_name(c->log_level));
        } else if (!strcmp(key, "debug")) {
            c->log_level = LOG_DEBUG;
            snprintf(c->log_name, sizeof(c->log_name), "debug");
        } else if (!strcmp(key, "num") && val) c->num = atoi(val);
        else if (!strcmp(key, "port") && val) c->port = atoi(val);
        else if (!strcmp(key, "http-port") && val) c->http_port = atoi(val);
        else if (!strcmp(key, "random")) c->random_mode = parse_bool(val);
        else if (!strcmp(key, "task") && val) c->task = atoi(val);
        else if (!strcmp(key, "cli") || !strcmp(key, "scan-only")) c->cli_mode = 1;
        else if (!strcmp(key, "health-log") && val) c->health_log = atoi(val);
    }

    /* 统一合并全局 exclude-colo 到 c->colo */
    if (exclude_colo_buf[0]) {
        char tmp_ex[sizeof(exclude_colo_buf)];
        snprintf(tmp_ex, sizeof(tmp_ex), "%s", exclude_colo_buf);
        char *save = nullptr;
        char *tok = strtok_r(tmp_ex, ",", &save);
        while (tok) {
            trim_line(tok);
            while (*tok == '-' || *tok == '^' || *tok == '!' || *tok == ' ') tok++;
            if (*tok) {
                if (c->colo[0]) snprintf(c->colo + strlen(c->colo), sizeof(c->colo) - strlen(c->colo), ",-%s", tok);
                else snprintf(c->colo, sizeof(c->colo), "-%s", tok);
            }
            tok = strtok_r(nullptr, ",", &save);
        }
    }

    if (c->delay_ms <= 0) c->delay_ms = 300;
    if (c->ipnum <= 0) c->ipnum = 20;
    if (c->num <= 0) c->num = 1;
    if (c->task <= 0) c->task = 1;
    if (c->baidu_port <= 0) c->baidu_port = 443;
    if (c->baidu_ipnum <= 0) c->baidu_ipnum = 12;

    /* 判定激活哪个 profile:
       1. 若用户显式指定了 -v4-listen, -v6-listen 或 -baidu-listen 中的任意一个，则按需开启；
       2. 若用户指定了旧的 -direct-listen 或 -baidu-listen，则兼容旧逻辑；
       3. 若用户全都没指定，则默认仅开启 IPv4，监听 0.0.0.0:4443。
    */
    int any_explicit_listen = (has_v4_listen || has_v6_listen || has_baidu_listen || c->direct_listen[0]);
    if (!any_explicit_listen && !c->cli_mode) {
        has_v4_listen = 1;
        snprintf(v4_listen_val, sizeof(v4_listen_val), "0.0.0.0:4443");
    }

    /* 如果指定了 -direct-listen，按照用户传入的 -ips=6 或 4 映射到对应 profile */
    if (c->direct_listen[0]) {
        if (c->ips_type == 6) {
            has_v6_listen = 1;
            format_listen_endpoint(c->direct_listen, 6443, v6_listen_val, sizeof(v6_listen_val));
        } else {
            has_v4_listen = 1;
            format_listen_endpoint(c->direct_listen, 4443, v4_listen_val, sizeof(v4_listen_val));
        }
    }

    /* 初始化 prof_v4 */
    c->prof_v4.enabled = has_v4_listen;
    c->prof_v4.ips_type = 4;
    snprintf(c->prof_v4.name, sizeof(c->prof_v4.name), "v4");
    snprintf(c->prof_v4.listen_addr, sizeof(c->prof_v4.listen_addr), "%s", v4_listen_val[0] ? v4_listen_val : "0.0.0.0:4443");
    c->prof_v4.port = v4_port > 0 ? v4_port : c->port;
    c->prof_v4.http_port = v4_http_port > 0 ? v4_http_port : c->http_port;
    c->prof_v4.delay_ms = v4_delay > 0 ? v4_delay : c->delay_ms;
    c->prof_v4.task = v4_task > 0 ? v4_task : c->task;
    c->prof_v4.ipnum = v4_ipnum > 0 ? v4_ipnum : c->ipnum;
    c->prof_v4.num = v4_num > 0 ? v4_num : c->num;
    c->prof_v4.code = v4_code >= 0 ? v4_code : c->code;
    c->prof_v4.random_mode = v4_random >= 0 ? v4_random : c->random_mode;
    c->prof_v4.v6_split = 0;
    snprintf(c->prof_v4.domain, sizeof(c->prof_v4.domain), "%s", v4_domain[0] ? v4_domain : c->domain);
    snprintf(c->prof_v4.colo, sizeof(c->prof_v4.colo), "%s", v4_colo[0] ? v4_colo : c->colo);
    if (v4_exclude_colo_buf[0]) {
        char tmp_ex[sizeof(v4_exclude_colo_buf)];
        snprintf(tmp_ex, sizeof(tmp_ex), "%s", v4_exclude_colo_buf);
        char *save = nullptr;
        char *tok = strtok_r(tmp_ex, ",", &save);
        while (tok) {
            trim_line(tok);
            while (*tok == '-' || *tok == '^' || *tok == '!' || *tok == ' ') tok++;
            if (*tok) {
                if (c->prof_v4.colo[0]) snprintf(c->prof_v4.colo + strlen(c->prof_v4.colo), sizeof(c->prof_v4.colo) - strlen(c->prof_v4.colo), ",-%s", tok);
                else snprintf(c->prof_v4.colo, sizeof(c->prof_v4.colo), "-%s", tok);
            }
            tok = strtok_r(nullptr, ",", &save);
        }
    }
    c->prof_v4.use_baidu_proxy = 0;

    /* 初始化 prof_v6 */
    c->prof_v6.enabled = has_v6_listen;
    c->prof_v6.ips_type = 6;
    snprintf(c->prof_v6.name, sizeof(c->prof_v6.name), "v6");
    snprintf(c->prof_v6.listen_addr, sizeof(c->prof_v6.listen_addr), "%s", v6_listen_val[0] ? v6_listen_val : "0.0.0.0:6443");
    c->prof_v6.port = v6_port > 0 ? v6_port : c->port;
    c->prof_v6.http_port = v6_http_port > 0 ? v6_http_port : c->http_port;
    c->prof_v6.delay_ms = v6_delay > 0 ? v6_delay : c->delay_ms;
    c->prof_v6.task = v6_task > 0 ? v6_task : c->task;
    c->prof_v6.ipnum = v6_ipnum > 0 ? v6_ipnum : c->ipnum;
    c->prof_v6.num = v6_num > 0 ? v6_num : c->num;
    c->prof_v6.code = v6_code >= 0 ? v6_code : c->code;
    c->prof_v6.random_mode = v6_random >= 0 ? v6_random : c->random_mode;
    c->prof_v6.v6_split = v6_split_val >= 48 && v6_split_val <= 64 ? v6_split_val : (c->v6_split >= 48 && c->v6_split <= 64 ? c->v6_split : 54);
    snprintf(c->prof_v6.domain, sizeof(c->prof_v6.domain), "%s", v6_domain[0] ? v6_domain : c->domain);
    snprintf(c->prof_v6.colo, sizeof(c->prof_v6.colo), "%s", v6_colo[0] ? v6_colo : c->colo);
    if (v6_exclude_colo_buf[0]) {
        char tmp_ex[sizeof(v6_exclude_colo_buf)];
        snprintf(tmp_ex, sizeof(tmp_ex), "%s", v6_exclude_colo_buf);
        char *save = nullptr;
        char *tok = strtok_r(tmp_ex, ",", &save);
        while (tok) {
            trim_line(tok);
            while (*tok == '-' || *tok == '^' || *tok == '!' || *tok == ' ') tok++;
            if (*tok) {
                if (c->prof_v6.colo[0]) snprintf(c->prof_v6.colo + strlen(c->prof_v6.colo), sizeof(c->prof_v6.colo) - strlen(c->prof_v6.colo), ",-%s", tok);
                else snprintf(c->prof_v6.colo, sizeof(c->prof_v6.colo), "-%s", tok);
            }
            tok = strtok_r(nullptr, ",", &save);
        }
    }
    c->prof_v6.use_baidu_proxy = 0;

    /* 初始化 prof_baidu */
    c->prof_baidu.enabled = has_baidu_listen;
    c->prof_baidu.ips_type = c->ips_type;
    snprintf(c->prof_baidu.name, sizeof(c->prof_baidu.name), "baidu");
    snprintf(c->prof_baidu.listen_addr, sizeof(c->prof_baidu.listen_addr), "%s", baidu_listen_val[0] ? baidu_listen_val : "0.0.0.0:5444");
    c->prof_baidu.port = c->port;
    c->prof_baidu.http_port = c->http_port;
    c->prof_baidu.delay_ms = c->delay_ms;
    c->prof_baidu.task = c->task;
    c->prof_baidu.ipnum = c->ipnum;
    c->prof_baidu.num = c->num;
    c->prof_baidu.code = c->code;
    c->prof_baidu.random_mode = c->random_mode;
    c->prof_baidu.v6_split = c->v6_split;
    snprintf(c->prof_baidu.domain, sizeof(c->prof_baidu.domain), "%s", c->domain);
    snprintf(c->prof_baidu.colo, sizeof(c->prof_baidu.colo), "%s", c->colo);
    c->prof_baidu.use_baidu_proxy = 1;
    if (has_baidu_listen) c->use_baidu_proxy = 1;
}

static void log_current_config(const Config *c) {
    log_msg("当前运行配置清单 (含缺省默认值):");
    if (c->prof_v4.enabled) {
        log_msg("  [IPv4 转发实例] 监听地址: %s", c->prof_v4.listen_addr);
        log_msg("    TLS目标端口: %d | HTTP目标端口: %d", c->prof_v4.port, c->prof_v4.http_port);
        log_msg("    并发扫描线程: %d | 延迟上限: %d ms | 候选IP保留: %d", c->prof_v4.task, c->prof_v4.delay_ms, c->prof_v4.ipnum);
        log_msg("    状态码校验 (-code): %s", c->prof_v4.code > 0 ? "启用" : "未启用 (仅测连通性)");
        if (c->prof_v4.code > 0) log_msg("    期望状态码: %d (域名: %s)", c->prof_v4.code, c->prof_v4.domain);
        log_msg("    数据中心筛选: %s", c->prof_v4.colo[0] ? c->prof_v4.colo : "(不限)");
    } else {
        log_msg("  [IPv4 转发实例] 未启用");
    }

    if (c->prof_v6.enabled) {
        log_msg("  [IPv6 转发实例] 监听地址: %s", c->prof_v6.listen_addr);
        log_msg("    TLS目标端口: %d | HTTP目标端口: %d", c->prof_v6.port, c->prof_v6.http_port);
        log_msg("    并发扫描线程: %d | 延迟上限: %d ms | 候选IP保留: %d", c->prof_v6.task, c->prof_v6.delay_ms, c->prof_v6.ipnum);
        log_msg("    IPv6 子网切分 (-v6-split): /%d (每个/48抽样 %d 个样本)", c->prof_v6.v6_split, 1 << (c->prof_v6.v6_split - 48));
        log_msg("    状态码校验 (-code): %s", c->prof_v6.code > 0 ? "启用" : "未启用 (仅测连通性)");
        if (c->prof_v6.code > 0) log_msg("    期望状态码: %d (域名: %s)", c->prof_v6.code, c->prof_v6.domain);
        log_msg("    数据中心筛选: %s", c->prof_v6.colo[0] ? c->prof_v6.colo : "(不限)");
    } else {
        log_msg("  [IPv6 转发实例] 未启用");
    }

    if (c->prof_baidu.enabled) {
        log_msg("  [百度前置实例] 监听地址: %s", c->prof_baidu.listen_addr);
        log_msg("    百度解析器 (-baidu-resolver): %s", c->baidu_resolver);
        log_msg("    百度前置目标: %s:%d (候选数: %d)", c->baidu_domain, c->baidu_port, c->baidu_ipnum);
    } else {
        log_msg("  [百度前置实例] 未启用");
    }

    if (!c->prof_v4.enabled && !c->prof_v6.enabled && !c->prof_baidu.enabled) {
        log_msg("  [CLI 单次测速模式] IP 类型: IPv%d | 端口: %d | 并发线程: %d | 延迟上限: %d ms",
                c->ips_type, c->port, c->task, c->delay_ms);
        if (c->ips_type == 6) {
            log_msg("    IPv6 子网切分 (-v6-split): /%d (每个/48抽样 %d 个样本)", c->v6_split, (c->v6_split >= 48 && c->v6_split <= 64) ? (1 << (c->v6_split - 48)) : 1);
        }
        if (c->colo[0]) log_msg("    数据中心筛选: %s", c->colo);
    }

    log_msg("  全局设置: 出站网卡: %s | 健康检查间隔: %d 秒 | 日志级别: %s",
            c->bind_if[0] ? c->bind_if : "(系统默认路由)", c->health_log, c->log_name);
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

#ifdef _WIN32
static wchar_t *utf8_to_wide_alloc(const char *s) {
    if (!s) return nullptr;
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (len <= 0) return nullptr;
    wchar_t *w = (wchar_t *)calloc((size_t)len, sizeof(wchar_t));
    if (!w) return nullptr;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, len) <= 0) {
        free(w);
        return nullptr;
    }
    return w;
}

static int download_file_wininet(const char *url, const char *filename) {
    wchar_t *wurl = utf8_to_wide_alloc(url);
    if (!wurl) return -1;

    HINTERNET hnet = InternetOpenW(L"cfnat/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hnet) {
        free(wurl);
        return -1;
    }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE;
    if (strncmp(url, "https://", 8) == 0) {
        flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }

    HINTERNET hurl = InternetOpenUrlW(hnet, wurl, nullptr, 0, flags, 0);
    free(wurl);
    if (!hurl) {
        InternetCloseHandle(hnet);
        return -1;
    }

    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", filename);
    FILE *out = fopen(tmp, "wb");
    if (!out) {
        InternetCloseHandle(hurl);
        InternetCloseHandle(hnet);
        return -1;
    }

    char buf[16384];
    DWORD got = 0;
    int rc = 0;
    for (;;) {
        if (!InternetReadFile(hurl, buf, sizeof(buf), &got)) {
            rc = -1;
            break;
        }
        if (got == 0) break;
        if (fwrite(buf, 1, got, out) != got) {
            rc = -1;
            break;
        }
    }

    fclose(out);
    InternetCloseHandle(hurl);
    InternetCloseHandle(hnet);

    if (rc != 0 || !file_exists(tmp)) {
        remove(tmp);
        return -1;
    }

    remove(filename);
    if (rename(tmp, filename) != 0) {
        remove(tmp);
        return -1;
    }
    return 0;
}
#endif

static int download_file_from_urls(const char **urls, const char *filename) {
#ifdef _WIN32
    for (int i = 0; urls[i]; i++) {
        if (download_file_wininet(urls[i], filename) == 0) return 0;
        log_msg("从 %s 下载失败，尝试下一个源", urls[i]);
    }
    return -1;
#else
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", filename);
    for (int i = 0; urls[i]; i++) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "curl -fsSL '%s' -o '%s' 2>/dev/null || wget -qO '%s' '%s' 2>/dev/null", urls[i], tmp, tmp, urls[i]);
        int rc = system(cmd);
        if (rc == 0 && file_exists(tmp)) {
            rename(tmp, filename);
            return 0;
        }
        unlink(tmp);
        log_msg("从 %s 下载失败，尝试下一个源", urls[i]);
    }
    return -1;
#endif
}

static int ensure_data_file(const char *expected, const char **urls) {
    if (file_exists(expected)) return 0;

    printf("文件 %s 不存在，正在下载数据\n", expected);
    return download_file_from_urls(urls, expected);
}

static char *read_file_all(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return nullptr;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) {
        fclose(f);
        return nullptr;
    }
    char *b = malloc((size_t)n + 1);
    if (!b) {
        fclose(f);
        return nullptr;
    }
    size_t r = fread(b, 1, (size_t)n, f);
    fclose(f);
    b[r] = 0;
    if (out_len) * out_len = r;
    return b;
}

static void trim_line(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) s[--n] = 0;
}

static int strlist_add(StringList *l, const char *s) {
    if (!l || !s) return -1;
    if (l->len == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 256;
        char **ni = realloc(l->items, nc * sizeof(char *));
        if (!ni) return -1;
        l->items = ni;
        l->cap = nc;
    }
    size_t slen = strlen(s) + 1;
    StringChunk *c = l->chunks;
    if (!c || c->used + slen > c->cap) {
        size_t ccap = 131072; /* 128 KB 连续内存池块，大幅减少 4 万多次碎块分配 */
        if (slen > ccap) ccap = slen + 4096;
        StringChunk *nc = (StringChunk *)malloc(sizeof(StringChunk) + ccap);
        if (!nc) return -1;
        nc->next = l->chunks;
        nc->used = 0;
        nc->cap = ccap;
        l->chunks = nc;
        c = nc;
    }
    char *dst = c->data + c->used;
    memcpy(dst, s, slen);
    c->used += slen;
    l->items[l->len++] = dst;
    return 0;
}

static void strlist_free(StringList *l) {
    if (!l) return;
    StringChunk *c = l->chunks;
    while (c) {
        StringChunk *next = c->next;
        free(c);
        c = next;
    }
    free(l->items);
    memset(l, 0, sizeof(*l));
}

static uint32_t ipv4_to_u32(const char *s) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return 0;
    return ntohl(a.s_addr);
}

static int is_fake_ipv4(const char *s) {
    uint32_t ip = ipv4_to_u32(s);
    if (ip == 0) return 0;
    return (ip & 0xfffe0000u) == 0xc6120000u;  /* 198.18.0.0/15 */
}

static void u32_to_ipv4(uint32_t v, char *out, size_t sz) {
    struct in_addr a;
    a.s_addr = htonl(v);
    inet_ntop(AF_INET, &a, out, sz);
}

#if CFNAT_IS_C23
static thread_local uint64_t g_tl_rng_state = 0;
#elif defined(_MSC_VER)
static __declspec(thread) uint64_t g_tl_rng_state = 0;
#elif defined(__GNUC__) || defined(__clang__)
static __thread uint64_t g_tl_rng_state = 0;
#else
static _Thread_local uint64_t g_tl_rng_state = 0;
#endif

static uint64_t rand_u64(void) {
    if (g_tl_rng_state == 0) {
        g_tl_rng_state = ((uint64_t)now_ms() << 16) ^ (uintptr_t)&g_tl_rng_state ^ 0x9e3779b97f4a7c15ULL;
    }
    uint64_t z = (g_tl_rng_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

/* 将 16 字节 IPv6 二进制地址转换为完全展开的 8 段 16 进制格式 (例如 2606:4700:9a68:1591:f76d:d848:b5de:8e02) */
static void format_ipv6_full(const unsigned char bytes[16], char *out, size_t outsz) {
    if (!bytes || !out || outsz < 40) return;
    uint16_t w[8];
    for (int i = 0; i < 8; i++) {
        w[i] = ((uint16_t)bytes[i * 2] << 8) | (uint16_t)bytes[i * 2 + 1];
    }
    snprintf(out, outsz, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
             w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
}

CFNAT_UNUSED static int ipv6_cidr_sample(const char *base_s, int prefix, char *out, size_t outsz) {
    if (!base_s || !out || outsz == 0 || prefix < 0 || prefix > 128) return -1;
    unsigned char bytes[16];
    if (inet_pton(AF_INET6, base_s, bytes) != 1) return -1;

    for (int bit = prefix; bit < 128; bit++) {
        bytes[bit / 8] &= (unsigned char)~(1u << (7 - (bit % 8)));
    }
    for (int bit = prefix; bit < 128; bit++) {
        if (rand_u64() & 1u) bytes[bit / 8] |= (unsigned char)(1u << (7 - (bit % 8)));
    }
    format_ipv6_full(bytes, out, outsz);
    return 0;
}

/* IPv6 CIDR 抽样与子网切分：支持 -v6-split (默认 54，即每个 /48 切分为 64 个 /54 子网各抽样 1 个) */
static int ipv6_cidr_sample_split(const char *base_s, int prefix, int v6_split, StringList *out) {
    if (!base_s || !out || prefix < 0 || prefix > 128) return -1;
    unsigned char bytes[16];
    if (inet_pton(AF_INET6, base_s, bytes) != 1) return -1;

    for (int bit = prefix; bit < 128; bit++) {
        bytes[bit / 8] &= (unsigned char)~(1u << (7 - (bit % 8)));
    }

    uint16_t w[8];
    for (int i = 0; i < 8; i++) {
        w[i] = ((uint16_t)bytes[i * 2] << 8) | (uint16_t)bytes[i * 2 + 1];
    }

    /* 针对标准的 Cloudflare /48 CIDR 进行指定子网切分 */
    if (prefix == 48 && v6_split >= 48 && v6_split <= 64) {
        int split_bits = v6_split - 48;
        int count = 1 << split_bits;
        int step = (split_bits == 16) ? 1 : (65536 / count);
        for (int i = 0; i < count; i++) {
            uint16_t seg4 = (uint16_t)(i * step + (step > 1 ? (uint16_t)(rand_u64() % (uint64_t)step) : 0));
            uint16_t seg5 = (uint16_t)(rand_u64() & 0xffff);
            uint16_t seg6 = (uint16_t)(rand_u64() & 0xffff);
            uint16_t seg7 = (uint16_t)(rand_u64() & 0xffff);
            uint16_t seg8 = (uint16_t)(rand_u64() & 0xffff);
            char ip[MAX_IP_LEN];
            snprintf(ip, sizeof(ip), "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                     w[0], w[1], w[2], seg4, seg5, seg6, seg7, seg8);
            strlist_add(out, ip);
        }
        return 0;
    }

    /* 其他前缀情况（例如 /64 或 /32）：在 prefix 之后随机生成主机位，格式化为 8 段完整展开格式 */
    for (int bit = prefix; bit < 128; bit++) {
        if (rand_u64() & 1u) {
            bytes[bit / 8] |= (unsigned char)(1u << (7 - (bit % 8)));
        }
    }
    char ip[MAX_IP_LEN];
    format_ipv6_full(bytes, ip, sizeof(ip));
    strlist_add(out, ip);
    return 0;
}

static int is_ip_literal(const char *s) {
    struct in_addr a4;
    struct in6_addr a6;
    return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1;
}

CFNAT_UNUSED static void format_host_literal(const char *ip, char *out, size_t outsz) {
    if (!out || outsz == 0) return;
    if (ip && strchr(ip, ':')) snprintf(out, outsz, "[%s]", ip);
    else snprintf(out, outsz, "%s", ip ? ip : "");
}

static void format_addr_port(const char *ip, int port, char *out, size_t outsz) {
    if (!out || outsz == 0) return;
    if (ip && strchr(ip, ':')) snprintf(out, outsz, "[%s]:%d", ip, port);
    else snprintf(out, outsz, "%s:%d", ip ? ip : "", port);
}

static StringList load_ip_list(const char *filename, int random_mode, int v6_split) {
    if (v6_split < 48 || v6_split > 64) v6_split = 54;
    StringList out = {0};
    FILE *f = fopen(filename, "r");
    if (!f) return out;
    if (strstr(filename, "v6") != nullptr) {
        /* IPv6 预分配容量（40960 项），避免数十次 realloc 与指针搬迁 */
        out.cap = 40960;
        out.items = malloc(out.cap * sizeof(char *));
        if (!out.items) { out.cap = 0; }
    }
    log_msg("正在读取 %s，模式：%s", filename, random_mode ? "CIDR随机抽样" : "完整展开CIDR");
    char line[MAX_LINE];
    long start_ms = now_ms();
    size_t cidr_count = 0;
    int warned_ipv6_expand = 0;
    srand((unsigned)time(nullptr));
    while (fgets(line, sizeof(line), f)) {
        trim_line(line);
        if (!line[0]) continue;
        char *slash = strchr(line, '/');
        if (!slash) {
            if (is_ip_literal(line)) {
                if (strchr(line, ':')) {
                    unsigned char b[16];
                    if (inet_pton(AF_INET6, line, b) == 1) {
                        char full_ip[MAX_IP_LEN];
                        format_ipv6_full(b, full_ip, sizeof(full_ip));
                        strlist_add(&out, full_ip);
                    } else {
                        strlist_add(&out, line);
                    }
                } else {
                    strlist_add(&out, line);
                }
            }
            continue;
        }
        cidr_count++;
        *slash = 0;
        int prefix = atoi(slash + 1);
        if (strchr(line, ':')) {
            if (!random_mode && !warned_ipv6_expand) {
                warn_msg("IPv6 空间过大不支持全量展开，已按 -v6-split=/%d 为每个 /48 子网抽样 %d 个候选",
                         v6_split, 1 << (v6_split - 48));
                warned_ipv6_expand = 1;
            }
            ipv6_cidr_sample_split(line, prefix, v6_split, &out);
            continue;
        }
        uint32_t base = ipv4_to_u32(line);
        if (base == 0 || prefix < 0 || prefix > 32) continue;
        uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
        uint32_t start = base & mask;
        uint64_t count = prefix == 32 ? 1ULL : (1ULL << (32 - prefix));
        if (random_mode) {
            uint32_t off = count > 1 ? (uint32_t)(rand_u64() % count) : 0;
            char ip[MAX_IP_LEN];
            u32_to_ipv4(start + off, ip, sizeof(ip));
            strlist_add(&out, ip);
        } else {
            for (uint64_t off = 0; off < count; off++) {
                char ip[MAX_IP_LEN];
                u32_to_ipv4(start + (uint32_t)off, ip, sizeof(ip));
                strlist_add(&out, ip);
            }
        }
        if (!random_mode && out.len > 0 && out.len % 50000 == 0) {
            log_msg("IP 列表展开进度: %zu 个", out.len);
        }
    }
    fclose(f);
    if (random_mode && out.len > 1) {
        for (size_t i = out.len - 1; i > 0; i--) {
            size_t j = (size_t)(rand_u64() % (uint64_t)(i + 1));
            char *tmp = out.items[i];
            out.items[i] = out.items[j];
            out.items[j] = tmp;
        }
    }
    log_msg("IP 列表加载完成: %zu 个候选，CIDR 行数: %zu，耗时 %ld 秒", out.len, cidr_count, (now_ms() - start_ms) / 1000);
    if (!random_mode && out.len > 100000) {
        warn_msg("当前使用 -random=false，已完整展开大量 IP，扫描会明显变慢；需要快速启动时建议使用 -random=true");
    }
    return out;
}

static char *json_string_value(char *p, const char *key, char *out, size_t outsz) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    char *k = strstr(p, pat);
    if (!k) return nullptr;
    char *colon = strchr(k + strlen(pat), ':');
    if (!colon) return nullptr;
    char *q = strchr(colon, '\"');
    if (!q) return nullptr;
    q++;
    char *e = strchr(q, '\"');
    if (!e) return nullptr;
    size_t n = (size_t)(e - q);
    if (n >= outsz) n = outsz - 1;
    memcpy(out, q, n);
    out[n] = 0;
    return e + 1;
}

static void load_locations(void) {
    if (ensure_data_file("locations.json", LOC_URLS) != 0) {
        log_msg("下载 locations.json 失败");
        return;
    }
    size_t len = 0;
    char *json = read_file_all("locations.json", &len);
    if (!json) return;
    size_t cap = 128;
    g_locations = calloc(cap, sizeof(Location));
    g_location_count = 0;
    char *p = json;
    while ((p = strstr(p, "\"iata\""))) {
        if (g_location_count == cap) {
            cap *= 2;
            Location *nl = realloc(g_locations, cap * sizeof(Location));
            if (!nl) break;
            g_locations = nl;
        }
        Location loc = {0};
        char *np = json_string_value(p, "iata", loc.iata, sizeof(loc.iata));
        if (!np) {
            p += 6;
            continue;
        }
        json_string_value(np, "region", loc.region, sizeof(loc.region));
        json_string_value(np, "city", loc.city, sizeof(loc.city));
        if (loc.iata[0]) g_locations[g_location_count++] = loc;
        p = np;
    }
    free(json);
}

static Location *find_location(const char *iata) {
    for (size_t i = 0; i < g_location_count; i++) if (!strcasecmp(g_locations[i].iata, iata)) return &g_locations[i];
    return nullptr;
}

static int colo_rule_allowed(const char *rule, const char *colo) {
    if (!rule || !rule[0] || !colo || !*colo) return 1;

    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", rule);

    int has_include = 0;
    int matched_include = 0;

    char *save = nullptr;
    char *tok = strtok_r(tmp, ",", &save);
    while (tok) {
        trim_line(tok);
        if (*tok) {
            if (*tok == '-' || *tok == '^' || *tok == '!') {
                const char *ex = tok + 1;
                while (*ex == ' ') ex++;
                if (*ex && !strcasecmp(ex, colo)) {
                    return 0; /* 命中排除项，直接拒绝 */
                }
            } else {
                has_include = 1;
                if (!strcasecmp(tok, colo)) {
                    matched_include = 1;
                }
            }
        }
        tok = strtok_r(nullptr, ",", &save);
    }
    return has_include ? matched_include : 1;
}

static int colo_allowed(const char *colo) __attribute__((unused));
static int colo_allowed(const char *colo) {
    return colo_rule_allowed(g_cfg.colo, colo);
}

static int set_nonblock(socket_t fd, int nb) {
#ifdef _WIN32
    u_long mode = nb ? 1UL : 0UL;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (nb) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
#endif
}

static void set_tcp_nodelay(socket_t fd) {
#if defined(TCP_NODELAY)
    int one = 1;
#ifdef _WIN32
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
#else
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif
#else
    (void)fd;
#endif
}

#ifdef _WIN32
#ifndef SIO_LOOPBACK_FAST_PATH
#define SIO_LOOPBACK_FAST_PATH _WSAIOW(IOC_VENDOR, 16)
#endif
/* Windows 回环快速通道加速：免除本地代理（如 Xray / sing-box）经过完整网络协议栈的开销 */
static void set_loopback_fast_path(socket_t s) {
    if (cfnat_socket_invalid(s)) return;
    int option = 1;
    DWORD bytes = 0;
    WSAIoctl(s, SIO_LOOPBACK_FAST_PATH, &option, sizeof(option), nullptr, 0, &bytes, nullptr, nullptr);
}
#else
static inline void set_loopback_fast_path(socket_t s) { (void)s; }
#endif

/* 套接字缓冲区深度优化：UDP 1MB 防丢包，TCP 256KB 保障高 BDP 吞吐 */
static void tune_socket_buffers(socket_t s, int is_udp) {
    if (cfnat_socket_invalid(s)) return;
    int buf_sz = is_udp ? (1024 * 1024) : (256 * 1024);
#ifdef _WIN32
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&buf_sz, sizeof(buf_sz));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char *)&buf_sz, sizeof(buf_sz));
#else
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf_sz, sizeof(buf_sz));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf_sz, sizeof(buf_sz));
#endif
}

CFNAT_NODISCARD static socket_t tcp_connect_sa(const struct sockaddr_storage *ss, socklen_t sslen, int port, int timeout_ms, int *latency_ms) {
    if (!ss || sslen == 0) return INVALID_SOCKET;
    long start = now_ms();
    int family = ss->ss_family;
    socket_t fd = socket(family, SOCK_STREAM, 0);
    if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
    if (bind_socket_to_interface(fd, family) != 0) {
        int err = errno;
        close(fd);
        errno = err;
        return INVALID_SOCKET;
    }
    set_nonblock(fd, 1);
    struct sockaddr_storage target;
    memcpy(&target, ss, sslen);
    if (family == AF_INET6) {
        ((struct sockaddr_in6 *)&target)->sin6_port = htons((uint16_t)port);
    } else {
        ((struct sockaddr_in *)&target)->sin_port = htons((uint16_t)port);
    }
    int rc = connect(fd, (struct sockaddr *)&target, sslen);
#ifdef _WIN32
    if (rc == SOCKET_ERROR) {
        int werr = WSAGetLastError();
        if (werr != WSAEWOULDBLOCK && werr != WSAEINPROGRESS && werr != WSAEALREADY) {
            close(fd);
            return INVALID_SOCKET;
        }
    }
#else
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return INVALID_SOCKET;
    }
#endif
    int pr = cfnat_poll_single(fd, 2, timeout_ms);
    if (pr <= 0) {
        close(fd);
        return INVALID_SOCKET;
    }
    int err = 0;
#ifdef _WIN32
    int len = (int)sizeof(err);
    int gs_res = getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
#else
    socklen_t len = sizeof(err);
    int gs_res = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
#endif
    if (gs_res < 0 || err != 0) {
        close(fd);
        return INVALID_SOCKET;
    }
    set_nonblock(fd, 0);
    set_tcp_nodelay(fd);
    if (latency_ms) {
        int elapsed = (int)(now_ms() - start);
        *latency_ms = elapsed > 0 ? elapsed : 1;
    }
    return fd;
}

CFNAT_NODISCARD static socket_t tcp_connect(const char *ip, int port, int timeout_ms, int *latency_ms) {
    if (!ip || !*ip) return INVALID_SOCKET;
    struct sockaddr_storage ss;
    socklen_t sslen = 0;
    memset(&ss, 0, sizeof(ss));
    if (strchr(ip, ':')) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
        s6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, ip, &s6->sin6_addr) != 1) return INVALID_SOCKET;
        sslen = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
        s4->sin_family = AF_INET;
        if (inet_pton(AF_INET, ip, &s4->sin_addr) != 1) return INVALID_SOCKET;
        sslen = sizeof(struct sockaddr_in);
    }
    return tcp_connect_sa(&ss, sslen, port, timeout_ms, latency_ms);
}

static inline int sockaddr_ip_equal(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    if (!a || !b || a->ss_family != b->ss_family) return 0;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
        const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
        return a4->sin_addr.s_addr == b4->sin_addr.s_addr;
    } else if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
        return memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(struct in6_addr)) == 0;
    }
    return 0;
}

static inline int sockaddr_equal(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    if (!a || !b || a->ss_family != b->ss_family) return 0;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
        const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
        return (a4->sin_port == b4->sin_port &&
                a4->sin_addr.s_addr == b4->sin_addr.s_addr);
    } else if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
        return (a6->sin6_port == b6->sin6_port &&
                memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(struct in6_addr)) == 0);
    }
    return 0;
}

static void format_endpoint_str(const struct sockaddr_storage *ss, char *out, size_t outsz) {
    if (!ss || !out || outsz == 0) return;
    out[0] = '\0';
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;
        char ipbuf[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf));
        snprintf(out, outsz, "%s:%d", ipbuf, ntohs(sin->sin_port));
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;
        char ipbuf[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, &sin6->sin6_addr, ipbuf, sizeof(ipbuf));
        snprintf(out, outsz, "[%s]:%d", ipbuf, ntohs(sin6->sin6_port));
    } else {
        snprintf(out, outsz, "unknown");
    }
}

static void format_bytes(uint64_t b, char *out, size_t outsz) {
    if (!out || outsz == 0) return;
    if (b < 1024) {
        snprintf(out, outsz, "%llu B", (unsigned long long)b);
    } else if (b < 1024ULL * 1024ULL) {
        snprintf(out, outsz, "%.1f KB", (double)b / 1024.0);
    } else if (b < 1024ULL * 1024ULL * 1024ULL) {
        snprintf(out, outsz, "%.2f MB", (double)b / (1024.0 * 1024.0));
    } else {
        snprintf(out, outsz, "%.2f GB", (double)b / (1024.0 * 1024.0 * 1024.0));
    }
}

/* RFC 9000 规范的 1200 字节 QUIC Version Negotiation 轻量探针
 * 利用保留版本号 0x5A5A5A5A 触发 Cloudflare 边缘节点立即回包 Version Negotiation
 * 零密钥协商，零 CPU 加密开销，单包 1200 字节符合防放大攻击标准，精准测出 UDP 443 真实延迟 */
CFNAT_NODISCARD static int quic_probe_ip(const char *ip, int port, int timeout_ms, int *latency_ms) {
    if (!ip || !*ip || port <= 0) return 0;
    int is_v6 = (strchr(ip, ':') != nullptr);
    socket_t fd = socket(is_v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (cfnat_socket_invalid(fd)) return 0;

#ifdef _WIN32
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
    BOOL bNewBehavior = FALSE;
    DWORD dwBytesReturned = 0;
    WSAIoctl(fd, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), nullptr, 0, &dwBytesReturned, nullptr, nullptr);
#endif

    bind_socket_to_interface(fd, is_v6 ? AF_INET6 : AF_INET);
    set_nonblock(fd, 1);

    uint8_t pkt[1200];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0xC0;
    pkt[1] = 0x5A; pkt[2] = 0x5A; pkt[3] = 0x5A; pkt[4] = 0x5A;
    pkt[5] = 0x08; /* DCID Len */
    uint32_t seed = (uint32_t)now_ms();
    memcpy(pkt + 6, &seed, 4);
    pkt[14] = 0x08; /* SCID Len */
    uint32_t scid = ~seed;
    memcpy(pkt + 15, &scid, 4);

    long start = now_ms();
    ssize_t sent = 0;
    if (is_v6) {
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons((uint16_t)port);
        inet_pton(AF_INET6, ip, &sa6.sin6_addr);
        sent = sendto(fd, (const char *)pkt, sizeof(pkt), 0, (struct sockaddr *)&sa6, sizeof(sa6));
    } else {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)port);
        inet_pton(AF_INET, ip, &sa.sin_addr);
        sent = sendto(fd, (const char *)pkt, sizeof(pkt), 0, (struct sockaddr *)&sa, sizeof(sa));
    }

    if (sent <= 0) {
        close(fd);
        return 0;
    }

    int rc = cfnat_poll_single(fd, 1, timeout_ms);
    if (rc <= 0) {
        close(fd);
        return 0;
    }

    char resp[512];
    struct sockaddr_storage from;
#ifdef _WIN32
    int fromlen = (int)sizeof(from);
#else
    socklen_t fromlen = sizeof(from);
#endif
    ssize_t n = recvfrom(fd, resp, sizeof(resp), 0, (struct sockaddr *)&from, &fromlen);
    close(fd);

    if (n > 0) {
        long elapsed = now_ms() - start;
        if (latency_ms) *latency_ms = elapsed > 0 ? (int)elapsed : 1;
        return 1;
    }
    return 0;
}

/* 读取 HTTP 响应头部直到 \r\n\r\n。
 * 返回值语义：成功时返回 HTTP 头部长度（偏移量 > 0），超时或未读到完整头部返回 -1。
 * 注意：返回值仅代表头部结束位置，不用于统计实际套接字总接收字节数。 */
static int recv_headers(socket_t fd, char *buf, size_t bufsz, int timeout_ms) {
    size_t used = 0;
    size_t search_pos = 0;
    long deadline = now_ms() + timeout_ms;
    while (used + 1 < bufsz && now_ms() < deadline) {
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;
        int rc = cfnat_poll_single(fd, 1, left);
        if (rc <= 0) break;
        ssize_t n = recv(fd, buf + used, bufsz - used - 1, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            break;
        }
        used += (size_t)n;
        buf[used] = 0;
        char *found = strstr(buf + search_pos, "\r\n\r\n");
        if (found) return (int)(found - buf + 4);
        search_pos = used > 3 ? used - 3 : 0;
    }
    buf[used] = 0;
    return -1;
}

static int send_all_timeout(socket_t fd, const void *buf, size_t len, int timeout_ms) {
    const char *p = (const char *)buf;
    size_t sent = 0;
    long deadline = now_ms() + timeout_ms;
    while (sent < len && now_ms() < deadline) {
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;
        int rc = cfnat_poll_single(fd, 2, left);
        if (rc <= 0) break;
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n <= 0) break;
        sent += (size_t)n;
    }
    return sent == len;
}

static size_t append_tls_ext_sni(unsigned char *buf, size_t pos, size_t cap, const char *host) {
    size_t host_len = strlen(host);
    size_t ext_len = 2 + 1 + 2 + host_len;
    if (pos + 4 + ext_len > cap || host_len > 255) return 0;
    buf[pos++] = 0x00; buf[pos++] = 0x00;
    buf[pos++] = (unsigned char)(ext_len >> 8); buf[pos++] = (unsigned char)ext_len;
    size_t list_len = 1 + 2 + host_len;
    buf[pos++] = (unsigned char)(list_len >> 8); buf[pos++] = (unsigned char)list_len;
    buf[pos++] = 0x00;
    buf[pos++] = (unsigned char)(host_len >> 8); buf[pos++] = (unsigned char)host_len;
    memcpy(buf + pos, host, host_len);
    return pos + host_len;
}

static size_t build_tls_client_hello(unsigned char *buf, size_t cap, const char *sni_host) {
    if (!buf || cap < 256 || !sni_host || !*sni_host) return 0;
    unsigned char body[384];
    size_t p = 0;
    body[p++] = 0x03; body[p++] = 0x03; /* TLS 1.2 */
    for (int i = 0; i < 32; i++) body[p++] = (unsigned char)(0xa0 + i);
    body[p++] = 0x00; /* Session ID len = 0 */
    /* 同时提供 ECDHE_ECDSA 与 ECDHE_RSA 套件，兼容所有 Cloudflare Workers 边缘证书 */
    body[p++] = 0x00; body[p++] = 0x0a;
    body[p++] = 0xc0; body[p++] = 0x2b; /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    body[p++] = 0xc0; body[p++] = 0x2f; /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    body[p++] = 0xc0; body[p++] = 0x2c; /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    body[p++] = 0xc0; body[p++] = 0x30; /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    body[p++] = 0x00; body[p++] = 0x9c; /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
    body[p++] = 0x01; body[p++] = 0x00; /* Compression: null */

    unsigned char exts[256];
    size_t e = 0;
    e = append_tls_ext_sni(exts, e, sizeof(exts), sni_host);
    if (e == 0 || e + 32 > sizeof(exts)) return 0;
    /* ec_point_formats (0x000b) */
    exts[e++] = 0x00; exts[e++] = 0x0b;
    exts[e++] = 0x00; exts[e++] = 0x02;
    exts[e++] = 0x01; exts[e++] = 0x00;
    /* supported_groups (0x000a): x25519 (0x001d), secp256r1 (0x0017), secp384r1 (0x0018) */
    exts[e++] = 0x00; exts[e++] = 0x0a;
    exts[e++] = 0x00; exts[e++] = 0x08;
    exts[e++] = 0x00; exts[e++] = 0x06;
    exts[e++] = 0x00; exts[e++] = 0x1d;
    exts[e++] = 0x00; exts[e++] = 0x17;
    exts[e++] = 0x00; exts[e++] = 0x18;
    /* signature_algorithms (0x000d) */
    exts[e++] = 0x00; exts[e++] = 0x0d;
    exts[e++] = 0x00; exts[e++] = 0x08;
    exts[e++] = 0x00; exts[e++] = 0x06;
    exts[e++] = 0x04; exts[e++] = 0x03; /* ecdsa_secp256r1_sha256 */
    exts[e++] = 0x08; exts[e++] = 0x04; /* rsa_pss_rsae_sha256 */
    exts[e++] = 0x04; exts[e++] = 0x01; /* rsa_pkcs1_sha256 */

    if (p + 2 + e > sizeof(body)) return 0;
    body[p++] = (unsigned char)(e >> 8); body[p++] = (unsigned char)e;
    memcpy(body + p, exts, e);
    p += e;

    size_t hs_len = p;
    size_t rec_len = 4 + hs_len;
    if (5 + rec_len > cap || hs_len > 0xffffff) return 0;
    size_t o = 0;
    buf[o++] = 0x16;
    buf[o++] = 0x03; buf[o++] = 0x01;
    buf[o++] = (unsigned char)(rec_len >> 8); buf[o++] = (unsigned char)rec_len;
    buf[o++] = 0x01;
    buf[o++] = (unsigned char)(hs_len >> 16);
    buf[o++] = (unsigned char)(hs_len >> 8);
    buf[o++] = (unsigned char)hs_len;
    memcpy(buf + o, body, hs_len);
    return o + hs_len;
}

static int tls_probe_host(socket_t fd, int timeout_ms, const char *sni_host) {
    unsigned char hello[512];
    size_t hello_len = build_tls_client_hello(hello, sizeof(hello), sni_host && *sni_host ? sni_host : "cloudflaremirrors.com");
    if (hello_len == 0) return 0;
    if (!send_all_timeout(fd, hello, hello_len, timeout_ms)) return 0;

    unsigned char first = 0;
    long deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline) {
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;
        int rc = cfnat_poll_single(fd, 1, left);
        if (rc <= 0) break;
        ssize_t n = recv(fd, (char *)&first, 1, 0);
        if (n <= 0) break;
        return first == 0x16;
    }
    return 0;
}

CFNAT_NODISCARD static int tls_probe(socket_t fd, int timeout_ms) {
    return tls_probe_host(fd, timeout_ms, "cloudflaremirrors.com");
}

static int recv_more_timeout(socket_t fd, unsigned char *buf, size_t *used, size_t need, size_t cap, int timeout_ms) {
    long deadline = now_ms() + timeout_ms;
    while (*used < need && *used < cap && now_ms() < deadline) {
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;
        int rc = cfnat_poll_single(fd, 1, left);
        if (rc <= 0) break;
        ssize_t n = recv(fd, (char *)buf + *used, cap - *used, 0);
        if (n <= 0) break;
        *used += (size_t)n;
    }
    return *used >= need;
}

static size_t read_tls_client_hello(socket_t client, unsigned char first, unsigned char *buf, size_t cap, int timeout_ms) {
    if (!buf || cap < 5 || first != 0x16) return 0;
    size_t used = 1;
    buf[0] = first;
    int wait_ms = timeout_ms > 0 && timeout_ms < 1500 ? timeout_ms : 1500;
    if (!recv_more_timeout(client, buf, &used, 5, cap, wait_ms)) return used;
    size_t record_len = ((size_t)buf[3] << 8) | buf[4];
    size_t need = 5 + record_len;
    if (need > cap) need = cap;
    recv_more_timeout(client, buf, &used, need, cap, wait_ms);
    return used;
}

static int parse_tls_sni(const unsigned char *buf, size_t len, char *out, size_t outsz) {
    if (!buf || len < 9 || !out || outsz == 0) return 0;
    out[0] = '\0';
    if (buf[0] != 0x16 || buf[5] != 0x01) return 0;
    size_t hs_len = ((size_t)buf[6] << 16) | ((size_t)buf[7] << 8) | buf[8];
    size_t p = 9;
    size_t end = p + hs_len;
    if (end > len) end = len;
    if (p + 34 > end) return 0;
    p += 2 + 32;
    if (p + 1 > end) return 0;
    size_t sid_len = buf[p++];
    if (p + sid_len + 2 > end) return 0;
    p += sid_len;
    size_t cipher_len = ((size_t)buf[p] << 8) | buf[p + 1];
    p += 2;
    if (p + cipher_len + 1 > end) return 0;
    p += cipher_len;
    size_t comp_len = buf[p++];
    if (p + comp_len + 2 > end) return 0;
    p += comp_len;
    size_t ext_total = ((size_t)buf[p] << 8) | buf[p + 1];
    p += 2;
    size_t ext_end = p + ext_total;
    if (ext_end > end) ext_end = end;
    while (p + 4 <= ext_end) {
        unsigned type = ((unsigned)buf[p] << 8) | buf[p + 1];
        size_t elen = ((size_t)buf[p + 2] << 8) | buf[p + 3];
        p += 4;
        if (p + elen > ext_end) break;
        if (type == 0x0000 && elen >= 5) {
            size_t q = p;
            size_t list_len = ((size_t)buf[q] << 8) | buf[q + 1];
            q += 2;
            size_t list_end = q + list_len;
            if (list_end > p + elen) list_end = p + elen;
            while (q + 3 <= list_end) {
                unsigned name_type = buf[q++];
                size_t name_len = ((size_t)buf[q] << 8) | buf[q + 1];
                q += 2;
                if (q + name_len > list_end) break;
                if (name_type == 0 && name_len > 0) {
                    size_t n = name_len < outsz ? name_len : outsz - 1;
                    /* 过滤非法字符: 仅复制合法域名字符, 跳过噪声字节 */
                    size_t o = 0;
                    for (size_t i = 0; i < n && o < outsz - 1; i++) {
                        unsigned char c = buf[q + i];
                        if ((c >= 'a' && c <= 'z') ||
                            (c >= 'A' && c <= 'Z') ||
                            (c >= '0' && c <= '9') ||
                            c == '-' || c == '.' || c == '_' || c == '*') {
                            out[o++] = (char)c;
                        }
                    }
                    out[o] = '\0';
                    return o > 0;
                }
                q += name_len;
            }
        }
        p += elen;
    }
    return 0;
}


static char *cfnat_strcasestr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return nullptr;
    size_t nl = strlen(needle);
    if (nl == 0) return (char *)haystack;
    for (const char *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == nl) return (char *)p;
    }
    return nullptr;
}

static int extract_cfray(const char *headers, char *colo, size_t sz) {
    const char *p = cfnat_strcasestr(headers, "CF-RAY:");
    if (!p) return -1;
    const char *line_end = strstr(p, "\r\n");
    if (!line_end) line_end = p + strlen(p);
    const char *val_start = p + 7; /* 跳过 "CF-RAY:" 前缀，杜绝匹配自身连字符的错误 */
    const char *dash = nullptr;
    for (const char *q = val_start; q < line_end; q++) if (*q == '-') dash = q;
    if (!dash || dash + 1 >= line_end) return -1;
    const char *s = dash + 1;
    size_t n = (size_t)(line_end - s);
    if (n >= sz) n = sz - 1;
    memcpy(colo, s, n);
    colo[n] = 0;
    trim_line(colo);
    return colo[0] ? 0 : -1;
}

static int extract_http_status_code(const char *headers) {
    if (!headers) return 0;
    const char *p = strstr(headers, "HTTP/");
    if (!p) return 0;
    p = strchr(p, ' ');
    if (!p) return 0;
    while (*p == ' ') p++;
    if (*p >= '0' && *p <= '9') {
        return atoi(p);
    }
    return 0;
}

static int str_eq_ci(const char *a, const char *b) {
    return a && b && strcasecmp(a, b) == 0;
}

static const char *carrier_display_name(const char *mode) {
    if (str_eq_ci(mode, "direct") || str_eq_ci(mode, "direct-v4")) return "IPv4直连优选";
    if (str_eq_ci(mode, "direct-v6")) return "IPv6直连优选";
    if (str_eq_ci(mode, "baidu")) return "百度前置优选";
    if (str_eq_ci(mode, "mixed")) return "混合优选";
    return mode ? mode : "unknown";
}

static void append_unique_addr(StringList *list, const char *value) {
    if (!list || !value || !*value) return;
    for (size_t i = 0; i < list->len; i++) {
        if (!strcmp(list->items[i], value)) return;
    }
    strlist_add(list, value);
}

static int baidu_pool_add(BaiduProxyPool *pool, const char *addr) {
    if (!pool || !addr || !*addr) return -1;
    for (size_t i = 0; i < pool->len; i++) if (!strcmp(pool->nodes[i].addr, addr)) return 0;
    if (pool->len == pool->cap) {
        size_t nc = pool->cap ? pool->cap * 2 : 8;
        BaiduProxyNode *nn = realloc(pool->nodes, nc * sizeof(BaiduProxyNode));
        if (!nn) return -1;
        pool->nodes = nn;
        pool->cap = nc;
    }
    BaiduProxyNode *node = &pool->nodes[pool->len++];
    memset(node, 0, sizeof(*node));
    snprintf(node->addr, sizeof(node->addr), "%s", addr);
    atomic_init(&node->active, 0);
    atomic_init(&node->failures, 0);
    atomic_init(&node->ewma_ms, g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 300);
    return 0;
}

static void baidu_pool_free(BaiduProxyPool *pool) {
    if (!pool) return;
    free(pool->nodes);
    pool->nodes = nullptr;
    pool->len = 0;
    pool->cap = 0;
    atomic_store(&pool->cached_best_idx, -1);
    atomic_store(&pool->cached_at_ms, 0);
}

static long proxy_node_score(const BaiduProxyNode *node) {
    long ewma = atomic_load(&node->ewma_ms);
    int active = atomic_load(&node->active);
    int failures = atomic_load(&node->failures);
    return ewma + (long)active * 50L + (long)failures * 300L;
}

/* P0-CACHE: 代理节点选择，带 5 秒缓存，原子并发安全 */
static BaiduProxyNode *baidu_pool_pick(BaiduProxyPool *pool) {
    if (!pool || pool->len == 0) return nullptr;

    long now = now_ms();
    long cat = atomic_load_explicit(&pool->cached_at_ms, memory_order_relaxed);
    int cidx = atomic_load_explicit(&pool->cached_best_idx, memory_order_relaxed);
    if (cidx >= 0 && (size_t)cidx < pool->len && (now - cat) < 5000) {
        return &pool->nodes[cidx];
    }

    size_t best_idx = 0;
    long best_score = proxy_node_score(&pool->nodes[0]);
    for (size_t i = 1; i < pool->len; i++) {
        long score = proxy_node_score(&pool->nodes[i]);
        if (score < best_score) {
            best_idx = i;
            best_score = score;
        }
    }

    /* 原子更新缓存 */
    atomic_store_explicit(&pool->cached_best_idx, (int)best_idx, memory_order_relaxed);
    atomic_store_explicit(&pool->cached_at_ms, now, memory_order_relaxed);
    return &pool->nodes[best_idx];
}

static socket_t tcp_connect_via_baidu(const char *node_addr, const char *target_addr, int timeout_ms, int *latency_ms) {
    long start = now_ms();
    char host[MAX_ADDR_LEN] = {0};
    int port = 0;
    if (parse_addr(node_addr, host, sizeof(host), &port) != 0) return INVALID_SOCKET;
    socket_t fd = tcp_connect(host, port, timeout_ms, nullptr);
    if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
    char req[1024];
    snprintf(req, sizeof(req),
            "CONNECT %s HTTP/1.1\r\n"
            "Host: sptest.baidu.com\r\n"
            "X-T5-Auth: 482857715\r\n"
            "User-Agent: okhttp/3.11.0 Dalvik/2.1.0 (Linux; Build/RKQ1.200826.002) baiduboxapp/11.0.5.12 (Baidu; P1 11)\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "Connection: keep-alive\r\n\r\n", target_addr);
    size_t req_len = strlen(req);
    size_t sent = 0;
    while (sent < req_len) {
        ssize_t s = send(fd, req + sent, req_len - sent, 0);
        if (s <= 0) {
            if (s < 0 && errno == EINTR) continue;
            close(fd);
            return INVALID_SOCKET;
        }
        sent += (size_t)s;
    }
    char hdr[4096];
    int n = recv_headers(fd, hdr, sizeof(hdr), timeout_ms);
    if (n <= 0) {
        debug_msg("百度 CONNECT 失败: 节点 %s 目标 %s 无响应", node_addr, target_addr);
        close(fd);
        return INVALID_SOCKET;
    }
    int status_code = extract_http_status_code(hdr);
    if (status_code != 200) {
        char status[128];
        size_t status_len = strcspn(hdr, "\r\n");
        if (status_len >= sizeof(status)) status_len = sizeof(status) - 1;
        memcpy(status, hdr, status_len);
        status[status_len] = '\0';
        debug_msg("百度 CONNECT 失败: 节点 %s 目标 %s 返回 %s (状态码 %d)", node_addr, target_addr, status, status_code);
        close(fd);
        return INVALID_SOCKET;
    }
    if (latency_ms) * latency_ms = (int)(now_ms() - start);
    return fd;
}

CFNAT_NODISCARD static socket_t dial_target_with_proxy_sa(const char *ip, const struct sockaddr_storage *ss, socklen_t sslen,
                                                          int port, int timeout_ms, BaiduProxyPool *pool, int *latency_ms) {
    if (!pool || pool->len == 0) {
        if (ss && sslen > 0) return tcp_connect_sa(ss, sslen, port, timeout_ms, latency_ms);
        return tcp_connect(ip, port, timeout_ms, latency_ms);
    }
    char target[MAX_ADDR_LEN];
    format_addr_port(ip, port, target, sizeof(target));
    BaiduProxyNode *node = baidu_pool_pick(pool);
    if (!node) return INVALID_SOCKET;
    atomic_fetch_add(&node->active, 1);
    socket_t fd = tcp_connect_via_baidu(node->addr, target, timeout_ms, latency_ms);
    if (cfnat_socket_valid(fd)) {
        if (latency_ms && *latency_ms > 0) atomic_store(&node->ewma_ms, (atomic_load(&node->ewma_ms) * 7 + *latency_ms) / 8);
        if (atomic_load(&node->failures) > 0) atomic_fetch_sub(&node->failures, 1);
    } else {
        atomic_fetch_add(&node->failures, 1);
    }
    atomic_fetch_sub(&node->active, 1);
    return fd;
}

CFNAT_NODISCARD static inline socket_t dial_target_with_proxy(const char *ip, int port, int timeout_ms, BaiduProxyPool *pool, int *latency_ms) {
    return dial_target_with_proxy_sa(ip, nullptr, 0, port, timeout_ms, pool, latency_ms);
}

CFNAT_NODISCARD static int parse_listen_modes(const Config *cfg, CarrierListenSpec **out_specs, size_t *out_len) {
    *out_specs = nullptr;
    *out_len = 0;
    if (!cfg) return -1;
    size_t len = 0;
    CarrierListenSpec *specs = calloc(4, sizeof(CarrierListenSpec));
    if (!specs) return -1;

    /* 优先使用分协议 profile (prof_v4, prof_v6, prof_baidu) */
    if (cfg->prof_v4.enabled) {
        snprintf(specs[len].mode, sizeof(specs[len].mode), "%s", "direct-v4");
        snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", cfg->prof_v4.listen_addr);
        specs[len].use_baidu_proxy = 0;
        specs[len].prof = cfg->prof_v4;
        len++;
    }
    if (cfg->prof_v6.enabled) {
        snprintf(specs[len].mode, sizeof(specs[len].mode), "%s", "direct-v6");
        snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", cfg->prof_v6.listen_addr);
        specs[len].use_baidu_proxy = 0;
        specs[len].prof = cfg->prof_v6;
        len++;
    }
    if (cfg->prof_baidu.enabled) {
        snprintf(specs[len].mode, sizeof(specs[len].mode), "%s", "baidu");
        snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", cfg->prof_baidu.listen_addr);
        specs[len].use_baidu_proxy = 1;
        specs[len].prof = cfg->prof_baidu;
        len++;
    }

    /* 兼容旧的 -direct-listen / -baidu-listen 单独指定但未走 profile 时的逻辑 */
    if (len == 0) {
        if (cfg->direct_listen[0] && cfg->baidu_listen[0] && strcmp(cfg->direct_listen, cfg->baidu_listen) == 0) {
            snprintf(specs[len].mode, sizeof(specs[len].mode), "%s", "mixed");
            snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", cfg->direct_listen);
            specs[len].use_baidu_proxy = 2;
            specs[len].prof = (cfg->ips_type == 6) ? cfg->prof_v6 : cfg->prof_v4;
            specs[len].prof.ips_type = cfg->ips_type;
            snprintf(specs[len].prof.listen_addr, sizeof(specs[len].prof.listen_addr), "%s", cfg->direct_listen);
            len++;
        } else {
            if (cfg->direct_listen[0]) {
                snprintf(specs[len].mode, sizeof(specs[len].mode), "%s", cfg->ips_type == 6 ? "direct-v6" : "direct-v4");
                snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", cfg->direct_listen);
                specs[len].use_baidu_proxy = 0;
                specs[len].prof = (cfg->ips_type == 6) ? cfg->prof_v6 : cfg->prof_v4;
                specs[len].prof.ips_type = cfg->ips_type;
                snprintf(specs[len].prof.listen_addr, sizeof(specs[len].prof.listen_addr), "%s", cfg->direct_listen);
                len++;
            }
            if (cfg->baidu_listen[0]) {
                snprintf(specs[len].mode, sizeof(specs[len].mode), "%s", "baidu");
                snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", cfg->baidu_listen);
                specs[len].use_baidu_proxy = 1;
                specs[len].prof = cfg->prof_baidu;
                snprintf(specs[len].prof.listen_addr, sizeof(specs[len].prof.listen_addr), "%s", cfg->baidu_listen);
                len++;
            }
        }
    }

    if (len == 0) {
        free(specs);
        return 0;
    }
    *out_specs = specs;
    *out_len = len;
    return 0;
}

static int dns_encode_name(const char *domain, unsigned char *buf, size_t bufsz, size_t *off) {
    if (!domain || !buf || !off) return -1;
    const char *p = domain;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len == 0 || len > 63 || *off + 1 + len >= bufsz) return -1;
        buf[(*off)++] = (unsigned char)len;
        memcpy(buf + *off, p, len);
        *off += len;
        if (!dot) break;
        p = dot + 1;
    }
    if (*off >= bufsz) return -1;
    buf[(*off)++] = 0;
    return 0;
}

static int dns_skip_name(const unsigned char *buf, size_t len, size_t *off) {
    if (!buf || !off || *off >= len) return -1;
    size_t p = *off;
    while (p < len) {
        unsigned char c = buf[p++];
        if (c == 0) {
            *off = p;
            return 0;
        }
        if ((c & 0xc0) == 0xc0) {
            if (p >= len) return -1;
            p++;
            *off = p;
            return 0;
        }
        if ((c & 0xc0) != 0 || p + c > len) return -1;
        p += c;
    }
    return -1;
}

static uint16_t dns_u16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static const char *bind_if_label(void) {
    return g_cfg.bind_if[0] ? g_cfg.bind_if : "default";
}

#ifndef _WIN32
CFNAT_UNUSED static int shell_token_is_safe(const char *s, const char *extra_allowed) {
    if (!s || !*s) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (isalnum(*p)) continue;
        if (strchr("._-/:?&=%[]", *p)) continue;
        if (extra_allowed && strchr(extra_allowed, *p)) continue;
        return 0;
    }
    return 1;
}

CFNAT_UNUSED static int parse_json_ipv4_values(const char *json, StringList *out, int *saw_fake_ip) {
    if (!json || !out) return -1;
    size_t before = out->len;
    const char *p = json;
    while ((p = strstr(p, "\"data\"")) != nullptr) {
        const char *colon = strchr(p, ':');
        const char *q1 = colon ? strchr(colon, '"') : nullptr;
        if (!q1) {
            p += 6;
            continue;
        }
        q1++;
        const char *q2 = strchr(q1, '"');
        if (!q2) break;
        size_t n = (size_t)(q2 - q1);
        if (n > 0 && n < INET_ADDRSTRLEN) {
            char value[INET_ADDRSTRLEN];
            memcpy(value, q1, n);
            value[n] = '\0';
            struct in_addr a4;
            if (inet_pton(AF_INET, value, &a4) == 1) {
                if (is_fake_ipv4(value)) {
                    if (saw_fake_ip) *saw_fake_ip = 1;
                } else {
                    append_unique_addr(out, value);
                }
            }
        }
        p = q2 + 1;
    }
    return out->len > before ? 0 : -1;
}
#endif

static int extract_query_param_value(const char *query, const char *key, char *out, size_t outsz) {
    if (!query || !key || !out || outsz == 0) return -1;
    size_t keylen = strlen(key);
    const char *p = query;
    while (p && *p) {
        if (!strncmp(p, key, keylen) && p[keylen] == '=') {
            p += keylen + 1;
            const char *end = strchr(p, '&');
            size_t n = end ? (size_t)(end - p) : strlen(p);
            if (n == 0 || n >= outsz) return -1;
            memcpy(out, p, n);
            out[n] = '\0';
            return 0;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    return -1;
}

static int strip_query_param(const char *query, const char *key, char *out, size_t outsz) {
    if (!query || !out || outsz == 0) return -1;
    size_t keylen = strlen(key);
    size_t used = 0;
    const char *p = query;
    int first = 1;
    while (p && *p) {
        const char *end = strchr(p, '&');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (!(n > keylen + 1 && !strncmp(p, key, keylen) && p[keylen] == '=')) {
            if (!first) {
                if (used + 1 >= outsz) return -1;
                out[used++] = '&';
            }
            if (used + n >= outsz) return -1;
            memcpy(out + used, p, n);
            used += n;
            first = 0;
        }
        p = end ? end + 1 : nullptr;
    }
    out[used] = '\0';
    return 0;
}

static int parse_custom_doh_resolver(const char *spec, CustomDohStorage *storage, DohResolver *out, char *label, size_t labelsz) {
    if (!spec || !storage || !out) return -1;
    const char *rest = spec + 6;  /* skip doh:// */
    const char *slash = strchr(rest, '/');
    if (!slash) return -1;
    size_t ip_len = (size_t)(slash - rest);
    if (ip_len == 0 || ip_len >= sizeof(storage->ip)) return -1;
    memcpy(storage->ip, rest, ip_len);
    storage->ip[ip_len] = '\0';
    const char *query = strchr(slash, '?');
    if (query) {
        size_t base_len = (size_t)(query - slash);
        char filtered[MAX_RESOLVER_SPEC_LEN] = {0};
        if (extract_query_param_value(query + 1, "host", storage->host, sizeof(storage->host)) != 0) return -1;
        if (strip_query_param(query + 1, "host", filtered, sizeof(filtered)) != 0) return -1;
        if (filtered[0]) snprintf(storage->path, sizeof(storage->path), "%.*s?%s", (int)base_len, slash, filtered);
        else snprintf(storage->path, sizeof(storage->path), "%.*s", (int)base_len, slash);
    } else {
        return -1;
    }
    if (!storage->ip[0] || !storage->host[0] || !storage->path[0]) return -1;
    out->label = label ? label : "custom DoH";
    out->host = storage->host;
    out->ip = storage->ip;
    out->path = storage->path;
    if (label && labelsz > 0) snprintf(label, labelsz, "DoH(%.50s)", storage->host);
    return 0;
}

static int doh_query_a_once(const DohResolver *resolver, const char *domain, int timeout_ms, StringList *out, int *saw_fake_ip) {
    if (!resolver || !resolver->host || !resolver->ip || !resolver->path || !domain || !out) return -1;
#ifdef _WIN32
    (void)timeout_ms;
    (void)saw_fake_ip;
    return -1;
#else
    if ((!g_cfg.bind_if[0] || shell_token_is_safe(g_cfg.bind_if, "")) &&
        shell_token_is_safe(domain, "") &&
        shell_token_is_safe(resolver->host, "") &&
        shell_token_is_safe(resolver->ip, "") &&
        shell_token_is_safe(resolver->path, "")) {
        int secs = timeout_ms > 0 ? (timeout_ms + 999) / 1000 : 2;
        if (secs < 2) secs = 2;
        if (secs > 8) secs = 8;
        char cmd[1024];
        if (g_cfg.bind_if[0]) {
            snprintf(cmd, sizeof(cmd),
                     "curl --interface %s --max-time %d -fsSL --resolve %s:443:%s -H 'accept: application/dns-json' 'https://%s%s%cname=%s&type=A' 2>/dev/null",
                     g_cfg.bind_if, secs, resolver->host, resolver->ip, resolver->host, resolver->path,
                     strchr(resolver->path, '?') ? '&' : '?', domain);
        } else {
            snprintf(cmd, sizeof(cmd),
                     "curl --max-time %d -fsSL --resolve %s:443:%s -H 'accept: application/dns-json' 'https://%s%s%cname=%s&type=A' 2>/dev/null",
                     secs, resolver->host, resolver->ip, resolver->host, resolver->path,
                     strchr(resolver->path, '?') ? '&' : '?', domain);
        }
        FILE *fp = popen(cmd, "r");
        if (!fp) return -1;
        char *json = nullptr;
        size_t cap = 0, len = 0;
        char buf[512];
        while (fgets(buf, sizeof(buf), fp)) {
            size_t chunk = strlen(buf);
            if (len + chunk + 1 > cap) {
                size_t nc = cap ? cap * 2 : 1024;
                while (nc < len + chunk + 1) nc *= 2;
                char *nn = realloc(json, nc);
                if (!nn) {
                    free(json);
                    pclose(fp);
                    return -1;
                }
                json = nn;
                cap = nc;
            }
            memcpy(json + len, buf, chunk);
            len += chunk;
            json[len] = '\0';
        }
        int rc = pclose(fp);
        if (rc != 0 || !json || len == 0) {
            free(json);
            return -1;
        }
        int ret = parse_json_ipv4_values(json, out, saw_fake_ip);
        free(json);
        return ret;
    }
    return -1;
#endif
}

static int dns_query_a_once(const char *resolver, const char *domain, int timeout_ms, StringList *out, int *saw_fake_ip) {
    if (!resolver || !domain || !out) return -1;
    unsigned char query[512];
    memset(query, 0, sizeof(query));
    uint16_t id = (uint16_t)(rand_u64() & 0xffffu);
    query[0] = (unsigned char)(id >> 8);
    query[1] = (unsigned char)(id & 0xff);
    query[2] = 0x01;  /* recursion desired */
    query[5] = 0x01;  /* qdcount */
    size_t qlen = 12;
    if (dns_encode_name(domain, query, sizeof(query), &qlen) != 0 || qlen + 4 > sizeof(query)) return -1;
    query[qlen++] = 0x00;
    query[qlen++] = 0x01;  /* A */
    query[qlen++] = 0x00;
    query[qlen++] = 0x01;  /* IN */

    socket_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (cfnat_socket_invalid(fd)) return -1;
    if (bind_socket_to_interface(fd, AF_INET) != 0) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    if (inet_pton(AF_INET, resolver, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (sendto(fd, (const char *)query, (int)qlen, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    int rc = cfnat_poll_single(fd, 1, timeout_ms);
    if (rc <= 0) {
        close(fd);
        return -1;
    }

    unsigned char resp[1500];
    ssize_t n = recv(fd, (char *)resp, sizeof(resp), 0);
    close(fd);
    if (n < 12) return -1;
    size_t rlen = (size_t)n;
    if (dns_u16(resp) != id) return -1;
    if ((resp[3] & 0x0f) != 0) return -1;
    uint16_t qd = dns_u16(resp + 4);
    uint16_t an = dns_u16(resp + 6);
    size_t off = 12;
    for (uint16_t i = 0; i < qd; i++) {
        if (dns_skip_name(resp, rlen, &off) != 0 || off + 4 > rlen) return -1;
        off += 4;
    }
    size_t before = out->len;
    for (uint16_t i = 0; i < an; i++) {
        if (dns_skip_name(resp, rlen, &off) != 0 || off + 10 > rlen) return -1;
        uint16_t type = dns_u16(resp + off);
        uint16_t klass = dns_u16(resp + off + 2);
        uint16_t rdlen = dns_u16(resp + off + 8);
        off += 10;
        if (off + rdlen > rlen) return -1;
        if (type == 1 && klass == 1 && rdlen == 4) {
            char ip[INET_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET, resp + off, ip, sizeof(ip))) {
                if (is_fake_ipv4(ip)) {
                    if (saw_fake_ip) *saw_fake_ip = 1;
                } else {
                    append_unique_addr(out, ip);
                }
            }
        }
        off += rdlen;
    }
    return out->len > before ? 0 : -1;
}

static int resolve_host_ips_via_default_doh(const char *domain, StringList *out) {
    if (!domain || !out) return -1;
    int timeout_ms = g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 1000;
    if (timeout_ms < 1000) timeout_ms = 1000;
    int saw_fake_ip = 0;
    size_t before = out->len;
    for (size_t i = 0; BAIDU_DOH_RESOLVERS[i].label; i++) {
        if (doh_query_a_once(&BAIDU_DOH_RESOLVERS[i], domain, timeout_ms, out, &saw_fake_ip) == 0) {
            log_msg("百度前置域名通过 %s 绑定 %s 解析到 %zu 个真实 IP",
                    BAIDU_DOH_RESOLVERS[i].label, bind_if_label(), out->len - before);
            return 0;
        }
    }
    if (saw_fake_ip) {
        warn_msg("绑定 %s 的 DoH 查询百度前置域名仍返回 Fake-IP", bind_if_label());
    }
    return -1;
}

static int resolve_host_ips_via_default_udp_dns(const char *domain, StringList *out) {
    if (!domain || !out) return -1;
    int timeout_ms = g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 1000;
    if (timeout_ms < 1000) timeout_ms = 1000;
    int saw_fake_ip = 0;
    size_t before = out->len;
    for (size_t i = 0; BAIDU_DNS_RESOLVERS[i]; i++) {
        if (dns_query_a_once(BAIDU_DNS_RESOLVERS[i], domain, timeout_ms, out, &saw_fake_ip) == 0) {
            log_msg("百度前置域名通过 %s 绑定 %s 解析到 %zu 个真实 IP",
                    BAIDU_DNS_RESOLVERS[i], bind_if_label(), out->len - before);
            return 0;
        }
    }
    if (saw_fake_ip) {
        warn_msg("绑定 %s 查询百度前置域名仍返回 Fake-IP", bind_if_label());
    }
    return -1;
}

static int resolve_host_ips_via_configured_resolver(const char *domain, StringList *out) {
    if (!domain || !out) return -1;
    const char *spec = g_cfg.baidu_resolver[0] ? g_cfg.baidu_resolver : "auto";
    if (!strcasecmp(spec, "auto")) {
        warn_msg("百度前置域名恢复解析使用默认 auto 策略");
        if (resolve_host_ips_via_default_doh(domain, out) == 0) return 0;
        warn_msg("默认 DoH 查询百度前置域名失败，回退到 UDP DNS");
        return resolve_host_ips_via_default_udp_dns(domain, out);
    }
    if (!strncasecmp(spec, "udp://", 6)) {
        int timeout_ms = g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 1000;
        if (timeout_ms < 1000) timeout_ms = 1000;
        int saw_fake_ip = 0;
        size_t before = out->len;
        const char *resolver = spec + 6;
        if (dns_query_a_once(resolver, domain, timeout_ms, out, &saw_fake_ip) == 0) {
            log_msg("百度前置域名通过配置的 UDP DNS %s 绑定 %s 解析到 %zu 个真实 IP",
                    resolver, bind_if_label(), out->len - before);
            return 0;
        }
        if (saw_fake_ip) warn_msg("配置的 UDP DNS %s 返回 Fake-IP", resolver);
        return -1;
    }
    if (!strncasecmp(spec, "doh://", 6)) {
        int timeout_ms = g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 1000;
        if (timeout_ms < 1000) timeout_ms = 1000;
        int saw_fake_ip = 0;
        size_t before = out->len;
        CustomDohStorage storage = {0};
        DohResolver resolver = {0};
        char label[64] = {0};
        if (parse_custom_doh_resolver(spec, &storage, &resolver, label, sizeof(label)) != 0) {
            warn_msg("非法 -baidu-resolver=%s，期望格式 doh://IP/path?host=HOST", spec);
            return -1;
        }
        if (doh_query_a_once(&resolver, domain, timeout_ms, out, &saw_fake_ip) == 0) {
            log_msg("百度前置域名通过配置的 %s 绑定 %s 解析到 %zu 个真实 IP",
                    label[0] ? label : "DoH", bind_if_label(), out->len - before);
            return 0;
        }
        if (saw_fake_ip) warn_msg("配置的 %s 返回 Fake-IP", label[0] ? label : "DoH");
        return -1;
    }
    warn_msg("不支持的 -baidu-resolver=%s，支持 auto / udp://IP / doh://IP/path?host=HOST", spec);
    return -1;
}

static int resolve_host_ips(const char *domain, StringList *out) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    struct addrinfo * res = nullptr;
    int saw_fake_ip = 0;
    if (getaddrinfo(domain, nullptr, &hints, &res) == 0) {
        for (struct addrinfo * ai = res; ai; ai = ai->ai_next) {
            char ip[INET_ADDRSTRLEN] = {0};
            struct sockaddr_in * sin = (struct sockaddr_in *) ai->ai_addr;
            if (!inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip))) continue;
            if (is_fake_ipv4(ip)) {
                saw_fake_ip = 1;
                continue;
            }
            append_unique_addr(out, ip);
        }
        freeaddrinfo(res);
    }
    if (out->len > 0) return 0;
    if (out->len == 0) {
        if (saw_fake_ip) {
            warn_msg("百度前置域名解析到 Fake-IP(198.18.0.0/15)，改用 -baidu-resolver=%s 恢复真实节点",
                    g_cfg.baidu_resolver[0] ? g_cfg.baidu_resolver : "auto");
            if (resolve_host_ips_via_configured_resolver(domain, out) == 0) return 0;
            warn_msg("配置的百度前置域名恢复解析失败");
        } else {
            warn_msg("百度前置域名解析失败，尝试 -baidu-resolver=%s",
                    g_cfg.baidu_resolver[0] ? g_cfg.baidu_resolver : "auto");
            if (resolve_host_ips_via_configured_resolver(domain, out) == 0) return 0;
        }
    }
    return out->len > 0 ? 0 : -1;
}

static void add_baidu_fallback_ips(StringList *ips) {
    if (!ips) return;
    for (size_t i = 0; BAIDU_PROXY_FALLBACK_IPS[i]; i++) {
        append_unique_addr(ips, BAIDU_PROXY_FALLBACK_IPS[i]);
    }
}

static void build_baidu_pool_from_ips(BaiduProxyPool *pool, StringList *ips) {
    if (!pool || !ips) return;
    for (size_t i = 0; i < ips->len; i++) {
        char addr[MAX_ADDR_LEN];
        snprintf(addr, sizeof(addr), "%s:%d", ips->items[i], g_cfg.baidu_port);
        int latency = 0;
        socket_t fd = tcp_connect_via_baidu(addr, g_cfg.baidu_scan_target,
                                            g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 1000, &latency);
        if (cfnat_socket_valid(fd)) {
            close(fd);
            baidu_pool_add(pool, addr);
            if ((int)pool->len >= g_cfg.baidu_ipnum) break;
        }
    }
}

static int build_baidu_pool_for_carrier(BaiduProxyPool *pool, const char *name) {
    memset(pool, 0, sizeof(*pool));
    snprintf(pool->name, sizeof(pool->name), "%s", name ? name : "default");
    StringList ips = {0};
    if (resolve_host_ips(g_cfg.baidu_domain, &ips) == 0) {
        build_baidu_pool_from_ips(pool, &ips);
    }
    if (pool->len == 0) {
        warn_msg("百度前置解析节点无法建立 CONNECT，改用内置真实节点候选");
        add_baidu_fallback_ips(&ips);
        build_baidu_pool_from_ips(pool, &ips);
    }
    strlist_free(&ips);
    return pool->len > 0 ? 0 : -1;
}

static int carrier_init_baidu_pool(CarrierRuntime *rt) {
    if (!rt || !rt->spec.use_baidu_proxy) return 0;
    rt->proxy_pool = calloc(1, sizeof(BaiduProxyPool));
    if (rt->proxy_pool && build_baidu_pool_for_carrier(rt->proxy_pool, rt->spec.mode) == 0) {
        log_msg("%s 百度代理池已建立，节点数: %zu", carrier_display_name(rt->spec.mode), rt->proxy_pool->len);
        return 1;
    }
    if (rt->proxy_pool) {
        baidu_pool_free(rt->proxy_pool);
        free(rt->proxy_pool);
        rt->proxy_pool = nullptr;
    }
    warn_msg("%s 百度代理池建立失败，无法启动百度前置监听", carrier_display_name(rt->spec.mode));
    return 0;
}

static int carrier_check_baidu_ipv6_support(CarrierRuntime *rt) {
    if (!rt || !rt->proxy_pool || rt->proxy_pool->len == 0) return 0;
    int latency = 0;
    socket_t fd = dial_target_with_proxy("2606:4700:4700::1111", 443,
                                         g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 1000,
                                         rt->proxy_pool, &latency);
    if (cfnat_socket_valid(fd)) {
        close(fd);
        return 1;
    }
    warn_msg("%s 百度前置节点无法 CONNECT IPv6 目标，-ips=6 不支持百度前置监听", carrier_display_name(rt->spec.mode));
    return 0;
}

static void resultlist_add(ResultList *rl, const Result *r) {
    if (!rl || !r) return;
    if (rl->len == rl->cap) {
        size_t nc = rl->cap ? rl->cap * 2 : 128;
        Result *ni = realloc(rl->items, nc * sizeof(Result));
        if (!ni) return;
        rl->items = ni;
        rl->cap = nc;
    }
    rl->items[rl->len] = *r;
    if (rl->items[rl->len].addr_len == 0) {
        result_init_addr(&rl->items[rl->len]);
    }
    rl->len++;
}

/* thread-local 结果批量写入全局列表 */
static void flush_local_results(ScanCtx *ctx, Result *local, int *count) {
    if (!ctx || !ctx->results || !local || !count || *count <= 0) return;
    pthread_mutex_lock(&ctx->results_mu);
    for (int i = 0; i < *count; i++) {
        resultlist_add(ctx->results, &local[i]);
    }
    pthread_mutex_unlock(&ctx->results_mu);
    *count = 0;
}

/* 解析配置中的域名与路径，严格符合 RFC 9112 Section 7.2 规范：Host 头部严禁包含路径 */
static void parse_domain_and_path(const char *raw_domain, char *out_host, size_t hostsz, char *out_path, size_t pathsz) {
    if (!out_host || hostsz == 0 || !out_path || pathsz == 0) return;
    out_host[0] = '\0';
    out_path[0] = '\0';

    const char *p = raw_domain ? raw_domain : "";
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;

    /* 跳过可能包含的 http:// 或 https:// scheme 前缀 */
    if (strncasecmp(p, "http://", 7) == 0) {
        p += 7;
    } else if (strncasecmp(p, "https://", 8) == 0) {
        p += 8;
    }

    const char *slash = strchr(p, '/');
    if (slash) {
        size_t hlen = (size_t)(slash - p);
        if (hlen >= hostsz) hlen = hostsz - 1;
        memcpy(out_host, p, hlen);
        out_host[hlen] = '\0';
        snprintf(out_path, pathsz, "%s", slash);
    } else {
        snprintf(out_host, hostsz, "%s", p);
        snprintf(out_path, pathsz, "/");
    }

    /* 缺省兜底 */
    if (!out_host[0]) snprintf(out_host, hostsz, "%s", "cloudflaremirrors.com");
    if (!out_path[0]) snprintf(out_path, pathsz, "%s", "/");
}

/* 新 scan_worker：Keep-Alive + 快速剪枝 + thread-local 结果 */
static void *scan_worker(void *arg) {
    ScanCtx *ctx = (ScanCtx *)arg;

    /* thread-local 结果积累 (16 已经足够批量减少互斥锁竞争，同时避免线程栈过度消耗) */
#define LOCAL_MAX 16
    Result local_results[LOCAL_MAX];
    int local_count = 0;

    /* 从 ScanCtx 直接获取预构建的请求模板与参数，彻底消灭每个工作线程重复的域名拆分与 snprintf 格式化 */
    const char *head_req = ctx->head_req;
    int head_req_len = ctx->head_req_len;
    const char *get_req = ctx->get_req;
    int get_req_len = ctx->get_req_len;
    int probe_port = ctx->probe_port;
    int hdr_timeout = ctx->hdr_timeout;

    while (atomic_load(&g_running)) {
        size_t idx = atomic_fetch_add(&ctx->index, 1);
        if (idx >= ctx->total || !atomic_load(&g_running)) break;

        /* 从 CidrList 按需生成 IP */
        char ip[MAX_IP_LEN];
        if (ctx->cidrs) {
            if (cidrlist_get_ip(ctx->cidrs, idx, ip, sizeof(ip)) != 0) continue;
        } else {
            /* 兼容旧模式：ctx->ips 不为 nullptr */
            snprintf(ip, sizeof(ip), "%s", ctx->ips[idx]);
        }

        /* 预解析二进制地址 sockaddr_storage，单 IP 全程复用，彻底消灭重复 inet_pton */
        struct sockaddr_storage target_sa = {0};
        socklen_t target_salen = 0;
        int is_v6 = (strchr(ip, ':') != nullptr);
        if (is_v6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&target_sa;
            s6->sin6_family = AF_INET6;
            s6->sin6_port = htons((uint16_t)probe_port);
            if (inet_pton(AF_INET6, ip, &s6->sin6_addr) == 1) target_salen = sizeof(*s6);
        } else {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&target_sa;
            s4->sin_family = AF_INET;
            s4->sin_port = htons((uint16_t)probe_port);
            if (inet_pton(AF_INET, ip, &s4->sin_addr) == 1) target_salen = sizeof(*s4);
        }

        int probes = ctx->cfg->num > 0 ? ctx->cfg->num : 1;
        int success_count = 0;
        int total_latency = 0;
        int best_latency = 0;
        int ewma_latency = 0;
        int jitter_ms = 0;
        int prev_latency = 0;
        char best_colo[MAX_COLO_LEN] = {0};
        int code_matched = 0;

        /* Keep-Alive 复用连接 */
        socket_t fd = INVALID_SOCKET;
        int conn_lat = 0;
        for (int attempt = 0; atomic_load(&g_running) && attempt < probes; attempt++) {
            if (cfnat_socket_invalid(fd)) {
                conn_lat = 0;
                fd = dial_target_with_proxy_sa(ip, &target_sa, target_salen, probe_port, ctx->cfg->delay_ms, ctx->proxy_pool, &conn_lat);
                if (cfnat_socket_invalid(fd)) {
                    atomic_fetch_add(&ctx->connect_fail, 1);
                    if (attempt == 0) break; /* 首轮 TCP 握手失败直接判定死节点，避免对死 IP 无效重复等待 */
                    continue;
                }
            }

            long t_start = now_ms();
            if (!send_all_timeout(fd, head_req, (size_t)head_req_len, hdr_timeout)) {
                close(fd);
                fd = INVALID_SOCKET;
                atomic_fetch_add(&ctx->header_fail, 1);
                if (attempt == 0) break;
                continue;
            }
            char hdr[4096];
            int n = recv_headers(fd, hdr, sizeof(hdr), hdr_timeout);
            long t_end = now_ms();
            if (n <= 0) {
                /* 连接断开或超时，关闭后下次重连 */
                close(fd);
                fd = INVALID_SOCKET;
                atomic_fetch_add(&ctx->header_fail, 1);
                if (attempt == 0) break; /* 首轮 HTTP 响应超时/断开直接放弃，不再对半死节点无效重试 */
                continue;
            }

            /* 如果服务端指示 Connection: close，关闭连接以供下次探测重新建立 */
            if (cfnat_strcasestr(hdr, "Connection: close")) {
                close(fd);
                fd = INVALID_SOCKET;
            }

            int resp_code = extract_http_status_code(hdr);
            if (ctx->cfg->code > 0) {
                if (resp_code == ctx->cfg->code) {
                    code_matched = 1;
                } else if (resp_code != 405) {
                    /* 非 405 的状态码不匹配（如 400、403、502）判定失败并直接剪枝 */
                    atomic_fetch_add(&ctx->http_code_mismatch, 1);
                    break;
                }
            }

            char colo[MAX_COLO_LEN] = {0};
            if (extract_cfray(hdr, colo, sizeof(colo)) != 0) {
                atomic_fetch_add(&ctx->cfray_miss, 1);
                break; /* 缺少 CF-RAY 报头直接剪枝 */
            }
            if (!colo_rule_allowed(ctx->cfg->colo, colo)) {
                atomic_fetch_add(&ctx->colo_skip, 1);
                break; /* 数据中心不匹配直接剪枝，避免对不合格机房浪费后续探测 */
            }

            int cur_latency = (int)(t_end - t_start);
            if (cur_latency <= 0) cur_latency = conn_lat > 0 ? conn_lat : 1;

            /* 慢节点早剪枝：首轮握手+探测延迟已超标 (> delay_ms * 2 且 > 250ms)，直接放弃 */
            if (attempt == 0 && ctx->cfg->delay_ms > 0 && cur_latency > ctx->cfg->delay_ms * 2 && cur_latency > 250) {
                break;
            }

            success_count++;
            total_latency += cur_latency;
            if (best_latency == 0 || cur_latency < best_latency) {
                best_latency = cur_latency;
            }

            /* P0-EWMA: 真实样本抖动与平滑延迟更新 */
            if (success_count == 1) {
                ewma_latency = cur_latency;
                jitter_ms = 0;
                prev_latency = cur_latency;
            } else {
                int diff = abs(cur_latency - prev_latency);
                jitter_ms = (jitter_ms * 7 + diff) / 8;
                ewma_latency = (ewma_latency * 7 + cur_latency) / 8;
                prev_latency = cur_latency;
            }

            if (!best_colo[0] || cur_latency <= best_latency) {
                snprintf(best_colo, sizeof(best_colo), "%s", colo);
            }
        }
        if (cfnat_socket_valid(fd)) close(fd);

        int avg_latency = success_count > 0 ? (total_latency / success_count) : 0;

        uint64_t done = atomic_fetch_add(&ctx->completed, 1) + 1;
        uint64_t step = ctx->total / 100;
        if (step < 5) step = 5;
        if (step > 500) step = 500;

        if (done == ctx->total || done % step == 0) {
            double pct = (double)done * 100.0 / (double)(ctx->total > 0 ? ctx->total : 1);
            if (pct > 100.0) pct = 100.0;
            if (g_cfg.log_level >= LOG_DEBUG) {
                if (done == ctx->total || done % (step * 5) == 0) {
                    log_msg("已完成: %llu 总数: %llu 已完成: %.2f%%",
                            (unsigned long long)done, (unsigned long long)ctx->total, pct);
                }
            } else if (terminal_has_color(stderr)) {
                pthread_mutex_lock(&g_log_mu);
                fprintf(stderr, "\r" ANSI_GRAY "[扫描进度]" ANSI_RESET " 已完成: " ANSI_BOLD "%llu" ANSI_RESET " / %llu (" ANSI_GREEN "%.2f%%" ANSI_RESET ")",
                        (unsigned long long)done, (unsigned long long)ctx->total, pct);
                if (done == ctx->total) fprintf(stderr, "\n");
                fflush(stderr);
                pthread_mutex_unlock(&g_log_mu);
            }
        }
        if (success_count <= 0 || !best_colo[0] || avg_latency <= 0 || (ctx->cfg->delay_ms > 0 && avg_latency > ctx->cfg->delay_ms)) continue;

        /* 若显式指定了 code (code > 0)，且初筛未完全确认（例如 HEAD 返回 405），使用 GET 做二次状态码校验 */
        if (ctx->cfg->code > 0 && !code_matched) {
            int target_code = ctx->cfg->code;
            socket_t check_fd = dial_target_with_proxy_sa(ip, &target_sa, target_salen, probe_port, ctx->cfg->delay_ms, ctx->proxy_pool, nullptr);
            if (cfnat_socket_invalid(check_fd)) {
                debug_msg("IP %s 状态码二次校验失败: 无法连接端口 %d", ip, probe_port);
                atomic_fetch_add(&ctx->http_code_mismatch, 1);
                continue;
            }
            if (!send_all_timeout(check_fd, get_req, (size_t)get_req_len, hdr_timeout)) {
                close(check_fd);
                atomic_fetch_add(&ctx->http_code_mismatch, 1);
                continue;
            }
            char check_hdr[4096];
            int chk_n = recv_headers(check_fd, check_hdr, sizeof(check_hdr), hdr_timeout);
            close(check_fd);
            if (chk_n <= 0) {
                debug_msg("IP %s 状态码二次校验失败: 读取响应头超时或失败", ip);
                atomic_fetch_add(&ctx->http_code_mismatch, 1);
                continue;
            }
            int resp_code = extract_http_status_code(check_hdr);
            if (resp_code != target_code) {
                debug_msg("IP %s 状态码二次校验不匹配: 期望 %d，实际返回 %d", ip, target_code, resp_code);
                atomic_fetch_add(&ctx->http_code_mismatch, 1);
                continue;
            }
        }

        Result r;
        memset(&r, 0, sizeof(r));
        snprintf(r.ip, sizeof(r.ip), "%s", ip);
        r.addr = target_sa;
        r.addr_len = target_salen;
        snprintf(r.data_center, sizeof(r.data_center), "%s", best_colo);
        r.latency_ms = avg_latency;
        r.probe_count = probes;
        r.success_count = success_count;
        r.loss_rate = (probes - success_count) * 100 / probes;
        r.ewma_latency = ewma_latency > 0 ? ewma_latency : avg_latency;
        r.jitter_ms = jitter_ms;
        r.consecutive_fail = 0;
        Location *loc = find_location(best_colo);
        if (loc) {
            snprintf(r.region, sizeof(r.region), "%s", loc->region);
            snprintf(r.city, sizeof(r.city), "%s", loc->city);
        }
        if (!loc && !strcmp(best_colo, "UNK")) {
            snprintf(r.region, sizeof(r.region), "%s", "Unknown");
            snprintf(r.city, sizeof(r.city), "%s", "Unknown");
        }
        if (g_cfg.log_level >= LOG_DEBUG) {
            int use_color = terminal_has_color(stderr);
            const char *c_ip = use_color ? ANSI_CYAN : "";
            const char *c_loc = use_color ? ANSI_YELLOW : "";
            const char *c_ms = use_color ? ANSI_GREEN : "";
            const char *reset = use_color ? ANSI_RESET : "";
            char loc_buf[128];
            if (r.city[0] && strcmp(r.city, "Unknown") != 0) {
                if (r.data_center[0] && strcmp(r.data_center, "UNK") != 0) {
                    snprintf(loc_buf, sizeof(loc_buf), "%s (%s)", r.city, r.data_center);
                } else {
                    snprintf(loc_buf, sizeof(loc_buf), "%s", r.city);
                }
            } else if (r.region[0] && strcmp(r.region, "Unknown") != 0) {
                if (r.data_center[0] && strcmp(r.data_center, "UNK") != 0) {
                    snprintf(loc_buf, sizeof(loc_buf), "%s (%s)", r.region, r.data_center);
                } else {
                    snprintf(loc_buf, sizeof(loc_buf), "%s", r.region);
                }
            } else if (r.data_center[0] && strcmp(r.data_center, "UNK") != 0) {
                snprintf(loc_buf, sizeof(loc_buf), "%s", r.data_center);
            } else {
                snprintf(loc_buf, sizeof(loc_buf), "Unknown");
            }
            debug_msg("发现有效IP %s%s%s 位置信息 %s%s%s 延迟 %s%d%s 毫秒",
                      c_ip, r.ip, reset,
                      c_loc, loc_buf, reset,
                      c_ms, r.latency_ms, reset);
        }

        /* thread-local 积累 */
        if (local_count < LOCAL_MAX) {
            local_results[local_count++] = r;
        }
        if (local_count >= LOCAL_MAX) {
            flush_local_results(ctx, local_results, &local_count);
        }
    }

    /* 剩余结果 flush */
    flush_local_results(ctx, local_results, &local_count);
    return nullptr;
}
#undef LOCAL_MAX


/* P0-EWMA: 增强评分函数，考虑 EWMA 延迟、抖动和连续失败 */
static int score_result(const Result *r) {
    int score = 0;
    /* 基础分：使用 EWMA 延迟（如果可用），否则用原始延迟 */
    int base_latency = r->ewma_latency > 0 ? r->ewma_latency : r->latency_ms;
    score += base_latency * 10;
    /* 丢包惩罚 */
    score += r->loss_rate * 25;
    /* 抖动惩罚：高抖动意味着不稳定 */
    score += r->jitter_ms * 5;
    /* 连续失败惩罚：指数级增长 */
    if (r->consecutive_fail > 0) {
        int penalty = 50;
        for (int i = 0; i < r->consecutive_fail && i < 10; i++) penalty *= 2;
        score += penalty;
    }
    return score;
}

static int cmp_result(const void *a, const void *b) {
    const Result *ra = (const Result *)a;
    const Result *rb = (const Result *)b;
    int sa = score_result(ra);
    int sb = score_result(rb);
    if (sa != sb) return sa - sb;
    if (ra->latency_ms != rb->latency_ms) return ra->latency_ms - rb->latency_ms;
    return ra->loss_rate - rb->loss_rate;
}


CFNAT_NODISCARD static int health_check_ip(const char *ip, BaiduProxyPool *proxy_pool);
CFNAT_NODISCARD static int carrier_health_check_ip(CarrierRuntime *rt, const char *ip);
static int carrier_set_current_candidate(CarrierRuntime *rt, size_t idx);
static int carrier_set_current_udp_candidate(CarrierRuntime *rt, size_t idx);
static void carrier_get_current_udp_ip(CarrierRuntime *rt, char *out, size_t sz);
static int carrier_switch_next_udp_ip(CarrierRuntime *rt);
static int carrier_rescan_dual_pools(CarrierRuntime *rt);
static void carrier_note_connection_success(CarrierRuntime *rt, const char *ip);
static void carrier_note_connection_failed(CarrierRuntime *rt, const char *ip);
static int carrier_choose_ip_for_sni(CarrierRuntime *rt, const char *sni_host, char *out, size_t sz);
static int carrier_try_use_candidate_caches(CarrierRuntime *rt);
static ResultList filter_udp_candidates_from_tcp(CarrierRuntime *rt, const Result *tcp_results, size_t count, size_t target_ipnum);
static void *carrier_udp_health_thread(void *arg);

#define CACHE_REFRESH_INTERVAL_SECONDS 3600L
#define CACHE_QUICK_CHECK_COUNT 5

static const char *candidate_cache_file_for_profile(const char *mode, int ips_type) {
    if (mode && strcmp(mode, "baidu") == 0) {
        return ips_type == 6 ? "baidu-cache-v6.txt" : "baidu-cache-v4.txt";
    }
    if (mode && strcmp(mode, "mixed") == 0) {
        return ips_type == 6 ? "mixed-cache-v6.txt" : "mixed-cache-v4.txt";
    }
    return ips_type == 6 ? "direct-cache-v6.txt" : "direct-cache-v4.txt";
}

static const char *candidate_cache_file_for_profile_udp(const char *mode, int ips_type) {
    if (mode && strcmp(mode, "baidu") == 0) {
        return ips_type == 6 ? "baidu-cache-v6-udp.txt" : "baidu-cache-v4-udp.txt";
    }
    if (mode && strcmp(mode, "mixed") == 0) {
        return ips_type == 6 ? "mixed-cache-v6-udp.txt" : "mixed-cache-v4-udp.txt";
    }
    return ips_type == 6 ? "direct-cache-v6-udp.txt" : "direct-cache-v4-udp.txt";
}

static const char *candidate_cache_file(const char *mode) {
    return candidate_cache_file_for_profile(mode, g_cfg.ips_type);
}


static void save_candidate_cache(const char *path, const Result *items, size_t len) {
    if (!path || !items || len == 0) return;
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        warn_msg("写入缓存 %s 失败", path);
        return;
    }
    /* P0-EWMA: 缓存格式升级为 v2，增加 ewma_latency, jitter_ms, consecutive_fail */
    fprintf(fp, "# cfnat-cache-v2 %ld\n", (long)time(nullptr));
    for (size_t i = 0; i < len; i++) {
        const Result *r = &items[i];
        fprintf(fp, "%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%d\n",
                r->ip,
                r->data_center[0] ? r->data_center : "UNK",
                r->region[0] ? r->region : "Unknown",
                r->city[0] ? r->city : "Unknown",
                r->latency_ms,
                r->loss_rate,
                r->success_count,
                r->probe_count,
                r->ewma_latency > 0 ? r->ewma_latency : r->latency_ms,
                r->jitter_ms,
                r->consecutive_fail);
    }
    fclose(fp);
    debug_msg("候选缓存已写入 %s，共 %zu 个", path, len);
}

static ResultList load_candidate_cache_for_profile(const char *path, const ProfileConfig *prof) {
    ResultList rl = {0};
    if (!path || !file_exists(path)) return rl;

    FILE *fp = fopen(path, "rb");
    if (!fp) return rl;

    char line[MAX_LINE];
    int is_v2 = 0;
    if (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "# cfnat-cache-v2", 16) == 0) {
            is_v2 = 1;
        } else if (strncmp(line, "# cfnat-cache-v1", 16) != 0) {
            rewind(fp);
        }
    }

    int delay_limit = (prof && prof->delay_ms > 0) ? prof->delay_ms : (g_cfg.delay_ms > 0 ? g_cfg.delay_ms : 300);
    int num_probes = (prof && prof->num > 0) ? prof->num : (g_cfg.num > 0 ? g_cfg.num : 5);
    int max_ips = (prof && prof->ipnum > 0) ? prof->ipnum : (g_cfg.ipnum > 0 ? g_cfg.ipnum : 20);
    const char *colo_rule = (prof && prof->colo[0]) ? prof->colo : g_cfg.colo;

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        Result r;
        memset(&r, 0, sizeof(r));
        int parsed;
        if (is_v2) {
            /* P0-EWMA: v2 格式包含 ewma_latency, jitter_ms, consecutive_fail */
            parsed = sscanf(line, "%63[^|]|%7[^|]|%63[^|]|%63[^|]|%d|%d|%d|%d|%d|%d|%d",
                            r.ip,
                            r.data_center,
                            r.region,
                            r.city,
                            &r.latency_ms,
                            &r.loss_rate,
                            &r.success_count,
                            &r.probe_count,
                            &r.ewma_latency,
                            &r.jitter_ms,
                            &r.consecutive_fail);
        } else {
            /* v1 格式兼容 */
            parsed = sscanf(line, "%63[^|]|%7[^|]|%63[^|]|%63[^|]|%d|%d|%d|%d",
                            r.ip,
                            r.data_center,
                            r.region,
                            r.city,
                            &r.latency_ms,
                            &r.loss_rate,
                            &r.success_count,
                            &r.probe_count);
        }
        if (parsed < 8 || !r.ip[0]) continue;
        if (prof && prof->ips_type == 6 && !strchr(r.ip, ':')) continue;
        if (prof && prof->ips_type == 4 && strchr(r.ip, ':')) continue;
        if (r.latency_ms <= 0) r.latency_ms = delay_limit;
        if (r.probe_count <= 0) r.probe_count = num_probes;
        if (r.success_count <= 0) r.success_count = 1;
        /* P0-EWMA: 如果 v1 格式没有 EWMA 字段，用原始延迟初始化 */
        if (r.ewma_latency <= 0) r.ewma_latency = r.latency_ms;
        if (colo_rule[0] && strcmp(r.data_center, "UNK") != 0 && !colo_rule_allowed(colo_rule, r.data_center)) continue;
        resultlist_add(&rl, &r);
        if (max_ips > 0 && rl.len >= (size_t)max_ips) break;
    }
    fclose(fp);
    qsort(rl.items, rl.len, sizeof(Result), cmp_result);
    if (rl.len > 0) log_msg("已读取候选缓存 %s，共 %zu 个（v%d格式），开始快速健康检查", path, rl.len, is_v2 ? 2 : 1);
    return rl;
}

static ResultList load_candidate_cache(const char *path) {
    return load_candidate_cache_for_profile(path, nullptr);
}

static int try_use_candidate_cache(BaiduProxyPool *proxy_pool, ResultList *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    const char *path = candidate_cache_file("direct");
    ResultList cached = load_candidate_cache(path);
    if (cached.len == 0) {
        return 0;
    }

    size_t check_count = cached.len < CACHE_QUICK_CHECK_COUNT ? cached.len : CACHE_QUICK_CHECK_COUNT;
    for (size_t i = 0; i < check_count; i++) {
        if (health_check_ip(cached.items[i].ip, proxy_pool)) {
            log_msg("命中候选缓存，快速启动使用 IP: %s，后台将继续刷新候选池", cached.items[i].ip);
            *out = cached;
            return 1;
        }
    }

    warn_msg("候选缓存健康检查未命中，将执行完整扫描");
    free(cached.items);
    return 0;
}

/* P0-H3: 基于 RFC 9000 规范从同网段衍生兄弟 IP (IPv4 /24 或 IPv6 /64) */
static int sample_sibling_ip_from_subnet(const char *seed_ip, char *out_ip, size_t outsz) {
    if (!seed_ip || !*seed_ip || !out_ip || outsz == 0) return 0;
    if (strchr(seed_ip, ':')) {
        unsigned char bytes[16];
        if (inet_pton(AF_INET6, seed_ip, bytes) != 1) return 0;
        uint16_t w[4];
        for (int i = 0; i < 4; i++) {
            w[i] = (uint16_t)(((uint16_t)bytes[i * 2] << 8) | (uint16_t)bytes[i * 2 + 1]);
        }
        uint64_t r = rand_u64();
        uint16_t seg4 = (uint16_t)(r & 0xffff);
        uint16_t seg5 = (uint16_t)((r >> 16) & 0xffff);
        uint16_t seg6 = (uint16_t)((r >> 32) & 0xffff);
        uint16_t seg7 = (uint16_t)((r >> 48) & 0xffff);
        if (seg4 == 0 && seg5 == 0 && seg6 == 0 && seg7 == 0) seg7 = 1;
        snprintf(out_ip, outsz, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                 w[0], w[1], w[2], w[3], seg4, seg5, seg6, seg7);
        return 1;
    } else {
        int a, b, c, d;
        if (sscanf(seed_ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return 0;
        int host = (int)(rand_u64() % 253) + 1; // 1..253
        if (host >= d) host++;                  // 保证避开种子 IP 本身 (1..254 != d)
        if (host < 1) host = 1;
        if (host > 254) host = 254;
        snprintf(out_ip, outsz, "%d.%d.%d.%d", a, b, c, host);
        return 1;
    }
}

typedef struct {
    Result res;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    long send_time;
    int latency_ms;
    int responded;
} QuicProbeItem;

/* 全异步非阻塞并发 QUIC 探针齐射批次执行函数 */
static size_t quic_batch_probe(CarrierRuntime *rt, socket_t fd4, socket_t fd6, int target_port,
                               int timeout_ms, QuicProbeItem *items, size_t count, size_t needed_responses) {
    if (!items || count == 0) return 0;

    /* C23 thread_local 预格式化探针模板，零栈分配、零每轮 memset 清零开销 */
    static thread_local uint8_t pkt[1200] = {
        0xC0, 0x5A, 0x5A, 0x5A, 0x5A, 0x08,
        [14] = 0x08
    };

    uint32_t seed = (uint32_t)now_ms();
    memcpy(pkt + 6, &seed, 4);

    long start_time = now_ms();

    for (size_t i = 0; i < count; i++) {
        items[i].responded = 0;
        items[i].latency_ms = 0;
        int is_v6 = (strchr(items[i].res.ip, ':') != nullptr);
        socket_t sfd = is_v6 ? fd6 : fd4;
        if (cfnat_socket_invalid(sfd)) continue;

        if (items[i].addr_len > 0) {
            if (is_v6) ((struct sockaddr_in6 *)&items[i].addr)->sin6_port = htons((uint16_t)target_port);
            else ((struct sockaddr_in *)&items[i].addr)->sin_port = htons((uint16_t)target_port);
        } else if (items[i].res.addr_len > 0) {
            items[i].addr = items[i].res.addr;
            items[i].addr_len = items[i].res.addr_len;
            if (is_v6) ((struct sockaddr_in6 *)&items[i].addr)->sin6_port = htons((uint16_t)target_port);
            else ((struct sockaddr_in *)&items[i].addr)->sin_port = htons((uint16_t)target_port);
        } else {
            /* 预解析缺失时的安全兜底 */
            if (is_v6) {
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&items[i].addr;
                memset(sa6, 0, sizeof(*sa6));
                sa6->sin6_family = AF_INET6;
                sa6->sin6_port = htons((uint16_t)target_port);
                inet_pton(AF_INET6, items[i].res.ip, &sa6->sin6_addr);
                items[i].addr_len = sizeof(struct sockaddr_in6);
            } else {
                struct sockaddr_in *sa4 = (struct sockaddr_in *)&items[i].addr;
                memset(sa4, 0, sizeof(*sa4));
                sa4->sin_family = AF_INET;
                sa4->sin_port = htons((uint16_t)target_port);
                inet_pton(AF_INET, items[i].res.ip, &sa4->sin_addr);
                items[i].addr_len = sizeof(struct sockaddr_in);
            }
        }

        uint32_t scid = seed ^ (uint32_t)(i + 1);
        memcpy(pkt + 15, &scid, 4);

        items[i].send_time = now_ms();
        sendto(sfd, (const char *)pkt, sizeof(pkt), 0, (struct sockaddr *)&items[i].addr, items[i].addr_len);
    }

    size_t responded_count = 0;
    long deadline = start_time + timeout_ms;

    while (responded_count < count && now_ms() < deadline) {
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;

#ifdef _WIN32
        WSAPOLLFD pfds[2];
#else
        struct pollfd pfds[2];
#endif
        int npfd = 0;
        if (cfnat_socket_valid(fd4)) {
            pfds[npfd].fd = fd4;
            pfds[npfd].events = POLLIN;
            pfds[npfd].revents = 0;
            npfd++;
        }
        if (cfnat_socket_valid(fd6)) {
            pfds[npfd].fd = fd6;
            pfds[npfd].events = POLLIN;
            pfds[npfd].revents = 0;
            npfd++;
        }
        if (npfd == 0) break;

        int poll_timeout = left > 20 ? 20 : left;
        int pr =
#ifdef _WIN32
            WSAPoll(pfds, npfd, poll_timeout);
#else
            poll(pfds, npfd, poll_timeout);
#endif
        if (pr <= 0) continue;

        for (int p = 0; p < npfd; p++) {
            if (!(pfds[p].revents & (POLLIN | POLLERR))) continue;
            socket_t rfd = pfds[p].fd;

            while (1) {
                char resp[512];
                struct sockaddr_storage from;
#ifdef _WIN32
                int fromlen = (int)sizeof(from);
#else
                socklen_t fromlen = sizeof(from);
#endif
                ssize_t n = recvfrom(rfd, resp, sizeof(resp), 0, (struct sockaddr *)&from, &fromlen);
                if (n < 0) {
                    if (errno == EINTR) continue;
#ifdef _WIN32
                    int werr = WSAGetLastError();
                    if (werr == WSAECONNRESET || werr == WSAENETRESET ||
                        werr == WSAEHOSTUNREACH || werr == WSAENETUNREACH || werr == WSAECONNREFUSED) continue;
#else
                    /* 仅在网络瞬态错误时消费并继续读取队列后续报文，杜绝 EBADF/ENOTSOCK 等致命错误导致死循环 */
                    if (errno == ECONNREFUSED || errno == EHOSTUNREACH ||
                        errno == ENETUNREACH || errno == ECONNRESET) continue;
#endif
                    break;
                }
                if (n <= 0) break;
                if (n < 7 || ((uint8_t)resp[0] & 0x80) == 0) continue; /* 过滤非 QUIC 长包头噪声 */

                long r_now = now_ms();
                for (size_t i = 0; i < count; i++) {
                    if (items[i].responded) continue;
                    if (sockaddr_ip_equal(&from, &items[i].addr)) {
                        items[i].responded = 1;
                        int lat = (int)(r_now - items[i].send_time);
                        if (lat <= 0) lat = 1;
                        items[i].latency_ms = lat;
                        responded_count++;
                        debug_msg("%s QUIC 探针响应成功: %s 延迟 %d ms",
                                  carrier_display_name(rt ? rt->spec.mode : nullptr), items[i].res.ip, lat);
                        break;
                    }
                }
            }
        }

        if (responded_count >= needed_responses && (now_ms() - start_time) >= 250) {
            break;
        }
    }

    return responded_count;
}

/* P0-H3: 高性能多轮滑动 + 网段裂变衍生 QUIC 探针引擎 (真实验证，绝不降级假节点) */
static ResultList filter_udp_candidates_from_tcp(CarrierRuntime *rt, const Result *tcp_results, size_t count, size_t target_ipnum) {
    ResultList udp_res = {0};
    if (!tcp_results || count == 0 || target_ipnum == 0) return udp_res;

    size_t desired_count = target_ipnum;
    if (desired_count > 64) desired_count = 64;
    if (desired_count < 2) desired_count = 2;

    int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
    if (target_port <= 0) target_port = 443;
    int timeout_ms = (rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms;
    if (timeout_ms < 600) timeout_ms = 600;
    if (timeout_ms > 2000) timeout_ms = 2000;

    socket_t fd4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (cfnat_socket_valid(fd4)) {
#ifdef _WIN32
        BOOL bNewBehavior = FALSE;
        DWORD dwBytesReturned = 0;
        WSAIoctl(fd4, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), nullptr, 0, &dwBytesReturned, nullptr, nullptr);
#endif
        bind_socket_to_interface(fd4, AF_INET);
        set_nonblock(fd4, 1);
    }

    socket_t fd6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (cfnat_socket_valid(fd6)) {
#ifdef _WIN32
        BOOL bNewBehavior = FALSE;
        DWORD dwBytesReturned = 0;
        WSAIoctl(fd6, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), nullptr, 0, &dwBytesReturned, nullptr, nullptr);
#endif
        bind_socket_to_interface(fd6, AF_INET6);
        set_nonblock(fd6, 1);
    }

    if (cfnat_socket_invalid(fd4) && cfnat_socket_invalid(fd6)) {
        warn_msg("[%s] 创建 UDP 探针套接字失败", carrier_display_name(rt->spec.mode));
        return udp_res; // 严禁降级假节点
    }

    long total_start = now_ms();
    size_t batch_size = desired_count > 32 ? 32 : desired_count;
    if (batch_size < 16 && count >= 16) batch_size = 16;

    size_t offset = 0;
    int round_idx = 1;

    Result seeds[64];
    size_t seed_count = 0;

    QuicProbeItem probe_items[64];

    // 阶段一：滑动批次检验 TCP 候选池
    while (offset < count && udp_res.len < desired_count) {
        size_t cur_len = count - offset;
        if (cur_len > batch_size) cur_len = batch_size;

        log_msg("[%s] [H3筛选/第%d轮] 正在并发检验第 %zu~%zu 个 TCP 候选 IP 的 UDP/QUIC 响应...",
                carrier_display_name(rt->spec.mode), round_idx, offset + 1, offset + cur_len);

        memset(probe_items, 0, sizeof(probe_items));
        for (size_t i = 0; i < cur_len; i++) {
            probe_items[i].res = tcp_results[offset + i];
            probe_items[i].addr = probe_items[i].res.addr;
            probe_items[i].addr_len = probe_items[i].res.addr_len;
        }

        size_t needed = desired_count - udp_res.len;
        size_t responded = quic_batch_probe(rt, fd4, fd6, target_port, timeout_ms, probe_items, cur_len, needed);

        if (responded > 0) {
            for (size_t i = 0; i < cur_len; i++) {
                if (probe_items[i].responded) {
                    Result r = probe_items[i].res;
                    r.latency_ms = probe_items[i].latency_ms;
                    r.ewma_latency = probe_items[i].latency_ms;
                    r.loss_rate = 0;
                    r.success_count = 1;
                    r.probe_count = 1;
                    resultlist_add(&udp_res, &r);

                    if (seed_count < 64) {
                        seeds[seed_count++] = r;
                    }
                }
            }

            // 阶段二：网段裂变衍生 (Subnet Expansion)
            if (seed_count > 0 && udp_res.len < desired_count) {
                size_t deficit = desired_count - udp_res.len;
                if (deficit > 32) deficit = 32;

                QuicProbeItem derived_items[32];
                memset(derived_items, 0, sizeof(derived_items));
                size_t derived_count = 0;

                for (size_t d = 0; d < deficit; d++) {
                    const Result *base_seed = &seeds[d % seed_count];
                    char sibling_ip[MAX_IP_LEN] = {0};

                    for (int tries = 0; tries < 5; tries++) {
                        if (!sample_sibling_ip_from_subnet(base_seed->ip, sibling_ip, sizeof(sibling_ip))) break;
                        int dup = 0;
                        for (size_t u = 0; u < udp_res.len; u++) {
                            if (strcmp(udp_res.items[u].ip, sibling_ip) == 0) { dup = 1; break; }
                        }
                        if (!dup) {
                            for (size_t u = 0; u < derived_count; u++) {
                                if (strcmp(derived_items[u].res.ip, sibling_ip) == 0) { dup = 1; break; }
                            }
                        }
                        if (!dup) break;
                    }

                    if (sibling_ip[0]) {
                        derived_items[derived_count].res = *base_seed;
                        snprintf(derived_items[derived_count].res.ip, sizeof(derived_items[derived_count].res.ip), "%s", sibling_ip);
                        result_init_addr(&derived_items[derived_count].res);
                        derived_items[derived_count].addr = derived_items[derived_count].res.addr;
                        derived_items[derived_count].addr_len = derived_items[derived_count].res.addr_len;
                        derived_count++;
                    }
                }

                if (derived_count > 0) {
                    log_msg("[%s] [H3网段衍生] 基于已捕获的 %zu 个优质种子网段，裂变衍生 %zu 个同网段 IP 启动快速并发检验...",
                            carrier_display_name(rt->spec.mode), seed_count, derived_count);
                    quic_batch_probe(rt, fd4, fd6, target_port, timeout_ms, derived_items, derived_count, desired_count - udp_res.len);

                    for (size_t d = 0; d < derived_count; d++) {
                        if (derived_items[d].responded) {
                            Result r = derived_items[d].res;
                            r.latency_ms = derived_items[d].latency_ms;
                            r.ewma_latency = derived_items[d].latency_ms;
                            r.loss_rate = 0;
                            r.success_count = 1;
                            r.probe_count = 1;
                            resultlist_add(&udp_res, &r);
                        }
                    }
                }
            }

            if (udp_res.len >= desired_count) {
                break;
            }
        } else {
            debug_msg("[%s] 第 %zu~%zu 个 TCP 候选 IP 全无 UDP 回包（可能被丢包/阻断），向后滑动选取下一批...",
                      carrier_display_name(rt->spec.mode), offset + 1, offset + cur_len);
        }

        offset += cur_len;
        round_idx++;
    }

    if (cfnat_socket_valid(fd4)) close(fd4);
    if (cfnat_socket_valid(fd6)) close(fd6);

    if (udp_res.len > 0) {
        qsort(udp_res.items, udp_res.len, sizeof(Result), cmp_result);
        if (udp_res.len > desired_count) udp_res.len = desired_count;
        log_msg("[%s] UDP/QUIC 精筛完成: 捕获 %zu 个真实有效 H3 候选 (目标: %zu)，最优延迟: %d ms (%s)，总耗时: %ld ms",
                carrier_display_name(rt->spec.mode), udp_res.len, desired_count,
                udp_res.items[0].latency_ms, udp_res.items[0].ip,
                now_ms() - total_start);
    } else {
        warn_msg("[%s] 遍历全部 %zu 个 TCP 候选 IP 均无 UDP/QUIC 回包（当前运营商可能阻断境外 UDP 443），绝不使用假节点降级，保持真实 UDP 状态等待自愈重扫",
                 carrier_display_name(rt->spec.mode), count);
    }

    return udp_res;
}

static int carrier_try_use_candidate_caches(CarrierRuntime *rt) {
    if (!rt) return 0;
    int ips_type = rt->spec.prof.ips_type > 0 ? rt->spec.prof.ips_type : g_cfg.ips_type;
    const char *tcp_path = candidate_cache_file_for_profile(rt->spec.mode, ips_type);
    const char *udp_path = candidate_cache_file_for_profile_udp(rt->spec.mode, ips_type);

    ResultList cached_tcp = load_candidate_cache_for_profile(tcp_path, &rt->spec.prof);
    if (cached_tcp.len == 0) {
        return 0;
    }

    size_t check_count = cached_tcp.len < CACHE_QUICK_CHECK_COUNT ? cached_tcp.len : CACHE_QUICK_CHECK_COUNT;
    size_t first_good_tcp = (size_t)-1;
    for (size_t i = 0; i < check_count; i++) {
        if (carrier_health_check_ip(rt, cached_tcp.items[i].ip)) {
            first_good_tcp = i;
            break;
        }
    }
    if (first_good_tcp == (size_t)-1) {
        warn_msg("[%s] TCP 候选缓存健康检查未命中，将执行完整扫描", carrier_display_name(rt->spec.mode));
        free(cached_tcp.items);
        return 0;
    }

    rt->candidates.items = cached_tcp.items;
    rt->candidates.len = cached_tcp.len;
    carrier_set_current_candidate(rt, first_good_tcp);
    atomic_store(&rt->candidates.cache_valid, 1);

    // 尝试载入并验证 UDP 缓存
    ResultList cached_udp = load_candidate_cache_for_profile(udp_path, &rt->spec.prof);
    int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
    if (target_port <= 0) target_port = 443;
    int delay_ms = (rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms;
    if (delay_ms < 1000) delay_ms = 1000;

    size_t first_good_udp = (size_t)-1;
    if (cached_udp.len > 0) {
        size_t ucheck = cached_udp.len < CACHE_QUICK_CHECK_COUNT ? cached_udp.len : CACHE_QUICK_CHECK_COUNT;
        for (size_t i = 0; i < ucheck; i++) {
            int lat = 0;
            if (quic_probe_ip(cached_udp.items[i].ip, target_port, delay_ms, &lat)) {
                first_good_udp = i;
                break;
            }
        }
    }

    if (first_good_udp != (size_t)-1) {
        rt->udp_candidates.items = cached_udp.items;
        rt->udp_candidates.len = cached_udp.len;
        carrier_set_current_udp_candidate(rt, first_good_udp);
        atomic_store(&rt->udp_candidates.cache_valid, 1);
    } else {
        // UDP 缓存未命中或失效：从 TCP 缓存的前 2x 个现场精筛
        free(cached_udp.items);
        size_t target_ipnum = (size_t)(rt->spec.prof.ipnum > 0 ? rt->spec.prof.ipnum : g_cfg.ipnum);
        ResultList fresh_udp = filter_udp_candidates_from_tcp(rt, cached_tcp.items, cached_tcp.len, target_ipnum > 0 ? target_ipnum : 20);
        if (fresh_udp.len > 0) {
            rt->udp_candidates.items = fresh_udp.items;
            rt->udp_candidates.len = fresh_udp.len;
            carrier_set_current_udp_candidate(rt, 0);
            atomic_store(&rt->udp_candidates.cache_valid, 1);
            save_candidate_cache(udp_path, fresh_udp.items, fresh_udp.len);
        }
    }

    int tcp_lat = (rt->candidates.items && rt->candidates.current_index < rt->candidates.len) ?
                  rt->candidates.items[rt->candidates.current_index].latency_ms : 0;
    int udp_lat = (rt->udp_candidates.items && rt->udp_candidates.current_index < rt->udp_candidates.len) ?
                  rt->udp_candidates.items[rt->udp_candidates.current_index].latency_ms : 0;

    if (rt->udp_candidates.len > 0 && rt->udp_candidates.current_ip[0]) {
        log_msg("[%s] 命中双轨候选缓存快速启动:\n"
                "  ├─ [TCP/H2] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)\n"
                "  └─ [UDP/H3] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)",
                carrier_display_name(rt->spec.mode),
                rt->candidates.current_ip, tcp_lat, rt->candidates.len,
                rt->udp_candidates.current_ip, udp_lat, rt->udp_candidates.len);
    } else {
        log_msg("[%s] 命中双轨候选缓存快速启动:\n"
                "  ├─ [TCP/H2] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)\n"
                "  └─ [UDP/H3] 无可用节点 (0 个候选)",
                carrier_display_name(rt->spec.mode),
                rt->candidates.current_ip, tcp_lat, rt->candidates.len);
    }
    if (g_cfg.log_level >= LOG_DEBUG) {
        debug_msg("[TCP/H2] [%s] 已载入缓存的候选 IP 列表 (共 %zu 个):", carrier_display_name(rt->spec.mode), rt->candidates.len);
        print_results_table(rt->candidates.items, rt->candidates.len, 0);
        if (rt->udp_candidates.len > 0) {
            debug_msg("[UDP/H3] [%s] 已载入缓存的候选 IP 列表 (共 %zu 个):", carrier_display_name(rt->spec.mode), rt->udp_candidates.len);
            print_results_table(rt->udp_candidates.items, rt->udp_candidates.len, 0);
        }
    }
    return 1;
}

CFNAT_UNUSED static int carrier_try_use_candidate_cache(CarrierRuntime *rt) {
    return carrier_try_use_candidate_caches(rt);
}

static void explain_selected_result(const Result *best) {
    if (!best) return;
    if (g_cfg.log_level < LOG_DEBUG) return;
    printf("结果解释: 选择 %s，因为延迟 %d ms，丢包 %d%%，综合分 %d。\n", best->ip, best->latency_ms, best->loss_rate, score_result(best));
}

static ResultList scan_ips(StringList *ips, CidrList *cidrs, Config *cfg, BaiduProxyPool *proxy_pool) {
    ResultList rl = {0};
    uint64_t total_ips = cidrs ? cidrlist_total(cidrs) : (ips ? ips->len : 0);
    int threads = cfg->task;
    if ((uint64_t)threads > total_ips) threads = (int)total_ips;
    if (threads <= 0 || total_ips == 0) {
        return rl;
    }
    pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
    if (!tids) {
        return rl;
    }
    char probe_host[MAX_DOMAIN_LEN];
    char probe_path[MAX_PATH_LEN];
    parse_domain_and_path(cfg->domain, probe_host, sizeof(probe_host), probe_path, sizeof(probe_path));
    int probe_port = cfg->http_port > 0 ? cfg->http_port : 80;
    int hdr_timeout = cfg->delay_ms > 0 ? cfg->delay_ms * 2 : 1000;
    if (hdr_timeout < 500) hdr_timeout = 500;
    if (hdr_timeout > 1500) hdr_timeout = 1500;

    ScanCtx ctx = {
        .ips = ips ? ips->items : nullptr,
        .cidrs = cidrs,
        .total = (size_t)total_ips,
        .results = &rl,
        .cfg = cfg,
        .proxy_pool = proxy_pool,
        .scan_start_ms = now_ms(),
        .probe_port = probe_port,
        .hdr_timeout = hdr_timeout
    };
    ctx.head_req_len = snprintf(ctx.head_req, sizeof(ctx.head_req),
                                "HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n",
                                probe_path, probe_host);
    ctx.get_req_len = snprintf(ctx.get_req, sizeof(ctx.get_req),
                               "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
                               probe_path, probe_host);
    pthread_mutex_init(&ctx.results_mu, nullptr);
    atomic_init(&ctx.index, 0);
    atomic_init(&ctx.completed, 0);
    atomic_init(&ctx.connect_fail, 0);
    atomic_init(&ctx.header_fail, 0);
    atomic_init(&ctx.cfray_miss, 0);
    atomic_init(&ctx.colo_skip, 0);
    atomic_init(&ctx.http_code_mismatch, 0);
    log_msg("开始扫描候选 IP: %llu 个，线程: %d，单 IP 探测次数: %d，超时: %d ms",
            (unsigned long long)total_ips, threads, cfg->num > 0 ? cfg->num : 1, cfg->delay_ms);
    pthread_attr_t scan_attr;
    pthread_attr_init(&scan_attr);
    size_t scan_stack_sz = 512 * 1024;
#if defined(PTHREAD_STACK_MIN)
    if (scan_stack_sz < (size_t)PTHREAD_STACK_MIN) scan_stack_sz = (size_t)PTHREAD_STACK_MIN;
#endif
    pthread_attr_setstacksize(&scan_attr, scan_stack_sz);
    int created = 0;
    for (int i = 0; i < threads; i++) {
        if (pthread_create(&tids[i], &scan_attr, scan_worker, &ctx) != 0) break;
        created++;
    }
    pthread_attr_destroy(&scan_attr);
    if (created < threads) {
        debug_msg("系统线程限制或资源受限，实际启动 %d/%d 个并发扫描线程", created, threads);
    }
    for (int i = 0; i < created; i++) pthread_join(tids[i], nullptr);
    free(tids);
    pthread_mutex_destroy(&ctx.results_mu);
    if (rl.items && rl.len > 1) {
        qsort(rl.items, rl.len, sizeof(Result), cmp_result);
    }
    if (rl.len > (size_t)cfg->ipnum) rl.len = (size_t)cfg->ipnum;
    log_msg("扫描完成: 有效候选 %zu 个，耗时 %ld 秒", rl.len, (now_ms() - ctx.scan_start_ms) / 1000);
    if (cfg->log_level >= LOG_DEBUG) {
        print_results_table(rl.items, rl.len, (now_ms() - ctx.scan_start_ms) / 1000);
    }
    if (rl.len == 0 || cfg->log_level >= LOG_DEBUG) {
        log_msg("扫描统计: 连接失败 %zu，读取响应失败 %zu，缺少 CF-RAY %zu，数据中心过滤 %zu，状态码不匹配 %zu",
                atomic_load(&ctx.connect_fail),
                atomic_load(&ctx.header_fail),
                atomic_load(&ctx.cfray_miss),
                atomic_load(&ctx.colo_skip),
                atomic_load(&ctx.http_code_mismatch));
        if (rl.len == 0 && atomic_load(&ctx.cfray_miss) > 0 && cfg->colo[0]) {
            warn_msg("已连接到部分 IP，但响应中没有 CF-RAY 或不匹配 -colo；可先去掉 -colo 验证网络链路");
        }
    }
    return rl;
}

CFNAT_NODISCARD static int http_probe(socket_t fd, int timeout_ms) {
    // 发送 HTTP GET 请求探测数据通路是否正常
    const char *req = "GET / HTTP/1.0\r\nHost: cloudflaremirrors.com\r\nConnection: close\r\n\r\n";
    size_t reqlen = strlen(req);
    long deadline = now_ms() + timeout_ms;
    size_t sent = 0;
    while (sent < reqlen && now_ms() < deadline) {
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;
        int rc = cfnat_poll_single(fd, 2, left);
        if (rc <= 0) break;
        ssize_t n = send(fd, req + sent, reqlen - sent, 0);
        if (n <= 0) break;
        sent += (size_t)n;
    }
    if (sent < reqlen) return 0;
    // 读取响应头，确认收到 HTTP 响应
    char buf[256];
    size_t used = 0;
    while (used < sizeof(buf) - 1 && now_ms() < deadline) {
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;
        int rc = cfnat_poll_single(fd, 1, left);
        if (rc <= 0) break;
        ssize_t n = recv(fd, buf + used, sizeof(buf) - used - 1, 0);
        if (n <= 0) break;
        used += (size_t)n;
        buf[used] = 0;
        if (strstr(buf, "HTTP/")) return 1;  // 收到 HTTP 响应头表示数据通路正常
    }
    return 0;
}

/* P0-EWMA: 增强健康检查，更新候选池中对应 IP 的 EWMA 和连续失败计数 */
CFNAT_NODISCARD static int health_check_ip(const char *ip, BaiduProxyPool *proxy_pool) {
    int latency = 0;
    int target_port = g_cfg.port > 0 ? g_cfg.port : 443;
    socket_t fd = dial_target_with_proxy(ip, target_port, g_cfg.delay_ms, proxy_pool, &latency);
    if (cfnat_socket_invalid(fd)) {
        return 0;
    }
    /* 仅当端口为明确的 HTTP 明文端口时使用 http_probe，TLS 端口统一使用 tls_probe */
    int is_cleartext = (target_port == 80 || target_port == 8080 || target_port == 8880 ||
                        target_port == 2052 || target_port == 2082 || target_port == 2086 || target_port == 2095);
    int ok = is_cleartext ? http_probe(fd, g_cfg.delay_ms) : tls_probe(fd, g_cfg.delay_ms);
    close(fd);
    return ok ? 1 : 0;
}


static void close_pair(socket_t a, socket_t b) {
    if (cfnat_socket_valid(a)) shutdown(a, SHUT_RDWR);
    if (cfnat_socket_valid(b)) shutdown(b, SHUT_RDWR);
}

/* P1-2: 带超时的 recv（支持 flags，如 MSG_PEEK），突破 FD_SETSIZE 限制 */
static ssize_t recv_flags_timeout(socket_t fd, void *buf, size_t len, int timeout_ms, int flags) {
    if (timeout_ms > 0) {
        int rc = cfnat_poll_single(fd, 1, timeout_ms);
        if (rc <= 0) {
            if (rc == 0) errno = ETIMEDOUT;
            return -1;
        }
    }
    return recv(fd, buf, len, flags);
}

static ssize_t recv_timeout(socket_t fd, void *buf, size_t len, int timeout_ms) {
    return recv_flags_timeout(fd, buf, len, timeout_ms, 0);
}

#if defined(__linux__) && !defined(__ANDROID__)
/* P1-4: Linux 零拷贝转发，使用 splice() 避免用户态内存拷贝 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
static void *pipe_worker_fallback(PipeCtx *pc) {
    char buf[COPY_BUF_SIZE];
    while (atomic_load(&g_running)) {
        /* 内核 SO_RCVTIMEO (300s) 超时保护，消除额外 poll 调用 */
        ssize_t n = recv(pc->from, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR && atomic_load(&g_running)) continue;
            break;
        }
        char *p = buf;
        ssize_t left = n;
        while (left > 0 && atomic_load(&g_running)) {
            ssize_t w = send(pc->to, p, (size_t)left, 0);
            if (w <= 0) {
                if (w < 0 && errno == EINTR && atomic_load(&g_running)) continue;
                goto err;
            }
            pc->bytes += (uint64_t)w;
            p += w;
            left -= w;
        }
    }
    /* 正常 EOF: 半关闭对端写方向，允许反向继续完整传输响应 */
    shutdown(pc->to, SHUT_WR);
    return nullptr;
err:
    close_pair(pc->from, pc->to);
    return nullptr;
}

static void *pipe_worker(void *arg) {
    PipeCtx *pc = (PipeCtx *)arg;
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return pipe_worker_fallback(pc);
    }
    while (atomic_load(&g_running)) {
        /* 去除 SPLICE_F_MORE，彻底杜绝尾包延迟引入的 40~200ms 卡顿 */
        ssize_t n = splice(pc->from, nullptr, pipefd[1], nullptr, 65536, SPLICE_F_MOVE);
        if (n < 0) {
            if (errno == EINTR && atomic_load(&g_running)) continue;
            if (errno == EINVAL || errno == ENOSYS) {
                close(pipefd[0]);
                close(pipefd[1]);
                return pipe_worker_fallback(pc);
            }
            goto err;
        }
        if (n == 0) break; /* 读到 EOF */
        while (n > 0 && atomic_load(&g_running)) {
            ssize_t w = splice(pipefd[0], nullptr, pc->to, nullptr, (size_t)n, SPLICE_F_MOVE);
            if (w < 0) {
                if (errno == EINTR && atomic_load(&g_running)) continue;
                goto err;
            }
            if (w == 0) goto err;
            pc->bytes += (uint64_t)w;
            n -= w;
        }
    }
    close(pipefd[0]);
    close(pipefd[1]);
    /* 读到 EOF 正常半关闭：通知下游无更多数据，保留逆向接收通道 */
    shutdown(pc->to, SHUT_WR);
    return nullptr;

err:
    close(pipefd[0]);
    close(pipefd[1]);
    close_pair(pc->from, pc->to);
    return nullptr;
}
#else
/* 非 Linux 平台使用普通 recv/send 转发 */
static void *pipe_worker(void *arg) {
    PipeCtx *pc = (PipeCtx *)arg;
    char buf[COPY_BUF_SIZE];
    while (atomic_load(&g_running)) {
        /* 内核 SO_RCVTIMEO (300s) 超时保护，消除额外 poll 调用 */
        ssize_t n = recv(pc->from, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR && atomic_load(&g_running)) continue;
            break;
        }
        char *p = buf;
        ssize_t left = n;
        while (left > 0 && atomic_load(&g_running)) {
            ssize_t w = send(pc->to, p, (size_t)left, 0);
            if (w <= 0) {
                if (w < 0 && errno == EINTR && atomic_load(&g_running)) continue;
                goto err;
            }
            pc->bytes += (uint64_t)w;
            p += w;
            left -= w;
        }
    }
    /* 正常半关闭 */
    shutdown(pc->to, SHUT_WR);
    return nullptr;
err:
    close_pair(pc->from, pc->to);
    return nullptr;
}
#endif

static int create_small_thread(pthread_t *tid, void *(*fn)(void *), void *arg) {
    if (tid) *tid = 0;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    size_t stack_sz = 256 * 1024;
#if defined(PTHREAD_STACK_MIN)
    if (stack_sz < (size_t)PTHREAD_STACK_MIN) stack_sz = (size_t)PTHREAD_STACK_MIN;
#endif
    pthread_attr_setstacksize(&attr, stack_sz);
    int rc = pthread_create(tid, &attr, fn, arg);
    pthread_attr_destroy(&attr);
    if (rc != 0 && tid) {
        *tid = 0;
    }
    return rc;
}

#ifdef _WIN32
#ifndef SIO_KEEPALIVE_VALS
#define SIO_KEEPALIVE_VALS _WSAIOW(IOC_VENDOR, 4)
struct tcp_keepalive {
    u_long onoff;
    u_long keepalivetime;
    u_long keepaliveinterval;
};
#endif
#endif

static void set_socket_timeouts_and_keepalive(socket_t s, int timeout_sec) {
    if (cfnat_socket_invalid(s)) return;
#ifdef _WIN32
    DWORD tv = (DWORD)(timeout_sec * 1000);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
    BOOL keepalive = TRUE;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&keepalive, sizeof(keepalive));
    struct tcp_keepalive ka = {
        .onoff = 1,
        .keepalivetime = 45000,     /* 45s 对齐 Xray/Chrome H2 空闲保活周期 */
        .keepaliveinterval = 10000  /* 10s 重试间隔 */
    };
    DWORD dwBytes = 0;
    WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &dwBytes, nullptr, nullptr);
#else
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int keepalive = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
#ifdef TCP_KEEPIDLE
    int keepidle = 45; /* 45s 对齐 Xray/Chrome H2 空闲保活周期 */
    setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
#elif defined(TCP_KEEPALIVE)
    int keepidle = 45;
    setsockopt(s, IPPROTO_TCP, TCP_KEEPALIVE, &keepidle, sizeof(keepidle));
#endif
#ifdef TCP_KEEPINTVL
    int keepintvl = 10;
    setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
#endif
#ifdef TCP_KEEPCNT
    int keepcnt = 3;
    setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
#endif
#endif
}

static int relay_bidirectional(socket_t c, socket_t u) {
    /* 为双向套接字设置 300 秒空闲超时及 KeepAlive，防止 Linux splice 及非阻塞管道永久卡死 */
    set_socket_timeouts_and_keepalive(c, 300);
    set_socket_timeouts_and_keepalive(u, 300);
    pthread_t t1 = 0;
    PipeCtx a = { .from = c, .to = u, .bytes = 0 };
    PipeCtx b = { .from = u, .to = c, .bytes = 0 };
    int rc1 = create_small_thread(&t1, pipe_worker, &a);
    if (rc1 != 0) {
        close_pair(c, u);
        return -1;
    }
    /* 当前 connection_thread 线程直接执行反向转发，免除第 2 个子线程的 clone/mmap 与调度开销 */
    pipe_worker(&b);
    pthread_join(t1, nullptr);
    return (b.bytes > 0) ? 1 : 0;
}

static void *connection_thread(void *arg) {
    ConnCtx *cc = (ConnCtx *)arg;
    socket_t client = cc->client_fd;
    socket_t upstream = INVALID_SOCKET;
    long conn_start_ms = now_ms();
    int conn_ok = 0;
    unsigned char first = 0;
    /* P1-2: 首字节使用 MSG_PEEK 嗅探协议类型，非 TLS 请求不消耗首字节，避免 1 字节拆包 */
    ssize_t n = recv_flags_timeout(client, (char *)&first, 1, 60000, MSG_PEEK);
    if (n <= 0) goto out;
    int is_tls = (first == 0x16);
    int target_port = is_tls ? cc->tls_port : cc->http_port;
    unsigned char client_hello[4096];
    size_t client_hello_len = 0;
    char sni_host[MAX_DOMAIN_LEN] = {0};
    if (is_tls) {
        recv(client, (char *)&first, 1, 0); /* 确认为 TLS，提取消耗首字节 0x16 并读取完整 ClientHello */
        client_hello_len = read_tls_client_hello(client, first, client_hello, sizeof(client_hello), cc->delay_ms);
        parse_tls_sni(client_hello, client_hello_len, sni_host, sizeof(sni_host));
    }
    const char *carrier_name = cc->runtime ? carrier_display_name(cc->runtime->spec.mode) : "-";
    conn_msg("[TCP/H2] #%llu [%s] 识别客户端协议: %s，转发到 IP: %s 端口: %d%s%s",
             cc->conn_id, carrier_name,
             is_tls ? "TLS" : "非TLS", cc->ip, target_port,
             sni_host[0] ? "，SNI: " : "", sni_host[0] ? sni_host : "");
    int best = 0;

    if (cc->use_mixed) {
        // 混合模式：先直连，不行再试百度前置
        for (int i = 0; i < cc->num; i++) {
            int lat = 0;
            socket_t fd = dial_target_with_proxy_sa(cc->ip, &cc->ip_addr, cc->ip_addr_len, target_port, cc->delay_ms, nullptr, &lat);
            if (cfnat_socket_valid(fd)) {
                upstream = fd;
                best = lat;
                conn_msg("[TCP/H2] #%llu [%s] 选择连接: %s:%d (延迟 %d ms, 直连)", cc->conn_id, carrier_name, cc->ip, target_port, best);
                break;
            }
        }
        if (cfnat_socket_invalid(upstream) && cc->proxy_pool) {
            for (int i = 0; i < cc->num; i++) {
                int lat = 0;
                socket_t fd = dial_target_with_proxy_sa(cc->ip, &cc->ip_addr, cc->ip_addr_len, target_port, cc->delay_ms, cc->proxy_pool, &lat);
                if (cfnat_socket_valid(fd)) {
                    upstream = fd;
                    best = lat;
                    conn_msg("[TCP/H2] #%llu [%s] 选择连接: %s:%d (延迟 %d ms, 百度前置)", cc->conn_id, carrier_name, cc->ip, target_port, best);
                    break;
                }
            }
        }
    } else {
        // 普通模式：首轮试当前 IP，若失败则立即顺位尝试候选池中的备用 IP，不原地死磕
        for (int i = 0; i < cc->num; i++) {
            char try_ip[MAX_IP_LEN];
            struct sockaddr_storage try_sa = {0};
            socklen_t try_salen = 0;
            size_t try_idx = 0;
            if (i == 0 || !cc->runtime || !atomic_load(&g_running)) {
                snprintf(try_ip, sizeof(try_ip), "%s", cc->ip);
                try_sa = cc->ip_addr;
                try_salen = cc->ip_addr_len;
            } else {
                pthread_mutex_lock(&cc->runtime->candidates.mu);
                size_t len = cc->runtime->candidates.len;
                if (len > 1) {
                    try_idx = (cc->runtime->candidates.current_index + (size_t)i) % len;
                    snprintf(try_ip, sizeof(try_ip), "%s", cc->runtime->candidates.items[try_idx].ip);
                    try_sa = cc->runtime->candidates.items[try_idx].addr;
                    try_salen = cc->runtime->candidates.items[try_idx].addr_len;
                } else {
                    snprintf(try_ip, sizeof(try_ip), "%s", cc->ip);
                    try_sa = cc->ip_addr;
                    try_salen = cc->ip_addr_len;
                }
                pthread_mutex_unlock(&cc->runtime->candidates.mu);
            }
            int lat = 0;
            socket_t fd = dial_target_with_proxy_sa(try_ip, &try_sa, try_salen, target_port, cc->delay_ms, cc->proxy_pool, &lat);
            if (cfnat_socket_valid(fd)) {
                upstream = fd;
                best = lat;
                if (i > 0 && cc->runtime && atomic_load(&g_running) && strcmp(try_ip, cc->ip) != 0) {
                    snprintf(cc->ip, sizeof(cc->ip), "%s", try_ip);
                    cc->ip_addr = try_sa;
                    cc->ip_addr_len = try_salen;
                    carrier_set_current_candidate(cc->runtime, try_idx);
                    atomic_store(&cc->runtime->candidates.cache_valid, 1);
                    log_msg("[TCP/H2] [%s] 首选节点握手超时，已实时无缝切换至备用 IP: %s (延迟 %d ms)",
                            carrier_name, try_ip, best);
                }
                conn_msg("[TCP/H2] #%llu [%s] 选择连接: %s:%d (延迟 %d ms)", cc->conn_id, carrier_name, cc->ip, target_port, best);
                break;
            }
        }
    }

    if (cfnat_socket_invalid(upstream)) {
        // 连接失败时尝试 SNI 级别的故障转移
        if (sni_host[0]) {
            char sni_ip[MAX_IP_LEN];
            if (carrier_choose_ip_for_sni(cc->runtime, sni_host, sni_ip, sizeof(sni_ip))) {
                snprintf(cc->ip, sizeof(cc->ip), "%s", sni_ip);
                conn_msg("[TCP/H2] #%llu [%s] SNI 故障转移: 为 %s 切换到备用 IP %s", cc->conn_id, carrier_name, sni_host, sni_ip);
                // 使用新 IP 重试一次
                int lat = 0;
                socket_t fd = dial_target_with_proxy(cc->ip, target_port, cc->delay_ms, cc->proxy_pool, &lat);
                if (cfnat_socket_valid(fd)) {
                    upstream = fd;
                    best = lat;
                    conn_msg("[TCP/H2] #%llu [%s] SNI 故障转移成功: %s:%d (延迟 %d ms)", cc->conn_id, carrier_name, cc->ip, target_port, best);
                }
            }
        }
        if (cfnat_socket_invalid(upstream)) {
            debug_msg("[TCP/H2] #%llu [%s] 未找到符合延迟要求的连接，关闭客户端连接", cc->conn_id, carrier_name);
            goto out;
        }
    }
    if (is_tls && client_hello_len > 0) {
        if (!send_all_timeout(upstream, client_hello, client_hello_len, cc->delay_ms > 0 ? cc->delay_ms : 1000)) {
            debug_msg("[TCP/H2] #%llu [%s] 转发客户端 ClientHello 失败，关闭连接", cc->conn_id, carrier_name);
            goto out;
        }
    }
    tune_socket_buffers(client, 0);
    tune_socket_buffers(upstream, 0);
    set_tcp_nodelay(client);
    set_tcp_nodelay(upstream);
    int had_data = relay_bidirectional(client, upstream);
    if (had_data > 0 || (now_ms() - conn_start_ms) >= 3000) {
        conn_ok = 1;
    }
out:
    if (cfnat_socket_valid(upstream)) close(upstream);
    if (cfnat_socket_valid(client)) close(client);
    if (atomic_load(&g_running) && cc->runtime && cc->ip[0]) {
        if (conn_ok) {
            carrier_note_connection_success(cc->runtime, cc->ip);
        } else {
            carrier_note_connection_failed(cc->runtime, cc->ip);
        }
    }
    int active = atomic_fetch_sub(&g_active_tcp_conns, 1) - 1;
    long lifetime_s = (now_ms() - conn_start_ms) / 1000;
    conn_msg("[TCP/H2] #%llu [%s] 客户端连接关闭 (存活 %lds, 当前活跃: %d)",
             cc->conn_id, carrier_name, lifetime_s > 0 ? lifetime_s : 0, active);
    free(cc);
    return nullptr;
}

/* P1-HC: 健康检查级别 */
#if CFNAT_IS_C23
typedef enum : uint8_t {
    HC_LIGHT = 0,   /* 仅 TCP 握手 */
    HC_MEDIUM,      /* TCP + 首字节响应 */
    HC_FULL         /* TCP + HTTP 完整探测 */
} HealthCheckLevel;
#else
typedef enum {
    HC_LIGHT = 0,   /* 仅 TCP 握手 */
    HC_MEDIUM,      /* TCP + 首字节响应 */
    HC_FULL         /* TCP + HTTP 完整探测 */
} HealthCheckLevel;
#endif

static int carrier_probe_and_check(CarrierRuntime *rt, socket_t fd, int timeout_ms) {
    int target_port = (rt && rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
    /* 仅当端口为明确的 HTTP 明文端口时使用 http_probe，TLS 端口统一使用 tls_probe */
    int is_cleartext = (target_port == 80 || target_port == 8080 || target_port == 8880 ||
                        target_port == 2052 || target_port == 2082 || target_port == 2086 || target_port == 2095);
    int ok = is_cleartext ? http_probe(fd, timeout_ms) : tls_probe(fd, timeout_ms);
    close(fd);
    return ok;
}

/* P1-HC: 增强 carrier 健康检查，支持级别参数，无锁采集延迟 */
CFNAT_NODISCARD static int carrier_health_check_ip_level(CarrierRuntime *rt, const char *ip, HealthCheckLevel level, int *out_lat) {
    if (!rt || !ip || !*ip) return 0;
    int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
    int timeout_ms = (rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms;
    /* HC_MEDIUM 使用更紧凑的 800ms 超时执行轻量首字节响应探测，HC_FULL 执行完整周期探测 */
    int probe_timeout = (level == HC_MEDIUM) ? (timeout_ms > 800 ? 800 : timeout_ms) : timeout_ms;

    // 混合模式：先试直连，不行再试百度代理
    if (rt->spec.use_baidu_proxy == 2) {
        int latency = 0;
        socket_t fd = dial_target_with_proxy(ip, target_port, timeout_ms, nullptr, &latency);
        if (cfnat_socket_valid(fd)) {
            if (level == HC_LIGHT) {
                close(fd);
                if (out_lat) *out_lat = latency;
                return 1;
            }
            if (carrier_probe_and_check(rt, fd, probe_timeout)) {
                if (out_lat) *out_lat = latency;
                return 1;
            }
        }
        if (rt->proxy_pool && rt->proxy_pool->len > 0) {
            fd = dial_target_with_proxy(ip, target_port, timeout_ms, rt->proxy_pool, &latency);
            if (cfnat_socket_valid(fd)) {
                if (level == HC_LIGHT) {
                    close(fd);
                    if (out_lat) *out_lat = latency;
                    return 1;
                }
                if (carrier_probe_and_check(rt, fd, probe_timeout)) {
                    if (out_lat) *out_lat = latency;
                    return 1;
                }
            }
        }
        return 0;
    }
    // 普通模式
    int latency = 0;
    socket_t fd = dial_target_with_proxy(ip, target_port, timeout_ms, rt->proxy_pool, &latency);
    if (cfnat_socket_invalid(fd)) {
        return 0;
    }
    if (level == HC_LIGHT) {
        close(fd);
        if (out_lat) *out_lat = latency;
        return 1;
    }
    if (carrier_probe_and_check(rt, fd, probe_timeout)) {
        if (out_lat) *out_lat = latency;
        return 1;
    }
    return 0;
}

CFNAT_NODISCARD static inline int carrier_health_check_ip(CarrierRuntime *rt, const char *ip) {
    return carrier_health_check_ip_level(rt, ip, HC_FULL, nullptr);
}

static int carrier_tls_sni_check_ip(CarrierRuntime *rt, const char *ip, const char *sni_host) {
    if (!rt || !ip || !*ip || !sni_host || !*sni_host) return 0;
    int latency = 0;
    socket_t fd = INVALID_SOCKET;
    int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
    int timeout_ms = (rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms;
    if (rt->spec.use_baidu_proxy == 2) {
        fd = dial_target_with_proxy(ip, target_port, timeout_ms, nullptr, &latency);
        if (cfnat_socket_valid(fd)) {
            int ok = tls_probe_host(fd, timeout_ms, sni_host);
            close(fd);
            if (ok) return 1;
        }
        if (rt->proxy_pool && rt->proxy_pool->len > 0) {
            fd = dial_target_with_proxy(ip, target_port, timeout_ms, rt->proxy_pool, &latency);
            if (cfnat_socket_valid(fd)) {
                int ok = tls_probe_host(fd, timeout_ms, sni_host);
                close(fd);
                if (ok) return 1;
            }
        }
        return 0;
    }
    fd = dial_target_with_proxy(ip, target_port, timeout_ms, rt->proxy_pool, &latency);
    if (cfnat_socket_invalid(fd)) return 0;
    int ok = tls_probe_host(fd, timeout_ms, sni_host);
    close(fd);
    return ok;
}

static int carrier_choose_ip_for_sni(CarrierRuntime *rt, const char *sni_host, char *out, size_t sz) {
    if (!rt || !sni_host || !*sni_host || !out || sz == 0) return 0;
    out[0] = '\0';
    char check_ips[32][MAX_IP_LEN];
    size_t count = 0;
    char current[MAX_IP_LEN] = {0};
    pthread_mutex_lock(&rt->candidates.mu);
    count = rt->candidates.len > 32 ? 32 : rt->candidates.len;
    for (size_t i = 0; i < count; i++) {
        snprintf(check_ips[i], sizeof(check_ips[i]), "%s", rt->candidates.items[i].ip);
    }
    snprintf(current, sizeof(current), "%s", rt->candidates.current_ip);
    pthread_mutex_unlock(&rt->candidates.mu);

    if (current[0] && carrier_tls_sni_check_ip(rt, current, sni_host)) {
        snprintf(out, sz, "%s", current);
        atomic_store(&rt->candidates.cache_valid, 1);
        return 1;
    }
    atomic_store(&rt->candidates.cache_valid, 0);
    for (size_t i = 0; i < count; i++) {
        if (current[0] && strcmp(check_ips[i], current) == 0) continue;
        if (carrier_tls_sni_check_ip(rt, check_ips[i], sni_host)) {
            snprintf(out, sz, "%s", check_ips[i]);
            carrier_set_current_candidate(rt, i);
            atomic_store(&rt->candidates.cache_valid, 1);
            log_msg("[TCP/H2] [%s] 为 SNI %s 切换到可用 IP: %s", carrier_display_name(rt->spec.mode), sni_host, check_ips[i]);
            return 1;
        }
    }
    return 0;
}

static int carrier_set_current_candidate(CarrierRuntime *rt, size_t idx) {
    if (!rt) return 0;
    pthread_mutex_lock(&rt->candidates.mu);
    if (idx < rt->candidates.len) {
        snprintf(rt->candidates.current_ip, sizeof(rt->candidates.current_ip), "%s", rt->candidates.items[idx].ip);
        rt->candidates.current_addr = rt->candidates.items[idx].addr;
        rt->candidates.current_addr_len = rt->candidates.items[idx].addr_len;
        rt->candidates.current_index = idx;
        atomic_store_explicit(&rt->candidates.fast_fail_count, 0, memory_order_relaxed);
        pthread_mutex_unlock(&rt->candidates.mu);
        return 1;
    }
    pthread_mutex_unlock(&rt->candidates.mu);
    return 0;
}

static void carrier_get_current_ip(CarrierRuntime *rt, char *out, size_t sz) {
    if (!rt || !out || sz == 0) return;
    pthread_mutex_lock(&rt->candidates.mu);
    snprintf(out, sz, "%s", rt->candidates.current_ip);
    pthread_mutex_unlock(&rt->candidates.mu);
}

static int carrier_choose_ip_fast(CarrierRuntime *rt, char *out, size_t sz, struct sockaddr_storage *out_sa, socklen_t *out_salen) {
    if (!rt || !out || sz == 0) return 0;
    out[0] = '\0';
    if (!atomic_load_explicit(&rt->candidates.cache_valid, memory_order_acquire)) return 0;
    pthread_mutex_lock(&rt->candidates.mu);
    if (rt->candidates.current_ip[0]) {
        size_t n = strlen(rt->candidates.current_ip);
        if (n >= sz) n = sz - 1;
        memcpy(out, rt->candidates.current_ip, n);
        out[n] = '\0';
        if (out_sa && out_salen) {
            *out_sa = rt->candidates.current_addr;
            *out_salen = rt->candidates.current_addr_len;
        }
    }
    pthread_mutex_unlock(&rt->candidates.mu);
    return out[0] ? 1 : 0;
}

static int carrier_select_valid_ip(CarrierRuntime *rt) {
    if (!rt) return 0;
    char check_ips[32][MAX_IP_LEN];
    size_t check_indices[32];
    size_t count = 0;

    pthread_mutex_lock(&rt->candidates.mu);
    for (size_t i = 0; i < rt->candidates.len && count < 32; i++) {
        snprintf(check_ips[count], sizeof(check_ips[count]), "%s", rt->candidates.items[i].ip);
        check_indices[count] = i;
        count++;
    }
    pthread_mutex_unlock(&rt->candidates.mu);

    for (size_t i = 0; i < count; i++) {
        int lat = 0;
        if (carrier_health_check_ip_level(rt, check_ips[i], HC_FULL, &lat)) {
            carrier_set_current_candidate(rt, check_indices[i]);
            atomic_store(&rt->candidates.cache_valid, 1);  /* P0-1: 选中有效 IP */
            log_msg("[TCP/H2] [%s] 可用 IP: %s (延迟: %d ms)", carrier_display_name(rt->spec.mode), check_ips[i], lat);
            return 1;
        }
    }
    return 0;
}

static int carrier_switch_next_ip(CarrierRuntime *rt) {
    if (!rt) return 0;
    char check_ips[32][MAX_IP_LEN];
    size_t check_indices[32];
    size_t count = 0;
    size_t total_len = 0;

    pthread_mutex_lock(&rt->candidates.mu);
    size_t len = rt->candidates.len;
    size_t start = rt->candidates.current_index + 1;
    total_len = len;
    if (len > 0) {
        size_t threshold = (size_t)(len * 0.70);
        if (threshold < 1) threshold = 1;
        if (start < threshold) {
            for (size_t i = start; i < threshold && i < len && count < 32; i++) {
                snprintf(check_ips[count], sizeof(check_ips[count]), "%s", rt->candidates.items[i].ip);
                check_indices[count] = i;
                count++;
            }
        }
    }
    pthread_mutex_unlock(&rt->candidates.mu);

    if (total_len == 0 || count == 0) return 0;

    for (size_t i = 0; i < count; i++) {
        int lat = 0;
        if (carrier_health_check_ip_level(rt, check_ips[i], HC_FULL, &lat)) {
            carrier_set_current_candidate(rt, check_indices[i]);
            atomic_store(&rt->candidates.cache_valid, 1);  /* P0-1: 新 IP 有效 */
            log_msg("[TCP/H2] [%s] 顺位切换到下一个最优 IP: %s (候选索引: %zu/%zu, 延迟 %d ms)",
                    carrier_display_name(rt->spec.mode), check_ips[i], check_indices[i], total_len, lat);
            return 1;
        }
    }
    return 0;
}

static void carrier_get_current_udp_ip_sa(CarrierRuntime *rt, char *out, size_t sz, struct sockaddr_storage *out_sa, socklen_t *out_salen) {
    if (!rt || !out || sz == 0) return;
    out[0] = '\0';
    pthread_mutex_lock(&rt->udp_candidates.mu);
    if (rt->udp_candidates.current_ip[0]) {
        snprintf(out, sz, "%s", rt->udp_candidates.current_ip);
        if (out_sa && out_salen) {
            *out_sa = rt->udp_candidates.current_addr;
            *out_salen = rt->udp_candidates.current_addr_len;
        }
    }
    pthread_mutex_unlock(&rt->udp_candidates.mu);
}

static void carrier_get_current_udp_ip(CarrierRuntime *rt, char *out, size_t sz) {
    carrier_get_current_udp_ip_sa(rt, out, sz, nullptr, nullptr);
}

static int carrier_set_current_udp_candidate(CarrierRuntime *rt, size_t idx) {
    if (!rt) return 0;
    pthread_mutex_lock(&rt->udp_candidates.mu);
    if (idx < rt->udp_candidates.len) {
        rt->udp_candidates.current_index = idx;
        snprintf(rt->udp_candidates.current_ip, sizeof(rt->udp_candidates.current_ip), "%s", rt->udp_candidates.items[idx].ip);
        rt->udp_candidates.current_addr = rt->udp_candidates.items[idx].addr;
        rt->udp_candidates.current_addr_len = rt->udp_candidates.items[idx].addr_len;
        atomic_store_explicit(&rt->udp_candidates.fast_fail_count, 0, memory_order_relaxed);
        pthread_mutex_unlock(&rt->udp_candidates.mu);
        return 1;
    }
    pthread_mutex_unlock(&rt->udp_candidates.mu);
    return 0;
}

CFNAT_UNUSED static int carrier_select_valid_udp_ip(CarrierRuntime *rt) {
    if (!rt) return 0;
    int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
    if (target_port <= 0) target_port = 443;
    int delay_ms = (rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms;
    if (delay_ms < 1000) delay_ms = 1000;

    char check_ips[32][MAX_IP_LEN];
    size_t check_indices[32];
    size_t count = 0;

    pthread_mutex_lock(&rt->udp_candidates.mu);
    for (size_t i = 0; i < rt->udp_candidates.len && count < 32; i++) {
        snprintf(check_ips[count], sizeof(check_ips[count]), "%s", rt->udp_candidates.items[i].ip);
        check_indices[count] = i;
        count++;
    }
    pthread_mutex_unlock(&rt->udp_candidates.mu);

    for (size_t i = 0; i < count; i++) {
        int lat = 0;
        if (quic_probe_ip(check_ips[i], target_port, delay_ms, &lat)) {
            carrier_set_current_udp_candidate(rt, check_indices[i]);
            atomic_store(&rt->udp_candidates.cache_valid, 1);
            log_msg("[UDP/H3] [%s] 可用 IP: %s (延迟: %d ms)",
                    carrier_display_name(rt->spec.mode), check_ips[i], lat);
            return 1;
        }
    }
    return 0;
}

CFNAT_NODISCARD static int carrier_switch_next_udp_ip(CarrierRuntime *rt) {
    if (!rt) return 0;
    int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
    if (target_port <= 0) target_port = 443;
    int delay_ms = (rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms;
    if (delay_ms < 1000) delay_ms = 1000;

    char check_ips[32][MAX_IP_LEN];
    size_t check_indices[32];
    size_t count = 0;
    size_t total_len = 0;

    pthread_mutex_lock(&rt->udp_candidates.mu);
    size_t len = rt->udp_candidates.len;
    size_t start = rt->udp_candidates.current_index + 1;
    total_len = len;
    if (len > 0) {
        size_t threshold = (size_t)(len * 0.70);
        if (threshold < 1) threshold = 1;
        if (start < threshold) {
            for (size_t i = start; i < threshold && i < len && count < 32; i++) {
                snprintf(check_ips[count], sizeof(check_ips[count]), "%s", rt->udp_candidates.items[i].ip);
                check_indices[count] = i;
                count++;
            }
        }
    }
    pthread_mutex_unlock(&rt->udp_candidates.mu);

    if (total_len == 0 || count == 0) return 0;

    for (size_t i = 0; i < count; i++) {
        int lat = 0;
        if (quic_probe_ip(check_ips[i], target_port, delay_ms, &lat)) {
            carrier_set_current_udp_candidate(rt, check_indices[i]);
            atomic_store(&rt->udp_candidates.cache_valid, 1);
            log_msg("[UDP/H3] [%s] 顺位切换到下一个最优 IP: %s (候选索引: %zu/%zu, 延迟 %d ms)",
                    carrier_display_name(rt->spec.mode), check_ips[i], check_indices[i], total_len, lat);
            return 1;
        }
    }
    return 0;
}

static void carrier_note_connection_success(CarrierRuntime *rt, const char *ip) {
    if (!rt || !ip || !*ip) return;
    pthread_mutex_lock(&rt->candidates.mu);
    if (strcmp(rt->candidates.current_ip, ip) == 0) {
        atomic_store_explicit(&rt->candidates.fast_fail_count, 0, memory_order_relaxed);
    }
    pthread_mutex_unlock(&rt->candidates.mu);
}

static void carrier_note_connection_failed(CarrierRuntime *rt, const char *ip) {
    if (!atomic_load(&g_running) || !rt || !ip || !*ip) return;
    int should_switch = 0;
    pthread_mutex_lock(&rt->candidates.mu);
    if (!atomic_load(&g_running)) {
        pthread_mutex_unlock(&rt->candidates.mu);
        return;
    }
    if (strcmp(rt->candidates.current_ip, ip) == 0) {
        if (atomic_fetch_add_explicit(&rt->candidates.fast_fail_count, 1, memory_order_relaxed) + 1 >= 2) {
            atomic_store(&rt->candidates.cache_valid, 0);
            should_switch = 1;
            atomic_store_explicit(&rt->candidates.fast_fail_count, 0, memory_order_relaxed);
        }
    }
    pthread_mutex_unlock(&rt->candidates.mu);
    if (should_switch && atomic_load(&g_running)) {
        log_msg("[TCP/H2] [%s] 当前 IP %s 连续异常断开，标记为不可用并顺位切换", carrier_display_name(rt->spec.mode), ip);
        if (!carrier_switch_next_ip(rt)) {
            log_msg("[TCP/H2] [%s] 候选池消耗达 70%% 或无可用顺位 IP，开始自愈维护双轨候选池", carrier_display_name(rt->spec.mode));
            carrier_rescan_dual_pools(rt);
        }
    }
}

CFNAT_NODISCARD static int carrier_choose_ip_for_connection(CarrierRuntime *rt, char *out, size_t sz, struct sockaddr_storage *out_sa, socklen_t *out_salen) {
    if (!rt || !out || sz == 0) return 0;
    out[0] = '\0';
    if (carrier_choose_ip_fast(rt, out, sz, out_sa, out_salen)) return 1;

    /* 缓存未命中或处于重选阶段，快速提取当前首选候选，禁止在 accept 循环中做阻塞式网络健康检查 */
    pthread_mutex_lock(&rt->candidates.mu);
    if (rt->candidates.current_ip[0]) {
        snprintf(out, sz, "%s", rt->candidates.current_ip);
        if (out_sa && out_salen) {
            *out_sa = rt->candidates.current_addr;
            *out_salen = rt->candidates.current_addr_len;
        }
    } else if (rt->candidates.len > 0) {
        snprintf(out, sz, "%s", rt->candidates.items[0].ip);
        if (out_sa && out_salen) {
            *out_sa = rt->candidates.items[0].addr;
            *out_salen = rt->candidates.items[0].addr_len;
        }
    }
    pthread_mutex_unlock(&rt->candidates.mu);
    return out[0] ? 1 : 0;
}

/* 双轨协同自愈与补充扫描引擎：
 * 无论 TCP 见底还是 UDP 见底，一次补充两个池；
 * 提取现有 TCP 与 UDP 的存活火种，与扫描新 IP 合并大排序，TCP 取前 ipnum，UDP 取前 2*ipnum 精筛 */
static int carrier_rescan_dual_pools(CarrierRuntime *rt) {
    if (!rt) return 0;
    int expected = 0;
    if (!atomic_compare_exchange_strong(&rt->rescanning_lock, &expected, 1)) {
        debug_msg("[%s] 自愈补充扫描已在进行中，跳过并发触发", carrier_display_name(rt->spec.mode));
        return 1;
    }

    const char *ipfile = (rt->spec.prof.ips_type == 6) ? "ips-v6.txt" : "ips-v4.txt";

    Config scan_cfg = g_cfg;
    scan_cfg.ips_type = rt->spec.prof.ips_type;
    if (rt->spec.prof.enabled) {
        scan_cfg.ips_type = rt->spec.prof.ips_type;
        if (rt->spec.prof.port > 0) scan_cfg.port = rt->spec.prof.port;
        if (rt->spec.prof.http_port > 0) scan_cfg.http_port = rt->spec.prof.http_port;
        if (rt->spec.prof.delay_ms > 0) scan_cfg.delay_ms = rt->spec.prof.delay_ms;
        if (rt->spec.prof.task > 0) scan_cfg.task = rt->spec.prof.task;
        if (rt->spec.prof.ipnum > 0) scan_cfg.ipnum = rt->spec.prof.ipnum;
        if (rt->spec.prof.num > 0) scan_cfg.num = rt->spec.prof.num;
        scan_cfg.code = rt->spec.prof.code;
        if (rt->spec.prof.domain[0]) snprintf(scan_cfg.domain, sizeof(scan_cfg.domain), "%s", rt->spec.prof.domain);
        if (rt->spec.prof.colo[0]) snprintf(scan_cfg.colo, sizeof(scan_cfg.colo), "%s", rt->spec.prof.colo);
        if (rt->spec.prof.v6_split > 0) scan_cfg.v6_split = rt->spec.prof.v6_split;
    }
    size_t target_ipnum = (size_t)scan_cfg.ipnum;
    if (target_ipnum == 0) target_ipnum = 20;

    /* 1. 提取当前 TCP 池与 UDP 池中的所有 IP，合并去重进行原地测活 (In-place Re-test) */
    StringList pool_ips = {0};
    pthread_mutex_lock(&rt->candidates.mu);
    size_t old_tcp_len = rt->candidates.len;
    for (size_t i = 0; i < old_tcp_len; i++) {
        if (rt->candidates.items && rt->candidates.items[i].ip[0]) {
            strlist_add(&pool_ips, rt->candidates.items[i].ip);
        }
    }
    pthread_mutex_unlock(&rt->candidates.mu);

    pthread_mutex_lock(&rt->udp_candidates.mu);
    size_t old_udp_len = rt->udp_candidates.len;
    for (size_t i = 0; i < old_udp_len; i++) {
        if (rt->udp_candidates.items && rt->udp_candidates.items[i].ip[0]) {
            int exists = 0;
            for (size_t j = 0; j < pool_ips.len; j++) {
                if (strcmp(pool_ips.items[j], rt->udp_candidates.items[i].ip) == 0) {
                    exists = 1; break;
                }
            }
            if (!exists) strlist_add(&pool_ips, rt->udp_candidates.items[i].ip);
        }
    }
    pthread_mutex_unlock(&rt->udp_candidates.mu);

    ResultList survivors = {0};
    if (pool_ips.len > 0) {
        Config retest_cfg = scan_cfg;
        retest_cfg.ipnum = (int)target_ipnum;
        if (retest_cfg.ipnum < (int)pool_ips.len) retest_cfg.ipnum = (int)pool_ips.len;
        if (retest_cfg.task > (int)pool_ips.len) retest_cfg.task = (int)pool_ips.len;
        if (rt->spec.use_baidu_proxy == 2) {
            ResultList direct_res = scan_ips(&pool_ips, nullptr, &retest_cfg, nullptr);
            ResultList baidu_res = {0};
            if (rt->proxy_pool && rt->proxy_pool->len > 0) {
                baidu_res = scan_ips(&pool_ips, nullptr, &retest_cfg, rt->proxy_pool);
            }
            for (size_t j = 0; j < direct_res.len; j++) resultlist_add(&survivors, &direct_res.items[j]);
            for (size_t j = 0; j < baidu_res.len; j++) {
                int exists = 0;
                for (size_t k = 0; k < survivors.len; k++) {
                    if (strcmp(survivors.items[k].ip, baidu_res.items[j].ip) == 0) { exists = 1; break; }
                }
                if (!exists) resultlist_add(&survivors, &baidu_res.items[j]);
            }
            free(direct_res.items);
            free(baidu_res.items);
            if (survivors.len > 0) qsort(survivors.items, survivors.len, sizeof(Result), cmp_result);
        } else {
            survivors = scan_ips(&pool_ips, nullptr, &retest_cfg, rt->proxy_pool);
        }
        strlist_free(&pool_ips);
    }

    ResultList all_candidates = {0};

    /* 2. 判定原地测活存活数量:
       若存活数量达到充足标准 (>= tcp_heal_min) 且 UDP (若开启) 也具备充足候选，才跳过全局扫描 */
    size_t heal_threshold = (target_ipnum * 25 + 99) / 100;
    if (heal_threshold < 1) heal_threshold = 1;
    size_t tcp_heal_min = (target_ipnum * 60 + 99) / 100;
    if (tcp_heal_min < 1) tcp_heal_min = 1;

    int can_heal_inplace = 0;
    ResultList inplace_udp = {0};
    if (survivors.len >= tcp_heal_min) {
        if (cfnat_socket_valid(rt->udp_listen_fd)) {
            ResultList test_udp = filter_udp_candidates_from_tcp(rt, survivors.items, survivors.len, target_ipnum);
            if (test_udp.len >= heal_threshold) {
                can_heal_inplace = 1;
                inplace_udp = test_udp;
            } else {
                free(test_udp.items);
            }
        } else {
            can_heal_inplace = 1;
        }
    }

    if (can_heal_inplace) {
        log_msg("[%s] 双轨候选池原地测活完成: 存活 %zu 个 (>= 达标线 %zu 个)，成功原地自愈，重排装填",
                carrier_display_name(rt->spec.mode), survivors.len, tcp_heal_min);
        for (size_t j = 0; j < survivors.len; j++) {
            resultlist_add(&all_candidates, &survivors.items[j]);
        }
        free(survivors.items);
    } else {
        memset(&inplace_udp, 0, sizeof(inplace_udp));
        /* 存活数量不足或 UDP 池候选不足，维持最优存活 IP，执行带电增量补充扫描 */
        if (survivors.len > 0) {
            pthread_mutex_lock(&rt->candidates.mu);
            snprintf(rt->candidates.current_ip, sizeof(rt->candidates.current_ip), "%s", survivors.items[0].ip);
            rt->candidates.current_addr = survivors.items[0].addr;
            rt->candidates.current_addr_len = survivors.items[0].addr_len;
            rt->candidates.current_index = 0;
            atomic_store_explicit(&rt->candidates.fast_fail_count, 0, memory_order_relaxed);
            pthread_mutex_unlock(&rt->candidates.mu);
            atomic_store(&rt->candidates.cache_valid, 1);

            log_msg("[%s] 存活候选 %zu 个 (< 达标线 %zu 个或需补充 UDP)，维持最优存活 IP %s 正常转发，后台启动补充扫描...",
                    carrier_display_name(rt->spec.mode), survivors.len, tcp_heal_min, survivors.items[0].ip);
        } else {
            warn_msg("[%s] 候选池已全部失效，启动扫描寻找可用候选 IP", carrier_display_name(rt->spec.mode));
            atomic_store(&rt->candidates.cache_valid, 0);
        }

        Config fresh_cfg = scan_cfg;
        fresh_cfg.ipnum = (int)target_ipnum;
        if (fresh_cfg.task > 60) fresh_cfg.task = 50;

        int cur_v6_split = (rt->spec.prof.enabled && rt->spec.prof.v6_split > 0) ? rt->spec.prof.v6_split : g_cfg.v6_split;
        int cur_random = rt->spec.prof.enabled ? rt->spec.prof.random_mode : g_cfg.random_mode;
        int use_cidr = (rt->spec.prof.ips_type == 4 && !cur_random);
        CidrList fresh_cidrs = {0};
        StringList ips = {0};
        uint64_t cand_count = 0;
        if (use_cidr) {
            fresh_cidrs = load_cidr_list(ipfile, 0);
            cand_count = fresh_cidrs.len;
        } else {
            ips = load_ip_list(ipfile, cur_random, cur_v6_split);
            cand_count = ips.len;
        }
        if (cand_count > 0) {
            ResultList fresh_results = {0};
            if (rt->spec.use_baidu_proxy == 2) {
                ResultList results_direct = scan_ips(use_cidr ? nullptr : &ips, use_cidr ? &fresh_cidrs : nullptr, &fresh_cfg, nullptr);
                ResultList results_baidu = {0};
                if (rt->proxy_pool && rt->proxy_pool->len > 0) {
                    results_baidu = scan_ips(use_cidr ? nullptr : &ips, use_cidr ? &fresh_cidrs : nullptr, &fresh_cfg, rt->proxy_pool);
                }
                for (size_t j = 0; j < results_direct.len; j++) resultlist_add(&fresh_results, &results_direct.items[j]);
                for (size_t j = 0; j < results_baidu.len; j++) {
                    int exists = 0;
                    for (size_t k = 0; k < fresh_results.len; k++) {
                        if (strcmp(fresh_results.items[k].ip, results_baidu.items[j].ip) == 0) { exists = 1; break; }
                    }
                    if (!exists) resultlist_add(&fresh_results, &results_baidu.items[j]);
                }
                free(results_direct.items);
                free(results_baidu.items);
                if (fresh_results.len > 0) qsort(fresh_results.items, fresh_results.len, sizeof(Result), cmp_result);
            } else {
                fresh_results = scan_ips(use_cidr ? nullptr : &ips, use_cidr ? &fresh_cidrs : nullptr, &fresh_cfg, rt->proxy_pool);
            }
            if (use_cidr) cidrlist_destroy(&fresh_cidrs);
            else strlist_free(&ips);

            /* 合并 survivors 与 fresh_results (去重) */
            for (size_t j = 0; j < survivors.len; j++) resultlist_add(&all_candidates, &survivors.items[j]);
            for (size_t j = 0; j < fresh_results.len; j++) {
                int exists = 0;
                for (size_t k = 0; k < all_candidates.len; k++) {
                    if (strcmp(all_candidates.items[k].ip, fresh_results.items[j].ip) == 0) { exists = 1; break; }
                }
                if (!exists) resultlist_add(&all_candidates, &fresh_results.items[j]);
            }
            free(fresh_results.items);
            free(survivors.items);
        } else {
            for (size_t j = 0; j < survivors.len; j++) resultlist_add(&all_candidates, &survivors.items[j]);
            free(survivors.items);
        }
    }

    if (all_candidates.len == 0) {
        atomic_store(&rt->rescanning_lock, 0);
        warn_msg("[%s] 补充扫描后仍未发现有效 IP", carrier_display_name(rt->spec.mode));
        return 0;
    }

    qsort(all_candidates.items, all_candidates.len, sizeof(Result), cmp_result);

    /* 3. 分发给 TCP 候选池 (精准截取前 target_ipnum 个) */
    size_t tcp_target = target_ipnum;
    size_t tcp_count = all_candidates.len > tcp_target ? tcp_target : all_candidates.len;
    Result *new_tcp_items = calloc(tcp_count, sizeof(Result));
    if (new_tcp_items) {
        memcpy(new_tcp_items, all_candidates.items, tcp_count * sizeof(Result));
        pthread_mutex_lock(&rt->candidates.mu);
        Result *old_tcp_items = rt->candidates.items;
        rt->candidates.items = new_tcp_items;
        rt->candidates.len = tcp_count;
        rt->candidates.current_index = 0;
        snprintf(rt->candidates.current_ip, sizeof(rt->candidates.current_ip), "%s", new_tcp_items[0].ip);
        rt->candidates.current_addr = new_tcp_items[0].addr;
        rt->candidates.current_addr_len = new_tcp_items[0].addr_len;
        atomic_store_explicit(&rt->candidates.fast_fail_count, 0, memory_order_relaxed);
        pthread_mutex_unlock(&rt->candidates.mu);
        free(old_tcp_items);
        atomic_store(&rt->candidates.cache_valid, 1);
    }

    /* 4. 分发给 UDP 候选池 (多轮滑动检验 + 网段裂变衍生) */
    ResultList udp_res = (inplace_udp.len > 0) ? inplace_udp :
        filter_udp_candidates_from_tcp(rt, all_candidates.items, all_candidates.len, target_ipnum);
    if (udp_res.len > 0) {
        pthread_mutex_lock(&rt->udp_candidates.mu);
        Result *old_udp_items = rt->udp_candidates.items;
        rt->udp_candidates.items = udp_res.items;
        rt->udp_candidates.len = udp_res.len;
        rt->udp_candidates.current_index = 0;
        snprintf(rt->udp_candidates.current_ip, sizeof(rt->udp_candidates.current_ip), "%s", udp_res.items[0].ip);
        rt->udp_candidates.current_addr = udp_res.items[0].addr;
        rt->udp_candidates.current_addr_len = udp_res.items[0].addr_len;
        atomic_store_explicit(&rt->udp_candidates.fast_fail_count, 0, memory_order_relaxed);
        pthread_mutex_unlock(&rt->udp_candidates.mu);
        free(old_udp_items);
        atomic_store(&rt->udp_candidates.cache_valid, 1);
    }

    free(all_candidates.items);

    /* 内存结构与旧指针已纯粹就绪并安全释放，最后异步/脱锁落盘候选文件，杜绝磁盘 I/O 阻塞内存清理 */
    if (new_tcp_items) {
        save_candidate_cache(candidate_cache_file_for_profile(rt->spec.mode, rt->spec.prof.ips_type), new_tcp_items, tcp_count);
    }
    if (udp_res.len > 0) {
        save_candidate_cache(candidate_cache_file_for_profile_udp(rt->spec.mode, rt->spec.prof.ips_type), udp_res.items, udp_res.len);
    }

    int tcp_lat = (rt->candidates.items && rt->candidates.current_index < rt->candidates.len) ?
                  rt->candidates.items[rt->candidates.current_index].latency_ms : 0;
    int udp_lat = (rt->udp_candidates.items && rt->udp_candidates.current_index < rt->udp_candidates.len) ?
                  rt->udp_candidates.items[rt->udp_candidates.current_index].latency_ms : 0;

    if (rt->udp_candidates.len > 0 && rt->udp_candidates.current_ip[0]) {
        log_msg("[%s] 双轨自愈维护完成:\n"
                "  ├─ [TCP/H2] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)\n"
                "  └─ [UDP/H3] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)",
                carrier_display_name(rt->spec.mode),
                rt->candidates.current_ip, tcp_lat, rt->candidates.len,
                rt->udp_candidates.current_ip, udp_lat, rt->udp_candidates.len);
    } else {
        log_msg("[%s] 双轨自愈维护完成:\n"
                "  ├─ [TCP/H2] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)\n"
                "  └─ [UDP/H3] 无可用节点 (0 个候选)",
                carrier_display_name(rt->spec.mode),
                rt->candidates.current_ip, tcp_lat, rt->candidates.len);
    }

    atomic_store(&rt->rescanning_lock, 0);
    return 1;
}

/* P1-HC: 渐进式 TCP 健康检查线程 */
static void *carrier_health_thread(void *arg) {
    CarrierRuntime *rt = (CarrierRuntime *)arg;
    int fail = 0;
    long last = 0;
    int consecutive_success = 0;
    while (atomic_load(&g_running)) {
        if (sleep_interruptible_ms(30000) != 0) break;
        char ip[MAX_IP_LEN];
        carrier_get_current_ip(rt, ip, sizeof(ip));

        HealthCheckLevel level;
        if (consecutive_success < 3) {
            level = HC_FULL;
        } else if (consecutive_success < 10) {
            level = HC_MEDIUM;
        } else {
            level = HC_LIGHT;
        }

        int latency = 0;
        if (!ip[0] || !carrier_health_check_ip_level(rt, ip, level, &latency)) {
            fail++;
            consecutive_success = 0;
            atomic_store(&rt->candidates.cache_valid, 0);
            warn_msg("[TCP/H2] [%s] 状态检查失败 (%d/2): 当前 IP %s 握手无响应",
                     carrier_display_name(rt->spec.mode), fail, ip[0] ? ip : "为空");
        } else {
            fail = 0;
            consecutive_success++;
            atomic_store(&rt->candidates.cache_valid, 1);
            long n = now_ms();
            if (g_cfg.log_level >= LOG_DEBUG && g_cfg.health_log > 0 && n - last >= g_cfg.health_log * 1000L) {
                debug_msg("[TCP/H2] [%s] 状态检查正常: 当前 IP %s 可用 (延迟 %d ms)",
                          carrier_display_name(rt->spec.mode), ip, latency);
                last = n;
            }
        }
        if (fail >= 2) {
            log_msg("[TCP/H2] [%s] 连续两次状态检查失败，顺位切换下一个候选 IP", carrier_display_name(rt->spec.mode));
            if (!carrier_switch_next_ip(rt)) {
                log_msg("[TCP/H2] [%s] 候选池消耗达 70%% 或无可用顺位 IP，开始自愈维护双轨候选池", carrier_display_name(rt->spec.mode));
                if (!carrier_rescan_dual_pools(rt)) {
                    warn_msg("[TCP/H2] [%s] 自愈重扫未发现可用 IP，将在下一周期重试", carrier_display_name(rt->spec.mode));
                }
            }
            fail = 0;
        }
    }
    return nullptr;
}

/* UDP/H3 定时轻量 QUIC 探针健康检查线程 */
static void *carrier_udp_health_thread(void *arg) {
    CarrierRuntime *rt = (CarrierRuntime *)arg;
    int fail = 0;
    long last_log = 0;
    while (atomic_load(&g_running)) {
        if (sleep_interruptible_ms(30000) != 0) break;
        char ip[MAX_IP_LEN] = {0};
        carrier_get_current_udp_ip(rt, ip, sizeof(ip));
        if (!ip[0]) continue;

        int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
        int delay_ms = (rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms;
        if (delay_ms < 1000) delay_ms = 1000;

        int latency = 0;
        int ok = quic_probe_ip(ip, target_port, delay_ms, &latency);
        if (!ok) {
            fail++;
            atomic_store(&rt->udp_candidates.cache_valid, 0);
            warn_msg("[UDP/H3] [%s] 状态检查失败 (%d/2): 当前 IP %s QUIC 无响应",
                     carrier_display_name(rt->spec.mode), fail, ip);
        } else {
            fail = 0;
            atomic_store(&rt->udp_candidates.cache_valid, 1);
            long n = now_ms();
            if (g_cfg.log_level >= LOG_DEBUG && g_cfg.health_log > 0 && n - last_log >= g_cfg.health_log * 1000L) {
                debug_msg("[UDP/H3] [%s] 状态检查正常: 当前 IP %s 可用 (延迟 %d ms)",
                          carrier_display_name(rt->spec.mode), ip, latency);
                last_log = n;
            }
        }

        if (fail >= 2) {
            log_msg("[UDP/H3] [%s] 连续两次状态检查失败，顺位切换下一个候选 IP",
                    carrier_display_name(rt->spec.mode));
            if (!carrier_switch_next_udp_ip(rt)) {
                log_msg("[UDP/H3] [%s] 候选池消耗达 70%% 或无可用顺位 IP，开始自愈维护双轨候选池",
                        carrier_display_name(rt->spec.mode));
                carrier_rescan_dual_pools(rt);
            }
            fail = 0;
        }
    }
    return nullptr;
}

static void *carrier_accept_thread(void *arg) {
    CarrierRuntime *rt = (CarrierRuntime *)arg;
    while (atomic_load(&g_running)) {
        struct sockaddr_storage ss;
#ifdef _WIN32
        int slen = (int)sizeof(ss);
#else
        socklen_t slen = sizeof(ss);
#endif
        socket_t cfd = accept_interruptible(rt->listen_fd, (struct sockaddr *)&ss, &slen);
        if (cfnat_socket_invalid(cfd)) {
            if (!atomic_load(&g_running)) break;
#ifdef _WIN32
            {
                int e = WSAGetLastError();
                if (e == WSAEINTR || e == WSAENOTSOCK) break;
            }
#else
            if (errno == EINTR || errno == EBADF) break;
#endif
            if (sleep_interruptible_ms(1000) != 0) break;
            continue;
        }
        char ip[MAX_IP_LEN];
        struct sockaddr_storage ip_sa = {0};
        socklen_t ip_salen = 0;
        if (!carrier_choose_ip_for_connection(rt, ip, sizeof(ip), &ip_sa, &ip_salen)) {
            close(cfd);
            continue;
        }
        int active = atomic_fetch_add(&g_active_tcp_conns, 1) + 1;
        unsigned long long conn_id = atomic_fetch_add(&g_tcp_conn_seq, 1) + 1;
        conn_msg("[TCP/H2] #%llu [%s] 客户端连接建立 (当前活跃: %d)", conn_id, carrier_display_name(rt->spec.mode), active);
        ConnCtx *cc = calloc(1, sizeof(ConnCtx));
        if (!cc) {
            close(cfd);
            atomic_fetch_sub(&g_active_tcp_conns, 1);
            continue;
        }
        cc->client_fd = cfd;
        snprintf(cc->ip, sizeof(cc->ip), "%s", ip);
        cc->ip_addr = ip_sa;
        cc->ip_addr_len = ip_salen;
        cc->tls_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
        cc->http_port = (rt->spec.prof.http_port > 0) ? rt->spec.prof.http_port : g_cfg.http_port;
        cc->num = (rt->spec.prof.num > 0) ? rt->spec.prof.num : g_cfg.num;
        cc->delay_ms = (rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms;
        cc->proxy_pool = rt->proxy_pool;
        cc->runtime = rt;
        cc->use_mixed = (rt->spec.use_baidu_proxy == 2) ? 1 : 0;
        cc->conn_id = conn_id;
        format_endpoint_str((const struct sockaddr_storage *)&ss, cc->client_addr, sizeof(cc->client_addr));
        pthread_t tid = 0;
        set_tcp_nodelay(cfd);
        set_loopback_fast_path(cfd);
        tune_socket_buffers(cfd, 0);
        if (create_small_thread(&tid, connection_thread, cc) != 0) {
            warn_msg("[TCP/H2] #%llu [%s] 创建连接处理线程失败", conn_id, carrier_display_name(rt->spec.mode));
            close(cfd);
            free(cc);
            atomic_fetch_sub(&g_active_tcp_conns, 1);
            continue;
        }
        pthread_detach(tid);
    }
    return nullptr;
}

static int parse_addr(const char *addr, char *host, size_t hostsz, int *port) {
    if (!addr || !host || !port) return -1;
    if (addr[0] == '[') {
        const char *end = strchr(addr, ']');
        if (!end || end[1] != ':') return -1;
        size_t n = (size_t)(end - (addr + 1));
        if (n >= hostsz) n = hostsz - 1;
        memcpy(host, addr + 1, n);
        host[n] = 0;
        *port = atoi(end + 2);
        return *port > 0 ? 0 : -1;
    }
    const char *colon = strrchr(addr, ':');
    if (!colon) {
        // 只有端口号的情况，例如 "1234"
        snprintf(host, hostsz, "0.0.0.0");
        *port = atoi(addr);
        return *port > 0 ? 0 : -1;
    }
    size_t n = (size_t)(colon - addr);
    if (n >= hostsz) n = hostsz - 1;
    memcpy(host, addr, n);
    host[n] = 0;
    *port = atoi(colon + 1);
    if (!host[0]) snprintf(host, hostsz, "0.0.0.0");
    return *port > 0 ? 0 : -1;
}

static socket_t listen_tcp(const char *addr) {
    char host[128];
    int port = 0;
    if (parse_addr(addr, host, sizeof(host), &port) != 0) return INVALID_SOCKET;
    int yes = 1;
    
    if (strchr(host, ':')) {
        socket_t fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&yes, sizeof(yes));
#ifdef SO_REUSEPORT
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, host, &sa6.sin6_addr) != 1) {
            close(fd);
            return INVALID_SOCKET;
        }
        if (bind(fd, (struct sockaddr *)&sa6, sizeof(sa6)) != 0) {
            int err = errno;
            close(fd);
            errno = err;
            return INVALID_SOCKET;
        }
        if (listen(fd, 1024) != 0) {
            int err = errno;
            close(fd);
            errno = err;
            return INVALID_SOCKET;
        }
        set_loopback_fast_path(fd);
        return fd;
    }
    socket_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&yes, sizeof(yes));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        close(fd);
        return INVALID_SOCKET;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        int err = errno;
        close(fd);
        errno = err;
        return INVALID_SOCKET;
    }
    if (listen(fd, 1024) != 0) {
        int err = errno;
        close(fd);
        errno = err;
        return INVALID_SOCKET;
    }
    set_loopback_fast_path(fd);
    return fd;
}

/* ── HTTP/3 (QUIC / UDP) 转发与会话管理引擎 ────────────────────────── */

#define UDP_SESSION_TIMEOUT_MS 60000L
#define UDP_MAX_SESSIONS 256
#define UDP_BUF_SIZE 65536

struct UdpSession {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    char client_addr_str[64];
    socket_t upstream_fd;
    char target_ip[MAX_IP_LEN];
    int target_port;
    unsigned long long sess_id;
    long created_ms;
    long last_active_ms;
    uint64_t bytes_up;
    uint64_t bytes_down;
    struct UdpSession *next;
};

static socket_t listen_udp(const char *addr) {
    char host[128];
    int port = 0;
    if (parse_addr(addr, host, sizeof(host), &port) != 0) return INVALID_SOCKET;
    int yes = 1;

    if (strchr(host, ':')) {
        socket_t fd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
#ifdef _WIN32
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
        BOOL bNewBehavior = FALSE;
        DWORD dwBytesReturned = 0;
        WSAIoctl(fd, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), nullptr, 0, &dwBytesReturned, nullptr, nullptr);
#endif
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&yes, sizeof(yes));
#ifdef SO_REUSEPORT
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, host, &sa6.sin6_addr) != 1) {
            close(fd);
            return INVALID_SOCKET;
        }
        if (bind(fd, (struct sockaddr *)&sa6, sizeof(sa6)) != 0) {
            close(fd);
            return INVALID_SOCKET;
        }
        tune_socket_buffers(fd, 1);
        set_nonblock(fd, 1);
        return fd;
    }

    socket_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
#ifdef _WIN32
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
    BOOL bNewBehavior = FALSE;
    DWORD dwBytesReturned = 0;
    WSAIoctl(fd, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), nullptr, 0, &dwBytesReturned, nullptr, nullptr);
#endif
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&yes, sizeof(yes));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        close(fd);
        return INVALID_SOCKET;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return INVALID_SOCKET;
    }
    tune_socket_buffers(fd, 1);
    set_nonblock(fd, 1);
    return fd;
}

static socket_t udp_connect_upstream_sa(const char *ip, const struct sockaddr_storage *target_sa, socklen_t target_salen, int port) {
    if ((!target_sa || target_salen == 0) && (!ip || !*ip)) return INVALID_SOCKET;
    int is_v6 = 0;
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    if (target_sa && target_salen > 0) {
        ss = *target_sa;
        slen = target_salen;
        is_v6 = (ss.ss_family == AF_INET6);
        if (is_v6) {
            ((struct sockaddr_in6 *)&ss)->sin6_port = htons((uint16_t)port);
        } else {
            ((struct sockaddr_in *)&ss)->sin_port = htons((uint16_t)port);
        }
    } else {
        is_v6 = (strchr(ip, ':') != nullptr);
        memset(&ss, 0, sizeof(ss));
        if (is_v6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
            s6->sin6_family = AF_INET6;
            s6->sin6_port = htons((uint16_t)port);
            if (inet_pton(AF_INET6, ip, &s6->sin6_addr) != 1) return INVALID_SOCKET;
            slen = sizeof(struct sockaddr_in6);
        } else {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
            s4->sin_family = AF_INET;
            s4->sin_port = htons((uint16_t)port);
            if (inet_pton(AF_INET, ip, &s4->sin_addr) != 1) return INVALID_SOCKET;
            slen = sizeof(struct sockaddr_in);
        }
    }

    socket_t fd = socket(is_v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;

#ifdef _WIN32
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
    BOOL bNewBehavior = FALSE;
    DWORD dwBytesReturned = 0;
    WSAIoctl(fd, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), nullptr, 0, &dwBytesReturned, nullptr, nullptr);
#endif

    bind_socket_to_interface(fd, is_v6 ? AF_INET6 : AF_INET);
    tune_socket_buffers(fd, 1);
    set_nonblock(fd, 1);

    if (connect(fd, (struct sockaddr *)&ss, slen) != 0) {
        close(fd);
        return INVALID_SOCKET;
    }
    return fd;
}

static socket_t udp_connect_upstream(const char *ip, int port) {
    return udp_connect_upstream_sa(ip, nullptr, 0, port);
}

static UdpSession *find_or_create_udp_session_sa(CarrierRuntime *rt, const struct sockaddr_storage *client_addr, socklen_t client_len, const char *target_ip, const struct sockaddr_storage *target_sa, socklen_t target_salen, int target_port, uint8_t first_byte) {
    if (!rt || !client_addr || !target_ip || !*target_ip) return nullptr;

    /* P0-MRU 协同加速：Xray XMUX H3 多路复用下，>95% 数据报来自同一客户端端口，优先 O(1) 命中缓存 */
    UdpSession *fast = rt->last_udp_sess;
    if (fast && sockaddr_equal(&fast->client_addr, client_addr)) {
        if (!cfnat_socket_valid(fast->upstream_fd)) {
            fast->upstream_fd = udp_connect_upstream_sa(target_ip, target_sa, target_salen, target_port);
            snprintf(fast->target_ip, sizeof(fast->target_ip), "%s", target_ip);
            fast->target_port = target_port;
        }
        return fast;
    }

    UdpSession *s = rt->udp_sessions;
    size_t count = 0;
    while (s) {
        count++;
        if (sockaddr_equal(&s->client_addr, client_addr)) {
            /* 会话保持粘性 (Session Stickiness): QUIC/H3 具有强加密连接状态与 Connection ID，
             * 只要现有 socket 仍有效活跃，不可中途突变目标 IP，避免客户端遭遇连接重置 (Stateless Reset)。
             * 仅在 upstream_fd 失效时才重新连接新优选 IP。 */
            if (!cfnat_socket_valid(s->upstream_fd)) {
                s->upstream_fd = udp_connect_upstream_sa(target_ip, target_sa, target_salen, target_port);
                snprintf(s->target_ip, sizeof(s->target_ip), "%s", target_ip);
                s->target_port = target_port;
            }
            rt->last_udp_sess = s;
            return s;
        }
        s = s->next;
    }

    // 会话数量上限保护 (淘汰最久未活跃的一项)
    if (count >= UDP_MAX_SESSIONS) {
        long oldest_time = 0;
        UdpSession *oldest = nullptr;
        UdpSession *prev_oldest = nullptr;
        UdpSession *prev = nullptr;
        s = rt->udp_sessions;
        while (s) {
            if (oldest == nullptr || s->last_active_ms < oldest_time) {
                oldest_time = s->last_active_ms;
                oldest = s;
                prev_oldest = prev;
            }
            prev = s;
            s = s->next;
        }
        if (oldest) {
            if (rt->last_udp_sess == oldest) rt->last_udp_sess = nullptr;
            if (prev_oldest) prev_oldest->next = oldest->next;
            else rt->udp_sessions = oldest->next;
            if (cfnat_socket_valid(oldest->upstream_fd)) close(oldest->upstream_fd);
            int active = atomic_fetch_sub(&g_active_udp_sessions, 1) - 1;
            long lifetime_s = (now_ms() - oldest->created_ms) / 1000;
            char up_s[32] = {0}, down_s[32] = {0};
            format_bytes(oldest->bytes_up, up_s, sizeof(up_s));
            format_bytes(oldest->bytes_down, down_s, sizeof(down_s));
            conn_msg("[UDP/H3] #%llu [%s] 客户端会话关闭 (LRU淘汰, 存活 %lds, 上行 %s, 下行 %s, 当前活跃: %d)",
                     oldest->sess_id, carrier_display_name(rt->spec.mode), lifetime_s > 0 ? lifetime_s : 0, up_s, down_s, active);
            free(oldest);
        }
    }

    // 创建新会话
    UdpSession *new_sess = (UdpSession *)calloc(1, sizeof(UdpSession));
    if (!new_sess) return nullptr;
    memcpy(&new_sess->client_addr, client_addr, client_len);
    new_sess->client_addr_len = client_len;
    format_endpoint_str(client_addr, new_sess->client_addr_str, sizeof(new_sess->client_addr_str));
    new_sess->upstream_fd = udp_connect_upstream_sa(target_ip, target_sa, target_salen, target_port);
    if (cfnat_socket_invalid(new_sess->upstream_fd)) {
        free(new_sess);
        return nullptr;
    }
    snprintf(new_sess->target_ip, sizeof(new_sess->target_ip), "%s", target_ip);
    new_sess->target_port = target_port;
    new_sess->created_ms = now_ms();
    new_sess->last_active_ms = new_sess->created_ms;
    new_sess->sess_id = atomic_fetch_add(&g_udp_sess_seq, 1) + 1;
    int active = atomic_fetch_add(&g_active_udp_sessions, 1) + 1;
    new_sess->next = rt->udp_sessions;
    rt->udp_sessions = new_sess;
    rt->last_udp_sess = new_sess;

    int is_quic = ((first_byte & 0x80) != 0 && (first_byte & 0x40) != 0);
    conn_msg("[UDP/H3] #%llu [%s] 客户端连接建立 (当前活跃: %d)",
             new_sess->sess_id, carrier_display_name(rt->spec.mode), active);
    conn_msg("[UDP/H3] #%llu [%s] 识别客户端协议: %s，转发到 IP: %s 端口: %d",
             new_sess->sess_id, carrier_display_name(rt->spec.mode),
             is_quic ? "QUIC/H3" : "UDP", new_sess->target_ip, new_sess->target_port);
    return new_sess;
}

static UdpSession *find_or_create_udp_session(CarrierRuntime *rt, const struct sockaddr_storage *client_addr, socklen_t client_len, const char *target_ip, int target_port, uint8_t first_byte) {
    return find_or_create_udp_session_sa(rt, client_addr, client_len, target_ip, nullptr, 0, target_port, first_byte);
}

static void prune_udp_sessions(CarrierRuntime *rt, long cur_ms) {
    if (!rt) return;
    int should_switch_udp = 0;
    pthread_mutex_lock(&rt->udp_mu);
    UdpSession *prev = nullptr;
    UdpSession *s = rt->udp_sessions;
    while (s) {
        /* 快速失效黑洞检测：若会话建立 >= 5s 且已发送报文 (>= 1200字节) 但从未收到任何回包 */
        int is_blackhole = (cur_ms - s->created_ms >= 5000 && s->bytes_up >= 1200 && s->bytes_down == 0);
        if (is_blackhole) {
            pthread_mutex_lock(&rt->udp_candidates.mu);
            if (strcmp(rt->udp_candidates.current_ip, s->target_ip) == 0) {
                if (atomic_fetch_add_explicit(&rt->udp_candidates.fast_fail_count, 1, memory_order_relaxed) + 1 >= 2) {
                    atomic_store_explicit(&rt->udp_candidates.fast_fail_count, 0, memory_order_relaxed);
                    atomic_store(&rt->udp_candidates.cache_valid, 0);
                    should_switch_udp = 1;
                }
            }
            pthread_mutex_unlock(&rt->udp_candidates.mu);
        }

        if (is_blackhole || cur_ms - s->last_active_ms > UDP_SESSION_TIMEOUT_MS) {
            UdpSession *del = s;
            if (rt->last_udp_sess == del) rt->last_udp_sess = nullptr;
            if (prev) {
                prev->next = s->next;
            } else {
                rt->udp_sessions = s->next;
            }
            s = s->next;
            if (cfnat_socket_valid(del->upstream_fd)) {
                close(del->upstream_fd);
            }
            int active = atomic_fetch_sub(&g_active_udp_sessions, 1) - 1;
            long lifetime_s = (cur_ms - del->created_ms) / 1000;
            char up_s[32] = {0}, down_s[32] = {0};
            format_bytes(del->bytes_up, up_s, sizeof(up_s));
            format_bytes(del->bytes_down, down_s, sizeof(down_s));
            conn_msg("[UDP/H3] #%llu [%s] 客户端会话关闭 (%s, 存活 %lds, 上行 %s, 下行 %s, 当前活跃: %d)",
                     del->sess_id, carrier_display_name(rt->spec.mode),
                     is_blackhole ? "黑洞剔除" : "空闲超时",
                     lifetime_s > 0 ? lifetime_s : 0, up_s, down_s, active);
            free(del);
        } else {
            prev = s;
            s = s->next;
        }
    }
    pthread_mutex_unlock(&rt->udp_mu);

    if (should_switch_udp && atomic_load(&g_running)) {
        log_msg("[UDP/H3] [%s] 检测到上游连续无回包响应 (可能受 UDP QoS 阻断)，触发顺位切换", carrier_display_name(rt->spec.mode));
        if (!carrier_switch_next_udp_ip(rt)) {
            log_msg("[UDP/H3] [%s] 候选池消耗达 70%% 或无可用顺位 IP，开始自愈维护双轨候选池", carrier_display_name(rt->spec.mode));
            carrier_rescan_dual_pools(rt);
        }
    }
}

static void *carrier_udp_thread(void *arg) {
    CarrierRuntime *rt = (CarrierRuntime *)arg;
    if (!rt || cfnat_socket_invalid(rt->udp_listen_fd)) return nullptr;

    /* C23 thread_local 线程局部缓冲区，零堆分配、零内存碎片、无小线程栈溢出隐患 */
    static thread_local char buf[UDP_BUF_SIZE];
    long last_prune_ms = now_ms();

    while (atomic_load(&g_running)) {
#ifdef _WIN32
        WSAPOLLFD pfds[UDP_MAX_SESSIONS + 1];
#else
        struct pollfd pfds[UDP_MAX_SESSIONS + 1];
#endif
        UdpSession *p_sess[UDP_MAX_SESSIONS + 1];
        size_t npfd = 0;

        pfds[0].fd = rt->udp_listen_fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        p_sess[0] = nullptr;
        npfd = 1;

        pthread_mutex_lock(&rt->udp_mu);
        UdpSession *s = rt->udp_sessions;
        while (s && npfd <= UDP_MAX_SESSIONS) {
            if (cfnat_socket_valid(s->upstream_fd)) {
                pfds[npfd].fd = s->upstream_fd;
                pfds[npfd].events = POLLIN;
                pfds[npfd].revents = 0;
                p_sess[npfd] = s;
                npfd++;
            }
            s = s->next;
        }
        pthread_mutex_unlock(&rt->udp_mu);

#ifdef _WIN32
        int nready = WSAPoll(pfds, (ULONG)npfd, 100);
#else
        int nready = poll(pfds, (nfds_t)npfd, 100);
#endif
        if (nready < 0) {
            if (!atomic_load(&g_running)) break;
            sleep_interruptible_ms(10);
            continue;
        }

        long cur_ms = now_ms();
        if (cur_ms - last_prune_ms >= 5000) {
            prune_udp_sessions(rt, cur_ms);
            last_prune_ms = cur_ms;
        }

        if (nready == 0) continue;

        int should_switch_udp = 0;

        /* 1. 优先检查各 upstream_fd 是否有来自 Cloudflare 的 UDP 回包或网络错误事件 */
        pthread_mutex_lock(&rt->udp_mu);
        for (size_t i = 1; i < npfd; i++) {
            if (pfds[i].revents & (POLLIN | POLLERR | POLLHUP)) {
                UdpSession *sess = p_sess[i];
                if (sess && cfnat_socket_valid(sess->upstream_fd) && sess->upstream_fd == pfds[i].fd) {
                    if (pfds[i].revents & (POLLERR | POLLHUP)) {
                        /* 触发 ICMP 不可达等套接字致命错误，关闭并失效上游 FD，杜绝 100% CPU 空转 */
                        close(sess->upstream_fd);
                        sess->upstream_fd = INVALID_SOCKET;
                        pthread_mutex_lock(&rt->udp_candidates.mu);
                        if (strcmp(rt->udp_candidates.current_ip, sess->target_ip) == 0) {
                            if (atomic_fetch_add_explicit(&rt->udp_candidates.fast_fail_count, 1, memory_order_relaxed) + 1 >= 2) {
                                atomic_store_explicit(&rt->udp_candidates.fast_fail_count, 0, memory_order_relaxed);
                                atomic_store(&rt->udp_candidates.cache_valid, 0);
                                should_switch_udp = 1;
                            }
                        }
                        pthread_mutex_unlock(&rt->udp_candidates.mu);
                        continue;
                    }
                    while (1) {
                        ssize_t n = recv(sess->upstream_fd, buf, UDP_BUF_SIZE, 0);
                        if (n <= 0) break;
                        sess->last_active_ms = cur_ms;
                        sess->bytes_down += (uint64_t)n;
                        atomic_store_explicit(&rt->udp_candidates.fast_fail_count, 0, memory_order_relaxed);
                        sendto(rt->udp_listen_fd, buf, (size_t)n, 0, (struct sockaddr *)&sess->client_addr, sess->client_addr_len);
                    }
                }
            }
        }
        pthread_mutex_unlock(&rt->udp_mu);

        if (should_switch_udp && atomic_load(&g_running)) {
            log_msg("[UDP/H3] [%s] 上游 UDP 连接返回网络错误 (ICMP 不可达)，触发顺位切换", carrier_display_name(rt->spec.mode));
            if (!carrier_switch_next_udp_ip(rt)) {
                log_msg("[UDP/H3] [%s] 候选池消耗达 70%% 或无可用顺位 IP，开始自愈维护双轨候选池", carrier_display_name(rt->spec.mode));
                carrier_rescan_dual_pools(rt);
            }
        }

        /* 2. 监听端口接收客户端 (如 Xray) 发来的 UDP / QUIC 报文 */
        if (pfds[0].revents & POLLIN) {
            char cur_target_ip[MAX_IP_LEN] = {0};
            struct sockaddr_storage cur_target_sa = {0};
            socklen_t cur_target_salen = 0;
            int have_target_info = 0;
            int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
            if (target_port <= 0) target_port = 443;

            pthread_mutex_lock(&rt->udp_mu);
            while (1) {
                struct sockaddr_storage client_ss;
#ifdef _WIN32
                int client_len = (int)sizeof(client_ss);
#else
                socklen_t client_len = sizeof(client_ss);
#endif
                ssize_t n = recvfrom(rt->udp_listen_fd, buf, UDP_BUF_SIZE, 0, (struct sockaddr *)&client_ss, &client_len);
                if (n <= 0) break;

                /* P0-MRU 协同加速：优先比对最近活跃会话，命中且 socket 有效时免查候选池，直通转发 */
                UdpSession *sess = rt->last_udp_sess;
                if (!sess || !sockaddr_equal(&sess->client_addr, &client_ss) || cfnat_socket_invalid(sess->upstream_fd)) {
                    if (!have_target_info) {
                        carrier_get_current_udp_ip_sa(rt, cur_target_ip, sizeof(cur_target_ip), &cur_target_sa, &cur_target_salen);
                        have_target_info = 1;
                    }
                    if (cur_target_ip[0]) {
                        sess = find_or_create_udp_session_sa(rt, &client_ss, (socklen_t)client_len, cur_target_ip, &cur_target_sa, cur_target_salen, target_port, (uint8_t)buf[0]);
                    } else {
                        sess = nullptr;
                    }
                }
                if (sess && cfnat_socket_valid(sess->upstream_fd)) {
                    sess->last_active_ms = cur_ms;
                    sess->bytes_up += (uint64_t)n;
                    send(sess->upstream_fd, buf, (size_t)n, 0);
                }
            }
            pthread_mutex_unlock(&rt->udp_mu);
        }
    }

    return nullptr;
}

static socket_t accept_interruptible(socket_t listen_fd, struct sockaddr *addr,
#ifdef _WIN32
        int *addrlen
#else
        socklen_t *addrlen
#endif
) {
    while (atomic_load(&g_running)) {
        int rc = cfnat_poll_single(listen_fd, 1, 1000);
        if (rc < 0) {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err == WSAEINTR) continue;
            return INVALID_SOCKET;
#else
            if (errno == EINTR) continue;
            return INVALID_SOCKET;
#endif
        }
        if (rc == 0) continue;

        socket_t cfd = accept(listen_fd, addr, addrlen);
#ifdef _WIN32
        if (cfnat_socket_invalid(cfd) && WSAGetLastError() == WSAEINTR) continue;
#else
        if (cfnat_socket_invalid(cfd) && errno == EINTR) continue;
#endif
        return cfd;
    }

#ifdef _WIN32
    WSASetLastError(WSAEINTR);
#else
    errno = EINTR;
#endif
    return INVALID_SOCKET;
}

static void on_signal(int sig) {
    (void)sig;
    atomic_store(&g_running, 0);
}

static void install_signals(void) {
#ifdef _WIN32
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
#endif
}

int main(int argc, char **argv) {
#ifdef _WIN32
    init_windows_console_utf8();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif
    parse_args(&g_cfg, argc, argv);
    log_current_config(&g_cfg);
    if (validate_bind_interface(&g_cfg) != 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    install_signals();
    if (g_cfg.bind_if[0]) log_msg("出站连接绑定网络接口: %s", g_cfg.bind_if);
    CarrierListenSpec *carrier_specs = nullptr;
    size_t carrier_spec_len = 0;
    if (parse_listen_modes(&g_cfg, &carrier_specs, &carrier_spec_len) != 0) {
        log_msg("解析监听模式失败");
        free(g_locations);
        return 1;
    }

    // 确保 locations.json 已经加载
    if (!g_locations || g_location_count == 0) {
        log_msg("正在加载 locations.json");
        load_locations();
        log_msg("locations 加载完成: %zu 条", g_location_count);
    }

    /* 检查并下载所需 IP 库文件 */
    int need_v4 = 0, need_v6 = 0;
    if (carrier_spec_len > 0) {
        for (size_t i = 0; i < carrier_spec_len; i++) {
            if (carrier_specs[i].prof.ips_type == 6) need_v6 = 1;
            else need_v4 = 1;
        }
    } else {
        if (g_cfg.ips_type == 6) need_v6 = 1;
        else need_v4 = 1;
    }

    if (need_v4 && ensure_data_file("ips-v4.txt", IPS_V4_URLS) != 0) {
        log_msg("下载 ips-v4.txt 失败");
        free(carrier_specs);
        free(g_locations);
        return 1;
    }
    if (need_v6 && ensure_data_file("ips-v6.txt", IPS_V6_URLS) != 0) {
        log_msg("下载 ips-v6.txt 失败");
        free(carrier_specs);
        free(g_locations);
        return 1;
    }
    if (carrier_spec_len > 0) {
        size_t started_count = 0;
        g_carrier_runtimes = calloc(carrier_spec_len, sizeof(CarrierRuntime));
        if (!g_carrier_runtimes) {
            free(carrier_specs);
            baidu_pool_free(&g_default_proxy_pool);
            free(g_locations);
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        g_carrier_runtime_count = carrier_spec_len;
        log_msg("转发监听模式启动，监听器数量: %zu", carrier_spec_len);
        for (size_t i = 0; i < carrier_spec_len; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];
            rt->listen_fd = INVALID_SOCKET;
            rt->udp_listen_fd = INVALID_SOCKET;
            rt->udp_sessions = nullptr;
            pthread_mutex_init(&rt->udp_mu, nullptr);
            rt->spec = carrier_specs[i];
            pthread_mutex_init(&rt->candidates.mu, nullptr);
            atomic_init(&rt->candidates.cache_valid, 0);  /* P0-1: 初始时缓存无效 */
            pthread_mutex_init(&rt->udp_candidates.mu, nullptr);
            atomic_init(&rt->udp_candidates.cache_valid, 0);
            atomic_init(&rt->rescanning_lock, 0);
        }
        int baidu_pool_ok = 1;
        for (size_t i = 0; i < carrier_spec_len; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];
            if (rt->spec.use_baidu_proxy) {
                if (!carrier_init_baidu_pool(rt)) {
                    baidu_pool_ok = 0;
                    break;
                }
                if (rt->spec.prof.ips_type == 6 && !carrier_check_baidu_ipv6_support(rt)) {
                    baidu_pool_ok = 0;
                    break;
                }
            }
        }
        if (!baidu_pool_ok) {
            free(carrier_specs);
            for (size_t i = 0; i < g_carrier_runtime_count; i++) {
                CarrierRuntime *rt = &g_carrier_runtimes[i];
                pthread_mutex_destroy(&rt->candidates.mu);
                pthread_mutex_destroy(&rt->udp_candidates.mu);
                pthread_mutex_destroy(&rt->udp_mu);
                if (rt->proxy_pool) {
                    baidu_pool_free(rt->proxy_pool);
                    free(rt->proxy_pool);
                }
            }
            free(g_carrier_runtimes);
            g_carrier_runtimes = nullptr;
            g_carrier_runtime_count = 0;
            baidu_pool_free(&g_default_proxy_pool);
            free(g_locations);
            g_locations = nullptr;
            g_location_count = 0;
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
        for (size_t i = 0; i < carrier_spec_len; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];

            ResultList carrier_results = {0};
            // 先尝试读取候选缓存 (TCP + UDP 双轨缓存)
            if (carrier_try_use_candidate_caches(rt)) {
                rt->listen_fd = listen_tcp(rt->spec.addr);
                rt->udp_listen_fd = listen_udp(rt->spec.addr);
                if (cfnat_socket_invalid(rt->listen_fd)) {
                    log_msg("[%s] 无法监听 %s: %s", carrier_display_name(rt->spec.mode), rt->spec.addr, strerror(errno));
                    if (cfnat_socket_valid(rt->udp_listen_fd)) {
                        close(rt->udp_listen_fd);
                        rt->udp_listen_fd = INVALID_SOCKET;
                    }
                    free(rt->candidates.items);
                    rt->candidates.items = nullptr;
                    rt->candidates.len = 0;
                    free(rt->udp_candidates.items);
                    rt->udp_candidates.items = nullptr;
                    rt->udp_candidates.len = 0;
                    continue;
                }
                log_msg("[%s] 正在监听 %s (双轨分流: TCP/H2 + UDP/H3)，TLS目标端口：%d，非TLS目标端口：%d",
                        carrier_display_name(rt->spec.mode), rt->spec.addr,
                        rt->spec.prof.port, rt->spec.prof.http_port);
                create_small_thread(&rt->health_tid, carrier_health_thread, rt);
                create_small_thread(&rt->udp_health_tid, carrier_udp_health_thread, rt);
                create_small_thread(&rt->accept_tid, carrier_accept_thread, rt);
                if (cfnat_socket_valid(rt->udp_listen_fd)) {
                    create_small_thread(&rt->udp_tid, carrier_udp_thread, rt);
                }
                started_count++;
                continue;
            }

            const char *cur_ipfile = (rt->spec.prof.ips_type == 6) ? "ips-v6.txt" : "ips-v4.txt";
            int cur_v6_split = (rt->spec.prof.v6_split > 0) ? rt->spec.prof.v6_split : g_cfg.v6_split;
            int use_cidr = (rt->spec.prof.ips_type == 4 && !rt->spec.prof.random_mode);
            CidrList profile_cidrs = {0};
            StringList profile_ips = {0};
            if (use_cidr) {
                profile_cidrs = load_cidr_list(cur_ipfile, 0);
                if (profile_cidrs.len == 0) {
                    warn_msg("[%s] 没有可扫描的 IP (%s 为空)", carrier_display_name(rt->spec.mode), cur_ipfile);
                    continue;
                }
            } else {
                profile_ips = load_ip_list(cur_ipfile, rt->spec.prof.random_mode, cur_v6_split);
                if (profile_ips.len == 0) {
                    warn_msg("[%s] 没有可扫描的 IP (%s 为空)", carrier_display_name(rt->spec.mode), cur_ipfile);
                    continue;
                }
            }

            Config scan_cfg = g_cfg;
            scan_cfg.ips_type = rt->spec.prof.ips_type;
            scan_cfg.port = rt->spec.prof.port;
            scan_cfg.http_port = rt->spec.prof.http_port;
            scan_cfg.delay_ms = rt->spec.prof.delay_ms;
            scan_cfg.task = rt->spec.prof.task;
            size_t target_ipnum = (size_t)(rt->spec.prof.ipnum > 0 ? rt->spec.prof.ipnum : g_cfg.ipnum);
            if (target_ipnum == 0) target_ipnum = 20;
            scan_cfg.ipnum = (int)target_ipnum;
            scan_cfg.num = rt->spec.prof.num;
            scan_cfg.random_mode = rt->spec.prof.random_mode;
            scan_cfg.v6_split = cur_v6_split;
            scan_cfg.code = rt->spec.prof.code;
            snprintf(scan_cfg.domain, sizeof(scan_cfg.domain), "%s", rt->spec.prof.domain);
            snprintf(scan_cfg.colo, sizeof(scan_cfg.colo), "%s", rt->spec.prof.colo);

            if (rt->spec.use_baidu_proxy == 2) {
                ResultList results_direct = scan_ips(use_cidr ? nullptr : &profile_ips, use_cidr ? &profile_cidrs : nullptr, &scan_cfg, nullptr);
                ResultList results_baidu = {0};
                if (rt->proxy_pool && rt->proxy_pool->len > 0) {
                    results_baidu = scan_ips(use_cidr ? nullptr : &profile_ips, use_cidr ? &profile_cidrs : nullptr, &scan_cfg, rt->proxy_pool);
                }

                for (size_t j = 0; j < results_direct.len; j++) {
                    resultlist_add(&carrier_results, &results_direct.items[j]);
                }
                for (size_t j = 0; j < results_baidu.len; j++) {
                    int exists = 0;
                    for (size_t k = 0; k < carrier_results.len; k++) {
                        if (strcmp(carrier_results.items[k].ip, results_baidu.items[j].ip) == 0) {
                            exists = 1;
                            break;
                        }
                    }
                    if (!exists) {
                        resultlist_add(&carrier_results, &results_baidu.items[j]);
                    }
                }
                free(results_direct.items);
                free(results_baidu.items);

                if (carrier_results.len > 0) {
                    qsort(carrier_results.items, carrier_results.len, sizeof(Result), cmp_result);
                }
            } else {
                carrier_results = scan_ips(use_cidr ? nullptr : &profile_ips, use_cidr ? &profile_cidrs : nullptr, &scan_cfg, rt->proxy_pool);
            }
            if (use_cidr) cidrlist_destroy(&profile_cidrs);
            else strlist_free(&profile_ips);

            if (carrier_results.len == 0) {
                warn_msg("[%s] 未扫描到可用候选 IP", carrier_display_name(rt->spec.mode));
                continue;
            }

            // 1. 设置 TCP 候选池 (精准截取前 target_ipnum 个)
            size_t tcp_target = target_ipnum;
            size_t tcp_count = carrier_results.len > tcp_target ? tcp_target : carrier_results.len;
            rt->candidates.items = calloc(tcp_count, sizeof(Result));
            if (rt->candidates.items) {
                memcpy(rt->candidates.items, carrier_results.items, tcp_count * sizeof(Result));
                rt->candidates.len = tcp_count;
                carrier_set_current_candidate(rt, 0);
                atomic_store(&rt->candidates.cache_valid, 1);
                save_candidate_cache(candidate_cache_file_for_profile(rt->spec.mode, rt->spec.prof.ips_type), rt->candidates.items, rt->candidates.len);
            }

            // 2. 设置 UDP 候选池 (多轮滑动检验 + 网段裂变衍生)
            ResultList udp_res = filter_udp_candidates_from_tcp(rt, carrier_results.items, carrier_results.len, target_ipnum);
            if (udp_res.len > 0) {
                rt->udp_candidates.items = udp_res.items;
                rt->udp_candidates.len = udp_res.len;
                carrier_set_current_udp_candidate(rt, 0);
                atomic_store(&rt->udp_candidates.cache_valid, 1);
                save_candidate_cache(candidate_cache_file_for_profile_udp(rt->spec.mode, rt->spec.prof.ips_type), udp_res.items, udp_res.len);
            } else {
                warn_msg("[%s] 经过多轮滑动检验，未捕获到有效 UDP/QUIC 节点（当地网络可能阻断境外 UDP 443），绝不使用假节点降级，等待自愈重扫",
                         carrier_display_name(rt->spec.mode));
            }

            free(carrier_results.items);

            if (!carrier_select_valid_ip(rt)) {
                warn_msg("[%s] TCP 候选 IP 健康检查全部失败", carrier_display_name(rt->spec.mode));
                free(rt->candidates.items);
                rt->candidates.items = nullptr;
                rt->candidates.len = 0;
                free(rt->udp_candidates.items);
                rt->udp_candidates.items = nullptr;
                rt->udp_candidates.len = 0;
                continue;
            }
            rt->listen_fd = listen_tcp(rt->spec.addr);
            rt->udp_listen_fd = listen_udp(rt->spec.addr);
            if (cfnat_socket_invalid(rt->listen_fd)) {
                log_msg("[%s] 无法监听 %s: %s", carrier_display_name(rt->spec.mode), rt->spec.addr, strerror(errno));
                if (cfnat_socket_valid(rt->udp_listen_fd)) {
                    close(rt->udp_listen_fd);
                    rt->udp_listen_fd = INVALID_SOCKET;
                }
                free(rt->candidates.items);
                rt->candidates.items = nullptr;
                rt->candidates.len = 0;
                free(rt->udp_candidates.items);
                rt->udp_candidates.items = nullptr;
                rt->udp_candidates.len = 0;
                continue;
            }
            int tcp_lat = (rt->candidates.items && rt->candidates.current_index < rt->candidates.len) ?
                          rt->candidates.items[rt->candidates.current_index].latency_ms : 0;
            int udp_lat = (rt->udp_candidates.items && rt->udp_candidates.current_index < rt->udp_candidates.len) ?
                          rt->udp_candidates.items[rt->udp_candidates.current_index].latency_ms : 0;

            if (rt->udp_candidates.len > 0 && rt->udp_candidates.current_ip[0]) {
                log_msg("[%s] 正在监听 %s (双轨分流: TCP/H2 + UDP/H3)，TLS目标端口：%d，非TLS目标端口：%d\n"
                        "  ├─ [TCP/H2] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)\n"
                        "  └─ [UDP/H3] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)",
                        carrier_display_name(rt->spec.mode), rt->spec.addr,
                        rt->spec.prof.port, rt->spec.prof.http_port,
                        rt->candidates.current_ip, tcp_lat, rt->candidates.len,
                        rt->udp_candidates.current_ip, udp_lat, rt->udp_candidates.len);
            } else {
                log_msg("[%s] 正在监听 %s (双轨分流: TCP/H2 + UDP/H3)，TLS目标端口：%d，非TLS目标端口：%d\n"
                        "  ├─ [TCP/H2] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)\n"
                        "  └─ [UDP/H3] 无可用节点 (0 个候选)",
                        carrier_display_name(rt->spec.mode), rt->spec.addr,
                        rt->spec.prof.port, rt->spec.prof.http_port,
                        rt->candidates.current_ip, tcp_lat, rt->candidates.len);
            }

            create_small_thread(&rt->health_tid, carrier_health_thread, rt);
            create_small_thread(&rt->udp_health_tid, carrier_udp_health_thread, rt);
            create_small_thread(&rt->accept_tid, carrier_accept_thread, rt);
            if (cfnat_socket_valid(rt->udp_listen_fd)) {
                create_small_thread(&rt->udp_tid, carrier_udp_thread, rt);
            }
            started_count++;
        }
        free(carrier_specs);
        if (started_count == 0) {
            for (size_t i = 0; i < g_carrier_runtime_count; i++) {
                CarrierRuntime *rt = &g_carrier_runtimes[i];
                free(rt->candidates.items);
                pthread_mutex_destroy(&rt->candidates.mu);
                free(rt->udp_candidates.items);
                pthread_mutex_destroy(&rt->udp_candidates.mu);
                pthread_mutex_destroy(&rt->udp_mu);
                if (rt->proxy_pool) {
                    baidu_pool_free(rt->proxy_pool);
                    free(rt->proxy_pool);
                }
            }
            free(g_carrier_runtimes);
            g_carrier_runtimes = nullptr;
            g_carrier_runtime_count = 0;
            baidu_pool_free(&g_default_proxy_pool);
            free(g_locations);
            g_locations = nullptr;
            g_location_count = 0;
            return 1;
        }
        while (atomic_load(&g_running)) {
            if (sleep_interruptible_ms(1000) != 0) break;
        }
        for (size_t i = 0; i < g_carrier_runtime_count; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];
            if (cfnat_socket_valid(rt->listen_fd)) {
                close(rt->listen_fd);
                rt->listen_fd = INVALID_SOCKET;
            }
            if (cfnat_socket_valid(rt->udp_listen_fd)) {
                close(rt->udp_listen_fd);
                rt->udp_listen_fd = INVALID_SOCKET;
            }
        }
        for (size_t i = 0; i < g_carrier_runtime_count; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];
            if (rt->health_tid) pthread_join(rt->health_tid, nullptr);
            if (rt->udp_health_tid) pthread_join(rt->udp_health_tid, nullptr);
            if (rt->accept_tid) pthread_join(rt->accept_tid, nullptr);
            if (rt->udp_tid) pthread_join(rt->udp_tid, nullptr);
        }
        /* 等待所有正在收尾的 TCP 活跃连接线程安全退出，杜绝 UAF */
        long drain_start = now_ms();
        while (atomic_load(&g_active_tcp_conns) > 0 && (now_ms() - drain_start) < 2000) {
            sleep_ms_raw(20);
        }
        for (size_t i = 0; i < g_carrier_runtime_count; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];
            pthread_mutex_lock(&rt->udp_mu);
            UdpSession *s = rt->udp_sessions;
            while (s) {
                UdpSession *next = s->next;
                if (cfnat_socket_valid(s->upstream_fd)) close(s->upstream_fd);
                atomic_fetch_sub(&g_active_udp_sessions, 1);
                free(s);
                s = next;
            }
            rt->udp_sessions = nullptr;
            rt->last_udp_sess = nullptr;
            pthread_mutex_unlock(&rt->udp_mu);
            pthread_mutex_destroy(&rt->udp_mu);
            free(rt->candidates.items);
            rt->candidates.items = nullptr;
            rt->candidates.len = 0;
            pthread_mutex_destroy(&rt->candidates.mu);
            free(rt->udp_candidates.items);
            rt->udp_candidates.items = nullptr;
            rt->udp_candidates.len = 0;
            pthread_mutex_destroy(&rt->udp_candidates.mu);
            if (rt->proxy_pool) {
                baidu_pool_free(rt->proxy_pool);
                free(rt->proxy_pool);
                rt->proxy_pool = nullptr;
            }
        }
        free(g_carrier_runtimes);
        g_carrier_runtimes = nullptr;
        g_carrier_runtime_count = 0;
        baidu_pool_free(&g_default_proxy_pool);
        free(g_locations);
        g_locations = nullptr;
        g_location_count = 0;
        return 0;
    }
    long start = now_ms();
    const char *cli_ipfile = (g_cfg.ips_type == 6) ? "ips-v6.txt" : "ips-v4.txt";
    // 先尝试读取候选缓存，如果命中且健康检查通过则跳过完整扫描
    ResultList results = {0};
    int cache_hit = try_use_candidate_cache(nullptr, &results);
    if (!cache_hit) {
        if (g_cfg.ips_type == 4 && !g_cfg.random_mode) {
            /* IPv4 顺序模式：惰性二分定位，O(1) 内存，零堆分配展开 */
            CidrList cidrs = load_cidr_list(cli_ipfile, 0);
            if (cidrs.len == 0) {
                log_msg("没有可扫描的 IP (%s 为空)", cli_ipfile);
                baidu_pool_free(&g_default_proxy_pool);
                free(g_locations);
                return 1;
            }
            results = scan_ips(nullptr, &cidrs, &g_cfg, nullptr);
            cidrlist_destroy(&cidrs);
        } else {
            StringList ips = load_ip_list(cli_ipfile, g_cfg.random_mode, g_cfg.v6_split);
            if (ips.len == 0) {
                log_msg("没有可扫描的 IP (%s 为空)", cli_ipfile);
                baidu_pool_free(&g_default_proxy_pool);
                free(g_locations);
                return 1;
            }
            results = scan_ips(&ips, nullptr, &g_cfg, nullptr);
            strlist_free(&ips);
        }
        if (results.len > 0) {
            save_candidate_cache(candidate_cache_file("direct"), results.items, results.len);
        }
    }
    if (!cache_hit || g_cfg.log_level >= LOG_DEBUG) {
        print_results_table_stream(stdout, results.items, results.len, (now_ms() - start) / 1000);
    }
    if (results.len > 0) {
        int use_color = terminal_has_color(stdout);
        const char *c_bold = use_color ? ANSI_BOLD : "";
        const char *c_cyan = use_color ? ANSI_CYAN : "";
        const char *c_green = use_color ? ANSI_GREEN : "";
        const char *reset = use_color ? ANSI_RESET : "";
        printf("%s评分最优 IP:%s %s%s%s\n", c_bold, reset, c_cyan, results.items[0].ip, reset);
        printf("%s最佳延迟:%s %s%d ms%s\n", c_bold, reset, c_green, results.items[0].latency_ms, reset);
        printf("%s最佳丢包率:%s %s%d%%%s\n", c_bold, reset, c_green, results.items[0].loss_rate, reset);
        explain_selected_result(&results.items[0]);
    }
    free(results.items);
    baidu_pool_free(&g_default_proxy_pool);
    free(g_locations);
    g_locations = nullptr;
    g_location_count = 0;
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
