#define CFNAT_VERSION "0.1.3"

/* =========================================================================
 * C23 (ISO/IEC 9899:2024) Standard Compatibility & Polyfill Layer
 * ========================================================================= */
#ifndef TCP_NOTSENT_LOWAT
#define TCP_NOTSENT_LOWAT 25
#endif
#ifndef TCP_USER_TIMEOUT
#define TCP_USER_TIMEOUT 18
#endif
#ifndef TCP_CONGESTION
#define TCP_CONGESTION 13
#endif
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
  #ifndef thread_local
    #if defined(_MSC_VER)
      #define thread_local __declspec(thread)
    #elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
      #define thread_local _Thread_local
    #else
      #define thread_local __thread
    #endif
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
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
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
CFNAT_NODISCARD static inline bool cfnat_is_transient_error(int err) {
    return (err == WSAECONNRESET || err == WSAENETRESET ||
            err == WSAEHOSTUNREACH || err == WSAENETUNREACH ||
            err == WSAECONNREFUSED || err == WSAEINTR);
}
CFNAT_NODISCARD static inline bool cfnat_last_socket_transient(void) {
    return cfnat_is_transient_error(WSAGetLastError());
}
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
CFNAT_NODISCARD static inline bool cfnat_is_transient_error(int err) {
    return (err == ECONNREFUSED || err == EHOSTUNREACH ||
            err == ENETUNREACH || err == ECONNRESET || err == EINTR);
}
CFNAT_NODISCARD static inline bool cfnat_last_socket_transient(void) {
    return cfnat_is_transient_error(errno);
}
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
#define COPY_BUF_SIZE 65'536
#else
#define COPY_BUF_SIZE 65536
#endif
#define MAX_ADDR_LEN 128
#define MAX_NAME_LEN 64
#define MAX_DOMAIN_LEN 256
#define MAX_PATH_LEN 256
#define MAX_RESOLVER_LEN 64
#define MAX_RESOLVER_SPEC_LEN 256

/* 疑似 QoS 窗口：探测侧（扫描/健康检查）与转发侧（下行猝死）共享的状态时长。
 * 必须定义在这里——扫描器（filter_udp_candidates_from_tcp）在会话管理章节之前就会用到，
 * 之前放在 UDP 章节导致 6 个目标全部编译失败（use of undeclared identifier）。 */
#define QOS_WINDOW_DEFAULT_MS 30000L   /* 转发侧（下行猝死）登记的窗口时长 */
#define QOS_WINDOW_SCAN_MS 8000L       /* 探测侧（金丝雀连挂 / 整批 0 回包）登记的窗口时长 */
static const char *DEFAULT_BAIDU_DOMAIN = "cloudnproxy.baidu.com";
CFNAT_CONSTEXPR int DEFAULT_BAIDU_PORT = 443;
CFNAT_CONSTEXPR int DEFAULT_BAIDU_IPNUM = 12;
/* 百度前置 CONNECT 的最小超时预算（毫秒）。CONNECT 是两跳握手（TCP 到节点 + 节点回源 CF + 200），
 * 实测 90~1200ms，不能用 -delay 这类「单程 RTT 上限」直接当预算，否则大比例误判连接失败。 */
CFNAT_CONSTEXPR int BAIDU_CONNECT_MIN_TIMEOUT_MS = 1500;
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
    int enable_h2;            /* 1=启用 TCP/H2 监听与测活, 0=关闭 (纯 H3 模式) */
    int enable_h3;            /* 1=启用 UDP/H3 测优与转发, 0=关闭 (纯 H2 模式) */
} ProfileConfig;

typedef struct {
    char colo[256], domain[256], log_name[16];
    char baidu_domain[MAX_DOMAIN_LEN], baidu_scan_target[MAX_ADDR_LEN];
    char direct_listen[MAX_ADDR_LEN], baidu_listen[MAX_ADDR_LEN];
    char v4_listen[MAX_ADDR_LEN], v6_listen[MAX_ADDR_LEN];
    char bind_if[MAX_NAME_LEN], baidu_resolver[MAX_RESOLVER_SPEC_LEN];
    int code, delay_ms, ipnum, ips_type, num, port, http_port, random_mode, task, health_log;
    int stats_interval;       /* 三栈双协议运行指标输出间隔（秒），0=关闭。
                               * 与健康检查节奏解耦：健康检查本身是自适应的 10s/30s/60s，
                               * health_log 只控制「健康状态行」这类 debug 明细的输出频率。 */
    int v6_split;             /* 全局 IPv6 细分子网前缀 (默认 54) */
    int use_baidu_proxy, baidu_port, baidu_ipnum;
    int cli_mode;             /* 显式单次 CLI 测速模式 (-cli / -scan-only) */
    int h3_client;            /* 1=使用真实加密 RFC 9001 QUIC v1 Initial (TLS 1.3 ClientHello) 探测 H3; 0=默认轻量 VN 探针 */
    int enable_h2;            /* 全局默认启用 TCP/H2 (默认 1) */
    int enable_h3;            /* 全局默认启用 UDP/H3 (默认 1) */
    LogLevel log_level;
    ProfileConfig prof_v4;
    ProfileConfig prof_v6;
    ProfileConfig prof_baidu;
    int listen_order[3];      /* 命令行传参顺序: 1=v4, 2=v6, 3=baidu (baidu 强制排在 v4 之后) */
    int listen_order_len;
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
    long last_fail_ms;
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
    int target_port;
    int is_tls;
    char probe_host[MAX_DOMAIN_LEN];
    char probe_path[MAX_PATH_LEN];
    int hdr_timeout;
    atomic_size_t code_meta_skip;  /* -code 校验因 80 端口不可达而被跳过的次数（用于一次性提示） */
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
        if (base == 0 || prefix < 8 || prefix > 32) continue;
        uint32_t mask = (0xffffffffu << (32 - prefix));
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
    struct sockaddr_storage sa;
    socklen_t salen;
    int port;
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
    atomic_int has_node_fail; /* 仅 TCP 候选池使用（UDP 池恒为 0）：避免连接关闭时无锁读取 items 导致 UAF */
    atomic_ullong epoch;      /* 候选变更版本号：UDP 热路径 O(1) 无锁感知优选 IP 切换 */
    pthread_mutex_t mu;
    atomic_int cache_valid;   /* P0-1: 1=当前 IP 可直接使用，0=需要重新选择 */
    atomic_int switch_lock;   /* P1-3: 防止并发切换竞争导致 current_index 乱序与抖动 */
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

#define MAINT_SWITCH_TCP 0x01
#define MAINT_SWITCH_UDP 0x02
#define MAINT_RESCAN     0x04

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
    pthread_t maint_tid;           /* P1-5: 异步维护线程 (顺位切换与自愈扫描解耦，转发面零阻塞) */
    atomic_int maint_pending;      /* 待处理维护任务位图 */
    pthread_mutex_t maint_mu;
    pthread_cond_t maint_cv;
    UdpSession *udp_sessions;
    UdpSession *udp_hash[256];     /* P1: 8位哈希分桶，提供 O(1) UDP 会话检索 */
    UdpSession *last_udp_sess;     /* P0-MRU: 单级热点会话缓存 (为 H3 多路复用提供 O(1) 检索) */
    size_t udp_session_count;      /* 本实例活跃 UDP 会话数，独立限额防跨实例互相挤压 */
    uint64_t udp_down_drop;        /* 下行非阻塞 sendmmsg/sendto 队列满丢包计数 */
    int udp_down_drop_warned;      /* 首次下行溢出使用 warn_msg 告警，后续回落 debug_msg 防刷屏 */
    atomic_uint tcp_switch_count;  /* H2 顺位切换累计次数（运行指标，仅统计） */
    atomic_uint udp_switch_count;  /* H3 顺位切换累计次数（运行指标，仅统计） */
    atomic_uint udp_up_drop;       /* 上行（客户端→上游）UDP 发送失败计数，与 udp_down_drop 对称 */
    atomic_ullong udp_down_drop_stats; /* 下行丢包周期统计原子计数（与 5s 告警解耦，零数据竞争） */
    atomic_int active_tcp_conns;       /* 本栈当前活跃 TCP 连接数（活跃态按需提速健康检查） */
    atomic_int active_udp_conns;       /* 本栈当前活跃 UDP 会话数（无锁读取，供健康检查判断活跃态） */
    atomic_llong last_tcp_active_ms;   /* 本栈最近一次 TCP 活跃时间戳 */
    atomic_llong last_udp_active_ms;   /* 本栈最近一次 UDP 活跃时间戳 */
    atomic_int last_udp_loss_pct;      /* 最近一轮 UDP 健康检查链路丢包率 (0..100, -1=未测) */
    /* 疑似 QoS 窗口（探测侧与转发侧共享）：
     * 到期前，扫描不把 IP 判死、健康检查不计失败、切换最多放行一次，避免双方同时误判造成空池与抖动。 */
    atomic_llong qos_suspect_until_ms;
    atomic_int qos_switch_used;        /* 本窗口内是否已执行过顺位切换（防连续切换抖动） */
    int udp_dirty;                 /* 会话表变更标记：未变更时直接复用 pollfd 数组，免除每轮链表遍历 */
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
    const char *no_color = getenv("NO_COLOR");
    if (no_color && no_color[0] != '\0' && strcmp(no_color, "0") != 0) return 0;
    const char *force = getenv("FORCE_COLOR");
    if (!force || !force[0]) force = getenv("CLICOLOR_FORCE");
    if (force && force[0] != '\0' && strcmp(force, "0") != 0) return 1;
    int fd = fileno(stream);
    if (fd < 0) return 0;
    return isatty(fd);
}

/* 协议 tag 染色：与 vlog_line 里 [TCP/H2] / [UDP/H3] 的配色保持一致，方便一眼区分双协议列表 */
static const char *proto_tag_color(const char *proto) {
    if (!proto) return "";
    if (strcmp(proto, "UDP/H3") == 0) return ANSI_MAGENTA ANSI_BOLD;
    return ANSI_CYAN ANSI_BOLD;
}

/* 输出候选列表表格。
 * proto: "TCP/H2" / "UDP/H3"（NULL 表示不打印协议 tag）；label: 栈名（可为 NULL）。 */
static void print_results_table_ex(FILE *stream, const char *proto, const char *label,
                                  const Result *items, size_t count, long duration_sec) {
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

    fprintf(stream, "\n");
    if (proto) {
        const char *pc = use_color ? proto_tag_color(proto) : "";
        fprintf(stream, "%s[%s]%s%s", pc, proto, reset, c_bold);
        if (label && label[0]) fprintf(stream, " [%s]", label);
        fprintf(stream, " 候选列表 (共 %zu 个)%s\n", count, reset);
    }
    fprintf(stream, "%sIP 地址%s          | %s数据中心%s | %s地区%s          | %s城市%s        | %s延迟%s\n",
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
    if (proto && strcmp(proto, "UDP/H3") == 0) {
        fprintf(stream, "\n%s%sH3 候选池共 %zu 个可用节点，耗时 %ld秒%s\n\n",
                c_bold, c_val_green, count, duration_sec, reset);
    } else {
        fprintf(stream, "\n%s%s成功提取 %zu 个有效IP，耗时 %ld秒%s\n\n",
                c_bold, c_val_green, count, duration_sec, reset);
    }
    fflush(stream);
    pthread_mutex_unlock(&g_log_mu);
}


static long now_ms(void) {
#ifdef _WIN32
    static atomic_llong s_qpf = 0;
    static atomic_llong s_qpc_base = 0;
    long long freq = atomic_load_explicit(&s_qpf, memory_order_acquire);
    if (freq == 0) {
        LARGE_INTEGER li_freq = {0}, li_now = {0};
        if (QueryPerformanceFrequency(&li_freq) && li_freq.QuadPart > 0 && QueryPerformanceCounter(&li_now)) {
            long long expected = 0;
            atomic_compare_exchange_strong(&s_qpc_base, &expected, (long long)li_now.QuadPart);
            atomic_store_explicit(&s_qpf, (long long)li_freq.QuadPart, memory_order_release);
            freq = (long long)li_freq.QuadPart;
        }
    }
    LARGE_INTEGER qpc;
    if (freq > 0 && QueryPerformanceCounter(&qpc)) {
        long long base = atomic_load_explicit(&s_qpc_base, memory_order_relaxed);
        long long delta = (long long)qpc.QuadPart - base;
        if (delta < 0) delta = 0;
        return (long)((delta * 1000LL) / freq);
    }
    return (long)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + (long)(ts.tv_nsec / 1000000L);
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
    static thread_local time_t s_last_sec = 0;
    static thread_local char s_cached_ts[32] = {0};
    char ts[32];
    if (t != s_last_sec || s_cached_ts[0] == '\0') {
        struct tm tmv;
#ifdef _WIN32
        localtime_s(&tmv, &t);
#else
        localtime_r(&t, &tmv);
#endif
        strftime(s_cached_ts, sizeof(s_cached_ts), "%Y/%m/%d %H:%M:%S", &tmv);
        s_last_sec = t;
    }
    memcpy(ts, s_cached_ts, 20);
    ts[19] = '\0';

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
    char raw_msg[2048];
    int n = vsnprintf(raw_msg, sizeof(raw_msg), fmt, ap);
    if (n < 0) return;

    /* 单一完整行缓冲输出，彻底杜绝并发日志交错与字符截断 */
    char line_buf[4096];
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
    printf("  -v6-listen[=addr]         开启 IPv6 本地监听地址 (默认 [::]:6443)\n");
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
    printf("  -v6-split=value           IPv6 细分抽样子网前缀 [1, 128] (单行上限 1024 样本，文件子网更小或完整IP按原粒度, default 54)\n");
    printf("  -task=value               并发扫描线程数 (default 200)\n");
    printf("  -cli, -scan-only          仅单次 CLI 测速并打印结果表格，不启动本地端口监听\n");
    printf("  -log=value                日志级别: silent,error,warn,info,debug (default info)\n");
    printf("  -stats-interval=value     三栈双协议运行指标汇报间隔秒数，0=关闭 (default 300)\n");
    printf("  -health-log=value         健康状态行(debug 级明细)输出间隔秒数，0=关闭 (default 60)\n");
    printf("  -h3-client[=bool]         H3 探测启用真实 QUIC v1 Initial (TLS 1.3 ClientHello) 模拟 (default false)\n");
    printf("  -h2[=bool] / -h3[=bool]   启用或关闭 H2(TCP) / H3(UDP) 协议，支持 -v4-/-v6-/-baidu- 前缀 (default true)\n");
    printf("  注: 以上参数均支持 -v4- 或 -v6- 前缀实现精细化覆盖，如 -v6-code=200 -v4-delay=150\n");
}

static int parse_bool(const char *v) {
    return !v || strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0 || strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0;
}

static void format_listen_endpoint(const char *in, int default_port, const char *default_host, char *out, size_t outsz) {
    if (!out || outsz == 0) return;
    if (!default_host || !*default_host) default_host = "0.0.0.0";
    int is_v6_host = (strchr(default_host, ':') != nullptr);
    if (!in || !*in) {
        if (is_v6_host && default_host[0] != '[') {
            snprintf(out, outsz, "[%s]:%d", default_host, default_port);
        } else {
            snprintf(out, outsz, "%s:%d", default_host, default_port);
        }
        return;
    }
    /* 如果输入是纯数字（端口），自动拼上缺省 host */
    int is_all_digit = 1;
    for (const char *p = in; *p; p++) {
        if (!isdigit((unsigned char)*p)) { is_all_digit = 0; break; }
    }
    if (is_all_digit) {
        if (is_v6_host && default_host[0] != '[') {
            snprintf(out, outsz, "[%s]:%s", default_host, in);
        } else {
            snprintf(out, outsz, "%s:%s", default_host, in);
        }
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
    c->health_log = 60;        /* 健康状态行 (debug 级) 输出间隔（秒），0 = 关闭；与运行指标无关 */
    c->stats_interval = 300;   /* 三栈双协议运行指标输出间隔（秒），0 = 关闭（-stats-interval=0） */
    c->h3_client = 0;          /* 默认关闭真实 QUIC ClientHello 模拟，使用轻量 VN 探针 */
    c->enable_h2 = 1;          /* 默认双协议启用 */
    c->enable_h3 = 1;
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
    c->listen_order_len = 0;
    char v4_listen_val[MAX_ADDR_LEN] = {0};
    char v6_listen_val[MAX_ADDR_LEN] = {0};
    char baidu_listen_val[MAX_ADDR_LEN] = {0};

    int v4_port = 0, v6_port = 0;
    int v4_http_port = 0, v6_http_port = 0;
    int v4_delay = 0, v6_delay = 0;
    int v4_task = 0, v6_task = 0;
    int v4_ipnum = 0, v6_ipnum = 0;
    int v4_num = 0, v6_num = 0;
    int v4_code = -1, v6_code = -1, baidu_code = -1; /* -1 表示未指定专属 */
    int v4_random = -1, v6_random = -1;
    int v4_h2 = -1, v4_h3 = -1, v6_h2 = -1, v6_h3 = -1, baidu_h2 = -1, baidu_h3 = -1;
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

        /* 本地监听参数解析: 支持 -v4-listen, -v6-listen, -baidu-listen, -direct-listen，记录传参顺序 */
        if (!strcmp(key, "v4-listen")) {
            has_v4_listen = 1;
            format_listen_endpoint(val, 4443, "0.0.0.0", v4_listen_val, sizeof(v4_listen_val));
            int dup = 0; for (int k = 0; k < c->listen_order_len; k++) if (c->listen_order[k] == 1) dup = 1;
            if (!dup && c->listen_order_len < 3) c->listen_order[c->listen_order_len++] = 1;
        } else if (!strcmp(key, "v6-listen")) {
            has_v6_listen = 1;
            format_listen_endpoint(val, 6443, "[::]", v6_listen_val, sizeof(v6_listen_val));
            int dup = 0; for (int k = 0; k < c->listen_order_len; k++) if (c->listen_order[k] == 2) dup = 1;
            if (!dup && c->listen_order_len < 3) c->listen_order[c->listen_order_len++] = 2;
        } else if (!strcmp(key, "baidu-listen")) {
            has_baidu_listen = 1;
            format_listen_endpoint(val, 5444, "0.0.0.0", baidu_listen_val, sizeof(baidu_listen_val));
            int dup = 0; for (int k = 0; k < c->listen_order_len; k++) if (c->listen_order[k] == 3) dup = 1;
            if (!dup && c->listen_order_len < 3) c->listen_order[c->listen_order_len++] = 3;
        } else if (!strcmp(key, "direct-listen") && val) {
            snprintf(c->direct_listen, sizeof(c->direct_listen), "%s", val);
            int kind = (c->ips_type == 6) ? 2 : 1;
            int dup = 0; for (int k = 0; k < c->listen_order_len; k++) if (c->listen_order[k] == kind) dup = 1;
            if (!dup && c->listen_order_len < 3) c->listen_order[c->listen_order_len++] = kind;
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
        else if (!strcmp(key, "baidu-code") && val) baidu_code = atoi(val);
        else if (!strcmp(key, "v6-domain") && val) snprintf(v6_domain, sizeof(v6_domain), "%s", val);
        else if (!strcmp(key, "v6-colo") && val) snprintf(v6_colo, sizeof(v6_colo), "%s", val);
        else if ((!strcmp(key, "v6-exclude-colo") || !strcmp(key, "v6-ex-colo")) && val) {
            if (v6_exclude_colo_buf[0]) snprintf(v6_exclude_colo_buf + strlen(v6_exclude_colo_buf), sizeof(v6_exclude_colo_buf) - strlen(v6_exclude_colo_buf), ",%s", val);
            else snprintf(v6_exclude_colo_buf, sizeof(v6_exclude_colo_buf), "%s", val);
        } else if (!strcmp(key, "v6-random")) v6_random = parse_bool(val);
        else if (!strcmp(key, "v6-split") && val) {
            const char *vp = (*val == '/') ? (val + 1) : val;
            int v = atoi(vp);
            if (v >= 1 && v <= 128) {
                v6_split_val = v;
                c->v6_split = v;
            } else {
                warn_msg("参数 -v6-split=%s 超出合法范围 [1, 128]，默认使用 54", val);
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
        else if (!strcmp(key, "h3-client")) c->h3_client = parse_bool(val);
        else if (!strcmp(key, "h2")) c->enable_h2 = parse_bool(val);
        else if (!strcmp(key, "h3")) c->enable_h3 = parse_bool(val);
        else if (!strcmp(key, "v4-h2")) v4_h2 = parse_bool(val);
        else if (!strcmp(key, "v4-h3")) v4_h3 = parse_bool(val);
        else if (!strcmp(key, "v6-h2")) v6_h2 = parse_bool(val);
        else if (!strcmp(key, "v6-h3")) v6_h3 = parse_bool(val);
        else if (!strcmp(key, "baidu-h2")) baidu_h2 = parse_bool(val);
        else if (!strcmp(key, "baidu-h3")) baidu_h3 = parse_bool(val);
        /* 运行指标汇报间隔：与健康检查解耦（-stats-interval 为主名，-log-interval 作兼容别名）。
         * 显式传负数一律按 0（关闭）处理，避免出现「间隔 -5 秒」这种无意义配置。 */
        else if ((!strcmp(key, "stats-interval") || !strcmp(key, "log-interval")) && val) {
            int v = atoi(val);
            c->stats_interval = v > 0 ? v : 0;
        }
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
    if (c->ipnum > 1000) c->ipnum = 1000;
    if (c->num <= 0) c->num = 1;
    if (c->num > 50) c->num = 50;
    if (c->task <= 0) c->task = 1;
    if (c->task > 2000) c->task = 2000;
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
            format_listen_endpoint(c->direct_listen, 6443, "[::]", v6_listen_val, sizeof(v6_listen_val));
        } else {
            has_v4_listen = 1;
            format_listen_endpoint(c->direct_listen, 4443, "0.0.0.0", v4_listen_val, sizeof(v4_listen_val));
        }
    }

    /* 补齐未在循环中入队的启用项并强制保证: 若同时启用 v4 与 baidu，v4 必须在 baidu 之前 */
    if (has_v4_listen) {
        int dup = 0; for (int k = 0; k < c->listen_order_len; k++) if (c->listen_order[k] == 1) dup = 1;
        if (!dup && c->listen_order_len < 3) c->listen_order[c->listen_order_len++] = 1;
    }
    if (has_v6_listen) {
        int dup = 0; for (int k = 0; k < c->listen_order_len; k++) if (c->listen_order[k] == 2) dup = 1;
        if (!dup && c->listen_order_len < 3) c->listen_order[c->listen_order_len++] = 2;
    }
    if (has_baidu_listen) {
        int dup = 0; for (int k = 0; k < c->listen_order_len; k++) if (c->listen_order[k] == 3) dup = 1;
        if (!dup && c->listen_order_len < 3) c->listen_order[c->listen_order_len++] = 3;
    }
    int pos_v4 = -1, pos_bd = -1;
    for (int k = 0; k < c->listen_order_len; k++) {
        if (c->listen_order[k] == 1) pos_v4 = k;
        else if (c->listen_order[k] == 3) pos_bd = k;
    }
    int eff_baidu_h3 = (baidu_h3 >= 0) ? baidu_h3 : c->enable_h3;
    if (pos_v4 >= 0 && pos_bd >= 0 && pos_bd < pos_v4 && eff_baidu_h3) {
        for (int k = pos_v4; k > pos_bd; k--) {
            c->listen_order[k] = c->listen_order[k - 1];
        }
        c->listen_order[pos_bd] = 1;
    }

    /* 初始化 prof_v4 */
    c->prof_v4.enabled = has_v4_listen;
    c->prof_v4.enable_h2 = (v4_h2 >= 0) ? v4_h2 : c->enable_h2;
    c->prof_v4.enable_h3 = (v4_h3 >= 0) ? v4_h3 : c->enable_h3;
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
    c->prof_v6.enable_h2 = (v6_h2 >= 0) ? v6_h2 : c->enable_h2;
    c->prof_v6.enable_h3 = (v6_h3 >= 0) ? v6_h3 : c->enable_h3;
    c->prof_v6.ips_type = 6;
    snprintf(c->prof_v6.name, sizeof(c->prof_v6.name), "v6");
    snprintf(c->prof_v6.listen_addr, sizeof(c->prof_v6.listen_addr), "%s", v6_listen_val[0] ? v6_listen_val : "[::]:6443");
    c->prof_v6.port = v6_port > 0 ? v6_port : c->port;
    c->prof_v6.http_port = v6_http_port > 0 ? v6_http_port : c->http_port;
    c->prof_v6.delay_ms = v6_delay > 0 ? v6_delay : c->delay_ms;
    c->prof_v6.task = v6_task > 0 ? v6_task : c->task;
    c->prof_v6.ipnum = v6_ipnum > 0 ? v6_ipnum : c->ipnum;
    c->prof_v6.num = v6_num > 0 ? v6_num : c->num;
    c->prof_v6.code = v6_code >= 0 ? v6_code : c->code;
    c->prof_v6.random_mode = v6_random >= 0 ? v6_random : c->random_mode;
    c->prof_v6.v6_split = (v6_split_val >= 1 && v6_split_val <= 128) ? v6_split_val : ((c->v6_split >= 1 && c->v6_split <= 128) ? c->v6_split : 54);
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
    c->prof_baidu.code = baidu_code >= 0 ? baidu_code : c->code;
    c->prof_baidu.random_mode = c->random_mode;
    c->prof_baidu.v6_split = c->v6_split;
    snprintf(c->prof_baidu.domain, sizeof(c->prof_baidu.domain), "%s", c->domain);
    snprintf(c->prof_baidu.colo, sizeof(c->prof_baidu.colo), "%s", c->colo);
    c->prof_baidu.use_baidu_proxy = 1;
    c->prof_baidu.enable_h2 = (baidu_h2 >= 0) ? baidu_h2 : c->enable_h2;
    c->prof_baidu.enable_h3 = (baidu_h3 >= 0) ? baidu_h3 : c->enable_h3;
    if (has_baidu_listen) c->use_baidu_proxy = 1;
    if ((c->prof_v4.enabled && !c->prof_v4.enable_h2 && !c->prof_v4.enable_h3) ||
        (c->prof_v6.enabled && !c->prof_v6.enable_h2 && !c->prof_v6.enable_h3) ||
        (c->prof_baidu.enabled && !c->prof_baidu.enable_h2 && !c->prof_baidu.enable_h3)) {
        fprintf(stderr, "配置错误: 已启用的监听实例不能同时关闭 H2 与 H3 (-h2=0 -h3=0)\n");
        exit(1);
    }
}

static void log_current_config(const Config *c) {
    log_msg("cfnat v%s 当前运行配置清单 (含缺省默认值):", CFNAT_VERSION);
    if (c->prof_v4.enabled) {
        log_msg("  [IPv4 转发实例] 监听地址: %s | 协议: %s", c->prof_v4.listen_addr,
                (c->prof_v4.enable_h2 && c->prof_v4.enable_h3) ? "H2+H3" : (c->prof_v4.enable_h2 ? "仅H2" : "仅H3"));
        log_msg("    TLS目标端口: %d | HTTP目标端口: %d", c->prof_v4.port, c->prof_v4.http_port);
        log_msg("    并发扫描线程: %d | 延迟上限: %d ms | 候选IP保留: %d", c->prof_v4.task, c->prof_v4.delay_ms, c->prof_v4.ipnum);
        log_msg("    状态码校验 (-code): %s", c->prof_v4.code > 0 ? "启用" : "未启用 (仅测连通性)");
        if (c->prof_v4.code > 0) log_msg("    期望状态码: %d (域名: %s)", c->prof_v4.code, c->prof_v4.domain);
        log_msg("    数据中心筛选: %s", c->prof_v4.colo[0] ? c->prof_v4.colo : "(不限)");
    } else {
        log_msg("  [IPv4 转发实例] 未启用");
    }

    if (c->prof_v6.enabled) {
        log_msg("  [IPv6 转发实例] 监听地址: %s | 协议: %s", c->prof_v6.listen_addr,
                (c->prof_v6.enable_h2 && c->prof_v6.enable_h3) ? "H2+H3" : (c->prof_v6.enable_h2 ? "仅H2" : "仅H3"));
        log_msg("    TLS目标端口: %d | HTTP目标端口: %d", c->prof_v6.port, c->prof_v6.http_port);
        log_msg("    并发扫描线程: %d | 延迟上限: %d ms | 候选IP保留: %d", c->prof_v6.task, c->prof_v6.delay_ms, c->prof_v6.ipnum);
        log_msg("    IPv6 子网切分 (-v6-split): /%d (单行上限 1024 样本，文件子网更小或完整 IP 按原粒度)", c->prof_v6.v6_split);
        log_msg("    状态码校验 (-code): %s", c->prof_v6.code > 0 ? "启用" : "未启用 (仅测连通性)");
        if (c->prof_v6.code > 0) log_msg("    期望状态码: %d (域名: %s)", c->prof_v6.code, c->prof_v6.domain);
        log_msg("    数据中心筛选: %s", c->prof_v6.colo[0] ? c->prof_v6.colo : "(不限)");
    } else {
        log_msg("  [IPv6 转发实例] 未启用");
    }

    if (c->prof_baidu.enabled) {
        log_msg("  [百度前置实例] 监听地址: %s | 协议: %s", c->prof_baidu.listen_addr,
                (c->prof_baidu.enable_h2 && c->prof_baidu.enable_h3) ? "H2+H3" : (c->prof_baidu.enable_h2 ? "仅H2" : "仅H3"));
        if (!c->prof_baidu.enable_h2 && c->prof_baidu.enable_h3) {
            warn_msg("  [百度前置实例] 提示: 百度前置仅代理 TCP，纯 H3 模式下 UDP 始终走本机直连");
        }
        log_msg("    百度解析器 (-baidu-resolver): %s", c->baidu_resolver);
        log_msg("    百度前置目标: %s:%d (候选数: %d)", c->baidu_domain, c->baidu_port, c->baidu_ipnum);
    } else {
        log_msg("  [百度前置实例] 未启用");
    }

    if (!c->prof_v4.enabled && !c->prof_v6.enabled && !c->prof_baidu.enabled) {
        log_msg("  [CLI 单次测速模式] IP 类型: IPv%d | 端口: %d | 并发线程: %d | 延迟上限: %d ms",
                c->ips_type, c->port, c->task, c->delay_ms);
        if (c->ips_type == 6) {
            log_msg("    IPv6 子网切分 (-v6-split): /%d (单行上限 1024 样本，文件子网更小或完整 IP 按原粒度)", c->v6_split);
        }
        if (c->colo[0]) log_msg("    数据中心筛选: %s", c->colo);
    }

    log_msg("  全局设置: 出站网卡: %s | 运行指标间隔: %d 秒 (0=关闭) | H3探针: %s | 日志级别: %s",
            c->bind_if[0] ? c->bind_if : "(系统默认路由)", c->stats_interval,
            c->h3_client ? "QUIC-v1-ClientHello" : "轻量VN", c->log_name);
    /* 健康检查节奏本身是自适应的（失败 10s / 稳定 30s / 连续成功 5 次后 60s），不受任何间隔参数影响；
     * -health-log 只决定「健康状态行」这类 debug 明细的输出频率。这里显式写出来，避免把两者混为一谈。 */
    log_msg("  健康检查节奏: 自适应 10s / 30s / 60s（与运行指标间隔解耦）| 健康状态行间隔: %d 秒 (0=关闭)",
            c->health_log);
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
        flags |= INTERNET_FLAG_SECURE;
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
    log_msg("下载 %s 失败：所有镜像源均不可达，或系统缺少 curl / wget 工具。请手动下载文件放置于当前目录，或安装 curl/wget 后重试", filename);
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

/* 单行 IPv6 CIDR 切分安全上限：2^10 = 1024 个分层样本（防止大网段配 /128 导致 OOM） */
#define MAX_V6_SPLIT_BITS_PER_LINE 10

/* 通用 IPv6 CIDR 抽样与子网切分：
 * - 支持任意文件前缀 prefix ∈ [0, 128] 与任意参数 v6_split ∈ [1, 128]（每行前缀可互不相同）
 * - prefix == 128：视为完整单 IP，零随机直接加入
 * - prefix >= v6_split（文件子网小于或等于参数子网，如参数 /50、文件 /64）：按文件子网粒度展开（抽样 1 个）
 * - prefix < v6_split（文件子网大于参数子网，如文件 /48、参数 /54，或文件 /124、参数 /128）：
 *   切分为 2^(v6_split - prefix) 个子网各抽样 1 个（当 v6_split == 128 时精确枚举全部 /128 IP）；
 *   若单行切分位数超过 10 位 (>1024 个子网)，按高 10 位分层抽样 1024 个并置位 *capped_out 防 OOM。 */
static int ipv6_cidr_sample_split(const char *base_s, int prefix, int v6_split, StringList *out, int *capped_out) {
    if (!base_s || !out || prefix < 0 || prefix > 128) return -1;
    if (v6_split < 1 || v6_split > 128) v6_split = 54;
    unsigned char base[16];
    if (inet_pton(AF_INET6, base_s, base) != 1) return -1;

    /* 完整 /128 单 IP 直接加入，不改任何位 */
    if (prefix == 128) {
        char ip[MAX_IP_LEN];
        format_ipv6_full(base, ip, sizeof(ip));
        strlist_add(out, ip);
        return 1;
    }

    /* 清零主机位 [prefix .. 127] 得到规范网络地址 */
    for (int bit = prefix; bit < 128; bit++) {
        base[bit / 8] &= (unsigned char)~(1u << (7 - (bit % 8)));
    }

    int eff_bits = 0;
    if (v6_split > prefix) {
        int split_bits = v6_split - prefix;
        if (split_bits > MAX_V6_SPLIT_BITS_PER_LINE) {
            eff_bits = MAX_V6_SPLIT_BITS_PER_LINE;
            if (capped_out) *capped_out = 1;
        } else {
            eff_bits = split_bits;
        }
    }
    /* eff_bits == 0 表示文件子网 <= 参数子网（prefix >= v6_split），按文件自身 /prefix 抽样 1 个 */
    int count = 1 << eff_bits;
    int rand_start = prefix + eff_bits;

    for (int i = 0; i < count; i++) {
        unsigned char cur[16];
        memcpy(cur, base, 16);
        /* 将分层序号 i 写入 [prefix .. prefix + eff_bits - 1] */
        for (int k = 0; k < eff_bits; k++) {
            if ((i >> (eff_bits - 1 - k)) & 1u) {
                int pos = prefix + k;
                cur[pos / 8] |= (unsigned char)(1u << (7 - (pos % 8)));
            }
        }
        /* 随机填充剩余主机位 [rand_start .. 127]（当 rand_start == 128 时精确枚举，零随机位） */
        uint64_t r = 0;
        int rbits = 0;
        for (int pos = rand_start; pos < 128; pos++) {
            if (rbits == 0) { r = rand_u64(); rbits = 64; }
            if (r & 1u) cur[pos / 8] |= (unsigned char)(1u << (7 - (pos % 8)));
            r >>= 1;
            rbits--;
        }
        char ip[MAX_IP_LEN];
        format_ipv6_full(cur, ip, sizeof(ip));
        strlist_add(out, ip);
    }
    return count;
}

static int is_ip_literal(const char *s) {
    struct in_addr a4;
    struct in6_addr a6;
    return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1;
}

static void format_addr_port(const char *ip, int port, char *out, size_t outsz) {
    if (!out || outsz == 0) return;
    if (ip && strchr(ip, ':')) snprintf(out, outsz, "[%s]:%d", ip, port);
    else snprintf(out, outsz, "%s:%d", ip ? ip : "", port);
}

/* 清洗单行 IP/CIDR 输入：去注释 (#/;//)、取首字段、剥离方括号与可选端口 ([v6]:443 -> v6) */
static void sanitize_ip_line(char *line) {
    if (!line) return;
    trim_line(line);
    if (!line[0]) return;
    for (char *p = line; *p; p++) {
        if (*p == '#' || *p == ';' || (*p == '/' && p[1] == '/')) {
            *p = '\0';
            break;
        }
    }
    trim_line(line);
    if (!line[0]) return;
    /* 仅保留首段 token（忽略行尾附加备注列如机房名/延迟等） */
    for (char *p = line; *p; p++) {
        if (*p == ' ' || *p == '	' || *p == ',') {
            *p = '\0';
            break;
        }
    }
    /* 处理 [2606:4700::1] 或 [2606:4700::1]:443 */
    if (line[0] == '[') {
        char *rb = strchr(line + 1, ']');
        if (rb) {
            size_t len = (size_t)(rb - (line + 1));
            memmove(line, line + 1, len);
            line[len] = '\0';
        }
    }
}

static StringList load_ip_list(const char *filename, int random_mode, int v6_split) {
    if (v6_split < 1 || v6_split > 128) v6_split = 54;
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
    size_t exact_ip_count = 0;
    int warned_ipv6_expand = 0;
    int warned_ipv6_cap = 0;
    srand((unsigned)time(nullptr));
    while (fgets(line, sizeof(line), f)) {
        sanitize_ip_line(line);
        if (!line[0]) continue;
        char *slash = strchr(line, '/');
        if (!slash) {
            if (is_ip_literal(line)) {
                exact_ip_count++;
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
        *slash = 0;
        const char *pfx_s = slash + 1;
        if (!pfx_s[0]) continue;
        int pfx_ok = 1;
        for (const char *p = pfx_s; *p; p++) {
            if (!isdigit((unsigned char)*p)) { pfx_ok = 0; break; }
        }
        if (!pfx_ok) continue;
        int prefix = atoi(pfx_s);
        if (strchr(line, ':')) {
            if (prefix < 0 || prefix > 128) continue;
            if (prefix == 128) {
                exact_ip_count++;
            } else {
                cidr_count++;
                if (!random_mode && !warned_ipv6_expand) {
                    warn_msg("IPv6 空间过大不支持全量展开，已按 -v6-split=/%d 分层抽样（单行上限 1024，文件子网更小时按文件子网展开）",
                             v6_split);
                    warned_ipv6_expand = 1;
                }
            }
            int capped = 0;
            ipv6_cidr_sample_split(line, prefix, v6_split, &out, &capped);
            if (capped && !warned_ipv6_cap) {
                warn_msg("部分 IPv6 子网按 -v6-split=/%d 切分超过单行 1024 上限，已自动按高 10 位分层抽样 1024 个防 OOM",
                         v6_split);
                warned_ipv6_cap = 1;
            }
            continue;
        }
        cidr_count++;
        uint32_t base = ipv4_to_u32(line);
        if (base == 0 || prefix < 8 || prefix > 32) continue;
        uint32_t mask = (0xffffffffu << (32 - prefix));
        uint32_t start = base & mask;
        uint64_t count = prefix == 32 ? 1ULL : (1ULL << (32 - prefix));
        if (!random_mode && count > 65536) count = 65536;
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
    log_msg("IP 列表加载完成: %zu 个候选（完整 IP 行: %zu，CIDR 行: %zu），耗时 %ld 秒", out.len, exact_ip_count, cidr_count, (now_ms() - start_ms) / 1000);
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

/* 套接字缓冲区分级调优：
 * mode 0: TCP 转发 (优先 2MB，回退 1MB/512KB)；
 * mode 1: UDP 监听 (优先 4MB，回退 2MB/1MB) 吸收多路复用突发；
 * mode 2: UDP 会话 (优先 1MB，回退 512KB/256KB) 避免 256+ 会话耗尽内核内存 */
static void tune_socket_buffers(socket_t s, int mode) {
    if (cfnat_socket_invalid(s)) return;
    const int tiers_tcp[3] = { 2 * 1024 * 1024, 1024 * 1024, 512 * 1024 };
    const int tiers_udp_listen[3] = { 4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024 };
    const int tiers_udp_session[3] = { 1024 * 1024, 512 * 1024, 256 * 1024 };
    const int tiers_udp_session_compact[3] = { 256 * 1024, 128 * 1024, 64 * 1024 };
    const int *tiers = (mode == 1) ? tiers_udp_listen
                     : (mode == 2) ? tiers_udp_session
                     : (mode == 3) ? tiers_udp_session_compact
                     : tiers_tcp;

#if defined(__linux__)
    /* Linux：TCP 一律不显式设缓冲。
     * 一旦显式 setsockopt(SO_RCVBUF / SO_SNDBUF)，内核的窗口自动调优（tcp_moderate_rcvbuf / tcp_wmem）
     * 会立即失效，窗口被钉死在 min(请求值, rmem_max / wmem_max)，高 BDP 链路反而被限速。
     * 因此只有 UDP 才按档位显式设置。
     * 注意：is_udp 必须声明在这个条件编译块内部——Windows / macOS 走 #else 分支，用不到它，
     * 放在外面会被 clang -Wall 判为 unused variable（即 Windows 构建报的那条警告）。 */
    const int is_udp = (mode != 0);

    if (is_udp) {
        for (int i = 0; i < 3; i++) {
            int sz = tiers[i];
            if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const void *)&sz, sizeof(sz)) == 0) break;
        }
    } else {
        /* A3: 限制未发送数据积压为 64KB，根除大发送缓冲带来的 Bufferbloat 延迟膨胀 */
        unsigned int lowat = 64 * 1024;
        setsockopt(s, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat, sizeof(lowat));
    }

    if (is_udp) {
        for (int i = 0; i < 3; i++) {
            int sz = tiers[i];
            if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const void *)&sz, sizeof(sz)) == 0) break;
        }
    }
#else
    /* Windows / macOS：没有 Linux 那套自动调优语义，收发两个方向都按档位显式设置 */
    for (int i = 0; i < 3; i++) {
        int sz = tiers[i];
#ifdef _WIN32
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&sz, sizeof(sz)) == 0) break;
#else
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)) == 0) break;
#endif
    }
    for (int i = 0; i < 3; i++) {
        int sz = tiers[i];
#ifdef _WIN32
        if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char *)&sz, sizeof(sz)) == 0) break;
#else
        if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)) == 0) break;
#endif
    }
#endif
}

CFNAT_NODISCARD static socket_t tcp_connect_sa(const struct sockaddr_storage *ss, socklen_t sslen, int port, int timeout_ms, int *latency_ms) {
    if (!ss || sslen == 0) return INVALID_SOCKET;
    long start = now_ms();
    int family = ss->ss_family;
    socket_t fd = socket(family, SOCK_STREAM, 0);
    if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
#if defined(__linux__)
    /* B1: 优先尝试启用 BBR 拥塞控制算法，抗 0.5%~2% 跨境随机丢包，保持高带宽时延积吞吐 */
    const char *cc_algo = "bbr";
    static int s_bbr_checked = 0;
    if (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, cc_algo, (socklen_t)strlen(cc_algo)) != 0) {
        if (!s_bbr_checked) {
            s_bbr_checked = 1;
            debug_msg("[TCP/H2] 当前系统内核未加载 BBR 模块，已平滑回退为系统默认拥塞控制算法");
        }
    } else if (!s_bbr_checked) {
        s_bbr_checked = 1;
        debug_msg("[TCP/H2] 已成功启用 BBR 拥塞控制算法");
    }
#endif
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
#if defined(__linux__) && defined(TCP_INFO)
        /* Perf 3: 读取内核高精度 SRTT，彻底消灭 200 线程下多任务调度排队延迟误差 */
        struct tcp_info t_info;
        socklen_t t_len = sizeof(t_info);
        if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &t_info, &t_len) == 0 && t_info.tcpi_rtt > 0) {
            /* 叠加 0.25*tcpi_rttvar 内核抖动权重，弱网下优先选低抖动稳定节点 */
            elapsed = (int)(t_info.tcpi_rtt / 1000) + (int)(t_info.tcpi_rttvar / 4000);
        }
#endif
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

/* RFC 9000 规范的 1200 字节 QUIC Version Negotiation 单发探针（与 0.0.16 逐字一致）
 * 利用保留版本号 0x5A5A5A5A 触发 Cloudflare 边缘节点立即回包 Version Negotiation
 * 零密钥协商，零 CPU 加密开销，单包 1200 字节符合防放大攻击标准，精准测出 UDP 443 真实延迟
 *
 * 关键约束：头部（0..22）之后的 1177 字节必须保持**全零**。
 * Cloudflare 会按 Initial 报文结构解析载荷，把随机字节当作 Token Length / Length 变长整数，
 * 绝大多数包被判为畸形包直接丢弃（同一节点实测：全零载荷 8/8 有回包，随机载荷仅 1~3/8）。
 * 一旦填充随机数据，表现为 v4/v6 的 H3 精筛恒为 0 个候选、健康检查一直「QUIC 无响应」。 */
/* ---- 自包含 RFC 9000 / RFC 9001 QUIC v1 Initial (TLS 1.3 ClientHello) 构造器（零外部加密库依赖） ---- */
static const uint32_t CF_SHA256_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static inline uint32_t cf_rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void cf_sha256_transform(uint32_t s[8], const uint8_t b[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)b[i*4] << 24) | ((uint32_t)b[i*4+1] << 16) | ((uint32_t)b[i*4+2] << 8) | b[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = cf_rotr32(w[i-15], 7) ^ cf_rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = cf_rotr32(w[i-2], 17) ^ cf_rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=s[0], bb=s[1], c=s[2], d=s[3], e=s[4], f=s[5], g=s[6], h=s[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = cf_rotr32(e, 6) ^ cf_rotr32(e, 11) ^ cf_rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + CF_SHA256_K[i] + w[i];
        uint32_t S0 = cf_rotr32(a, 2) ^ cf_rotr32(a, 13) ^ cf_rotr32(a, 22);
        uint32_t maj = (a & bb) ^ (a & c) ^ (bb & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = bb; bb = a; a = t1 + t2;
    }
    s[0]+=a; s[1]+=bb; s[2]+=c; s[3]+=d; s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
}

static void cf_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t s[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    size_t i = 0;
    while (i + 64 <= len) { cf_sha256_transform(s, data + i); i += 64; }
    uint8_t pad[128] = {0};
    size_t rem = len - i;
    if (rem > 0) memcpy(pad, data + i, rem);
    pad[rem] = 0x80;
    size_t total = (rem < 56) ? 64 : 128;
    uint64_t bitlen = (uint64_t)len * 8ULL;
    for (int k = 0; k < 8; k++) pad[total - 1 - k] = (uint8_t)(bitlen >> (k * 8));
    cf_sha256_transform(s, pad);
    if (total == 128) cf_sha256_transform(s, pad + 64);
    for (int k = 0; k < 8; k++) {
        out[k*4]   = (uint8_t)(s[k] >> 24);
        out[k*4+1] = (uint8_t)(s[k] >> 16);
        out[k*4+2] = (uint8_t)(s[k] >> 8);
        out[k*4+3] = (uint8_t)(s[k]);
    }
}

static void cf_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
    uint8_t k0[64] = {0};
    if (key_len > 64) cf_sha256(key, key_len, k0);
    else if (key_len > 0) memcpy(k0, key, key_len);
    uint8_t ibuf[64 + 128];
    for (int i = 0; i < 64; i++) ibuf[i] = k0[i] ^ 0x36;
    if (msg_len > 128) msg_len = 128;
    if (msg_len > 0) memcpy(ibuf + 64, msg, msg_len);
    uint8_t ihash[32];
    cf_sha256(ibuf, 64 + msg_len, ihash);
    uint8_t obuf[64 + 32];
    for (int i = 0; i < 64; i++) obuf[i] = k0[i] ^ 0x5c;
    memcpy(obuf + 64, ihash, 32);
    cf_sha256(obuf, 96, out);
}

static void cf_hkdf_expand_label(const uint8_t secret[32], const char *label, uint8_t *out, size_t out_len) {
    uint8_t info[64];
    size_t l_len = strlen(label);
    size_t pos = 0;
    info[pos++] = (uint8_t)(out_len >> 8);
    info[pos++] = (uint8_t)(out_len & 0xff);
    info[pos++] = (uint8_t)(6 + l_len);
    memcpy(info + pos, "tls13 ", 6); pos += 6;
    memcpy(info + pos, label, l_len); pos += l_len;
    info[pos++] = 0x00;
    info[pos++] = 0x01;
    uint8_t t[32];
    cf_hmac_sha256(secret, 32, info, pos, t);
    memcpy(out, t, out_len);
}

static const uint8_t CF_AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static inline uint8_t cf_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00)); }

static void cf_aes128_expand(const uint8_t key[16], uint8_t rk[176]) {
    static const uint8_t rcon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
    memcpy(rk, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        memcpy(t, rk + (i - 1) * 4, 4);
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0] = CF_AES_SBOX[t[1]] ^ rcon[i / 4 - 1];
            t[1] = CF_AES_SBOX[t[2]];
            t[2] = CF_AES_SBOX[t[3]];
            t[3] = CF_AES_SBOX[tmp];
        }
        for (int j = 0; j < 4; j++) rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ t[j];
    }
}

static void cf_aes128_encrypt_block(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];
    for (int r = 1; r <= 10; r++) {
        for (int i = 0; i < 16; i++) s[i] = CF_AES_SBOX[s[i]];
        uint8_t t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
        if (r < 10) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = s[c*4], a1 = s[c*4+1], a2 = s[c*4+2], a3 = s[c*4+3];
                uint8_t xr = a0 ^ a1 ^ a2 ^ a3;
                s[c*4]   ^= xr ^ cf_xtime(a0 ^ a1);
                s[c*4+1] ^= xr ^ cf_xtime(a1 ^ a2);
                s[c*4+2] ^= xr ^ cf_xtime(a2 ^ a3);
                s[c*4+3] ^= xr ^ cf_xtime(a3 ^ a0);
            }
        }
        for (int i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
    }
    memcpy(out, s, 16);
}

static void cf_ghash_mul(uint8_t x[16], const uint8_t h[16]) {
    uint8_t z[16] = {0}, v[16];
    memcpy(v, h, 16);
    for (int i = 0; i < 128; i++) {
        if ((x[i >> 3] >> (7 - (i & 7))) & 1) {
            for (int j = 0; j < 16; j++) z[j] ^= v[j];
        }
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; j--) v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1;
    }
    memcpy(x, z, 16);
}

static void cf_ghash_update(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        size_t chunk = (len - i >= 16) ? 16 : (len - i);
        for (size_t j = 0; j < chunk; j++) y[j] ^= data[i + j];
        cf_ghash_mul(y, h);
        i += chunk;
    }
}

static void cf_aes128_gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *pt, size_t pt_len,
                                  uint8_t *ct, uint8_t tag[16]) {
    uint8_t rk[176], h[16], zero[16] = {0};
    cf_aes128_expand(key, rk);
    cf_aes128_encrypt_block(rk, zero, h);

    uint8_t j0[16] = {0};
    memcpy(j0, iv, 12);
    j0[15] = 1;

    uint8_t ctr[16], ek[16];
    memcpy(ctr, j0, 16);
    for (size_t i = 0; i < pt_len; i += 16) {
        for (int k = 15; k >= 12; k--) { if (++ctr[k] != 0) break; }
        cf_aes128_encrypt_block(rk, ctr, ek);
        size_t chunk = (pt_len - i >= 16) ? 16 : (pt_len - i);
        for (size_t j = 0; j < chunk; j++) ct[i + j] = pt[i + j] ^ ek[j];
    }

    uint8_t y[16] = {0};
    cf_ghash_update(y, h, aad, aad_len);
    cf_ghash_update(y, h, ct, pt_len);
    uint8_t len_blk[16] = {0};
    uint64_t ab = (uint64_t)aad_len * 8ULL, cb = (uint64_t)pt_len * 8ULL;
    for (int k = 0; k < 8; k++) {
        len_blk[7 - k] = (uint8_t)(ab >> (k * 8));
        len_blk[15 - k] = (uint8_t)(cb >> (k * 8));
    }
    cf_ghash_update(y, h, len_blk, 16);

    cf_aes128_encrypt_block(rk, j0, ek);
    for (int j = 0; j < 16; j++) tag[j] = y[j] ^ ek[j];
}

static void quic_extract_sni_host(const char *domain, char *out, size_t outsz) {
    if (!out || outsz == 0) return;
    const char *src = (domain && *domain) ? domain : "cloudflaremirrors.com";
    if (strncmp(src, "https://", 8) == 0) src += 8;
    else if (strncmp(src, "http://", 7) == 0) src += 7;
    size_t n = 0;
    while (src[n] && src[n] != '/' && src[n] != ':' && src[n] != '?' && n + 1 < outsz) {
        out[n] = src[n];
        n++;
    }
    out[n] = '\0';
    if (n == 0) snprintf(out, outsz, "%s", "cloudflaremirrors.com");
}

static size_t quic_put_varint(uint8_t *p, uint64_t v) {
    if (v < 64) { p[0] = (uint8_t)v; return 1; }
    if (v < 16384) { p[0] = (uint8_t)(0x40 | (v >> 8)); p[1] = (uint8_t)(v & 0xff); return 2; }
    p[0] = (uint8_t)(0x80 | ((v >> 24) & 0x3f));
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >> 8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
    return 4;
}

static void quic_build_initial_client_hello(uint8_t pkt[1200], const uint8_t dcid[8], const uint8_t scid[8], const char *domain) {
    static const uint8_t QUIC_V1_SALT[20] = {
        0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
        0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a
    };
    char sni[128];
    quic_extract_sni_host(domain, sni, sizeof(sni));
    size_t sni_len = strlen(sni);
    if (sni_len > 100) sni_len = 100;

    /* 1. 构造 TLS 1.3 ClientHello (SNI + ALPN h3 + x25519 + quic_transport_parameters) */
    uint8_t ch[512];
    size_t cp = 0;
    ch[cp++] = 0x01; /* HandshakeType: client_hello */
    size_t ch_len_pos = cp; cp += 3;
    ch[cp++] = 0x03; ch[cp++] = 0x03; /* legacy_version = TLS 1.2 */
    for (int i = 0; i < 32; i++) ch[cp++] = (uint8_t)(dcid[i & 7] ^ scid[(i + 3) & 7] ^ (uint8_t)(i * 37 + 11));
    ch[cp++] = 0x00; /* legacy_session_id: empty (RFC 9001 Section 8.4) */
    ch[cp++] = 0x00; ch[cp++] = 0x06;
    ch[cp++] = 0x13; ch[cp++] = 0x01;
    ch[cp++] = 0x13; ch[cp++] = 0x02;
    ch[cp++] = 0x13; ch[cp++] = 0x03;
    ch[cp++] = 0x01; ch[cp++] = 0x00;

    size_t ext_len_pos = cp; cp += 2;

    /* ext: server_name (0x0000) */
    ch[cp++] = 0x00; ch[cp++] = 0x00;
    ch[cp++] = (uint8_t)((sni_len + 5) >> 8); ch[cp++] = (uint8_t)((sni_len + 5) & 0xff);
    ch[cp++] = (uint8_t)((sni_len + 3) >> 8); ch[cp++] = (uint8_t)((sni_len + 3) & 0xff);
    ch[cp++] = 0x00;
    ch[cp++] = (uint8_t)(sni_len >> 8); ch[cp++] = (uint8_t)(sni_len & 0xff);
    memcpy(ch + cp, sni, sni_len); cp += sni_len;

    /* ext: supported_groups (0x000a): x25519, secp256r1 */
    ch[cp++] = 0x00; ch[cp++] = 0x0a;
    ch[cp++] = 0x00; ch[cp++] = 0x06;
    ch[cp++] = 0x00; ch[cp++] = 0x04;
    ch[cp++] = 0x00; ch[cp++] = 0x1d;
    ch[cp++] = 0x00; ch[cp++] = 0x17;

    /* ext: signature_algorithms (0x000d) */
    ch[cp++] = 0x00; ch[cp++] = 0x0d;
    ch[cp++] = 0x00; ch[cp++] = 0x08;
    ch[cp++] = 0x00; ch[cp++] = 0x06;
    ch[cp++] = 0x04; ch[cp++] = 0x03;
    ch[cp++] = 0x08; ch[cp++] = 0x04;
    ch[cp++] = 0x04; ch[cp++] = 0x01;

    /* ext: ALPN (0x0010): "h3" */
    ch[cp++] = 0x00; ch[cp++] = 0x10;
    ch[cp++] = 0x00; ch[cp++] = 0x05;
    ch[cp++] = 0x00; ch[cp++] = 0x03;
    ch[cp++] = 0x02; ch[cp++] = 'h'; ch[cp++] = '3';

    /* ext: supported_versions (0x002b): TLS 1.3 (0x0304) */
    ch[cp++] = 0x00; ch[cp++] = 0x2b;
    ch[cp++] = 0x00; ch[cp++] = 0x03;
    ch[cp++] = 0x02; ch[cp++] = 0x03; ch[cp++] = 0x04;

    /* ext: key_share (0x0033): x25519 32B */
    ch[cp++] = 0x00; ch[cp++] = 0x33;
    ch[cp++] = 0x00; ch[cp++] = 0x26;
    ch[cp++] = 0x00; ch[cp++] = 0x24;
    ch[cp++] = 0x00; ch[cp++] = 0x1d;
    ch[cp++] = 0x00; ch[cp++] = 0x20;
    for (int i = 0; i < 32; i++) ch[cp++] = (uint8_t)(scid[i & 7] ^ (uint8_t)(i * 19 + 0x5a));

    /* ext: quic_transport_parameters (0x0039) */
    uint8_t tp[64];
    size_t tpp = 0;
    tp[tpp++] = 0x01; tp[tpp++] = 0x04; tpp += quic_put_varint(tp + tpp, 30000);
    tp[tpp++] = 0x04; tp[tpp++] = 0x04; tpp += quic_put_varint(tp + tpp, 0x400000);
    tp[tpp++] = 0x05; tp[tpp++] = 0x04; tpp += quic_put_varint(tp + tpp, 0x100000);
    tp[tpp++] = 0x06; tp[tpp++] = 0x04; tpp += quic_put_varint(tp + tpp, 0x100000);
    tp[tpp++] = 0x08; tp[tpp++] = 0x02; tpp += quic_put_varint(tp + tpp, 100);
    tp[tpp++] = 0x0f; tp[tpp++] = 0x08; memcpy(tp + tpp, scid, 8); tpp += 8;

    ch[cp++] = 0x00; ch[cp++] = 0x39;
    ch[cp++] = (uint8_t)(tpp >> 8); ch[cp++] = (uint8_t)(tpp & 0xff);
    memcpy(ch + cp, tp, tpp); cp += tpp;

    size_t ext_len = cp - (ext_len_pos + 2);
    ch[ext_len_pos]     = (uint8_t)(ext_len >> 8);
    ch[ext_len_pos + 1] = (uint8_t)(ext_len & 0xff);

    size_t ch_body_len = cp - (ch_len_pos + 3);
    ch[ch_len_pos]     = (uint8_t)(ch_body_len >> 16);
    ch[ch_len_pos + 1] = (uint8_t)((ch_body_len >> 8) & 0xff);
    ch[ch_len_pos + 2] = (uint8_t)(ch_body_len & 0xff);

    /* 2. 组装 QUIC v1 Initial Header (固定 27 字节含 1 字节 PN=0) */
    uint8_t hdr[32];
    size_t hp_len = 0;
    hdr[hp_len++] = 0xC0;
    hdr[hp_len++] = 0x00; hdr[hp_len++] = 0x00; hdr[hp_len++] = 0x00; hdr[hp_len++] = 0x01;
    hdr[hp_len++] = 0x08; memcpy(hdr + hp_len, dcid, 8); hp_len += 8;
    hdr[hp_len++] = 0x08; memcpy(hdr + hp_len, scid, 8); hp_len += 8;
    hdr[hp_len++] = 0x00;
    size_t pn_offset = hp_len + 2;
    size_t pt_len = 1200 - (pn_offset + 1) - 16;
    size_t quic_len = 1 + pt_len + 16;
    hdr[hp_len++] = (uint8_t)(0x40 | (quic_len >> 8));
    hdr[hp_len++] = (uint8_t)(quic_len & 0xff);
    hdr[hp_len++] = 0x00;

    /* 3. 构造明文载荷: CRYPTO Frame + PADDING 至 pt_len */
    uint8_t pt[1200] = {0};
    size_t pp = 0;
    pt[pp++] = 0x06;
    pt[pp++] = 0x00;
    pp += quic_put_varint(pt + pp, cp);
    memcpy(pt + pp, ch, cp);

    /* 4. RFC 9001 初始密钥派生 + AES-128-GCM 加密 + Header Protection */
    uint8_t init_sec[32], client_in[32], key[16], iv[12], hp_key[16];
    cf_hmac_sha256(QUIC_V1_SALT, 20, dcid, 8, init_sec);
    cf_hkdf_expand_label(init_sec, "client in", client_in, 32);
    cf_hkdf_expand_label(client_in, "quic key", key, 16);
    cf_hkdf_expand_label(client_in, "quic iv", iv, 12);
    cf_hkdf_expand_label(client_in, "quic hp", hp_key, 16);

    memcpy(pkt, hdr, hp_len);
    cf_aes128_gcm_encrypt(key, iv, hdr, hp_len, pt, pt_len, pkt + hp_len, pkt + hp_len + pt_len);

    uint8_t hp_rk[176], mask[16];
    cf_aes128_expand(hp_key, hp_rk);
    cf_aes128_encrypt_block(hp_rk, pkt + pn_offset + 4, mask);
    pkt[0] ^= (uint8_t)(mask[0] & 0x0f);
    pkt[pn_offset] ^= mask[1];
}

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
    uint32_t seed = (uint32_t)now_ms();
    if (g_cfg.h3_client) {
        uint64_t d_val = rand_u64() ^ ((uint64_t)seed << 17);
        uint64_t s_val = rand_u64() ^ ((uint64_t)(~seed) << 11);
        uint8_t dcid[8], scid_b[8];
        memcpy(dcid, &d_val, 8);
        memcpy(scid_b, &s_val, 8);
        quic_build_initial_client_hello(pkt, dcid, scid_b, g_cfg.domain);
    } else {
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0xC0;
        pkt[1] = 0x5A; pkt[2] = 0x5A; pkt[3] = 0x5A; pkt[4] = 0x5A;
        pkt[5] = 0x08; /* DCID Len */
        memcpy(pkt + 6, &seed, 4);
        pkt[14] = 0x08; /* SCID Len */
        uint32_t scid = ~seed;
        memcpy(pkt + 15, &scid, 4);
    }

    struct sockaddr_storage ss;
    socklen_t sslen = 0;
    if (is_v6) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&ss;
        memset(sa6, 0, sizeof(*sa6));
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, ip, &sa6->sin6_addr) != 1) { close(fd); return 0; }
        sslen = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *sa4 = (struct sockaddr_in *)&ss;
        memset(sa4, 0, sizeof(*sa4));
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, ip, &sa4->sin_addr) != 1) { close(fd); return 0; }
        sslen = sizeof(struct sockaddr_in);
    }

    if (connect(fd, (struct sockaddr *)&ss, sslen) != 0) {
        close(fd);
        return 0;
    }

    long start = now_ms();
    ssize_t sent = send(fd, (const char *)pkt, sizeof(pkt), 0);
    if (sent <= 0) {
        close(fd);
        return 0;
    }

    int rc = cfnat_poll_single(fd, 1, timeout_ms);
    if (rc <= 0) {
        close(fd);
        return 0;
    }

    char resp[2048];
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    close(fd);

    /* 合法的 QUIC 长包头回包 (Version Negotiation / Initial)：首字节 0x80 置位且长度 >= 7 */
    if (n >= 7 && ((uint8_t)resp[0] & 0x80) != 0) {
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

static inline int is_cleartext_port(int port) {
    return (port == 80 || port == 8080 || port == 8880 ||
            port == 2052 || port == 2082 || port == 2086 || port == 2095);
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
    char host[MAX_ADDR_LEN] = {0};
    int port = 0;
    if (parse_addr(addr, host, sizeof(host), &port) == 0 && port > 0) {
        node->port = port;
        if (strchr(host, ':')) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&node->sa;
            s6->sin6_family = AF_INET6;
            if (inet_pton(AF_INET6, host, &s6->sin6_addr) == 1) node->salen = sizeof(*s6);
        } else {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&node->sa;
            s4->sin_family = AF_INET;
            if (inet_pton(AF_INET, host, &s4->sin_addr) == 1) node->salen = sizeof(*s4);
        }
    }
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

/* P2-5: 读取代理 CONNECT 响应头，使用 MSG_PEEK 与精确消费，
 * 绝不提前透支或丢弃握手后的首包有效载荷数据 (如 TLS 0-RTT/握手包) */
static int recv_connect_headers_peek(socket_t fd, char *hdr, size_t bufsz, int timeout_ms) {
    long deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline) {
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;
        int rc = cfnat_poll_single(fd, 1, left);
        if (rc <= 0) break;
        ssize_t peeked = recv(fd, hdr, bufsz - 1, MSG_PEEK);
        if (peeked <= 0) {
            if (peeked < 0 && errno == EINTR) continue;
            return -1;
        }
        hdr[peeked] = '\0';
        char *found = strstr(hdr, "\r\n\r\n");
        if (found) {
            size_t hdr_len = (size_t)(found - hdr + 4);
            size_t consumed = 0;
            while (consumed < hdr_len) {
                ssize_t n = recv(fd, hdr + consumed, hdr_len - consumed, 0);
                if (n <= 0) {
                    if (n < 0 && errno == EINTR) continue;
                    return -1;
                }
                consumed += (size_t)n;
            }
            hdr[hdr_len] = '\0';
            return (int)hdr_len;
        }
        if (peeked >= (ssize_t)(bufsz - 1)) return -1;
    }
    return -1;
}

static socket_t tcp_connect_via_baidu_node(const BaiduProxyNode *node, const char *node_addr_str, const char *target_addr, int timeout_ms, int *latency_ms) {
    long start = now_ms();
    const char *node_addr = (node && node->addr[0]) ? node->addr : node_addr_str;
    socket_t fd = INVALID_SOCKET;
    if (node && node->salen > 0 && node->port > 0) {
        fd = tcp_connect_sa(&node->sa, node->salen, node->port, timeout_ms, nullptr);
    } else {
        char host[MAX_ADDR_LEN] = {0};
        int port = 0;
        if (!node_addr || parse_addr(node_addr, host, sizeof(host), &port) != 0) return INVALID_SOCKET;
        fd = tcp_connect(host, port, timeout_ms, nullptr);
    }
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
    int n = recv_connect_headers_peek(fd, hdr, sizeof(hdr), timeout_ms);
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
    /* 百度前置的 CONNECT 是「TCP 连节点 + 节点回源 Cloudflare + 回 200」两跳，
     * 实测单次耗时 90~1200ms，远大于 TCP RTT。若沿用 -delay（默认 300ms）做预算，
     * 扫描阶段会出现 90% 以上的「连接失败」，节点少/并发高时直接全灭（baidu 扫描 0 候选）。
     * 因此走代理时给 CONNECT 一个独立下限，直连路径不受影响。 */
    int dial_timeout = timeout_ms;
    if (dial_timeout < BAIDU_CONNECT_MIN_TIMEOUT_MS) dial_timeout = BAIDU_CONNECT_MIN_TIMEOUT_MS;
    atomic_fetch_add(&node->active, 1);
    socket_t fd = tcp_connect_via_baidu_node(node, node->addr, target, dial_timeout, latency_ms);
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

    /* 按命令行传参顺序（且 baidu 强制排在 v4 之后）依次激活分协议 profile */
    int fallback_order[3] = {1, 2, 3};
    const int *order = (cfg->listen_order_len > 0) ? cfg->listen_order : fallback_order;
    int order_len = (cfg->listen_order_len > 0) ? cfg->listen_order_len : 3;
    for (int oi = 0; oi < order_len && len < 3; oi++) {
        int kind = order[oi];
        if (kind == 1 && cfg->prof_v4.enabled) {
            snprintf(specs[len].mode, sizeof(specs[len].mode), "%s", "direct-v4");
            snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", cfg->prof_v4.listen_addr);
            specs[len].use_baidu_proxy = 0;
            specs[len].prof = cfg->prof_v4;
            len++;
        } else if (kind == 2 && cfg->prof_v6.enabled) {
            snprintf(specs[len].mode, sizeof(specs[len].mode), "%s", "direct-v6");
            snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", cfg->prof_v6.listen_addr);
            specs[len].use_baidu_proxy = 0;
            specs[len].prof = cfg->prof_v6;
            len++;
        } else if (kind == 3 && cfg->prof_baidu.enabled) {
            snprintf(specs[len].mode, sizeof(specs[len].mode), "%s", "baidu");
            snprintf(specs[len].addr, sizeof(specs[len].addr), "%s", cfg->prof_baidu.listen_addr);
            specs[len].use_baidu_proxy = 1;
            specs[len].prof = cfg->prof_baidu;
            len++;
        }
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
    struct sockaddr_in from_sa;
#ifdef _WIN32
    int from_len = (int)sizeof(from_sa);
#else
    socklen_t from_len = sizeof(from_sa);
#endif
    ssize_t n = recvfrom(fd, (char *)resp, sizeof(resp), 0, (struct sockaddr *)&from_sa, &from_len);
    close(fd);
    if (n < 12) return -1;
    if (from_sa.sin_addr.s_addr != sa.sin_addr.s_addr) return -1; /* P2: 校验应答来源必须为目标 resolver */
    if ((resp[2] & 0x02) != 0) return -1; /* P2: TC (Truncated) 应答丢弃，避免截断数据污染 */
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
        /* 探测节点的 CONNECT 可用性同样是「两跳」，必须用 CONNECT 预算而不是 -delay：
         * 用 300ms 时绝大多数真实节点会因为回源慢被判死，池子只剩 2~3 个节点，
         * 后续扫描/转发的并发全压在这几个节点上，进一步恶化成功率。 */
        int timeout_ms = g_cfg.delay_ms > 0 ? (g_cfg.delay_ms > 800 ? g_cfg.delay_ms : 800) : 800;
        if (timeout_ms < BAIDU_CONNECT_MIN_TIMEOUT_MS) timeout_ms = BAIDU_CONNECT_MIN_TIMEOUT_MS;
        socket_t fd = tcp_connect_via_baidu_node(nullptr, addr, g_cfg.baidu_scan_target, timeout_ms, &latency);
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
    int target_port = ctx->target_port;
    int is_tls = ctx->is_tls;
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

        /* 预解析二进制地址 sockaddr_storage，预解析 probe_sa (用于 HTTP CF-RAY 探测) 与 target_sa (用于真实转发目标) */
        struct sockaddr_storage probe_sa = {0};
        socklen_t probe_salen = 0;
        struct sockaddr_storage target_sa = {0};
        socklen_t target_salen = 0;
        int is_v6 = (strchr(ip, ':') != nullptr);
        if (is_v6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&probe_sa;
            s6->sin6_family = AF_INET6;
            s6->sin6_port = htons((uint16_t)probe_port);
            if (inet_pton(AF_INET6, ip, &s6->sin6_addr) == 1) probe_salen = sizeof(*s6);

            struct sockaddr_in6 *t6 = (struct sockaddr_in6 *)&target_sa;
            t6->sin6_family = AF_INET6;
            t6->sin6_port = htons((uint16_t)target_port);
            if (inet_pton(AF_INET6, ip, &t6->sin6_addr) == 1) target_salen = sizeof(*t6);
        } else {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&probe_sa;
            s4->sin_family = AF_INET;
            s4->sin_port = htons((uint16_t)probe_port);
            if (inet_pton(AF_INET, ip, &s4->sin_addr) == 1) probe_salen = sizeof(*s4);

            struct sockaddr_in *t4 = (struct sockaddr_in *)&target_sa;
            t4->sin_family = AF_INET;
            t4->sin_port = htons((uint16_t)target_port);
            if (inet_pton(AF_INET, ip, &t4->sin_addr) == 1) target_salen = sizeof(*t4);
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
        int code_failed = 0;

        /* 判定链（is_tls = 直连栈且目标端口非明文）：
         *   1) 唯一存活/延迟门槛 = 目标端口(443) 的 TLS 握手 —— 与真实转发路径一致；
         *   2) 80 端口仅在首轮做一次「尽力而为」的 CF-RAY / 状态码采集，不参与存活与延迟统计。
         * 百度前置走 CONNECT 隧道，is_tls 为 0，直接走下面的「明文端口」分支：
         * 以 80 端口 HTTP HEAD 作为存活与延迟门槛（与基线 cfnat-old 一致），
         * 因为隧道内 CONNECT 已是两跳（90~1200ms），再叠一次 TLS 会被 -delay 预算误杀。 */
        socket_t fd = INVALID_SOCKET;     /* 仅非 TLS 分支使用的 Keep-Alive 连接 */
        int conn_lat = 0;
        int eff_probes = is_tls ? (probes > 2 ? 2 : probes) : probes;
        int code_meta_unavailable = 0;
        for (int attempt = 0; atomic_load(&g_running) && attempt < eff_probes; attempt++) {
            int cur_latency = 0;
            char cur_colo[MAX_COLO_LEN] = {0};

            if (is_tls) {
                /* ── 主路径：目标端口 TLS 握手，既是存活门槛也是延迟样本 ── */
                int tls_conn_lat = 0;
                socket_t tls_fd = dial_target_with_proxy_sa(ip, &target_sa, target_salen, target_port,
                                                            ctx->cfg->delay_ms, ctx->proxy_pool, &tls_conn_lat);
                if (cfnat_socket_invalid(tls_fd)) {
                    atomic_fetch_add(&ctx->connect_fail, 1);
                    if (attempt == 0) break;
                    continue;
                }
                long t_tls_start = now_ms();
                int tls_ok = tls_probe_host(tls_fd, hdr_timeout, ctx->probe_host);
                long t_tls_end = now_ms();
                close(tls_fd);
                if (!tls_ok) {
                    atomic_fetch_add(&ctx->header_fail, 1);
                    if (attempt == 0) break;
                    continue;
                }
                int tls_rtt = (int)(t_tls_end - t_tls_start);
                cur_latency = tls_rtt > 0 ? tls_rtt : (tls_conn_lat > 0 ? tls_conn_lat : 1);

                /* ── 首轮附带一次 :80 元数据采集（短超时，失败绝不淘汰该 IP）── */
                if (attempt == 0) {
                    int meta_to = hdr_timeout > 600 ? 600 : hdr_timeout;
                    socket_t mfd = dial_target_with_proxy_sa(ip, &probe_sa, probe_salen, probe_port,
                                                             meta_to, ctx->proxy_pool, nullptr);
                    if (cfnat_socket_invalid(mfd)) {
                        code_meta_unavailable = 1;
                        if (ctx->cfg->code > 0) atomic_fetch_add(&ctx->code_meta_skip, 1);
                    } else {
                        char mhdr[4096];
                        int mn = -1;
                        if (send_all_timeout(mfd, head_req, (size_t)head_req_len, meta_to)) {
                            mn = recv_headers(mfd, mhdr, sizeof(mhdr), meta_to);
                        }
                        close(mfd);
                        if (mn > 0) {
                            if (extract_cfray(mhdr, cur_colo, sizeof(cur_colo)) == 0) {
                                /* 仅当用户显式指定 -colo 时，机房不匹配才淘汰 */
                                if (ctx->cfg->colo[0] && !colo_rule_allowed(ctx->cfg->colo, cur_colo)) {
                                    atomic_fetch_add(&ctx->colo_skip, 1);
                                    code_failed = 1;
                                    break;
                                }
                            } else {
                                atomic_fetch_add(&ctx->cfray_miss, 1); /* 只统计，不再淘汰 */
                            }
                            if (ctx->cfg->code > 0) {
                                int rc_meta = extract_http_status_code(mhdr);
                                if (rc_meta == ctx->cfg->code) {
                                    code_matched = 1;
                                } else if (rc_meta != 405) {
                                    atomic_fetch_add(&ctx->http_code_mismatch, 1);
                                    code_failed = 1;
                                    break;
                                }
                            }
                        } else {
                            code_meta_unavailable = 1;
                            if (ctx->cfg->code > 0) atomic_fetch_add(&ctx->code_meta_skip, 1);
                        }
                    }
                }
            } else {
                /* ── 明文目标端口：沿用 80/自定义端口的 HTTP HEAD 作为存活判定 ── */
                if (cfnat_socket_invalid(fd)) {
                    conn_lat = 0;
                    fd = dial_target_with_proxy_sa(ip, &probe_sa, probe_salen, probe_port, ctx->cfg->delay_ms, ctx->proxy_pool, &conn_lat);
                    if (cfnat_socket_invalid(fd)) {
                        atomic_fetch_add(&ctx->connect_fail, 1);
                        /* 直连：首轮握手失败即判定死节点（避免对死 IP 无效等待）；
                         * 百度前置：每次拨号随机挑节点，某个节点劣化不代表该 IP 不可用，允许换节点重试一次。 */
                        if (ctx->proxy_pool) {
                            if (attempt >= 1) break;
                        } else {
                            break;
                        }
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
                    close(fd);
                    fd = INVALID_SOCKET;
                    atomic_fetch_add(&ctx->header_fail, 1);
                    if (attempt == 0) break;
                    continue;
                }

                if (cfnat_strcasestr(hdr, "Connection: close")) {
                    close(fd);
                    fd = INVALID_SOCKET;
                }

                int resp_code = extract_http_status_code(hdr);
                if (ctx->cfg->code > 0) {
                    if (resp_code == ctx->cfg->code) {
                        code_matched = 1;
                    } else if (resp_code != 405) {
                        atomic_fetch_add(&ctx->http_code_mismatch, 1);
                        code_failed = 1;
                        break;
                    }
                }

                if (extract_cfray(hdr, cur_colo, sizeof(cur_colo)) != 0) {
                    /* 仅统计：确实有部分边缘/部分时段 80 端口不回 CF-RAY（或本地 ISP 改写了响应头），
                     * 曾经「缺失即淘汰」会把这类健全节点整批误杀。只有用户显式要求按机房筛选时才必须淘汰。 */
                    atomic_fetch_add(&ctx->cfray_miss, 1);
                    if (ctx->cfg->colo[0]) {
                        code_failed = 1;
                        break;
                    }
                }
                if (!colo_rule_allowed(ctx->cfg->colo, cur_colo)) {
                    atomic_fetch_add(&ctx->colo_skip, 1);
                    code_failed = 1;
                    break;
                }

                cur_latency = (int)(t_end - t_start);
                if (cur_latency <= 0) cur_latency = conn_lat > 0 ? conn_lat : 1;
            }

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

            if (cur_colo[0] && (!best_colo[0] || cur_latency <= best_latency)) {
                snprintf(best_colo, sizeof(best_colo), "%s", cur_colo);
            }
        }

        /* 百度前置兜底通道：隧道内 80 端口 HEAD 全部失败时，改用目标端口(443) TLS 再验一次。
         * 隧道出口的 80/443 策略可能不同（0.0.16 只测 80，没有这条兜底），
         * 若只剩 443 可用，没有它就会整栈 0 候选（表现为「百度前置完全不可用」）。
         * 该兜底只在 80 完全无果时触发，健康节点不会付出额外开销。 */
        if (success_count == 0 && ctx->proxy_pool && !is_tls && atomic_load(&g_running)) {
            int tls_conn_lat = 0;
            socket_t tfd = dial_target_with_proxy_sa(ip, &target_sa, target_salen, target_port,
                                                     ctx->cfg->delay_ms, ctx->proxy_pool, &tls_conn_lat);
            if (cfnat_socket_valid(tfd)) {
                long t0 = now_ms();
                int ok = tls_probe_host(tfd, hdr_timeout, ctx->probe_host);
                long t1 = now_ms();
                close(tfd);
                if (ok) {
                    int lat = (int)(t1 - t0);
                    if (lat <= 0) lat = tls_conn_lat > 0 ? tls_conn_lat : 1;
                    success_count = eff_probes; /* 兜底路径视为本轮全部存活，避免 loss_rate 误判重罚 */
                    total_latency = lat * success_count;
                    best_latency = lat;
                    ewma_latency = lat;
                    jitter_ms = 0;
                    debug_msg("IP %s 的 80 端口 HEAD 无果，已由 443 TLS 兜底判定存活 (延迟 %d ms)", ip, lat);
                }
            }
        }
        if (cfnat_socket_valid(fd)) close(fd);
        /* 机房标签缺失时统一回落 UNK，保证展示/缓存/过滤三处语义一致 */
        if (!best_colo[0]) snprintf(best_colo, sizeof(best_colo), "%s", "UNK");

        int avg_latency = success_count > 0 ? (total_latency / success_count) : 0;

        uint64_t done = atomic_fetch_add(&ctx->completed, 1) + 1;
        /* debug 模式下已逐条输出探测明细，不再穿插百分比进度日志 */
        if (g_cfg.log_level < LOG_DEBUG && terminal_has_color(stderr)) {
            uint64_t step = ctx->total / 100;
            if (step < 5) step = 5;
            if (step > 500) step = 500;
            if (done == ctx->total || done % step == 0) {
                double pct = (double)done * 100.0 / (double)(ctx->total > 0 ? ctx->total : 1);
                if (pct > 100.0) pct = 100.0;
                pthread_mutex_lock(&g_log_mu);
                fprintf(stderr, "\r" ANSI_GRAY "[扫描进度]" ANSI_RESET " 已完成: " ANSI_BOLD "%llu" ANSI_RESET " / %llu (" ANSI_GREEN "%.2f%%" ANSI_RESET ")",
                        (unsigned long long)done, (unsigned long long)ctx->total, pct);
                if (done == ctx->total) fprintf(stderr, "\n");
                fflush(stderr);
                pthread_mutex_unlock(&g_log_mu);
            }
        }
        if (code_failed || success_count <= 0 || avg_latency <= 0 || (ctx->cfg->delay_ms > 0 && avg_latency > ctx->cfg->delay_ms)) continue;

        /* 若显式指定了 code (code > 0)，且初筛未完全确认（例如 HEAD 返回 405），使用 GET 在 80 端口做二次状态码校验。
         * 但当 80 端口完全不可达（IPv6 常见 / ISP 过滤）时不再做「连不上就淘汰」的判定：
         * -code 的语义是校验 HTTP 状态码，而不是要求 80 必须可达；否则会与 TLS 主路径互相打架，
         * 造成「443 完全可用、却因 80 不通被整批淘汰」。此时仅计数并在扫描结束时提示一次。 */
        if (ctx->cfg->code > 0 && !code_matched && !code_meta_unavailable) {
            int target_code = ctx->cfg->code;
            socket_t check_fd = dial_target_with_proxy_sa(ip, &probe_sa, probe_salen, probe_port, ctx->cfg->delay_ms, ctx->proxy_pool, nullptr);
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
        r.probe_count = eff_probes;
        r.success_count = success_count;
        r.loss_rate = (eff_probes - success_count) * 100 / eff_probes;
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
            debug_msg("[TCP/H2] 发现有效IP %s%s%s 位置信息 %s%s%s 延迟 %s%d%s 毫秒",
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
static void carrier_trigger_maintenance(CarrierRuntime *rt, int flags);
static void *carrier_maintenance_thread(void *arg);
static void carrier_note_connection_success(CarrierRuntime *rt, const char *ip);
static void carrier_note_connection_failed(CarrierRuntime *rt, const char *ip);
static int carrier_try_use_candidate_caches(CarrierRuntime *rt);
static ResultList filter_udp_candidates_from_tcp(CarrierRuntime *rt, const Result *tcp_results, size_t count, size_t target_ipnum);
static void *carrier_udp_health_thread(void *arg);
static int create_small_thread(pthread_t *tid, void *(*fn)(void *), void *arg);

/* 统一 UDP/QUIC 探测超时口径：默认保底 800ms，高延迟用户显式配置 >800ms 时遵循其设定 */
CFNAT_NODISCARD static inline int udp_probe_timeout_ms(int cfg_delay_ms) {
    return (cfg_delay_ms >= 800) ? cfg_delay_ms : 800;
}

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
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%u", path, (unsigned int)(rand_u64() & 0xffff));
    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        warn_msg("写入临时缓存 %s 失败", tmp_path);
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
    fflush(fp);
#ifdef _WIN32
    int fd = _fileno(fp);
    if (fd >= 0) _commit(fd);
    fclose(fp);
    if (!MoveFileExA(tmp_path, path, MOVEFILE_REPLACE_EXISTING)) {
        remove(path);
        MoveFileExA(tmp_path, path, 0);
    }
#else
    int fd = fileno(fp);
    if (fd >= 0) fsync(fd);
    fclose(fp);
    rename(tmp_path, path);
#endif
    debug_msg("候选缓存已安全原子写入 %s，共 %zu 个", path, len);
}

static ResultList load_candidate_cache_for_profile(const char *path, const ProfileConfig *prof) {
    ResultList rl = {0};
    if (!path || !file_exists(path)) return rl;
    struct stat st;
    if (stat(path, &st) == 0) {
        long age_sec = (long)(time(nullptr) - st.st_mtime);
        if (age_sec > CACHE_REFRESH_INTERVAL_SECONDS) {
            log_msg("候选缓存 %s 已超过 %ld 秒 (当前 %ld 秒)，将在后续故障自愈时更新", path, (long)CACHE_REFRESH_INTERVAL_SECONDS, age_sec);
        }
    }

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
        if (colo_rule[0] && strcmp(r.data_center, "UNK") != 0 && r.data_center[0] != '\0' && !colo_rule_allowed(colo_rule, r.data_center)) continue;
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

/* 全异步非阻塞并发 QUIC 探针齐射批次执行函数（与 0.0.16 逐字一致）
 * 使用「每协议族一个共享非阻塞 UDP 套接字 + sendto」齐射，再用 poll + recvfrom 按来源地址配对。
 * 不使用 per-IP connect()：连通性探针一旦被内核/防火墙记上 ICMP 错误，per-IP 套接字会整条失效，
 * 且 32~64 个 fd 在 Windows 上更容易触发瞬时耗尽；共享套接字是 0.0.16 实测三栈可用的唯一形态。 */
static size_t quic_batch_probe(CarrierRuntime *rt, socket_t fd4, socket_t fd6, int target_port,
                               int timeout_ms, QuicProbeItem *items, size_t count, size_t needed_responses, int pacing_ms) {
    if (!items || count == 0) return 0;

    /* C23 thread_local 预格式化探针模板：头部 0..22 固定，其余 1177 字节必须保持全零 */
    static thread_local uint8_t pkt[1200] = {
        0xC0, 0x5A, 0x5A, 0x5A, 0x5A, 0x08,
        [14] = 0x08
    };

    uint32_t seed = (uint32_t)now_ms();
    memcpy(pkt + 6, &seed, 4);

    long start_time = now_ms();
    size_t sent_v4 = 0, sent_v6 = 0;

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

        if (i > 0 && pacing_ms > 0) {
            if (sleep_interruptible_ms(pacing_ms) != 0) break;
        }
        uint8_t ch_pkt[1200];
        const uint8_t *send_buf = pkt;
        if (g_cfg.h3_client) {
            uint64_t d_val = rand_u64() ^ ((uint64_t)seed << 17) ^ (uint64_t)(i + 1);
            uint64_t s_val = rand_u64() ^ ((uint64_t)(~seed) << 11) ^ ((uint64_t)(i + 1) << 29);
            uint8_t dcid[8], scid_b[8];
            memcpy(dcid, &d_val, 8);
            memcpy(scid_b, &s_val, 8);
            const char *dom = (rt && rt->spec.prof.domain[0]) ? rt->spec.prof.domain : g_cfg.domain;
            quic_build_initial_client_hello(ch_pkt, dcid, scid_b, dom);
            send_buf = ch_pkt;
        } else {
            uint32_t scid = seed ^ (uint32_t)(i + 1);
            memcpy(pkt + 15, &scid, 4);
        }

        items[i].send_time = now_ms();
        if (sendto(sfd, (const char *)send_buf, sizeof(pkt), 0,
                   (struct sockaddr *)&items[i].addr, items[i].addr_len) > 0) {
            if (is_v6) sent_v6++;
            else sent_v4++;
        }
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
        /* 仅轮询实际发过包的地址族，避免 Windows WSAPoll 传入未绑定空闲 UDP 套接字触发 POLLNVAL/WSAEINVAL */
        if (sent_v4 > 0 && cfnat_socket_valid(fd4)) {
            pfds[npfd].fd = fd4;
            pfds[npfd].events = POLLIN;
            pfds[npfd].revents = 0;
            npfd++;
        }
        if (sent_v6 > 0 && cfnat_socket_valid(fd6)) {
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
                char resp[2048];
                struct sockaddr_storage from;
#ifdef _WIN32
                int fromlen = (int)sizeof(from);
#else
                socklen_t fromlen = sizeof(from);
#endif
                ssize_t n = recvfrom(rfd, resp, sizeof(resp), 0, (struct sockaddr *)&from, &fromlen);
                if (n < 0) {
                    /* 仅在网络瞬态与中断错误时消费并继续读取队列后续报文，杜绝致命错误导致死循环 */
                    if (cfnat_last_socket_transient()) continue;
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
                        debug_msg("[UDP/H3] [%s] QUIC 探针响应成功: %s 延迟 %d ms",
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

    debug_msg("[UDP/H3] [%s] QUIC 批量探测汇总: 候选 %zu，成功发出 %zu，收到回包 %zu，超时上限 %d ms",
              carrier_display_name(rt ? rt->spec.mode : nullptr), count, sent_v4 + sent_v6, responded_count, timeout_ms);
    return responded_count;
}

static void quic_drain_socket(socket_t fd) {
    if (cfnat_socket_invalid(fd)) return;
    char dump[2048];
    for (int i = 0; i < 64; i++) {
        ssize_t n = recvfrom(fd, dump, sizeof(dump), 0, nullptr, nullptr);
        if (n <= 0) break;
    }
}

static int ip_in_list(char (*ips)[MAX_IP_LEN], size_t len, const char *ip) {
    for (size_t i = 0; i < len; i++) {
        if (strcmp(ips[i], ip) == 0) return 1;
    }
    return 0;
}

static int ip_in_resultlist(const ResultList *rl, const char *ip) {
    for (size_t i = 0; i < rl->len; i++) {
        if (strcmp(rl->items[i].ip, ip) == 0) return 1;
    }
    return 0;
}

static socket_t quic_open_probe_socket(int af) {
    socket_t fd = socket(af, SOCK_DGRAM, 0);
    if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
#ifdef _WIN32
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
    BOOL bNewBehavior = FALSE;
    DWORD dwBytesReturned = 0;
    WSAIoctl(fd, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), nullptr, 0, &dwBytesReturned, nullptr, nullptr);
#endif
    bind_socket_to_interface(fd, af);
    set_nonblock(fd, 1);
    return fd;
}

/* 对单个小批次执行 num 轮 QUIC 测速（每批重建共享 socket 轮换源端口 + 发包节拍 + 首轮无回包熔断），
 * 将满足延迟阈值的合格节点合并进 udp_res，并通过 out_any_resp 返回本批次收到过回包的节点数。 */
static size_t quic_probe_batch_multi_round(CarrierRuntime *rt,
                                           int target_port, int timeout_ms, int max_delay, int probe_rounds,
                                           const QuicProbeItem *batch, size_t cur_len,
                                           ResultList *udp_res, size_t *out_any_resp) {
    if (out_any_resp) *out_any_resp = 0;
    if (!batch || cur_len == 0) return 0;

    int need_v4 = 0, need_v6 = 0;
    for (size_t i = 0; i < cur_len; i++) {
        if (strchr(batch[i].res.ip, ':')) need_v6 = 1;
        else need_v4 = 1;
    }

    socket_t fd4 = need_v4 ? quic_open_probe_socket(AF_INET) : INVALID_SOCKET;
    socket_t fd6 = need_v6 ? quic_open_probe_socket(AF_INET6) : INVALID_SOCKET;
    if (cfnat_socket_invalid(fd4) && cfnat_socket_invalid(fd6)) {
        return 0;
    }

    QuicProbeItem *round_items = calloc(cur_len, sizeof(QuicProbeItem));
    size_t *idx_map = calloc(cur_len, sizeof(size_t));
    int *ok_cnt = calloc(cur_len, sizeof(int));
    int *total_lat = calloc(cur_len, sizeof(int));
    int *min_lat = calloc(cur_len, sizeof(int));
    int *max_lat = calloc(cur_len, sizeof(int));
    int *miss_cnt = calloc(cur_len, sizeof(int));   /* 连续无回包轮数：QoS 抖动常只丢一轮，不能首轮即熔断 */
    uint8_t *active = calloc(cur_len, sizeof(uint8_t));
    if (!round_items || !idx_map || !ok_cnt || !total_lat || !min_lat || !max_lat || !miss_cnt || !active) {
        free(round_items);
        free(idx_map);
        free(ok_cnt);
        free(total_lat);
        free(min_lat);
        free(max_lat);
        free(miss_cnt);
        free(active);
        if (cfnat_socket_valid(fd4)) close(fd4);
        if (cfnat_socket_valid(fd6)) close(fd6);
        return 0;
    }

    for (size_t i = 0; i < cur_len; i++) {
        active[i] = 1;
        min_lat[i] = 1000000;
    }

    for (int r = 0; r < probe_rounds && atomic_load(&g_running); r++) {
        if (r > 0 && sleep_interruptible_ms(200) != 0) break;

        size_t active_cnt = 0;
        for (size_t i = 0; i < cur_len; i++) {
            if (!active[i]) continue;
            round_items[active_cnt] = batch[i];
            round_items[active_cnt].responded = 0;
            round_items[active_cnt].latency_ms = 0;
            idx_map[active_cnt] = i;
            active_cnt++;
        }
        if (active_cnt == 0) break;

        quic_drain_socket(fd4);
        quic_drain_socket(fd6);
        quic_batch_probe(rt, fd4, fd6, target_port, timeout_ms, round_items, active_cnt, active_cnt, 20);

        for (size_t k = 0; k < active_cnt; k++) {
            size_t orig = idx_map[k];
            if (round_items[k].responded) {
                int lat = round_items[k].latency_ms;
                ok_cnt[orig]++;
                total_lat[orig] += lat;
                if (lat < min_lat[orig]) min_lat[orig] = lat;
                if (lat > max_lat[orig]) max_lat[orig] = lat;
            } else {
                /* 连续 2 轮无回包才熔断：QoS 窗口内首轮丢包极常见，原来「首轮即熔断」会把
                 * 大量健康节点永久跳过，导致要测很多轮才能凑够 num 个（且误判率极高）。 */
                miss_cnt[orig]++;
                if (miss_cnt[orig] >= 2) active[orig] = 0;
            }
        }
    }

    size_t added = 0;
    size_t any_resp = 0;
    for (size_t i = 0; i < cur_len; i++) {
        if (ok_cnt[i] <= 0) continue;
        any_resp++;
        int avg_lat = total_lat[i] / ok_cnt[i];
        /* 用「成功样本中的最小 RTT」判合格：单次被 QoS 排队（如 400ms）不应该淘汰一条本身很健康的链路；
         * 延迟也取 min（best-case path RTT），比均值稳定，直接对症「某一轮延迟不好就被淘汰」。 */
        int judge_lat = (min_lat[i] < 1000000) ? min_lat[i] : avg_lat;
        if (judge_lat <= 0 || (max_delay > 0 && judge_lat > max_delay)) continue;
        if (ip_in_resultlist(udp_res, batch[i].res.ip)) continue;

        Result res = batch[i].res;
        res.latency_ms = judge_lat;
        res.ewma_latency = judge_lat;
        res.jitter_ms = (ok_cnt[i] > 1 && max_lat[i] >= min_lat[i]) ? (max_lat[i] - min_lat[i]) : 0;
        res.probe_count = probe_rounds;
        res.success_count = ok_cnt[i];
        res.loss_rate = ((probe_rounds - ok_cnt[i]) * 100) / probe_rounds;
        resultlist_add(udp_res, &res);
        added++;
    }

    if (out_any_resp) *out_any_resp = any_resp;

    free(round_items);
    free(idx_map);
    free(ok_cnt);
    free(total_lat);
    free(min_lat);
    free(max_lat);
    free(miss_cnt);
    free(active);
    if (cfnat_socket_valid(fd4)) close(fd4);
    if (cfnat_socket_valid(fd6)) close(fd6);
    return added;
}

/* P0-H3: 方案C抗QoS多轮QUIC测速引擎（冷却 -> 金丝雀探路 -> 小批次换源端口+节拍 -> 子网裂变循环补齐） */
static ResultList filter_udp_candidates_from_tcp(CarrierRuntime *rt, const Result *tcp_results, size_t count, size_t target_ipnum) {
    ResultList udp_res = {0};
    if (!tcp_results || count == 0 || target_ipnum == 0) return udp_res;

    size_t desired_count = target_ipnum;
    if (desired_count > 64) desired_count = 64;
    if (desired_count < 2) desired_count = 2;

    int probe_rounds = (rt->spec.prof.num > 0) ? rt->spec.prof.num : g_cfg.num;
    if (probe_rounds < 1) probe_rounds = 1;
    if (probe_rounds > 50) probe_rounds = 50;

    int max_delay = (rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms;
    int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
    if (target_port <= 0) target_port = 443;
    int timeout_ms = udp_probe_timeout_ms(max_delay);
    if (timeout_ms < 1000) timeout_ms = 1000;
    if (timeout_ms > 2500) timeout_ms = 2500;

    long total_start = now_ms();

    /* 1. TCP 扫描结束后冷却 500ms，让路由器 conntrack 与出口突发配额先回落 */
    if (sleep_interruptible_ms(500) != 0) return udp_res;

    /* 2. 金丝雀单点探路：批量开测前先单发验证头部节点，确认未触发 UDP QoS / 阻断 */
    /* 金丝雀重试跨度必须覆盖典型 QoS 窗口（实测 5~30s）：
     * 原来 3 次 × 800ms 只能覆盖 2.4s，窗口内必然放弃 → 空池 → 走 30s 起步的退避，一次窗口代价就是几分钟。
     * 现改为 4 次探测、间隔 0.5/2/5.5s（共 ~8s，仅 4 个包），足以骑过短窗口。 */
    static const int k_canary_gap_ms[4] = { 500, 2000, 5500, 0 };
    size_t canary_tries = count < 4 ? count : 4;
    int canary_ok = 0;
    size_t canary_idx = 0;
    int canary_lat = 0;
    for (size_t c = 0; c < canary_tries && atomic_load(&g_running); c++) {
        int c_lat = 0;
        if (quic_probe_ip(tcp_results[c].ip, target_port, timeout_ms, &c_lat)) {
            canary_ok = 1;
            canary_idx = c;
            canary_lat = c_lat;
            debug_msg("[UDP/H3] [%s] [金丝雀探路] 节点 %s UDP/QUIC 连通正常 (延迟 %d ms)，启动低突发小批次测速",
                      carrier_display_name(rt->spec.mode), tcp_results[c].ip, c_lat);
            break;
        }
        if (c + 1 < canary_tries) {
            int gap = k_canary_gap_ms[c < 3 ? c : 3];
            if (gap > 0 && sleep_interruptible_ms(gap) != 0) return udp_res;
        }
    }
    if (!canary_ok) {
        /* 整段链路都无回包 ≠ 没有可用节点，而是「疑似 QoS 窗口」：登记窗口，让健康检查/切换侧
         * 在到期前不要把节点判死，也让上层知道这次空池是窗口造成的而非池子质量下降。 */
        atomic_store_explicit(&rt->qos_suspect_until_ms, (long long)(now_ms() + QOS_WINDOW_SCAN_MS), memory_order_relaxed);
        warn_msg("[UDP/H3] [%s] [金丝雀探路] 连续 %zu 个头部节点均无 UDP 回包（疑似 QoS 惩罚窗/链路阻断），登记 %lds 窗口后等待自愈重扫",
                 carrier_display_name(rt->spec.mode), canary_tries, (long)(QOS_WINDOW_SCAN_MS / 1000));
        return udp_res;
    }

    /* 金丝雀成功后间隔 300ms 再开首批，避免紧贴金丝雀触发瞬时令牌桶 */
    if (sleep_interruptible_ms(300) != 0) return udp_res;

    /* 3. 小批次 (<= 6) + 每批重建 socket 换源端口 + 发包节拍 */
    size_t batch_size = 6;
    if (desired_count * 2 < batch_size) batch_size = desired_count * 2;
    if (batch_size < 2) batch_size = 2;

    QuicProbeItem *probe_items = calloc(batch_size, sizeof(QuicProbeItem));
    size_t tried_cap = 1024;
    size_t tried_len = 0;
    char (*tried_ips)[MAX_IP_LEN] = calloc(tried_cap, sizeof(*tried_ips));
    if (!probe_items || !tried_ips) {
        free(probe_items);
        free(tried_ips);
        return udp_res;
    }

    for (size_t i = 0; i < count && tried_len < tried_cap; i++) {
        snprintf(tried_ips[tried_len++], MAX_IP_LEN, "%s", tcp_results[i].ip);
    }

    size_t stage1_any_resp = 0;
    size_t offset = 0;
    int batch_idx = 1;
    int gentle_mode = 0;

    /* 阶段一：小批次遍历原 TCP 候选池，每批独立源端口并测 num 轮；
     * 若金丝雀刚通但第 1 批并发全无回包，自动降级为单点节拍模式（每 IP 独立 socket + 150ms 间隔），避免继续齐射加深 QoS */
    while (offset < count && udp_res.len < desired_count && atomic_load(&g_running)) {
        if (batch_idx > 1 && sleep_interruptible_ms(250) != 0) break;

        size_t cur_len = count - offset;
        if (cur_len > batch_size) cur_len = batch_size;

        log_msg("[UDP/H3] [%s] [筛选/第%d批] 并发检验第 %zu~%zu 个 TCP 候选 IP (批次 %zu, 测速 %d 轮)...",
                carrier_display_name(rt->spec.mode), batch_idx, offset + 1, offset + cur_len, cur_len, probe_rounds);

        memset(probe_items, 0, cur_len * sizeof(QuicProbeItem));
        for (size_t i = 0; i < cur_len; i++) {
            probe_items[i].res = tcp_results[offset + i];
            probe_items[i].addr = probe_items[i].res.addr;
            probe_items[i].addr_len = probe_items[i].res.addr_len;
        }

        size_t batch_resp = 0;
        size_t added = quic_probe_batch_multi_round(rt, target_port, timeout_ms, max_delay, probe_rounds,
                                                    probe_items, cur_len, &udp_res, &batch_resp);
        stage1_any_resp += batch_resp;
        if (batch_idx == 1 && batch_resp == 0) {
            gentle_mode = 1;
            log_msg("[UDP/H3] [%s] [降速自保] 金丝雀连通但首批并发无回包（疑似并发触发短时 QoS），冷却 1.2s 后切换为单点慢速节拍测速",
                    carrier_display_name(rt->spec.mode));
            if (sleep_interruptible_ms(1200) != 0) break;
            int consec_miss = 0;
            size_t scan_limit = count < desired_count ? count : desired_count;
            for (size_t i = 0; i < scan_limit && udp_res.len < desired_count && atomic_load(&g_running); i++) {
                if (i > 0 && sleep_interruptible_ms(150) != 0) break;
                int ok_cnt = 0, total_lat = 0, min_lat = 1000000, max_lat = 0, miss = 0;
                for (int r = 0; r < probe_rounds && atomic_load(&g_running); r++) {
                    if (r > 0 && sleep_interruptible_ms(120) != 0) break;
                    int lat = 0;
                    if (quic_probe_ip(tcp_results[i].ip, target_port, timeout_ms, &lat)) {
                        ok_cnt++;
                        total_lat += lat;
                        min_lat = (lat < min_lat) ? lat : min_lat;
                        max_lat = (lat > max_lat) ? lat : max_lat;
                        miss = 0;
                    } else if (++miss >= 2) {
                        break;   /* 与批次模式一致：连续 2 轮无回包才放弃，单轮抖动不算死 */
                    }
                }
                if (ok_cnt > 0) {
                    consec_miss = 0;
                    stage1_any_resp++;
                    int avg_lat = total_lat / ok_cnt;
                    int judge_lat = (min_lat < 1000000) ? min_lat : avg_lat;
                    if (judge_lat > 0 && (max_delay <= 0 || judge_lat <= max_delay) && !ip_in_resultlist(&udp_res, tcp_results[i].ip)) {
                        Result res = tcp_results[i];
                        res.latency_ms = judge_lat;
                        res.ewma_latency = judge_lat;
                        res.jitter_ms = (ok_cnt > 1 && max_lat >= min_lat) ? (max_lat - min_lat) : 0;
                        res.probe_count = probe_rounds;
                        res.success_count = ok_cnt;
                        res.loss_rate = ((probe_rounds - ok_cnt) * 100) / probe_rounds;
                        resultlist_add(&udp_res, &res);
                    }
                } else {
                    consec_miss++;
                    if (consec_miss >= 5 && udp_res.len > 0) break;
                    if (consec_miss >= 5 && udp_res.len == 0) break;
                }
            }
            /* 若降速后仍暂未捕到新节点，保留金丝雀刚验证通过的真实节点避免白白归零 */
            if (udp_res.len == 0 && canary_lat > 0 && (max_delay <= 0 || canary_lat <= max_delay)) {
                Result res = tcp_results[canary_idx];
                res.latency_ms = canary_lat;
                res.ewma_latency = canary_lat;
                res.jitter_ms = 0;
                res.probe_count = 1;
                res.success_count = 1;
                res.loss_rate = 0;
                resultlist_add(&udp_res, &res);
                stage1_any_resp++;
            }
            break;
        }
        if (added == 0 && batch_resp == 0) {
            /* 一整批（>=4 个）同时 0 回包，几乎不可能是这些 IP 一起坏掉，判为「疑似 QoS 窗口」：
             * 登记窗口，让健康检查在到期前不把节点判死（窗口内整段链路都不通，探针失败没有归因价值）。 */
            if (cur_len >= 4) {
                long long now_v = (long long)now_ms();
                long long want = now_v + QOS_WINDOW_SCAN_MS;
                if (atomic_load_explicit(&rt->qos_suspect_until_ms, memory_order_relaxed) < want) {
                    atomic_store_explicit(&rt->qos_suspect_until_ms, want, memory_order_relaxed);
                }
            }
            debug_msg("[%s] 第 %zu~%zu 个 TCP 候选 IP 全无 UDP 回包，向后滑动选取下一批...",
                      carrier_display_name(rt->spec.mode), offset + 1, offset + cur_len);
        }

        offset += cur_len;
        batch_idx++;
    }

    /* 阶段二：若合格 H3 节点不足 ipnum 个，从原 ipnum 个 IP 的 IPv6 /64 或 IPv4 /24 子网循环裂变补齐 */
    if (!gentle_mode && stage1_any_resp > 0 && udp_res.len < desired_count && atomic_load(&g_running)) {
        size_t base_count = (count < desired_count) ? count : desired_count;
        size_t max_derived = base_count * 2;
        QuicProbeItem *derived_items = calloc(max_derived, sizeof(QuicProbeItem));

        if (derived_items) {
            const int max_fission_rounds = 6;
            for (int f_round = 1; f_round <= max_fission_rounds && udp_res.len < desired_count && atomic_load(&g_running); f_round++) {
                size_t derived_count = 0;
                for (size_t b = 0; b < base_count; b++) {
                    const Result *base_seed = &tcp_results[b];
                    for (int s = 0; s < 2; s++) {
                        char sibling_ip[MAX_IP_LEN] = {0};
                        int picked = 0;
                        for (int tries = 0; tries < 8; tries++) {
                            if (!sample_sibling_ip_from_subnet(base_seed->ip, sibling_ip, sizeof(sibling_ip))) break;
                            if (!ip_in_list(tried_ips, tried_len, sibling_ip)) {
                                picked = 1;
                                break;
                            }
                        }
                        if (!picked) continue;
                        if (tried_len < tried_cap) {
                            snprintf(tried_ips[tried_len++], MAX_IP_LEN, "%s", sibling_ip);
                        }
                        derived_items[derived_count] = (QuicProbeItem){0};
                        derived_items[derived_count].res = *base_seed;
                        snprintf(derived_items[derived_count].res.ip, sizeof(derived_items[derived_count].res.ip), "%s", sibling_ip);
                        result_init_addr(&derived_items[derived_count].res);
                        derived_items[derived_count].addr = derived_items[derived_count].res.addr;
                        derived_items[derived_count].addr_len = derived_items[derived_count].res.addr_len;
                        derived_count++;
                    }
                }

                if (derived_count == 0) break;

                log_msg("[UDP/H3] [%s] [子网裂变/第%d轮] 当前合格 %zu/%zu，从原 %zu 个 IP 各裂变 2 个共 %zu 个同网段 IP (批次 %zu, 测速 %d 轮)...",
                        carrier_display_name(rt->spec.mode), f_round, udp_res.len, desired_count,
                        base_count, derived_count, batch_size, probe_rounds);

                size_t round_added = 0;
                size_t round_resp = 0;
                for (size_t d_off = 0; d_off < derived_count && udp_res.len < desired_count && atomic_load(&g_running); d_off += batch_size) {
                    if (sleep_interruptible_ms(250) != 0) break;
                    size_t d_len = derived_count - d_off;
                    if (d_len > batch_size) d_len = batch_size;
                    size_t b_resp = 0;
                    round_added += quic_probe_batch_multi_round(rt, target_port, timeout_ms, max_delay, probe_rounds,
                                                                &derived_items[d_off], d_len, &udp_res, &b_resp);
                    round_resp += b_resp;
                }

                if (round_added == 0 && round_resp == 0) {
                    break;
                }
            }
            free(derived_items);
        }
    }

    free(probe_items);
    free(tried_ips);

    if (udp_res.len > 0) {
        qsort(udp_res.items, udp_res.len, sizeof(Result), cmp_result);
        if (udp_res.len > desired_count) udp_res.len = desired_count;
        log_msg("[%s] UDP/QUIC 多轮精筛完成: 捕获 %zu 个真实有效 H3 候选 (目标: %zu, 每IP %d 轮)，最优延迟: %d ms (%s)，总耗时: %ld ms",
                carrier_display_name(rt->spec.mode), udp_res.len, desired_count, probe_rounds,
                udp_res.items[0].latency_ms, udp_res.items[0].ip,
                now_ms() - total_start);
        /* 与 TCP 扫描一致：精筛结束后输出格式化列表（带 [UDP/H3] 染色 tag），便于直接核对 H3 池子质量 */
        if (g_cfg.log_level >= LOG_INFO) {
            print_results_table_ex(stderr, "UDP/H3", carrier_display_name(rt->spec.mode),
                                   udp_res.items, udp_res.len, (now_ms() - total_start) / 1000);
        }
    } else {
        warn_msg("[%s] 遍历全部 %zu 个 TCP 候选 IP 均无合格 UDP/QUIC 节点（当前运营商可能阻断境外 UDP 443 或超时），绝不使用假节点降级，保持真实 UDP 状态等待自愈重扫",
                 carrier_display_name(rt->spec.mode), count);
    }

    return udp_res;
}

typedef struct {
    CarrierRuntime *rt;
    const char *ip;
    int is_udp;
    int port;
    int delay_ms;
    int ok;
    int lat;
} CacheProbeTask;

static void *cache_probe_worker(void *arg) {
    CacheProbeTask *t = (CacheProbeTask *)arg;
    if (t->is_udp) {
        t->ok = quic_probe_ip(t->ip, t->port, t->delay_ms, &t->lat) ? 1 : 0;
    } else {
        t->ok = carrier_health_check_ip(t->rt, t->ip) ? 1 : 0;
    }
    return nullptr;
}

static size_t cache_quick_check_parallel(CarrierRuntime *rt, const Result *items, size_t len, int is_udp, int port, int delay_ms) {
    size_t n = len < CACHE_QUICK_CHECK_COUNT ? len : CACHE_QUICK_CHECK_COUNT;
    if (n == 0) return (size_t)-1;
    CacheProbeTask tasks[CACHE_QUICK_CHECK_COUNT];
    pthread_t tids[CACHE_QUICK_CHECK_COUNT] = {0};
    for (size_t i = 0; i < n; i++) {
        tasks[i] = (CacheProbeTask){ .rt = rt, .ip = items[i].ip, .is_udp = is_udp, .port = port, .delay_ms = delay_ms, .ok = 0, .lat = 0 };
        if (i > 0 && create_small_thread(&tids[i], cache_probe_worker, &tasks[i]) != 0) {
            tids[i] = 0;
            cache_probe_worker(&tasks[i]);
        }
    }
    cache_probe_worker(&tasks[0]);
    for (size_t i = 1; i < n; i++) {
        if (tids[i]) pthread_join(tids[i], nullptr);
    }
    for (size_t i = 0; i < n; i++) {
        if (tasks[i].ok) return i; /* 优先返回排序最靠前的存活缓存节点 */
    }
    return (size_t)-1;
}

static int carrier_try_use_candidate_caches(CarrierRuntime *rt) {
    if (!rt) return 0;
    int use_h2 = rt->spec.prof.enable_h2;
    int use_h3 = rt->spec.prof.enable_h3;
    int ips_type = rt->spec.prof.ips_type > 0 ? rt->spec.prof.ips_type : g_cfg.ips_type;
    const char *tcp_path = candidate_cache_file_for_profile(rt->spec.mode, ips_type);
    const char *udp_path = candidate_cache_file_for_profile_udp(rt->spec.mode, ips_type);
    int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
    if (target_port <= 0) target_port = 443;
    int delay_ms = udp_probe_timeout_ms((rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms);
    size_t target_ipnum = (size_t)(rt->spec.prof.ipnum > 0 ? rt->spec.prof.ipnum : g_cfg.ipnum);
    if (target_ipnum == 0) target_ipnum = 20;

    /* 纯 H3 模式：优先命中 udpcache 直接秒启；无有效 udpcache 时再读 tcpcache 作种子精筛 H3；两者皆无才走全量扫描 */
    if (!use_h2 && use_h3) {
        ResultList cached_udp = load_candidate_cache_for_profile(udp_path, &rt->spec.prof);
        size_t first_good_udp = (cached_udp.len > 0)
                                ? cache_quick_check_parallel(rt, cached_udp.items, cached_udp.len, 1, target_port, delay_ms)
                                : (size_t)-1;
        if (first_good_udp != (size_t)-1) {
            rt->udp_candidates.items = cached_udp.items;
            rt->udp_candidates.len = cached_udp.len;
            carrier_set_current_udp_candidate(rt, first_good_udp);
            atomic_store(&rt->udp_candidates.cache_valid, 1);
            int udp_lat = rt->udp_candidates.items[rt->udp_candidates.current_index].latency_ms;
            log_msg("[%s] 纯 H3 模式命中 UDP 缓存快速启动:\n"
                    "  └─ [UDP/H3] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)",
                    carrier_display_name(rt->spec.mode),
                    rt->udp_candidates.current_ip, udp_lat, rt->udp_candidates.len);
            if (g_cfg.log_level >= LOG_DEBUG) {
                debug_msg("[UDP/H3] [%s] 已载入缓存的候选 IP 列表 (共 %zu 个):", carrier_display_name(rt->spec.mode), rt->udp_candidates.len);
                print_results_table_ex(stderr, "UDP/H3", carrier_display_name(rt->spec.mode),
                                       rt->udp_candidates.items, rt->udp_candidates.len, 0);
            }
            return 1;
        }
        free(cached_udp.items);

        ResultList cached_tcp = load_candidate_cache_for_profile(tcp_path, &rt->spec.prof);
        if (cached_tcp.len == 0) return 0;
        size_t first_good_tcp = cache_quick_check_parallel(rt, cached_tcp.items, cached_tcp.len, 0, 0, 0);
        if (first_good_tcp == (size_t)-1) {
            warn_msg("[%s] 纯 H3 模式无有效 UDP/TCP 缓存，将执行前置 TCP 扫描生成 H3 种子", carrier_display_name(rt->spec.mode));
            free(cached_tcp.items);
            return 0;
        }
        /* 保留 tcpcache 作为种子池供后续空池自愈，但不开启 TCP 监听与测活 */
        rt->candidates.items = cached_tcp.items;
        rt->candidates.len = cached_tcp.len;
        carrier_set_current_candidate(rt, first_good_tcp);
        atomic_store(&rt->candidates.cache_valid, 1);

        ResultList fresh_udp = filter_udp_candidates_from_tcp(rt, cached_tcp.items, cached_tcp.len, target_ipnum);
        if (fresh_udp.len > 0) {
            rt->udp_candidates.items = fresh_udp.items;
            rt->udp_candidates.len = fresh_udp.len;
            carrier_set_current_udp_candidate(rt, 0);
            atomic_store(&rt->udp_candidates.cache_valid, 1);
            save_candidate_cache(udp_path, fresh_udp.items, fresh_udp.len);
            int udp_lat = rt->udp_candidates.items[0].latency_ms;
            log_msg("[%s] 纯 H3 模式基于 TCP 缓存精筛快速启动:\n"
                    "  └─ [UDP/H3] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)",
                    carrier_display_name(rt->spec.mode),
                    rt->udp_candidates.current_ip, udp_lat, rt->udp_candidates.len);
        } else {
            log_msg("[%s] 纯 H3 模式基于 TCP 缓存启动，暂未捕获有效 H3 节点 (0 个候选，等待空池退避自愈)",
                    carrier_display_name(rt->spec.mode));
        }
        return 1;
    }

    ResultList cached_tcp = load_candidate_cache_for_profile(tcp_path, &rt->spec.prof);
    if (cached_tcp.len == 0) {
        return 0;
    }

    size_t first_good_tcp = cache_quick_check_parallel(rt, cached_tcp.items, cached_tcp.len, 0, 0, 0);
    if (first_good_tcp == (size_t)-1) {
        warn_msg("[%s] TCP 候选缓存健康检查未命中，将执行完整扫描", carrier_display_name(rt->spec.mode));
        free(cached_tcp.items);
        return 0;
    }

    rt->candidates.items = cached_tcp.items;
    rt->candidates.len = cached_tcp.len;
    carrier_set_current_candidate(rt, first_good_tcp);
    atomic_store(&rt->candidates.cache_valid, 1);

    if (use_h3) {
        ResultList cached_udp = load_candidate_cache_for_profile(udp_path, &rt->spec.prof);
        size_t first_good_udp = (cached_udp.len > 0)
                                ? cache_quick_check_parallel(rt, cached_udp.items, cached_udp.len, 1, target_port, delay_ms)
                                : (size_t)-1;
        if (first_good_udp != (size_t)-1) {
            rt->udp_candidates.items = cached_udp.items;
            rt->udp_candidates.len = cached_udp.len;
            carrier_set_current_udp_candidate(rt, first_good_udp);
            atomic_store(&rt->udp_candidates.cache_valid, 1);
        } else {
            free(cached_udp.items);
            ResultList fresh_udp = filter_udp_candidates_from_tcp(rt, cached_tcp.items, cached_tcp.len, target_ipnum);
            if (fresh_udp.len > 0) {
                rt->udp_candidates.items = fresh_udp.items;
                rt->udp_candidates.len = fresh_udp.len;
                carrier_set_current_udp_candidate(rt, 0);
                atomic_store(&rt->udp_candidates.cache_valid, 1);
                save_candidate_cache(udp_path, fresh_udp.items, fresh_udp.len);
            }
        }
    }

    int tcp_lat = (rt->candidates.items && rt->candidates.current_index < rt->candidates.len) ?
                  rt->candidates.items[rt->candidates.current_index].latency_ms : 0;
    int udp_lat = (rt->udp_candidates.items && rt->udp_candidates.current_index < rt->udp_candidates.len) ?
                  rt->udp_candidates.items[rt->udp_candidates.current_index].latency_ms : 0;

    if (!use_h3) {
        log_msg("[%s] 纯 H2 模式命中 TCP 候选缓存快速启动:\n"
                "  └─ [TCP/H2] 最优 IP: %s (延迟 %d ms, 候选 %zu 个) | [UDP/H3] 已禁用",
                carrier_display_name(rt->spec.mode),
                rt->candidates.current_ip, tcp_lat, rt->candidates.len);
    } else if (rt->udp_candidates.len > 0 && rt->udp_candidates.current_ip[0]) {
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
        print_results_table_ex(stderr, "TCP/H2", carrier_display_name(rt->spec.mode),
                               rt->candidates.items, rt->candidates.len, 0);
        if (use_h3 && rt->udp_candidates.len > 0) {
            debug_msg("[UDP/H3] [%s] 已载入缓存的候选 IP 列表 (共 %zu 个):", carrier_display_name(rt->spec.mode), rt->udp_candidates.len);
            print_results_table_ex(stderr, "UDP/H3", carrier_display_name(rt->spec.mode),
                                   rt->udp_candidates.items, rt->udp_candidates.len, 0);
        }
    }
    return 1;
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
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int nprocs = (int)si.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_ONLN)
    int nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
#else
    int nprocs = 4;
#endif
    if (nprocs < 1) nprocs = 1;
    if (threads > nprocs * 64) threads = nprocs * 64; /* 弱算力核心自适应降载，杜绝线程过度切换争抢 */
    if (threads < 16 && (uint64_t)total_ips >= 16) threads = 16;
    if ((uint64_t)threads > total_ips) threads = (int)total_ips;
    if (threads <= 0 || total_ips == 0) {
        return rl;
    }
    pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
    if (!tids) {
        return rl;
    }
    char probe_host[MAX_DOMAIN_LEN] = "cloudflaremirrors.com";
    char probe_path[MAX_PATH_LEN] = "/";
    if (cfg->domain[0]) {
        parse_domain_and_path(cfg->domain, probe_host, sizeof(probe_host), probe_path, sizeof(probe_path));
    }
    int target_port = cfg->port > 0 ? cfg->port : 443;
    int is_cleartext = is_cleartext_port(target_port);
    /* 直连：以目标端口(443) TLS 握手作为存活与延迟门槛，与真实转发路径一致。
     * 百度前置：HTTP CONNECT 隧道只能承载 TCP，且隧道内的 CONNECT 本身是两跳
     * （TCP 到节点 + 节点回源 Cloudflare + 200），实测 90~1200ms，与 -delay 这类
     * 单程 RTT 上限不是一个量级；在隧道里再做一次完整 TLS 握手既拖慢扫描又极易
     * 因 CONNECT 预算不足被判「连接失败」。因此这里沿用基线（cfnat-old）的语义：
     * 走代理时用 80 端口 HTTP HEAD 取 CF-RAY + 测延迟，443 的真实可用性交给
     * 启动/周期健康检查（HC_FULL，走同一条隧道做 TLS）兜底。 */
    int is_tls = !is_cleartext && proxy_pool == nullptr;
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
        .target_port = target_port,
        .is_tls = is_tls,
        .hdr_timeout = hdr_timeout
    };
    snprintf(ctx.probe_host, sizeof(ctx.probe_host), "%s", probe_host);
    snprintf(ctx.probe_path, sizeof(ctx.probe_path), "%s", probe_path);
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
    atomic_init(&ctx.code_meta_skip, 0);
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
    /* CLI 模式自己在末尾打印结果表（还要附评分摘要），此处跳过避免同一张表打印两遍 */
    if (cfg->log_level >= LOG_INFO && !cfg->cli_mode) {
        print_results_table_ex(stderr, "TCP/H2", nullptr, rl.items, rl.len,
                               (now_ms() - ctx.scan_start_ms) / 1000);
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
        if (atomic_load(&ctx.code_meta_skip) > 0) {
            warn_msg("有 %zu 个候选因 %d 端口不可达而跳过 -code 状态码校验（其 443 TLS 与转发均正常）；如需强制校验请确保该端口可达",
                     atomic_load(&ctx.code_meta_skip), probe_port);
        }
    }
    return rl;
}

static int http_probe_host(socket_t fd, int timeout_ms, const char *host, const char *path) {
    if (!host || !*host) host = "cloudflaremirrors.com";
    if (!path || !*path) path = "/";
    char req[512];
    int reqlen = snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
    if (reqlen <= 0 || reqlen >= (int)sizeof(req)) return 0;
    long deadline = now_ms() + timeout_ms;
    size_t sent = 0;
    while (sent < (size_t)reqlen && now_ms() < deadline) {
        int left = (int)(deadline - now_ms());
        if (left <= 0) break;
        int rc = cfnat_poll_single(fd, 2, left);
        if (rc <= 0) break;
        ssize_t n = send(fd, req + sent, (size_t)reqlen - sent, 0);
        if (n <= 0) break;
        sent += (size_t)n;
    }
    if (sent < (size_t)reqlen) return 0;

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
    int is_cleartext = is_cleartext_port(target_port);
    char probe_host[MAX_DOMAIN_LEN] = "cloudflaremirrors.com";
    char probe_path[MAX_PATH_LEN] = "/";
    if (g_cfg.domain[0]) {
        parse_domain_and_path(g_cfg.domain, probe_host, sizeof(probe_host), probe_path, sizeof(probe_path));
    }
    int ok = is_cleartext ? http_probe_host(fd, g_cfg.delay_ms, probe_host, probe_path)
                          : tls_probe_host(fd, g_cfg.delay_ms, probe_host);
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
        /* 死连接完全交由内核 TCP_KEEPALIVE (75s) 与 TCP_USER_TIMEOUT (25s) 判定，不吞掉 ETIMEDOUT */
        ssize_t n = recv(pc->from, buf, sizeof(buf), 0);
        if (n < 0) {
            if ((errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) && atomic_load(&g_running)) continue;
            goto err;
        }
        if (n == 0) break;
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
#ifdef F_SETPIPE_SZ
    if (fcntl(pipefd[0], F_SETPIPE_SZ, 262144) < 0) {
        fcntl(pipefd[0], F_SETPIPE_SZ, 131072);
    }
#endif
    while (atomic_load(&g_running)) {
        /* 256KB 零拷贝大块吞吐，去除 SPLICE_F_MORE 杜绝尾包延迟 */
        ssize_t n = splice(pc->from, nullptr, pipefd[1], nullptr, 262144, SPLICE_F_MOVE);
        if (n < 0) {
            if ((errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) && atomic_load(&g_running)) continue;
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
        /* 死连接交由内核 TCP_KEEPALIVE / TCP_USER_TIMEOUT 判定，避免单向长流被 300s 误拆 */
        ssize_t n = recv(pc->from, buf, sizeof(buf), 0);
        if (n < 0) {
#ifdef _WIN32
            int werr = WSAGetLastError();
            if ((werr == WSAEINTR || werr == WSAEWOULDBLOCK) && atomic_load(&g_running)) continue;
#else
            if ((errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) && atomic_load(&g_running)) continue;
#endif
            goto err;
        }
        if (n == 0) break;
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
    size_t stack_sz = 512 * 1024;
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
    if (timeout_sec > 0) {
        DWORD tv = (DWORD)(timeout_sec * 1000);
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
    } else {
        /* Windows 无 TCP_USER_TIMEOUT 且保活不覆盖零窗口发送阻塞，仅保留 90s SO_SNDTIMEO 兜底，不设 SO_RCVTIMEO */
        DWORD snd_tv = 90000;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&snd_tv, sizeof(snd_tv));
    }
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
    if (timeout_sec > 0) {
        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
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
#if defined(__linux__)
    unsigned int user_timeout = 25000; /* A4: 25s 强制回收未确认黑洞死连接，加速线程与资源释放 */
    setsockopt(s, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout, sizeof(user_timeout));
#endif
#endif
}

static int relay_bidirectional(socket_t c, socket_t u, uint64_t *out_up_bytes) {
    /* 启用内核 KeepAlive (45s+10s*3) 与 TCP_USER_TIMEOUT (25s)，不设 SO_RCVTIMEO 避免单向大流量长连接被误拆 */
    set_socket_timeouts_and_keepalive(c, 0);
    set_socket_timeouts_and_keepalive(u, 0);
    pthread_t t1 = 0;
    PipeCtx a = { .from = c, .to = u, .bytes = 0 };
    PipeCtx b = { .from = u, .to = c, .bytes = 0 };
    int rc1 = create_small_thread(&t1, pipe_worker, &a);
    if (rc1 != 0) {
        close_pair(c, u);
        if (out_up_bytes) *out_up_bytes = 0;
        return -1;
    }
    /* 当前 connection_thread 线程直接执行反向转发，免除第 2 个子线程的 clone/mmap 与调度开销 */
    pipe_worker(&b);
    pthread_join(t1, nullptr);
    if (out_up_bytes) *out_up_bytes = a.bytes;
    if (b.bytes > 0) return 1;
    if (a.bytes > 0 && b.bytes == 0) return -2; /* 客户端已发请求但上游无应答/异常中断 */
    return 0;
}

static void *connection_thread(void *arg) {
    ConnCtx *cc = (ConnCtx *)arg;
    socket_t client = cc->client_fd;
    socket_t upstream = INVALID_SOCKET;
    long conn_start_ms = now_ms();
    int conn_ok = 0;
    int upstream_failed = 0;
    const char *carrier_name = cc->runtime ? carrier_display_name(cc->runtime->spec.mode) : "-";
    unsigned char first = 0;
    /* P1-2: 仅用 MSG_PEEK 嗅探首字节识别 TLS (0x16) 或 HTTP，绝不从内核缓冲区消费或重组 ClientHello：
     * 1. 缩短等待首字节超时至 15s，杜绝空闲探测连接长时间占满工作线程；
     * 2. Linux 下首包直接走 splice 内核零拷贝，Windows/Android 下直接走大缓冲直通转发并保留分片特征。 */
    ssize_t n = recv_flags_timeout(client, (char *)&first, 1, 15000, MSG_PEEK);
    if (n <= 0) goto out;
    int is_tls = (first == 0x16);
    int target_port = is_tls ? cc->tls_port : cc->http_port;
    conn_msg("[TCP/H2] #%llu [%s] 识别客户端协议: %s，转发到 IP: %s 端口: %d",
             cc->conn_id, carrier_name,
             is_tls ? "TLS" : "非TLS", cc->ip, target_port);
    int best = 0;

    if (cc->use_mixed) {
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
                    atomic_fetch_add_explicit(&cc->runtime->tcp_switch_count, 1, memory_order_relaxed);
                }
                conn_msg("[TCP/H2] #%llu [%s] 选择连接: %s:%d (延迟 %d ms)", cc->conn_id, carrier_name, cc->ip, target_port, best);
                break;
            }
        }
    }

    /* 非 TLS 流量（如 VMess/VLESS 明文、SS）80 连接失败时自动回退 443 端口 */
    if (cfnat_socket_invalid(upstream) && !is_tls && cc->tls_port > 0 && target_port != cc->tls_port) {
        target_port = cc->tls_port;
        int lat = 0;
        upstream = dial_target_with_proxy_sa(cc->ip, &cc->ip_addr, cc->ip_addr_len, target_port, cc->delay_ms, cc->proxy_pool, &lat);
        if (cfnat_socket_valid(upstream)) {
            best = lat;
            conn_msg("[TCP/H2] #%llu [%s] 非TLS 80失败回退443成功: %s:%d (延迟 %d ms)", cc->conn_id, carrier_name, cc->ip, target_port, best);
        }
    }

    if (cfnat_socket_invalid(upstream)) {
        debug_msg("[TCP/H2] #%llu [%s] 未找到符合延迟要求的连接，关闭客户端连接", cc->conn_id, carrier_name);
        upstream_failed = 1; /* 拨号失败，确定为上游故障 */
        goto out;
    }
    /* client 已在 accept 阶段设置 TCP_NODELAY 与 256KB 缓冲，upstream 已在 connect 阶段设置 TCP_NODELAY，仅需补充 upstream 缓冲 */
    tune_socket_buffers(upstream, 0);
    uint64_t up_bytes = 0;
    int had_data = relay_bidirectional(client, upstream, &up_bytes);
    if (had_data > 0 || (now_ms() - conn_start_ms) >= 3000) {
        conn_ok = 1;
    } else if (had_data == -2) {
        upstream_failed = 1; /* 客户端正常发包但上游无应答或异常中断，判定上游故障 */
    }
#if defined(__linux__) && defined(TCP_INFO)
    /* C3: 连接收尾时采样内核总重传数 (tcpi_total_retrans)，作为软信号温和抬高 EWMA 延迟而不触发 fast_fail 切换抖动 */
    if (conn_ok && up_bytes > 65536ULL && cfnat_socket_valid(upstream) && cc->runtime && cc->ip[0]) {
        struct tcp_info tinfo;
        socklen_t tlen = sizeof(tinfo);
        if (getsockopt(upstream, IPPROTO_TCP, TCP_INFO, &tinfo, &tlen) == 0 &&
            tinfo.tcpi_total_retrans >= 12 &&
            (uint64_t)tinfo.tcpi_total_retrans * 1400ULL * 100ULL > up_bytes * 15ULL) {
            pthread_mutex_lock(&cc->runtime->candidates.mu);
            for (size_t i = 0; i < cc->runtime->candidates.len; i++) {
                if (strcmp(cc->runtime->candidates.items[i].ip, cc->ip) == 0) {
                    Result *it = &cc->runtime->candidates.items[i];
                    int ref_lat = it->latency_ms > 0 ? it->latency_ms : 100;
                    int base = it->ewma_latency > 0 ? it->ewma_latency : ref_lat;
                    int cap = ref_lat + 100; /* 软惩罚封顶 +100ms，避免永久沉底 */
                    if (base < cap) {
                        it->ewma_latency = (base + 20 < cap) ? (base + 20) : cap;
                        atomic_store_explicit(&cc->runtime->candidates.has_node_fail, 1, memory_order_relaxed);
                    }
                    break;
                }
            }
            pthread_mutex_unlock(&cc->runtime->candidates.mu);
        }
    }
#endif
out:
    if (cfnat_socket_valid(upstream)) close(upstream);
    if (cfnat_socket_valid(client)) close(client);
    if (atomic_load(&g_running) && cc->runtime && cc->ip[0]) {
        if (conn_ok) {
            carrier_note_connection_success(cc->runtime, cc->ip);
        } else if (upstream_failed) {
            /* 严格排除客户端首字节前挂断或取消预连接的误判，仅在上游拨号失败或上游异常中断时惩罚节点 */
            carrier_note_connection_failed(cc->runtime, cc->ip);
        }
    }
    if (cc->runtime) {
        atomic_fetch_sub_explicit(&cc->runtime->active_tcp_conns, 1, memory_order_relaxed);
        atomic_store_explicit(&cc->runtime->last_tcp_active_ms, (long long)now_ms(), memory_order_relaxed);
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
    if (target_port <= 0) target_port = 443;
    int is_cleartext = is_cleartext_port(target_port);
    const char *domain_cfg = (rt && rt->spec.prof.domain[0]) ? rt->spec.prof.domain : g_cfg.domain;
    char probe_host[MAX_DOMAIN_LEN] = "cloudflaremirrors.com";
    char probe_path[MAX_PATH_LEN] = "/";
    if (domain_cfg && *domain_cfg) {
        parse_domain_and_path(domain_cfg, probe_host, sizeof(probe_host), probe_path, sizeof(probe_path));
    }
    int ok = is_cleartext ? http_probe_host(fd, timeout_ms, probe_host, probe_path)
                          : tls_probe_host(fd, timeout_ms, probe_host);
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
            long probe_t0 = now_ms();
            if (carrier_probe_and_check(rt, fd, probe_timeout)) {
                /* 与扫描口径一致：上报「建连 + TLS/首字节」的完整往返，而非仅 CONNECT 时间 */
                if (out_lat) *out_lat = latency + (int)(now_ms() - probe_t0);
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
                long probe_t1 = now_ms();
                if (carrier_probe_and_check(rt, fd, probe_timeout)) {
                    if (out_lat) *out_lat = latency + (int)(now_ms() - probe_t1);
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
    long probe_t2 = now_ms();
    if (carrier_probe_and_check(rt, fd, probe_timeout)) {
        if (out_lat) *out_lat = latency + (int)(now_ms() - probe_t2);
        return 1;
    }
    return 0;
}

CFNAT_NODISCARD static inline int carrier_health_check_ip(CarrierRuntime *rt, const char *ip) {
    return carrier_health_check_ip_level(rt, ip, HC_FULL, nullptr);
}

static int carrier_set_current_candidate(CarrierRuntime *rt, size_t idx) {
    if (!rt || !atomic_load(&g_running)) return 0;
    pthread_mutex_lock(&rt->candidates.mu);
    if (!atomic_load(&g_running)) {
        pthread_mutex_unlock(&rt->candidates.mu);
        return 0;
    }
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

typedef struct {
    CarrierRuntime *rt;
    const char *ip;
    size_t idx;
    int is_udp;
    int port;
    int delay_ms;
    int ok;
    int lat;
} SwitchProbeTask;

static void *switch_probe_worker(void *arg) {
    SwitchProbeTask *t = (SwitchProbeTask *)arg;
    if (t->is_udp) {
        t->ok = quic_probe_ip(t->ip, t->port, t->delay_ms, &t->lat) ? 1 : 0;
    } else {
        t->ok = carrier_health_check_ip_level(t->rt, t->ip, HC_FULL, &t->lat) ? 1 : 0;
    }
    return nullptr;
}

/* 判断两个 IP 是否属于同一子网（IPv6 按 /64，IPv4 按 /24）。
 * 同一 /64 内的 Cloudflare 候选往往落在同一台边缘/同一条上游路径上，QoS、拥塞与限速
 * 通常同时作用于整个前缀——切换时若还留在同一前缀，等于没换路径。 */
static int ip_same_subnet(const char *a, const char *b) {
    if (!a || !b || !a[0] || !b[0]) return 0;
    if (strchr(a, ':') || strchr(b, ':')) {
        struct in6_addr x, y;
        if (inet_pton(AF_INET6, a, &x) != 1 || inet_pton(AF_INET6, b, &y) != 1) return 0;
        return memcmp(&x, &y, 8) == 0;   /* 前 64 位 */
    }
    struct in_addr x, y;
    if (inet_pton(AF_INET, a, &x) != 1 || inet_pton(AF_INET, b, &y) != 1) return 0;
    /* 按内存字节序比较前 3 字节，避免大小端差异导致 /24 判断错误 */
    const unsigned char *pa = (const unsigned char *)&x.s_addr;
    const unsigned char *pb = (const unsigned char *)&y.s_addr;
    return pa[0] == pb[0] && pa[1] == pb[1] && pa[2] == pb[2];
}

/* 切换候选排序：先按「是否与当前 IP 同子网」分组（不同子网优先），组内再按综合分升序。
 * 这样在池里存在跨子网候选时，切换会真正换一条路径；只有全都同子网才退化为纯按分排序。 */
static void sort_switch_candidates(const char *cur_ip, char ips[][MAX_IP_LEN], size_t *indices, int *scores, size_t count) {
    if (count > 64) count = 64;
    uint8_t same[64];
    for (size_t i = 0; i < count; i++) same[i] = ip_same_subnet(ips[i], cur_ip) ? 1 : 0;
    for (size_t i = 1; i < count; i++) {
        int key_sc = scores[i];
        size_t key_idx = indices[i];
        uint8_t key_same = same[i];
        char key_ip[MAX_IP_LEN];
        memcpy(key_ip, ips[i], MAX_IP_LEN);
        size_t j = i;
        while (j > 0) {
            if (same[j - 1] < key_same) break;                                   /* 不同子网优先：前驱更"同族"则停 */
            if (same[j - 1] == key_same && scores[j - 1] <= key_sc) break;       /* 同组内按分数升序 */
            scores[j] = scores[j - 1];
            indices[j] = indices[j - 1];
            same[j] = same[j - 1];
            memcpy(ips[j], ips[j - 1], MAX_IP_LEN);
            j--;
        }
        scores[j] = key_sc;
        indices[j] = key_idx;
        same[j] = key_same;
        memcpy(ips[j], key_ip, MAX_IP_LEN);
    }
}

static int carrier_switch_next_ip(CarrierRuntime *rt) {
    if (!rt || !atomic_load(&g_running)) return 0;
    if (atomic_exchange_explicit(&rt->candidates.switch_lock, 1, memory_order_acq_rel) != 0) {
        return 0; /* P1-3: 已有其他线程正在执行切换，避免并发竞争 */
    }
    char check_ips[64][MAX_IP_LEN];
    size_t check_indices[64];
    int check_scores[64];
    size_t count = 0;
    size_t total_len = 0;
    long cur_ms = now_ms();

    pthread_mutex_lock(&rt->candidates.mu);
    size_t len = rt->candidates.len;
    size_t start = rt->candidates.current_index;
    total_len = len;

    if (len > 0) {
        /* 第一遍：在整个池 (0..len-1) 环形收集未处于 30s 冷却期的候选，再按综合分升序优先探测 */
        for (size_t step = 1; step <= len && count < 64; step++) {
            size_t idx = (start + step) % len;
            Result *item = &rt->candidates.items[idx];
            if (item->consecutive_fail == 0 || (cur_ms - item->last_fail_ms) >= 30000) {
                snprintf(check_ips[count], sizeof(check_ips[count]), "%s", item->ip);
                check_indices[count] = idx;
                check_scores[count] = score_result(item);
                count++;
            }
        }
        /* 若所有候选均处于冷却期（极端全抖动），回退挑选冷却超过 5s 的候选 */
        if (count == 0) {
            for (size_t step = 1; step <= len && count < 64; step++) {
                size_t idx = (start + step) % len;
                Result *item = &rt->candidates.items[idx];
                if ((cur_ms - item->last_fail_ms) >= 5000) {
                    snprintf(check_ips[count], sizeof(check_ips[count]), "%s", item->ip);
                    check_indices[count] = idx;
                    check_scores[count] = score_result(item);
                    count++;
                }
            }
        }
    }
    pthread_mutex_unlock(&rt->candidates.mu);

    if (total_len == 0 || count == 0) {
        atomic_store_explicit(&rt->candidates.switch_lock, 0, memory_order_release);
        return 0;
    }

    char cur_ip[MAX_IP_LEN] = {0};
    pthread_mutex_lock(&rt->candidates.mu);
    snprintf(cur_ip, sizeof(cur_ip), "%s", rt->candidates.current_ip);
    pthread_mutex_unlock(&rt->candidates.mu);
    sort_switch_candidates(cur_ip, check_ips, check_indices, check_scores, count);

    /* 首波 2 路快探（降低等待长尾），后续每波 4 路并发探测，择最低延迟胜出 */
    for (size_t base = 0, step_w = 2; base < count && atomic_load(&g_running); base += step_w, step_w = 4) {
        size_t wave = (count - base < step_w) ? (count - base) : step_w;
        SwitchProbeTask tasks[4];
        pthread_t tids[4] = {0};
        for (size_t k = 0; k < wave; k++) {
            tasks[k] = (SwitchProbeTask){
                .rt = rt, .ip = check_ips[base + k], .idx = check_indices[base + k],
                .is_udp = 0, .port = 0, .delay_ms = 0, .ok = 0, .lat = 0
            };
            if (k > 0 && create_small_thread(&tids[k], switch_probe_worker, &tasks[k]) != 0) {
                tids[k] = 0;
                switch_probe_worker(&tasks[k]);
            }
        }
        switch_probe_worker(&tasks[0]);
        for (size_t k = 1; k < wave; k++) {
            if (tids[k]) pthread_join(tids[k], nullptr);
        }
        int best_k = -1;
        for (size_t k = 0; k < wave; k++) {
            if (tasks[k].ok) {
                if (best_k < 0 || tasks[k].lat < tasks[best_k].lat) best_k = (int)k;
            } else {
                pthread_mutex_lock(&rt->candidates.mu);
                if (tasks[k].idx < rt->candidates.len &&
                    strcmp(rt->candidates.items[tasks[k].idx].ip, tasks[k].ip) == 0) {
                    rt->candidates.items[tasks[k].idx].consecutive_fail++;
                    rt->candidates.items[tasks[k].idx].last_fail_ms = now_ms();
                    atomic_store_explicit(&rt->candidates.has_node_fail, 1, memory_order_relaxed);
                }
                pthread_mutex_unlock(&rt->candidates.mu);
            }
        }
        if (best_k >= 0) {
            size_t idx = tasks[best_k].idx;
            carrier_set_current_candidate(rt, idx);
            atomic_store(&rt->candidates.cache_valid, 1);
            pthread_mutex_lock(&rt->candidates.mu);
            if (idx < rt->candidates.len &&
                strcmp(rt->candidates.items[idx].ip, tasks[best_k].ip) == 0) {
                rt->candidates.items[idx].consecutive_fail = 0;
            }
            pthread_mutex_unlock(&rt->candidates.mu);
            log_msg("[TCP/H2] [%s] 并行切换/按分回灌至可用节点: %s (候选索引: %zu/%zu, 延迟 %d ms)",
                    carrier_display_name(rt->spec.mode), tasks[best_k].ip, idx + 1, total_len, tasks[best_k].lat);
            atomic_fetch_add_explicit(&rt->tcp_switch_count, 1, memory_order_relaxed);
            atomic_store_explicit(&rt->candidates.switch_lock, 0, memory_order_release);
            return 1;
        }
    }
    atomic_store_explicit(&rt->candidates.switch_lock, 0, memory_order_release);
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
        atomic_fetch_add_explicit(&rt->udp_candidates.epoch, 1, memory_order_release);
        pthread_mutex_unlock(&rt->udp_candidates.mu);
        return 1;
    }
    pthread_mutex_unlock(&rt->udp_candidates.mu);
    return 0;
}

CFNAT_NODISCARD static int carrier_switch_next_udp_ip(CarrierRuntime *rt) {
    if (!rt || !atomic_load(&g_running)) return 0;
    if (atomic_exchange_explicit(&rt->udp_candidates.switch_lock, 1, memory_order_acq_rel) != 0) {
        return 0; /* P1-3: 已有其他线程正在执行切换，避免并发竞争 */
    }
    int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
    if (target_port <= 0) target_port = 443;
    int delay_ms = udp_probe_timeout_ms((rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms);

    char check_ips[64][MAX_IP_LEN];
    size_t check_indices[64];
    int check_scores[64];
    size_t count = 0;
    size_t total_len = 0;
    long cur_ms = now_ms();

    pthread_mutex_lock(&rt->udp_candidates.mu);
    size_t len = rt->udp_candidates.len;
    size_t start = rt->udp_candidates.current_index;
    total_len = len;

    if (len > 0) {
        /* 第一遍：环形收集未处于 30s 冷却期的候选，按综合分升序优先探测 */
        for (size_t step = 1; step <= len && count < 64; step++) {
            size_t idx = (start + step) % len;
            Result *item = &rt->udp_candidates.items[idx];
            if (item->consecutive_fail == 0 || (cur_ms - item->last_fail_ms) >= 30000) {
                snprintf(check_ips[count], sizeof(check_ips[count]), "%s", item->ip);
                check_indices[count] = idx;
                check_scores[count] = score_result(item);
                count++;
            }
        }
        /* 若所有候选均处于冷却期，回退挑选冷却超过 5s 的候选 */
        if (count == 0) {
            for (size_t step = 1; step <= len && count < 64; step++) {
                size_t idx = (start + step) % len;
                Result *item = &rt->udp_candidates.items[idx];
                if ((cur_ms - item->last_fail_ms) >= 5000) {
                    snprintf(check_ips[count], sizeof(check_ips[count]), "%s", item->ip);
                    check_indices[count] = idx;
                    check_scores[count] = score_result(item);
                    count++;
                }
            }
        }
    }
    pthread_mutex_unlock(&rt->udp_candidates.mu);

    if (total_len == 0 || count == 0) {
        atomic_store_explicit(&rt->udp_candidates.switch_lock, 0, memory_order_release);
        return 0;
    }

    /* QoS 窗口内最多放行一次切换：同一个窗口里连续切换只会把健康的会话反复拆掉。
     * 窗口登记时会把额度归还（qos_switch_used=0），所以恢复后不受影响。 */
    {
        long long win_until = atomic_load_explicit(&rt->qos_suspect_until_ms, memory_order_relaxed);
        if ((long long)now_ms() < win_until &&
            atomic_load_explicit(&rt->qos_switch_used, memory_order_relaxed) != 0) {
            debug_msg("[UDP/H3] [%s] 疑似 QoS 窗口内已切换过一次，暂不再切换（窗口剩余 %llds）",
                      carrier_display_name(rt->spec.mode), (win_until - (long long)now_ms()) / 1000);
            atomic_store_explicit(&rt->udp_candidates.switch_lock, 0, memory_order_release);
            return 0;
        }
    }

    char cur_ip[MAX_IP_LEN] = {0};
    pthread_mutex_lock(&rt->udp_candidates.mu);
    snprintf(cur_ip, sizeof(cur_ip), "%s", rt->udp_candidates.current_ip);
    pthread_mutex_unlock(&rt->udp_candidates.mu);
    sort_switch_candidates(cur_ip, check_ips, check_indices, check_scores, count);

    /* 首波 2 路快探，后续每波 4 路并发 QUIC 探测，择最低延迟胜出 */
    for (size_t base = 0, step_w = 2; base < count && atomic_load(&g_running); base += step_w, step_w = 4) {
        size_t wave = (count - base < step_w) ? (count - base) : step_w;
        SwitchProbeTask tasks[4];
        pthread_t tids[4] = {0};
        for (size_t k = 0; k < wave; k++) {
            tasks[k] = (SwitchProbeTask){
                .rt = rt, .ip = check_ips[base + k], .idx = check_indices[base + k],
                .is_udp = 1, .port = target_port, .delay_ms = delay_ms, .ok = 0, .lat = 0
            };
            if (k > 0 && create_small_thread(&tids[k], switch_probe_worker, &tasks[k]) != 0) {
                tids[k] = 0;
                switch_probe_worker(&tasks[k]);
            }
        }
        switch_probe_worker(&tasks[0]);
        for (size_t k = 1; k < wave; k++) {
            if (tids[k]) pthread_join(tids[k], nullptr);
        }
        int best_k = -1;
        for (size_t k = 0; k < wave; k++) {
            if (tasks[k].ok) {
                if (best_k < 0 || tasks[k].lat < tasks[best_k].lat) best_k = (int)k;
            } else {
                pthread_mutex_lock(&rt->udp_candidates.mu);
                if (tasks[k].idx < rt->udp_candidates.len &&
                    strcmp(rt->udp_candidates.items[tasks[k].idx].ip, tasks[k].ip) == 0) {
                    rt->udp_candidates.items[tasks[k].idx].consecutive_fail++;
                    rt->udp_candidates.items[tasks[k].idx].last_fail_ms = now_ms();
                }
                pthread_mutex_unlock(&rt->udp_candidates.mu);
            }
        }
        if (best_k >= 0) {
            size_t idx = tasks[best_k].idx;
            carrier_set_current_udp_candidate(rt, idx);
            atomic_store(&rt->udp_candidates.cache_valid, 1);
            pthread_mutex_lock(&rt->udp_candidates.mu);
            if (idx < rt->udp_candidates.len &&
                strcmp(rt->udp_candidates.items[idx].ip, tasks[best_k].ip) == 0) {
                rt->udp_candidates.items[idx].consecutive_fail = 0;
            }
            pthread_mutex_unlock(&rt->udp_candidates.mu);
            log_msg("[UDP/H3] [%s] 并行切换/按分回灌至可用节点: %s (候选索引: %zu/%zu, 延迟 %d ms)",
                    carrier_display_name(rt->spec.mode), tasks[best_k].ip, idx + 1, total_len, tasks[best_k].lat);
            atomic_fetch_add_explicit(&rt->udp_switch_count, 1, memory_order_relaxed);
            atomic_store_explicit(&rt->udp_candidates.switch_lock, 0, memory_order_release);
            return 1;
        }
    }
    atomic_store_explicit(&rt->udp_candidates.switch_lock, 0, memory_order_release);
    return 0;
}

static void carrier_note_connection_success(CarrierRuntime *rt, const char *ip) {
    if (!atomic_load(&g_running) || !rt || !ip || !*ip) return;
    if (atomic_load_explicit(&rt->candidates.fast_fail_count, memory_order_relaxed) == 0 &&
        atomic_load_explicit(&rt->candidates.has_node_fail, memory_order_relaxed) == 0) {
        return;
    }
    pthread_mutex_lock(&rt->candidates.mu);
    if (!atomic_load(&g_running)) {
        pthread_mutex_unlock(&rt->candidates.mu);
        return;
    }
    int any_fail = 0;
    for (size_t i = 0; i < rt->candidates.len; i++) {
        Result *it = &rt->candidates.items[i];
        if (strcmp(it->ip, ip) == 0) {
            it->consecutive_fail = 0;
            /* 正常连接成功时缓慢衰减重传软惩罚 (-5ms)，直至恢复基线延迟 */
            if (it->latency_ms > 0 && it->ewma_latency > it->latency_ms) {
                it->ewma_latency -= 5;
                if (it->ewma_latency < it->latency_ms) it->ewma_latency = it->latency_ms;
                if (it->ewma_latency > it->latency_ms) any_fail = 1;
            }
        } else if (it->consecutive_fail > 0 || (it->latency_ms > 0 && it->ewma_latency > it->latency_ms)) {
            any_fail = 1;
        }
    }
    atomic_store_explicit(&rt->candidates.has_node_fail, any_fail, memory_order_relaxed);
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
    for (size_t i = 0; i < rt->candidates.len; i++) {
        if (strcmp(rt->candidates.items[i].ip, ip) == 0) {
            rt->candidates.items[i].consecutive_fail++;
            rt->candidates.items[i].last_fail_ms = now_ms();
            atomic_store_explicit(&rt->candidates.has_node_fail, 1, memory_order_relaxed);
            break;
        }
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
        carrier_trigger_maintenance(rt, MAINT_SWITCH_TCP);
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
    if (!rt->spec.prof.enable_h2 && rt->spec.prof.enable_h3 && survivors.len < tcp_heal_min) {
        const char *tcp_cache_path = candidate_cache_file_for_profile(rt->spec.mode, rt->spec.prof.ips_type > 0 ? rt->spec.prof.ips_type : g_cfg.ips_type);
        ResultList cached_tcp = load_candidate_cache_for_profile(tcp_cache_path, &rt->spec.prof);
        if (cached_tcp.len > 0 && cache_quick_check_parallel(rt, cached_tcp.items, cached_tcp.len, 0, 0, 0) != (size_t)-1) {
            log_msg("[%s] 纯 H3 自愈命中 TCP 缓存 (%zu 个种子)，跳过全量 TCP 扫描", carrier_display_name(rt->spec.mode), cached_tcp.len);
            free(survivors.items);
            survivors = cached_tcp;
        } else {
            free(cached_tcp.items);
        }
    }

    if (survivors.len >= tcp_heal_min) {
        if (rt->spec.prof.enable_h3 && cfnat_socket_valid(rt->udp_listen_fd)) {
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
        atomic_store_explicit(&rt->candidates.has_node_fail, 0, memory_order_relaxed);
        pthread_mutex_unlock(&rt->candidates.mu);
        free(old_tcp_items);
        atomic_store(&rt->candidates.cache_valid, 1);
    }

    /* 4. 分发给 UDP 候选池 (仅在启用 H3 时执行) */
    ResultList udp_res = {0};
    if (rt->spec.prof.enable_h3) {
        udp_res = (inplace_udp.len > 0) ? inplace_udp :
            filter_udp_candidates_from_tcp(rt, all_candidates.items, all_candidates.len, target_ipnum);
    } else {
        free(inplace_udp.items);
    }
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
        atomic_fetch_add_explicit(&rt->udp_candidates.epoch, 1, memory_order_release);
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

/* P1-5: 异步维护触发器与维护线程 (顺位切换与自愈扫描解耦，转发面零阻塞) */
static void carrier_trigger_maintenance(CarrierRuntime *rt, int flags) {
    if (!rt || !atomic_load(&g_running) || flags == 0) return;
    atomic_fetch_or_explicit(&rt->maint_pending, flags, memory_order_release);
    pthread_mutex_lock(&rt->maint_mu);
    pthread_cond_signal(&rt->maint_cv);
    pthread_mutex_unlock(&rt->maint_mu);
}

static void *carrier_maintenance_thread(void *arg) {
    CarrierRuntime *rt = (CarrierRuntime *)arg;
    if (!rt) return nullptr;

    while (atomic_load(&g_running)) {
        pthread_mutex_lock(&rt->maint_mu);
        while (atomic_load(&g_running) && atomic_load_explicit(&rt->maint_pending, memory_order_acquire) == 0) {
            struct timespec ts;
#if defined(_WIN32) && !defined(CLOCK_REALTIME)
            ts.tv_sec = (time_t)time(nullptr) + 1;
            ts.tv_nsec = 0;
#else
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
#endif
            pthread_cond_timedwait(&rt->maint_cv, &rt->maint_mu, &ts);
        }
        int pending = atomic_exchange_explicit(&rt->maint_pending, 0, memory_order_acq_rel);
        pthread_mutex_unlock(&rt->maint_mu);

        if (!atomic_load(&g_running)) break;
        if (!pending) continue;

        int rescan_needed = (pending & MAINT_RESCAN) != 0;

        if (pending & MAINT_SWITCH_TCP) {
            log_msg("[TCP/H2] [%s] 后台维护线程触发顺位切换", carrier_display_name(rt->spec.mode));
            if (!carrier_switch_next_ip(rt)) {
                log_msg("[TCP/H2] [%s] 候选池消耗达 70%% 或无可用顺位 IP，开始自愈维护双轨候选池", carrier_display_name(rt->spec.mode));
                rescan_needed = 1;
            }
        }

        if (pending & MAINT_SWITCH_UDP) {
            log_msg("[UDP/H3] [%s] 后台维护线程触发顺位切换", carrier_display_name(rt->spec.mode));
            if (!carrier_switch_next_udp_ip(rt)) {
                log_msg("[UDP/H3] [%s] 候选池消耗达 70%% 或无可用顺位 IP，开始自愈维护双轨候选池", carrier_display_name(rt->spec.mode));
                rescan_needed = 1;
            }
        }

        if (rescan_needed && atomic_load(&g_running)) {
            carrier_rescan_dual_pools(rt);
        }
    }
    return nullptr;
}

/* P1-HC: 渐进式 TCP 健康检查线程 */
static void *carrier_health_thread(void *arg) {
    CarrierRuntime *rt = (CarrierRuntime *)arg;
    int fail = 0;
    long last = 0;
    int consecutive_success = 0;
    while (atomic_load(&g_running)) {
        long long last_act = atomic_load_explicit(&rt->last_tcp_active_ms, memory_order_relaxed);
        int is_active = (atomic_load_explicit(&rt->active_tcp_conns, memory_order_relaxed) > 0) ||
                        (last_act > 0 && ((long long)now_ms() - last_act) < 30000LL);
        int sleep_dur = (fail > 0) ? 10000 : (is_active ? 20000 : ((consecutive_success >= 5) ? 60000 : 30000));
        if (sleep_interruptible_ms(sleep_dur) != 0) break;
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
            pthread_mutex_lock(&rt->candidates.mu);
            for (size_t i = 0; i < rt->candidates.len; i++) {
                if (strcmp(rt->candidates.items[i].ip, ip) == 0) {
                    rt->candidates.items[i].consecutive_fail++;
                    rt->candidates.items[i].last_fail_ms = now_ms();
                    break;
                }
            }
            pthread_mutex_unlock(&rt->candidates.mu);
            warn_msg("[TCP/H2] [%s] 状态检查失败 (%d/2): 当前 IP %s 握手无响应",
                     carrier_display_name(rt->spec.mode), fail, ip[0] ? ip : "为空");
        } else {
            fail = 0;
            consecutive_success++;
            atomic_store(&rt->candidates.cache_valid, 1);
            pthread_mutex_lock(&rt->candidates.mu);
            for (size_t i = 0; i < rt->candidates.len; i++) {
                if (strcmp(rt->candidates.items[i].ip, ip) == 0) {
                    rt->candidates.items[i].consecutive_fail = 0;
                    break;
                }
            }
            pthread_mutex_unlock(&rt->candidates.mu);
            long n = now_ms();
            if (g_cfg.log_level >= LOG_DEBUG && g_cfg.health_log > 0 && n - last >= g_cfg.health_log * 1000L) {
                debug_msg("[TCP/H2] [%s] 状态检查正常: 当前 IP %s 可用 (延迟 %d ms)",
                          carrier_display_name(rt->spec.mode), ip, latency);
                last = n;
            }
        }
        if (fail >= 2) {
            log_msg("[TCP/H2] [%s] 连续两次状态检查失败，顺位切换下一个候选 IP", carrier_display_name(rt->spec.mode));
            carrier_trigger_maintenance(rt, MAINT_SWITCH_TCP);
            fail = 0;
        }
    }
    return nullptr;
}

/* UDP/H3 定时轻量 QUIC 探针健康检查线程 */
static void *carrier_udp_health_thread(void *arg) {
    CarrierRuntime *rt = (CarrierRuntime *)arg;
    int fail = 0;
    int consecutive_success = 0;
    int empty_backoff_s = 5; /* H3 空池轻量自愈退避: 5s -> 10s -> 20s -> 40s -> 60s -> 120s
                              * 起点必须短于常见 QoS 窗口（5~30s），否则一次 10s 的窗口要等 30s+ 才复测。 */
    long last_log = 0;
    while (atomic_load(&g_running)) {
        char cur_ip[MAX_IP_LEN] = {0};
        carrier_get_current_udp_ip(rt, cur_ip, sizeof(cur_ip));
        long long last_u_act = atomic_load_explicit(&rt->last_udp_active_ms, memory_order_relaxed);
        int udp_active = (atomic_load_explicit(&rt->active_udp_conns, memory_order_relaxed) > 0) ||
                         (last_u_act > 0 && ((long long)now_ms() - last_u_act) < 30000LL);
        int sleep_dur = !cur_ip[0]
                            ? (empty_backoff_s * 1000)
                            : ((fail > 0) ? 10000 : (udp_active ? 15000 : ((consecutive_success >= 5) ? 60000 : 30000)));
        if (sleep_interruptible_ms(sleep_dur) != 0) break;

        char ip[MAX_IP_LEN] = {0};
        carrier_get_current_udp_ip(rt, ip, sizeof(ip));
        int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
        if (target_port <= 0) target_port = 443;
        int delay_ms = udp_probe_timeout_ms((rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms);

        if (!ip[0]) {
            /* 空池轻量自愈：仅单发 1~2 个探针确认 QoS 是否解除，绝不打扰 TCP 转发，也不在限流窗内盲目齐射 */
            Result *tcp_copy = nullptr;
            size_t tcp_len = 0;
            pthread_mutex_lock(&rt->candidates.mu);
            if (rt->candidates.len > 0 && rt->candidates.items) {
                tcp_len = rt->candidates.len;
                tcp_copy = malloc(tcp_len * sizeof(Result));
                if (tcp_copy) memcpy(tcp_copy, rt->candidates.items, tcp_len * sizeof(Result));
                else tcp_len = 0;
            }
            pthread_mutex_unlock(&rt->candidates.mu);

            if (tcp_len == 0) {
                /* 纯 H3 从 udpcache 启动时可能尚未加载 tcp 种子池：先读 tcpcache，仍为空则触发后台自愈补扫 */
                const char *tcp_path = candidate_cache_file_for_profile(rt->spec.mode, rt->spec.prof.ips_type > 0 ? rt->spec.prof.ips_type : g_cfg.ips_type);
                ResultList cached_tcp = load_candidate_cache_for_profile(tcp_path, &rt->spec.prof);
                if (cached_tcp.len > 0 && cache_quick_check_parallel(rt, cached_tcp.items, cached_tcp.len, 0, 0, 0) != (size_t)-1) {
                    tcp_copy = cached_tcp.items;
                    tcp_len = cached_tcp.len;
                } else {
                    free(cached_tcp.items);
                    carrier_trigger_maintenance(rt, MAINT_RESCAN);
                    empty_backoff_s = (empty_backoff_s < 60) ? (empty_backoff_s * 2) : 120;
                    continue;
                }
            }

            int probe_ok = 0;
            int probe_lat = 0;
            size_t probe_idx = 0;
            size_t tries = tcp_len < 2 ? tcp_len : 2;
            for (size_t t = 0; t < tries && atomic_load(&g_running); t++) {
                int lat = 0;
                if (quic_probe_ip(tcp_copy[t].ip, target_port, delay_ms, &lat)) {
                    probe_ok = 1;
                    probe_lat = lat;
                    probe_idx = t;
                    break;
                }
                if (t + 1 < tries && sleep_interruptible_ms(500) != 0) break;
            }

            if (probe_ok && atomic_load(&g_running)) {
                if (atomic_exchange_explicit(&rt->rescanning_lock, 1, memory_order_acq_rel) == 0) {
                    size_t target_ipnum = (rt->spec.prof.ipnum > 0) ? (size_t)rt->spec.prof.ipnum
                                                                    : (g_cfg.ipnum > 0 ? (size_t)g_cfg.ipnum : 20);
                    log_msg("[UDP/H3] [%s] 空池退避试探成功 (%s 延迟 %d ms)，开始无感重建 H3 候选池...",
                            carrier_display_name(rt->spec.mode), tcp_copy[probe_idx].ip, probe_lat);
                    ResultList udp_res = filter_udp_candidates_from_tcp(rt, tcp_copy, tcp_len, target_ipnum);
                    if (udp_res.len > 0) {
                        pthread_mutex_lock(&rt->udp_candidates.mu);
                        free(rt->udp_candidates.items);
                        rt->udp_candidates.items = udp_res.items;
                        rt->udp_candidates.len = udp_res.len;
                        pthread_mutex_unlock(&rt->udp_candidates.mu);
                        carrier_set_current_udp_candidate(rt, 0);
                        atomic_store(&rt->udp_candidates.cache_valid, 1);
                        save_candidate_cache(candidate_cache_file_for_profile_udp(rt->spec.mode, rt->spec.prof.ips_type),
                                             udp_res.items, udp_res.len);
                        log_msg("[UDP/H3] [%s] 空池自愈恢复成功: 捕获 %zu 个 H3 候选，最优 IP: %s (延迟 %d ms)",
                                carrier_display_name(rt->spec.mode), udp_res.len,
                                udp_res.items[0].ip, udp_res.items[0].latency_ms);
                        empty_backoff_s = 5;
                        fail = 0;
                        consecutive_success = 0;
                    } else {
                        empty_backoff_s = (empty_backoff_s < 60) ? (empty_backoff_s * 2) : 120;
                    }
                    atomic_store_explicit(&rt->rescanning_lock, 0, memory_order_release);
                }
            } else if (rt->spec.use_baidu_proxy && atomic_load(&g_running)) {
                /* 百度前置栈若直连 H3 缓存已恢复，直接复用 */
                ResultList fb = load_candidate_cache_for_profile(
                    candidate_cache_file_for_profile_udp("direct", rt->spec.prof.ips_type), &rt->spec.prof);
                if (fb.len > 0 &&
                    cache_quick_check_parallel(rt, fb.items, fb.len, 1, target_port, delay_ms) != (size_t)-1) {
                    if (atomic_exchange_explicit(&rt->rescanning_lock, 1, memory_order_acq_rel) == 0) {
                        pthread_mutex_lock(&rt->udp_candidates.mu);
                        free(rt->udp_candidates.items);
                        rt->udp_candidates.items = fb.items;
                        rt->udp_candidates.len = fb.len;
                        pthread_mutex_unlock(&rt->udp_candidates.mu);
                        carrier_set_current_udp_candidate(rt, 0);
                        atomic_store(&rt->udp_candidates.cache_valid, 1);
                        log_msg("[UDP/H3] [%s] 空池自愈已复用直连 H3 缓存，共 %zu 个节点",
                                carrier_display_name(rt->spec.mode), fb.len);
                        empty_backoff_s = 5;
                        fail = 0;
                        consecutive_success = 0;
                        atomic_store_explicit(&rt->rescanning_lock, 0, memory_order_release);
                    } else {
                        free(fb.items);
                    }
                } else {
                    free(fb.items);
                    debug_msg("[UDP/H3] [%s] 空池轻量试探仍无回包，%ds 后再次退避试探",
                              carrier_display_name(rt->spec.mode),
                              (empty_backoff_s < 60) ? (empty_backoff_s * 2) : 120);
                    empty_backoff_s = (empty_backoff_s < 60) ? (empty_backoff_s * 2) : 120;
                }
            } else {
                debug_msg("[UDP/H3] [%s] 空池轻量试探仍无回包，%ds 后再次退避试探",
                          carrier_display_name(rt->spec.mode),
                          (empty_backoff_s < 60) ? (empty_backoff_s * 2) : 120);
                empty_backoff_s = (empty_backoff_s < 60) ? (empty_backoff_s * 2) : 120;
            }
            free(tcp_copy);
            continue;
        }
        empty_backoff_s = 5;

        /* 活跃态：每轮 3 包（间隔 50ms）测丢包，丢包 >= 2/3 (67%) 判异常以抓出半死限速节点；闲置态：单包轻检 */
        long long now_u = (long long)now_ms();
        long long last_u2 = atomic_load_explicit(&rt->last_udp_active_ms, memory_order_relaxed);
        int active_now = (atomic_load_explicit(&rt->active_udp_conns, memory_order_relaxed) > 0) ||
                         (last_u2 > 0 && (now_u - last_u2) < 30000LL);
        int probe_n = active_now ? 3 : 1;
        int ok_cnt = 0;
        int total_lat = 0;
        int lats[3] = {-1, -1, -1};
        for (int p = 0; p < probe_n && atomic_load(&g_running); p++) {
            if (p > 0 && sleep_interruptible_ms(50) != 0) break;
            int plat = 0;
            if (quic_probe_ip(ip, target_port, delay_ms, &plat)) {
                lats[p] = plat;
                ok_cnt++;
                total_lat += plat;
            }
        }
        int latency = (ok_cnt > 0) ? (total_lat / ok_cnt) : 0;
        int loss_pct = ((probe_n - ok_cnt) * 100) / probe_n;
        atomic_store_explicit(&rt->last_udp_loss_pct, loss_pct, memory_order_relaxed);

        char detail_buf[64] = {0};
        if (active_now) {
            char s0[12], s1[12], s2[12];
            if (lats[0] >= 0) snprintf(s0, sizeof(s0), "%d", lats[0]); else snprintf(s0, sizeof(s0), "-");
            if (lats[1] >= 0) snprintf(s1, sizeof(s1), "%d", lats[1]); else snprintf(s1, sizeof(s1), "-");
            if (lats[2] >= 0) snprintf(s2, sizeof(s2), "%d", lats[2]); else snprintf(s2, sizeof(s2), "-");
            snprintf(detail_buf, sizeof(detail_buf), "[%s, %s, %s]ms", s0, s1, s2);
        }

        int ok = active_now ? (ok_cnt >= 2) : (ok_cnt >= 1);
        if (!ok) {
            long long win_until = atomic_load_explicit(&rt->qos_suspect_until_ms, memory_order_relaxed);
            long long now_v = (long long)now_ms();
            if (now_v < win_until) {
                /* 疑似 QoS 窗口内：此刻整段链路都不通，探针失败不能作为「这个 IP 坏了」的证据。
                 * 只记录、不改状态，避免健康检查把节点判死、与转发侧的下行猝死判定互相加剧。 */
                debug_msg("[UDP/H3] [%s] 疑似 QoS 窗口内检查失败，暂不计入节点失败: %s (窗口剩余 %llds)",
                          carrier_display_name(rt->spec.mode), ip, (win_until - now_v) / 1000);
                continue;
            }
            fail++;
            consecutive_success = 0;
            atomic_store(&rt->udp_candidates.cache_valid, 0);
            pthread_mutex_lock(&rt->udp_candidates.mu);
            for (size_t i = 0; i < rt->udp_candidates.len; i++) {
                if (strcmp(rt->udp_candidates.items[i].ip, ip) == 0) {
                    rt->udp_candidates.items[i].consecutive_fail++;
                    rt->udp_candidates.items[i].last_fail_ms = now_ms();
                    break;
                }
            }
            pthread_mutex_unlock(&rt->udp_candidates.mu);
            if (active_now) {
                if (ok_cnt > 0) {
                    warn_msg("[UDP/H3] [%s] 活跃态检查失败 (%d/2): %s (丢包 %d%%, %d/%d 包, 明细 %s, 均延迟 %dms)",
                             carrier_display_name(rt->spec.mode), fail, ip, loss_pct, ok_cnt, probe_n, detail_buf, latency);
                } else {
                    warn_msg("[UDP/H3] [%s] 活跃态检查失败 (%d/2): %s (丢包 100%%, 0/%d 包, 明细 %s)",
                             carrier_display_name(rt->spec.mode), fail, ip, probe_n, detail_buf);
                }
            } else {
                warn_msg("[UDP/H3] [%s] 闲置态检查失败 (%d/2): %s (丢包 100%%, 0/1 包, QUIC 无响应)",
                         carrier_display_name(rt->spec.mode), fail, ip);
            }
        } else {
            /* 探针恢复成功 = QoS 窗口结束：清除窗口并归还「本窗口切换额度」 */
            atomic_store_explicit(&rt->qos_suspect_until_ms, 0, memory_order_relaxed);
            atomic_store_explicit(&rt->qos_switch_used, 0, memory_order_relaxed);
            fail = 0;
            consecutive_success++;
            atomic_store(&rt->udp_candidates.cache_valid, 1);
            pthread_mutex_lock(&rt->udp_candidates.mu);
            for (size_t i = 0; i < rt->udp_candidates.len; i++) {
                if (strcmp(rt->udp_candidates.items[i].ip, ip) == 0) {
                    rt->udp_candidates.items[i].consecutive_fail = 0;
                    break;
                }
            }
            pthread_mutex_unlock(&rt->udp_candidates.mu);
            long n = now_ms();
            if (active_now && ok_cnt < probe_n) {
                debug_msg("[UDP/H3] [%s] 活跃态检查抖动: %s (丢包 %d%%, %d/%d 包, 明细 %s, 均延迟 %dms)",
                          carrier_display_name(rt->spec.mode), ip, loss_pct, ok_cnt, probe_n, detail_buf, latency);
                last_log = n;
            } else if (g_cfg.log_level >= LOG_DEBUG && g_cfg.health_log > 0 && n - last_log >= g_cfg.health_log * 1000L) {
                if (active_now) {
                    debug_msg("[UDP/H3] [%s] 活跃态检查正常: %s (丢包 0%%, %d/%d 包, 明细 %s, 均延迟 %dms)",
                              carrier_display_name(rt->spec.mode), ip, ok_cnt, probe_n, detail_buf, latency);
                } else {
                    debug_msg("[UDP/H3] [%s] 闲置态检查正常: %s (丢包 0%%, 1/1 包, 延迟 %dms)",
                              carrier_display_name(rt->spec.mode), ip, latency);
                }
                last_log = n;
            }
        }

        if (fail >= 2) {
            log_msg("[UDP/H3] [%s] 连续两次状态检查失败，顺位切换下一个候选 IP",
                    carrier_display_name(rt->spec.mode));
            carrier_trigger_maintenance(rt, MAINT_SWITCH_UDP);
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
        atomic_fetch_add_explicit(&rt->active_tcp_conns, 1, memory_order_relaxed);
        atomic_store_explicit(&rt->last_tcp_active_ms, (long long)now_ms(), memory_order_relaxed);
        unsigned long long conn_id = atomic_fetch_add(&g_tcp_conn_seq, 1) + 1;
        conn_msg("[TCP/H2] #%llu [%s] 客户端连接建立 (当前活跃: %d)", conn_id, carrier_display_name(rt->spec.mode), active);
        ConnCtx *cc = calloc(1, sizeof(ConnCtx));
        if (!cc) {
            close(cfd);
            atomic_fetch_sub_explicit(&rt->active_tcp_conns, 1, memory_order_relaxed);
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
            atomic_fetch_sub_explicit(&rt->active_tcp_conns, 1, memory_order_relaxed);
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
        return (*port > 0 && *port <= 65535) ? 0 : -1;
    }
    const char *colon = strrchr(addr, ':');
    if (!colon) {
        // 只有端口号的情况，例如 "1234"
        snprintf(host, hostsz, "0.0.0.0");
        *port = atoi(addr);
        return (*port > 0 && *port <= 65535) ? 0 : -1;
    }
    size_t n = (size_t)(colon - addr);
    if (n >= hostsz) n = hostsz - 1;
    memcpy(host, addr, n);
    host[n] = 0;
    *port = atoi(colon + 1);
    if (!host[0]) snprintf(host, hostsz, "0.0.0.0");
    return (*port > 0 && *port <= 65535) ? 0 : -1;
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
#ifdef IPV6_V6ONLY
        int v6only = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *)&v6only, sizeof(v6only));
#endif
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, host, &sa6.sin6_addr) != 1) {
            close(fd);
            return INVALID_SOCKET;
        }
        /* Windows SIO_LOOPBACK_FAST_PATH 必须在 bind/listen 之前设置才生效 */
        set_loopback_fast_path(fd);
        if (bind(fd, (struct sockaddr *)&sa6, sizeof(sa6)) != 0) {
            int err = errno;
            close(fd);
            errno = err;
            return INVALID_SOCKET;
        }
        if (listen(fd, 4096) != 0) {
            int err = errno;
            close(fd);
            errno = err;
            return INVALID_SOCKET;
        }
        return fd;
    }
    socket_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfnat_socket_invalid(fd)) return INVALID_SOCKET;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&yes, sizeof(yes));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        close(fd);
        return INVALID_SOCKET;
    }
    /* Windows SIO_LOOPBACK_FAST_PATH 必须在 bind/listen 之前设置才生效 */
    set_loopback_fast_path(fd);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        int err = errno;
        close(fd);
        errno = err;
        return INVALID_SOCKET;
    }
    if (listen(fd, 4096) != 0) {
        int err = errno;
        close(fd);
        errno = err;
        return INVALID_SOCKET;
    }
    return fd;
}

/* ── HTTP/3 (QUIC / UDP) 转发与会话管理引擎 ────────────────────────── */

#define UDP_SESSION_TIMEOUT_MS 60000L
#define UDP_STALL_WINDOW_MS 5000L
#define UDP_STALL_MIN_UP_BYTES 2560ULL
#define UDP_STALL_MAX_DOWN_BYTES 8192ULL
#define UDP_STALL_CLEAR_DOWN_BYTES 32768ULL
#define UDP_STALL_MAX_STRIKES 2

/* ── 下行猝死检测（QoS 定向限速下行大流量）────────────────────────────────
 * 背景：QUIC VN 探针是「1200B 上行 + 27B 回包」，令牌桶对孤立小包几乎不设限，
 * 因此探针永远显示 80ms，而实际下行被压到几百 kbps。下行容量无法用探针测量，
 * 只能用「会话真实字节」作为传感器：以会话自身的历史峰值为基准判断「猝死」。
 *
 * 判据（窗口 5s，一次性强证据，不必等两轮）：
 *   d_up > 0  且  d_down < max(FLOOR, peak / RATIO)  且  peak >= PEAK_MIN  且  peak 距今 <= PEAK_AGE_MS
 * 四个约束分别排除：完全静默的空闲隧道 / 正常低速会话 / 从没跑起来过的会话 / 用户主动暂停。 */
#define UDP_STALL_PEAK_MIN 98304ULL        /* 5s 窗口下行峰值 >= 96KB（≈19KB/s）才算"跑过速度" */
#define UDP_STALL_PEAK_RATIO 8ULL          /* 当前窗口低于峰值的 1/8 视为猝死 */
#define UDP_STALL_PEAK_FLOOR 4096ULL       /* 低于 4KB/5s 才可能是猝死，避免低码率场景误判 */
#define UDP_STALL_PEAK_AGE_MS 20000L       /* 峰值必须发生在 20s 内，否则视为"已正常空闲" */
#define UDP_STALL_CONFIRM_MS 8000L         /* 第一段降级后 8s 仍无下行 → 第二段剔除会话 */

/* 疑似 QoS 窗口的时长常量见文件顶部 QOS_WINDOW_* 定义（扫描器先用、会话管理后用，必须前置） */

#define UDP_MAX_SESSIONS 1024
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
    long last_down_ms;
    uint64_t bytes_up;
    uint64_t bytes_down;
    uint64_t bytes_up_at_down;
    long stall_snap_ms;
    uint64_t stall_snap_up;
    uint64_t stall_snap_down;
    int stall_count;
    /* 下行猝死：历史峰值 + 第一段降级时刻（用于 8s 后二次确认） */
    uint64_t down_peak;
    long down_peak_ms;
    long down_collapse_ms;
    int down_collapsed;
    struct UdpSession *next;
    struct UdpSession *hash_next;
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
#ifdef IPV6_V6ONLY
        int v6only = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *)&v6only, sizeof(v6only));
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

static inline uint8_t hash_client_addr(const struct sockaddr_storage *ss) {
    if (!ss) return 0;
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;
        uint32_t a = (uint32_t)sin->sin_addr.s_addr;
        uint16_t p = (uint16_t)sin->sin_port;
        return (uint8_t)((a ^ (a >> 8) ^ (a >> 16) ^ (a >> 24) ^ p ^ (p >> 8)) & 0xFF);
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;
        uint32_t h = (uint32_t)sin6->sin6_port;
        for (int i = 0; i < 16; i++) h ^= sin6->sin6_addr.s6_addr[i];
        return (uint8_t)(h & 0xFF);
    }
    return 0;
}

static inline void udp_hash_insert(CarrierRuntime *rt, UdpSession *sess) {
    if (!rt || !sess) return;
    uint8_t h = hash_client_addr(&sess->client_addr);
    sess->hash_next = rt->udp_hash[h];
    rt->udp_hash[h] = sess;
}

static inline void udp_hash_remove(CarrierRuntime *rt, UdpSession *del) {
    if (!rt || !del) return;
    uint8_t h = hash_client_addr(&del->client_addr);
    UdpSession *cur = rt->udp_hash[h];
    UdpSession *prev = nullptr;
    while (cur) {
        if (cur == del) {
            if (prev) prev->hash_next = cur->hash_next;
            else rt->udp_hash[h] = cur->hash_next;
            del->hash_next = nullptr;
            break;
        }
        prev = cur;
        cur = cur->hash_next;
    }
}

static inline UdpSession *udp_hash_find(CarrierRuntime *rt, const struct sockaddr_storage *client_addr) {
    if (!rt || !client_addr) return nullptr;
    uint8_t h = hash_client_addr(client_addr);
    UdpSession *s = rt->udp_hash[h];
    while (s) {
        if (sockaddr_equal(&s->client_addr, client_addr)) return s;
        s = s->hash_next;
    }
    return nullptr;
}

static socket_t udp_connect_upstream_sa(const char *ip, const struct sockaddr_storage *target_sa, socklen_t target_salen, int port, size_t active_sessions) {
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
    tune_socket_buffers(fd, active_sessions > 32 ? 3 : 2); /* 低并发 (<=32) 用 1MB/512KB 提速，高并发 (>32) 收敛 256KB 防软路由 OOM */
    set_nonblock(fd, 1);

    if (connect(fd, (struct sockaddr *)&ss, slen) != 0) {
        close(fd);
        return INVALID_SOCKET;
    }
    return fd;
}

static UdpSession *find_or_create_udp_session_sa(CarrierRuntime *rt, const struct sockaddr_storage *client_addr, socklen_t client_len, const char *target_ip, const struct sockaddr_storage *target_sa, socklen_t target_salen, int target_port, uint8_t first_byte) {
    if (!rt || !client_addr || !target_ip || !*target_ip) return nullptr;

    /* 1. MRU 极速热点命中 (单连接连续高吞吐场景 O(1) 零分桶) */
    UdpSession *s = rt->last_udp_sess;
    if (!s || !sockaddr_equal(&s->client_addr, client_addr)) {
        /* 2. 8 位哈希分桶检索 (多客户端/并发流场景 O(1) 定位) */
        s = udp_hash_find(rt, client_addr);
    }

    if (s) {
        /* P1: 上游会话动态热迁移——当优选 IP 切换或上游套接字异常断开时，平滑重连至新上游 */
        if (strcmp(s->target_ip, target_ip) != 0 || !cfnat_socket_valid(s->upstream_fd)) {
            if (cfnat_socket_valid(s->upstream_fd)) close(s->upstream_fd);
            s->upstream_fd = udp_connect_upstream_sa(target_ip, target_sa, target_salen, target_port, rt->udp_session_count);
            snprintf(s->target_ip, sizeof(s->target_ip), "%s", target_ip);
            s->target_port = target_port;
            long migrate_ms = now_ms();
            s->last_down_ms = migrate_ms;
            s->bytes_up_at_down = s->bytes_up;
            s->stall_snap_ms = migrate_ms;
            s->stall_snap_up = s->bytes_up;
            s->stall_snap_down = s->bytes_down;
            s->stall_count = 0;
            rt->udp_dirty = 1;
        }
        rt->last_udp_sess = s;
        return s;
    }

    /* 3. 本实例会话数量上限保护 (达到 1024 上限时 LRU 淘汰最久未活跃项，避免跨实例挤压) */
    if (rt->udp_session_count >= UDP_MAX_SESSIONS) {
        long oldest_time = 0;
        UdpSession *oldest = nullptr;
        UdpSession *prev_oldest = nullptr;
        UdpSession *prev = nullptr;
        UdpSession *cur = rt->udp_sessions;
        while (cur) {
            if (oldest == nullptr || cur->last_active_ms < oldest_time) {
                oldest_time = cur->last_active_ms;
                oldest = cur;
                prev_oldest = prev;
            }
            prev = cur;
            cur = cur->next;
        }
        if (oldest) {
            if (rt->last_udp_sess == oldest) rt->last_udp_sess = nullptr;
            if (prev_oldest) prev_oldest->next = oldest->next;
            else rt->udp_sessions = oldest->next;
            udp_hash_remove(rt, oldest);
            if (cfnat_socket_valid(oldest->upstream_fd)) close(oldest->upstream_fd);
            if (rt->udp_session_count > 0) rt->udp_session_count--;
            atomic_store_explicit(&rt->active_udp_conns, (int)rt->udp_session_count, memory_order_relaxed);
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
    new_sess->upstream_fd = udp_connect_upstream_sa(target_ip, target_sa, target_salen, target_port, rt->udp_session_count);
    if (cfnat_socket_invalid(new_sess->upstream_fd)) {
        free(new_sess);
        return nullptr;
    }
    snprintf(new_sess->target_ip, sizeof(new_sess->target_ip), "%s", target_ip);
    new_sess->target_port = target_port;
    new_sess->created_ms = now_ms();
    new_sess->last_active_ms = new_sess->created_ms;
    new_sess->last_down_ms = new_sess->created_ms;
    new_sess->stall_snap_ms = new_sess->created_ms;
    new_sess->stall_snap_up = 0;
    new_sess->stall_snap_down = 0;
    new_sess->stall_count = 0;
    new_sess->down_peak = 0;
    new_sess->down_peak_ms = new_sess->created_ms;
    new_sess->down_collapse_ms = 0;
    new_sess->down_collapsed = 0;
    new_sess->sess_id = atomic_fetch_add(&g_udp_sess_seq, 1) + 1;
    rt->udp_session_count++;
    atomic_store_explicit(&rt->active_udp_conns, (int)rt->udp_session_count, memory_order_relaxed);
    atomic_store_explicit(&rt->last_udp_active_ms, (long long)new_sess->created_ms, memory_order_relaxed);
    int active = atomic_fetch_add(&g_active_udp_sessions, 1) + 1;
    new_sess->next = rt->udp_sessions;
    rt->udp_sessions = new_sess;
    udp_hash_insert(rt, new_sess);
    rt->last_udp_sess = new_sess;
    rt->udp_dirty = 1;

    int is_quic = ((first_byte & 0x80) != 0 && (first_byte & 0x40) != 0);
    conn_msg("[UDP/H3] #%llu [%s] 客户端连接建立 (当前活跃: %d)",
             new_sess->sess_id, carrier_display_name(rt->spec.mode), active);
    conn_msg("[UDP/H3] #%llu [%s] 识别客户端协议: %s，转发到 IP: %s 端口: %d",
             new_sess->sess_id, carrier_display_name(rt->spec.mode),
             is_quic ? "QUIC/H3" : "UDP", new_sess->target_ip, new_sess->target_port);
    return new_sess;
}

static int prune_udp_sessions(CarrierRuntime *rt, long cur_ms) {
    if (!rt) return 0;
    int should_switch_udp = 0;
    int switch_by_blackhole = 0;
    int switch_by_stall = 0;
    int switch_by_collapse = 0;      /* 下行猝死第一段触发的切换（速率崩塌，非完全无响应） */
    int pruned_count = 0;
    pthread_mutex_lock(&rt->udp_mu);
    UdpSession *prev = nullptr;
    UdpSession *s = rt->udp_sessions;
    while (s) {
        /* 1. 双条件黑洞检测：覆盖初始握手黑洞与传输中途黑洞 (4s 零下行判定) */
        int is_blackhole = (s->bytes_down == 0 && cur_ms - s->created_ms >= 4000 && s->bytes_up >= 1200) ||
                           (s->bytes_down > 0 && cur_ms - s->last_down_ms >= 4000 && (s->bytes_up - s->bytes_up_at_down) >= 1200);
        /* 2. 窒息低速检测 (Stall Detection)：应对“延迟极低但下载卡死/被 QoS 令牌桶极低速限流”场景
         * 每 >=5s (配合 3s 巡检实际每 ~6s) 滑动快照：
         * - 窗口内上行 >= 2.5KB (覆盖 QUIC PTO 退避期重传) 且下行 < 8KB 且上行 >= 2×下行 (收发倒挂)，记 1 次窒息告警；
         * - 仅当下行真正恢复 (>= 32KB/窗口) 或完全静默 (上行=0) 时才清零计数，灰区 (退避小包/微量漏水) 保留计数防误重置；
         * - 累计 2 次窒息告警即判定窒息低速剔除，直接触发顺位切换 (适配 Xray XMUX 单长连接复用)。 */
        int is_stalled = 0;
        int collapse_first_stage = 0;   /* 下行猝死第一段：只降级 IP / 影响新会话，不杀现有会话 */
        if (!is_blackhole && cur_ms - s->stall_snap_ms >= UDP_STALL_WINDOW_MS) {
            long win_s = (cur_ms - s->stall_snap_ms) / 1000;
            uint64_t d_up = (s->bytes_up >= s->stall_snap_up) ? (s->bytes_up - s->stall_snap_up) : 0;
            uint64_t d_down = (s->bytes_down >= s->stall_snap_down) ? (s->bytes_down - s->stall_snap_down) : 0;

            /* 3. 下行猝死检测：以会话自身历史峰值为基准，与上行字节无关。
             * 这是唯一能抓住「探针 80ms、实际下载 0」的判据——探针只有 1200B 上行 + 27B 回包，
             * 令牌桶对孤立小包不设限，而下行 bulk 会被直接压死。 */
            if (d_down > s->down_peak) {
                s->down_peak = d_down;
                s->down_peak_ms = cur_ms;
            }
            /* d_up > 0 是必要条件：完全静默（用户暂停/下载已结束）不能算猝死，
             * 只有「客户端还在发包、却收不到数据」才是被限速的特征。 */
            if (d_up > 0 && s->down_peak >= UDP_STALL_PEAK_MIN &&
                (cur_ms - s->down_peak_ms) <= UDP_STALL_PEAK_AGE_MS) {
                uint64_t thr = s->down_peak / UDP_STALL_PEAK_RATIO;
                if (thr < UDP_STALL_PEAK_FLOOR) thr = UDP_STALL_PEAK_FLOOR;
                if (d_down < thr) {
                    if (!s->down_collapsed) {
                        s->down_collapsed = 1;
                        s->down_collapse_ms = cur_ms;
                        collapse_first_stage = 1;
                    } else if (cur_ms - s->down_collapse_ms >= UDP_STALL_CONFIRM_MS) {
                        /* 第二段：降级后 8s 仍无下行，说明客户端自身 PTO/idle 也没能恢复 → 剔除会话 */
                        is_stalled = 1;
                    }
                }
            }
            if (d_down >= UDP_STALL_CLEAR_DOWN_BYTES) {
                s->down_collapsed = 0;      /* 下行恢复（含用户重新开始下载）→ 撤销降级标记 */
                s->down_collapse_ms = 0;
            }

            /* 2. 上行型窒息检测：覆盖握手黑洞与上行重传型卡死 */
            if (d_up >= UDP_STALL_MIN_UP_BYTES && d_down < UDP_STALL_MAX_DOWN_BYTES && d_up >= d_down * 2) {
                s->stall_count++;
                if (s->stall_count >= UDP_STALL_MAX_STRIKES) {
                    is_stalled = 1;
                } else {
                    debug_msg("[UDP/H3] #%llu [%s] 会话窒息低速预警 (%d/%d, %lds 上行 %llu B, 下行 %llu B, 目标 %s)",
                              s->sess_id, carrier_display_name(rt->spec.mode),
                              s->stall_count, UDP_STALL_MAX_STRIKES,
                              win_s > 0 ? win_s : 5L,
                              (unsigned long long)d_up, (unsigned long long)d_down, s->target_ip);
                }
            } else if (d_down >= UDP_STALL_CLEAR_DOWN_BYTES || d_up == 0) {
                s->stall_count = 0;
            }

            if (collapse_first_stage) {
                long long now_v = (long long)now_ms();
                if (atomic_load_explicit(&rt->qos_suspect_until_ms, memory_order_relaxed) <= now_v) {
                    atomic_store_explicit(&rt->qos_switch_used, 0, memory_order_relaxed); /* 新窗口：归还一次切换额度 */
                }
                atomic_store_explicit(&rt->qos_suspect_until_ms, now_v + QOS_WINDOW_DEFAULT_MS, memory_order_relaxed);
                /* 单位统一为 KB/s，便于直接对照实际下载速度 */
                double cur_kbps = (win_s > 0) ? ((double)d_down / 1024.0 / (double)win_s) : 0.0;
                double peak_kbps = (double)s->down_peak / 1024.0 / (double)(UDP_STALL_WINDOW_MS / 1000);
                long peak_age_s = (cur_ms - s->down_peak_ms) / 1000;
                log_msg("[UDP/H3] #%llu [%s] [下行猝死] 目标 %s: %.1f KB/s (峰值 %.1f KB/s, %lds 前) → 标记降级，新会话优先切走（现有会话保留 8s 观察）",
                        s->sess_id, carrier_display_name(rt->spec.mode), s->target_ip,
                        cur_kbps, peak_kbps, peak_age_s > 0 ? peak_age_s : 0);
            }

            s->stall_snap_ms = cur_ms;
            s->stall_snap_up = s->bytes_up;
            s->stall_snap_down = s->bytes_down;
        }

        if (is_blackhole || is_stalled || collapse_first_stage) {
            pthread_mutex_lock(&rt->udp_candidates.mu);
            for (size_t i = 0; i < rt->udp_candidates.len; i++) {
                if (strcmp(rt->udp_candidates.items[i].ip, s->target_ip) == 0) {
                    rt->udp_candidates.items[i].consecutive_fail++;
                    rt->udp_candidates.items[i].last_fail_ms = now_ms();
                    break;
                }
            }
            if (strcmp(rt->udp_candidates.current_ip, s->target_ip) == 0) {
                if (is_stalled) {
                    atomic_store_explicit(&rt->udp_candidates.fast_fail_count, 0, memory_order_relaxed);
                    atomic_store(&rt->udp_candidates.cache_valid, 0);
                    should_switch_udp = 1;
                    if (is_blackhole) switch_by_blackhole = 1;
                    if (s->down_collapsed) switch_by_collapse = 1;  /* 二段确认的下行猝死，日志按猝死归因 */
                    switch_by_stall = 1;
                } else if (collapse_first_stage) {
                    /* 第一段：同一 QoS 窗口内最多切换一次，避免「切过去—再切回来」的抖动 */
                    if (atomic_exchange_explicit(&rt->qos_switch_used, 1, memory_order_relaxed) == 0) {
                        atomic_store(&rt->udp_candidates.cache_valid, 0);
                        should_switch_udp = 1;
                        switch_by_collapse = 1;
                    }
                } else if (atomic_fetch_add_explicit(&rt->udp_candidates.fast_fail_count, 1, memory_order_relaxed) + 1 >= 2) {
                    atomic_store_explicit(&rt->udp_candidates.fast_fail_count, 0, memory_order_relaxed);
                    atomic_store(&rt->udp_candidates.cache_valid, 0);
                    should_switch_udp = 1;
                }
            }
            pthread_mutex_unlock(&rt->udp_candidates.mu);
        }

        if (is_blackhole || is_stalled || cur_ms - s->last_active_ms > UDP_SESSION_TIMEOUT_MS) {
            UdpSession *del = s;
            rt->udp_dirty = 1;
            pruned_count++;
            if (rt->last_udp_sess == del) rt->last_udp_sess = nullptr;
            if (prev) {
                prev->next = s->next;
            } else {
                rt->udp_sessions = s->next;
            }
            udp_hash_remove(rt, del);
            s = s->next;
            if (cfnat_socket_valid(del->upstream_fd)) {
                close(del->upstream_fd);
            }
            if (rt->udp_session_count > 0) rt->udp_session_count--;
            atomic_store_explicit(&rt->active_udp_conns, (int)rt->udp_session_count, memory_order_relaxed);
            int active = atomic_fetch_sub(&g_active_udp_sessions, 1) - 1;
            long lifetime_s = (cur_ms - del->created_ms) / 1000;
            char up_s[32] = {0}, down_s[32] = {0};
            format_bytes(del->bytes_up, up_s, sizeof(up_s));
            format_bytes(del->bytes_down, down_s, sizeof(down_s));
            const char *close_reason = is_blackhole ? "黑洞剔除"
                                     : del->down_collapsed ? "下行猝死剔除"
                                     : (is_stalled ? "窒息低速剔除" : "空闲超时");
            conn_msg("[UDP/H3] #%llu [%s] 客户端会话关闭 (%s, 存活 %lds, 上行 %s, 下行 %s, 当前活跃: %d)",
                     del->sess_id, carrier_display_name(rt->spec.mode),
                     close_reason,
                     lifetime_s > 0 ? lifetime_s : 0, up_s, down_s, active);
            free(del);
        } else {
            prev = s;
            s = s->next;
        }
    }
    pthread_mutex_unlock(&rt->udp_mu);

    if (rt->udp_down_drop > 0) {
        if (!rt->udp_down_drop_warned) {
            rt->udp_down_drop_warned = 1;
            warn_msg("[UDP/H3] [%s] 检测到下行非阻塞写队列溢出丢包: %llu（后续统计将在 debug 级别输出）",
                     carrier_display_name(rt->spec.mode), (unsigned long long)rt->udp_down_drop);
        } else {
            debug_msg("[UDP/H3] [%s] 近 3s 下行非阻塞写队列溢出丢包: %llu",
                      carrier_display_name(rt->spec.mode), (unsigned long long)rt->udp_down_drop);
        }
        rt->udp_down_drop = 0;
    }
    if (should_switch_udp && atomic_load(&g_running)) {
        const char *switch_reason = switch_by_collapse
                                        ? "检测到下行速率崩塌 (探针正常但下载被限速，疑似 QoS 定向压制下行)"
                                        : (switch_by_stall && !switch_by_blackhole)
                                              ? "检测到上游连续窒息低速 (可能受 UDP QoS 极低速限流)"
                                              : (switch_by_stall && switch_by_blackhole)
                                                    ? "检测到上游连续无回包或窒息低速 (可能受 UDP QoS 限流/阻断)"
                                                    : "检测到上游连续无回包响应 (可能受 UDP QoS 阻断)";
        log_msg("[UDP/H3] [%s] %s，触发顺位切换", carrier_display_name(rt->spec.mode), switch_reason);
        carrier_trigger_maintenance(rt, MAINT_SWITCH_UDP);
    }
    return pruned_count;
}

static void *carrier_udp_thread(void *arg) {
    CarrierRuntime *rt = (CarrierRuntime *)arg;
    if (!rt || cfnat_socket_invalid(rt->udp_listen_fd)) return nullptr;

    /* C23 thread_local 静态缓冲区与缓存 pollfd 表：
     * 1. Windows/Linux/Android 全平台共享 udp_dirty 增量缓存，会话未变更时零链表遍历、零互斥锁开销；
     * 2. Linux 与 Android (API 24+) 额外启用 recvmmsg 批量系统调用接收 QUIC 突发报文，降低内核态切换开销。
     * P1-7: 单包槽位提升至 4096 字节，适配 Jumbo frame 与大包 QUIC 突发，避免 MSG_TRUNC 截断 */
#ifdef __linux__
    #define UDP_BATCH_SZ 32
    static thread_local char batch_bufs[UDP_BATCH_SZ][4096];
    struct mmsghdr msgs[UDP_BATCH_SZ];
    struct iovec iovs[UDP_BATCH_SZ];
    for (int b = 0; b < UDP_BATCH_SZ; b++) {
        iovs[b].iov_base = batch_bufs[b];
        iovs[b].iov_len = sizeof(batch_bufs[b]);
        memset(&msgs[b], 0, sizeof(msgs[b]));
        msgs[b].msg_hdr.msg_iov = &iovs[b];
        msgs[b].msg_hdr.msg_iovlen = 1;
    }
#else
    static thread_local char buf[UDP_BUF_SIZE];
#endif
#ifdef _WIN32
    WSAPOLLFD pfds[UDP_MAX_SESSIONS + 1];
#else
    struct pollfd pfds[UDP_MAX_SESSIONS + 1];
#endif
    UdpSession *p_sess[UDP_MAX_SESSIONS + 1];
    size_t npfd = 1;
    rt->udp_dirty = 1;
    long last_prune_ms = now_ms();
    char cur_target_ip[MAX_IP_LEN] = {0};
    struct sockaddr_storage cur_target_sa = {0};
    socklen_t cur_target_salen = 0;
    unsigned long long cached_udp_epoch = (unsigned long long)-1;
    int target_port = (rt->spec.prof.port > 0) ? rt->spec.prof.port : g_cfg.port;
    if (target_port <= 0) target_port = 443;

    while (atomic_load(&g_running)) {
        if (rt->udp_dirty) {
            pfds[0].fd = rt->udp_listen_fd;
            pfds[0].events = POLLIN;
            pfds[0].revents = 0;
            p_sess[0] = nullptr;
            npfd = 1;

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
            rt->udp_dirty = 0;
        }

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
        if (cur_ms - last_prune_ms >= 3000) {
            last_prune_ms = cur_ms;
            int pruned = prune_udp_sessions(rt, cur_ms);
            /* P0-1: 若会话发生清理或会话表变更，原 pollfd 与 p_sess 表已悬垂，
             * 必须立即 continue 跳过后续事件分发，直接在循环首部重建 pollfd 数组，
             * 杜绝 Use-After-Free 与向已关闭/复用套接字分发报文 */
            if (pruned > 0 || rt->udp_dirty) continue;
        }

        if (nready == 0) continue;

        int should_switch_udp = 0;

        /* 1. 优先检查各 upstream_fd 是否有来自 Cloudflare 的 UDP 回包或网络错误事件 */
        for (size_t i = 1; i < npfd; i++) {
            if (pfds[i].revents & (POLLIN | POLLERR | POLLHUP)) {
                UdpSession *sess = p_sess[i];
                if (sess && cfnat_socket_valid(sess->upstream_fd) && sess->upstream_fd == pfds[i].fd) {
                    if (pfds[i].revents & (POLLERR | POLLHUP)) {
                        close(sess->upstream_fd);
                        sess->upstream_fd = INVALID_SOCKET;
                        rt->udp_dirty = 1;
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
#ifdef __linux__
                    while (1) {
                        int nmsg = recvmmsg(sess->upstream_fd, msgs, UDP_BATCH_SZ, MSG_DONTWAIT, nullptr);
                        if (nmsg <= 0) break;
                        if (sess->bytes_down == 0) {
                            atomic_store_explicit(&rt->udp_candidates.fast_fail_count, 0, memory_order_relaxed);
                        }
                        sess->last_active_ms = cur_ms;
                        struct mmsghdr d_msgs[UDP_BATCH_SZ];
                        struct iovec d_iovs[UDP_BATCH_SZ];
                        int out_cnt = 0;
                        for (int m = 0; m < nmsg; m++) {
#ifdef MSG_TRUNC
                            if (msgs[m].msg_hdr.msg_flags & MSG_TRUNC) continue; /* L5: 丢弃内核截断残报文 */
#endif
                            d_iovs[out_cnt].iov_base = batch_bufs[m];
                            d_iovs[out_cnt].iov_len = msgs[m].msg_len;
                            memset(&d_msgs[out_cnt], 0, sizeof(d_msgs[out_cnt]));
                            d_msgs[out_cnt].msg_hdr.msg_name = (void *)&sess->client_addr;
                            d_msgs[out_cnt].msg_hdr.msg_namelen = sess->client_addr_len;
                            d_msgs[out_cnt].msg_hdr.msg_iov = &d_iovs[out_cnt];
                            d_msgs[out_cnt].msg_hdr.msg_iovlen = 1;
                            out_cnt++;
                        }
                        if (out_cnt > 0) {
                            int sent_n = sendmmsg(rt->udp_listen_fd, d_msgs, (unsigned int)out_cnt, 0);
                            if (sent_n > 0) {
                                for (int s = 0; s < sent_n; s++) {
                                    sess->bytes_down += (uint64_t)d_msgs[s].msg_len;
                                }
                                sess->last_down_ms = cur_ms;
                                sess->bytes_up_at_down = sess->bytes_up;
                            }
                            if (sent_n < out_cnt) {
                                int start_idx = (sent_n > 0) ? sent_n : 0;
                                for (int s = start_idx; s < out_cnt; s++) {
                                    ssize_t sent = sendto(rt->udp_listen_fd, d_iovs[s].iov_base, d_iovs[s].iov_len, 0,
                                                          (struct sockaddr *)&sess->client_addr, sess->client_addr_len);
                                    if (sent > 0) {
                                        sess->bytes_down += (uint64_t)sent;
                                        sess->last_down_ms = cur_ms;
                                        sess->bytes_up_at_down = sess->bytes_up;
                                    } else {
                                        uint64_t dropped = (uint64_t)(out_cnt - s);
                                        rt->udp_down_drop += dropped;
                                        atomic_fetch_add_explicit(&rt->udp_down_drop_stats, (unsigned long long)dropped, memory_order_relaxed);
                                        break;
                                    }
                                }
                            }
                        }
                        if (nmsg < UDP_BATCH_SZ) break;
                    }
#else
                    while (1) {
                        ssize_t n = recv(sess->upstream_fd, buf, UDP_BUF_SIZE, 0);
                        if (n <= 0) break;
                        if (sess->bytes_down == 0) {
                            atomic_store_explicit(&rt->udp_candidates.fast_fail_count, 0, memory_order_relaxed);
                        }
                        sess->last_active_ms = cur_ms;
                        ssize_t sent = sendto(rt->udp_listen_fd, buf, (size_t)n, 0, (struct sockaddr *)&sess->client_addr, sess->client_addr_len);
                        if (sent > 0) {
                            sess->bytes_down += (uint64_t)sent;
                            sess->last_down_ms = cur_ms;
                            sess->bytes_up_at_down = sess->bytes_up;
                        } else {
                            rt->udp_down_drop++;
                            atomic_fetch_add_explicit(&rt->udp_down_drop_stats, 1, memory_order_relaxed);
                        }
                    }
#endif
                }
            }
        }

        if (should_switch_udp && atomic_load(&g_running)) {
            log_msg("[UDP/H3] [%s] 上游 UDP 连接返回网络错误 (ICMP 不可达)，触发顺位切换", carrier_display_name(rt->spec.mode));
            carrier_trigger_maintenance(rt, MAINT_SWITCH_UDP);
        }

        /* 2. 监听端口接收客户端 (如 Xray) 发来的 UDP / QUIC 报文 */
        if (pfds[0].revents & POLLIN) {
            atomic_store_explicit(&rt->last_udp_active_ms, (long long)cur_ms, memory_order_relaxed);
            unsigned long long cur_epoch = atomic_load_explicit(&rt->udp_candidates.epoch, memory_order_acquire);
            if (cur_epoch != cached_udp_epoch || !cur_target_ip[0]) {
                carrier_get_current_udp_ip_sa(rt, cur_target_ip, sizeof(cur_target_ip), &cur_target_sa, &cur_target_salen);
                cached_udp_epoch = cur_epoch;
            }

#ifdef __linux__
            while (1) {
                struct sockaddr_storage client_addrs[UDP_BATCH_SZ];
                socklen_t client_lens[UDP_BATCH_SZ];
                for (int b = 0; b < UDP_BATCH_SZ; b++) {
                    msgs[b].msg_hdr.msg_name = &client_addrs[b];
                    msgs[b].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
                }
                int nmsg = recvmmsg(rt->udp_listen_fd, msgs, UDP_BATCH_SZ, MSG_DONTWAIT, nullptr);
                for (int b = 0; b < UDP_BATCH_SZ; b++) {
                    client_lens[b] = (b < nmsg) ? (socklen_t)msgs[b].msg_hdr.msg_namelen : 0;
                    msgs[b].msg_hdr.msg_name = nullptr;
                    msgs[b].msg_hdr.msg_namelen = 0;
                }
                if (nmsg <= 0) break;
                for (int m = 0; m < nmsg; m++) {
#ifdef MSG_TRUNC
                    if (msgs[m].msg_hdr.msg_flags & MSG_TRUNC) continue; /* L5: 丢弃内核截断残报文 */
#endif
                    unsigned int blen = msgs[m].msg_len;
                    if (blen == 0) continue;
                    struct sockaddr_storage *c_ss = &client_addrs[m];
                    socklen_t c_len = client_lens[m];
                    UdpSession *sess = rt->last_udp_sess;
                    if (!sess || !sockaddr_equal(&sess->client_addr, c_ss) || cfnat_socket_invalid(sess->upstream_fd) || strcmp(sess->target_ip, cur_target_ip) != 0) {
                        if (cur_target_ip[0]) {
                            sess = find_or_create_udp_session_sa(rt, c_ss, c_len, cur_target_ip, &cur_target_sa, cur_target_salen, target_port, (uint8_t)batch_bufs[m][0]);
                        } else {
                            sess = nullptr;
                        }
                    }
                    if (sess && cfnat_socket_valid(sess->upstream_fd)) {
                        sess->last_active_ms = cur_ms;
                        /* B4: 严格排除内核截断报文，连续收集同一客户端/XMUX 会话数据报 */
                        int run_end = m + 1;
                        while (run_end < nmsg) {
                            unsigned int nxt_len = msgs[run_end].msg_len;
                            if (nxt_len == 0) break;
#ifdef MSG_TRUNC
                            /* N1: 遇内核截断报文立即终止批量 run，交由外层循环安全丢弃 */
                            if (msgs[run_end].msg_hdr.msg_flags & MSG_TRUNC) break;
#endif
                            struct sockaddr_storage *nxt_c = &client_addrs[run_end];
                            if (!sockaddr_equal(&sess->client_addr, nxt_c)) break;
                            run_end++;
                        }
                        int batch_count = run_end - m;
                        if (batch_count > 1) {
                            struct mmsghdr send_mvec[UDP_BATCH_SZ];
                            struct iovec send_iov[UDP_BATCH_SZ];
                            memset(send_mvec, 0, (size_t)batch_count * sizeof(struct mmsghdr));
                            for (int k = 0; k < batch_count; k++) {
                                send_iov[k].iov_base = batch_bufs[m + k];
                                send_iov[k].iov_len = msgs[m + k].msg_len;
                                send_mvec[k].msg_hdr.msg_iov = &send_iov[k];
                                send_mvec[k].msg_hdr.msg_iovlen = 1;
                            }
                            int sent_pkts = sendmmsg(sess->upstream_fd, send_mvec, (unsigned int)batch_count, 0);
                            if (sent_pkts > 0) {
                                for (int k = 0; k < sent_pkts; k++) {
                                    sess->bytes_up += (uint64_t)send_mvec[k].msg_len;
                                }
                                /* N2: 仅跳过实际成功发出的报文；若发生部分发送，外层循环自然处理后续未发报文 */
                                m += (sent_pkts - 1);
                            } else {
                                /* N2: sendmmsg 遭遇非阻塞 EAGAIN/错误时，回退单包发送首包 */
                                ssize_t sent = send(sess->upstream_fd, batch_bufs[m], blen, 0);
                                if (sent > 0) sess->bytes_up += (uint64_t)sent;
                                else atomic_fetch_add_explicit(&rt->udp_up_drop, 1, memory_order_relaxed);
                            }
                        } else {
                            ssize_t sent = send(sess->upstream_fd, batch_bufs[m], blen, 0);
                            if (sent > 0) sess->bytes_up += (uint64_t)sent;
                            else atomic_fetch_add_explicit(&rt->udp_up_drop, 1, memory_order_relaxed);
                        }
                    }
                }
                if (nmsg < UDP_BATCH_SZ) break;
            }
#else
            while (1) {
                struct sockaddr_storage client_ss;
                socklen_t client_len = sizeof(client_ss);
                ssize_t n = recvfrom(rt->udp_listen_fd, buf, UDP_BUF_SIZE, 0, (struct sockaddr *)&client_ss, &client_len);
                if (n <= 0) break;

                UdpSession *sess = rt->last_udp_sess;
                if (!sess || !sockaddr_equal(&sess->client_addr, &client_ss) || cfnat_socket_invalid(sess->upstream_fd) || strcmp(sess->target_ip, cur_target_ip) != 0) {
                    if (cur_target_ip[0]) {
                        sess = find_or_create_udp_session_sa(rt, &client_ss, (socklen_t)client_len, cur_target_ip, &cur_target_sa, cur_target_salen, target_port, (uint8_t)buf[0]);
                    } else {
                        sess = nullptr;
                    }
                }
                if (sess && cfnat_socket_valid(sess->upstream_fd)) {
                    sess->last_active_ms = cur_ms;
                    ssize_t sent = send(sess->upstream_fd, buf, (size_t)n, 0);
                    if (sent > 0) sess->bytes_up += (uint64_t)sent;
                    else atomic_fetch_add_explicit(&rt->udp_up_drop, 1, memory_order_relaxed); /* 上行发送失败（原实现完全静默） */
                }
            }
#endif
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

static int carrier_start_threads(CarrierRuntime *rt) {
    if (!rt) return -1;
    int use_h2 = rt->spec.prof.enable_h2;
    int use_h3 = rt->spec.prof.enable_h3;
    if (create_small_thread(&rt->maint_tid, carrier_maintenance_thread, rt) != 0) {
        log_msg("[ERROR] [%s] 创建后台维护线程失败: %s", carrier_display_name(rt->spec.mode), strerror(errno));
    }
    if (use_h2) {
        if (create_small_thread(&rt->health_tid, carrier_health_thread, rt) != 0) {
            log_msg("[ERROR] [%s] 创建 TCP 健康检查线程失败: %s", carrier_display_name(rt->spec.mode), strerror(errno));
        }
        if (create_small_thread(&rt->accept_tid, carrier_accept_thread, rt) != 0) {
            log_msg("[FATAL] [%s] 创建 TCP 监听线程失败: %s", carrier_display_name(rt->spec.mode), strerror(errno));
            return -1;
        }
    }
    if (use_h3 && cfnat_socket_valid(rt->udp_listen_fd)) {
        if (create_small_thread(&rt->udp_health_tid, carrier_udp_health_thread, rt) != 0) {
            log_msg("[ERROR] [%s] 创建 UDP 健康检查线程失败: %s", carrier_display_name(rt->spec.mode), strerror(errno));
        }
        if (create_small_thread(&rt->udp_tid, carrier_udp_thread, rt) != 0) {
            log_msg("[FATAL] [%s] 创建 UDP 转发线程失败: %s", carrier_display_name(rt->spec.mode), strerror(errno));
            if (!use_h2) return -1;
        }
    }
    return 0;
}

static void log_runtime_stats(void) {
    if (!g_carrier_runtimes || g_carrier_runtime_count == 0) return;

    char buf[4096];
    size_t pos = 0;
    int active_tcp = atomic_load_explicit(&g_active_tcp_conns, memory_order_relaxed);
    int active_udp = atomic_load_explicit(&g_active_udp_sessions, memory_order_relaxed);
    int n = snprintf(buf + pos, sizeof(buf) - pos,
                     "[运行指标] 活跃连接 TCP=%d, 活跃会话 UDP=%d (统计周期 %ds)",
                     active_tcp, active_udp, g_cfg.stats_interval);
    if (n > 0) pos += ((size_t)n < sizeof(buf) - pos) ? (size_t)n : (sizeof(buf) - pos - 1);

    for (size_t i = 0; i < g_carrier_runtime_count; i++) {
        CarrierRuntime *rt = &g_carrier_runtimes[i];
        char tcp_ip[MAX_IP_LEN] = "";
        char tcp_colo[MAX_COLO_LEN] = "";
        int tcp_lat = -1;
        size_t tcp_len = 0;

        pthread_mutex_lock(&rt->candidates.mu);
        tcp_len = rt->candidates.len;
        if (rt->candidates.current_ip[0]) {
            snprintf(tcp_ip, sizeof(tcp_ip), "%s", rt->candidates.current_ip);
        }
        if (rt->candidates.current_index < rt->candidates.len) {
            const Result *cur = &rt->candidates.items[rt->candidates.current_index];
            tcp_lat = (cur->ewma_latency > 0) ? cur->ewma_latency : cur->latency_ms;
            if (cur->data_center[0]) {
                snprintf(tcp_colo, sizeof(tcp_colo), "%s", cur->data_center);
            }
        }
        pthread_mutex_unlock(&rt->candidates.mu);

        char udp_ip[MAX_IP_LEN] = "";
        char udp_colo[MAX_COLO_LEN] = "";
        int udp_lat = -1;
        size_t udp_len = 0;

        pthread_mutex_lock(&rt->udp_candidates.mu);
        udp_len = rt->udp_candidates.len;
        if (rt->udp_candidates.current_ip[0]) {
            snprintf(udp_ip, sizeof(udp_ip), "%s", rt->udp_candidates.current_ip);
        }
        if (rt->udp_candidates.current_index < rt->udp_candidates.len) {
            const Result *cur = &rt->udp_candidates.items[rt->udp_candidates.current_index];
            udp_lat = (cur->ewma_latency > 0) ? cur->ewma_latency : cur->latency_ms;
            if (cur->data_center[0]) {
                snprintf(udp_colo, sizeof(udp_colo), "%s", cur->data_center);
            }
        }
        pthread_mutex_unlock(&rt->udp_candidates.mu);

        pthread_mutex_lock(&rt->udp_mu);
        size_t udp_sess = rt->udp_session_count;
        pthread_mutex_unlock(&rt->udp_mu);

        unsigned int tcp_sw = atomic_load_explicit(&rt->tcp_switch_count, memory_order_relaxed);
        unsigned int udp_sw = atomic_load_explicit(&rt->udp_switch_count, memory_order_relaxed);
        unsigned int up_drop = atomic_exchange_explicit(&rt->udp_up_drop, 0, memory_order_relaxed);
        unsigned long long down_drop = atomic_exchange_explicit(&rt->udp_down_drop_stats, 0, memory_order_relaxed);

        int last_loss = atomic_load_explicit(&rt->last_udp_loss_pct, memory_order_relaxed);
        char loss_str[24];
        if (last_loss >= 0) snprintf(loss_str, sizeof(loss_str), "%d%%", last_loss);
        else snprintf(loss_str, sizeof(loss_str), "-");

        int is_last_rt = (i + 1 >= g_carrier_runtime_count);
        const char *tcp_branch = "├─";
        const char *udp_branch = is_last_rt ? "└─" : "├─";
        const char *name = carrier_display_name(rt->spec.mode);

        char tcp_part[256];
        if (!rt->spec.prof.enable_h2) {
            snprintf(tcp_part, sizeof(tcp_part), "已禁用");
        } else if (tcp_ip[0] && tcp_len > 0) {
            snprintf(tcp_part, sizeof(tcp_part), "%s (%s, %dms, 池%zu, 累计切%u)",
                     tcp_ip, tcp_colo[0] ? tcp_colo : "UNK", tcp_lat >= 0 ? tcp_lat : 0, tcp_len, tcp_sw);
        } else {
            snprintf(tcp_part, sizeof(tcp_part), "无可用节点 (池%zu, 累计切%u)", tcp_len, tcp_sw);
        }

        char udp_part[256];
        if (!rt->spec.prof.enable_h3) {
            snprintf(udp_part, sizeof(udp_part), "已禁用");
        } else if (udp_ip[0] && udp_len > 0) {
            snprintf(udp_part, sizeof(udp_part), "%s (%s, %dms, 链路丢包%s, 池%zu, 会话%zu, 累计切%u, 队列丢包 %u/%llu)",
                     udp_ip, udp_colo[0] ? udp_colo : "UNK", udp_lat >= 0 ? udp_lat : 0,
                     loss_str, udp_len, udp_sess, udp_sw, up_drop, down_drop);
        } else {
            snprintf(udp_part, sizeof(udp_part), "无可用节点 (链路丢包%s, 池%zu, 会话%zu, 累计切%u, 队列丢包 %u/%llu)",
                     loss_str, udp_len, udp_sess, udp_sw, up_drop, down_drop);
        }

        if (pos + 2 < sizeof(buf)) {
            n = snprintf(buf + pos, sizeof(buf) - pos, "\n  %s [TCP/H2] [%s] %s", tcp_branch, name, tcp_part);
            if (n > 0) pos += ((size_t)n < sizeof(buf) - pos) ? (size_t)n : (sizeof(buf) - pos - 1);
        }
        if (pos + 2 < sizeof(buf)) {
            n = snprintf(buf + pos, sizeof(buf) - pos, "\n  %s [UDP/H3] [%s] %s", udp_branch, name, udp_part);
            if (n > 0) pos += ((size_t)n < sizeof(buf) - pos) ? (size_t)n : (sizeof(buf) - pos - 1);
        }
    }

    log_msg("%s", buf);
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
            atomic_init(&rt->candidates.switch_lock, 0);
            atomic_init(&rt->candidates.fast_fail_count, 0);
            atomic_init(&rt->candidates.has_node_fail, 0);
            atomic_init(&rt->candidates.epoch, 0);
            pthread_mutex_init(&rt->udp_candidates.mu, nullptr);
            atomic_init(&rt->udp_candidates.cache_valid, 0);
            atomic_init(&rt->udp_candidates.switch_lock, 0);
            atomic_init(&rt->udp_candidates.fast_fail_count, 0);
            atomic_init(&rt->udp_candidates.has_node_fail, 0);
            atomic_init(&rt->udp_candidates.epoch, 0);
            atomic_init(&rt->rescanning_lock, 0);
            atomic_init(&rt->tcp_switch_count, 0);
            atomic_init(&rt->udp_switch_count, 0);
            atomic_init(&rt->udp_up_drop, 0);
            atomic_init(&rt->udp_down_drop_stats, 0);
            atomic_init(&rt->active_tcp_conns, 0);
            atomic_init(&rt->active_udp_conns, 0);
            atomic_init(&rt->last_tcp_active_ms, 0);
            atomic_init(&rt->last_udp_active_ms, 0);
            atomic_init(&rt->last_udp_loss_pct, -1);
            atomic_init(&rt->qos_suspect_until_ms, 0);
            atomic_init(&rt->qos_switch_used, 0);
            atomic_init(&rt->maint_pending, 0);
            pthread_mutex_init(&rt->maint_mu, nullptr);
            pthread_cond_init(&rt->maint_cv, nullptr);
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
                pthread_mutex_destroy(&rt->maint_mu);
                pthread_cond_destroy(&rt->maint_cv);
                if (rt->proxy_pool) {
                    baidu_pool_free(rt->proxy_pool);
                    free(rt->proxy_pool);
                }
            }
            free(g_carrier_runtimes);
            g_carrier_runtimes = nullptr;
            g_carrier_runtime_count = 0;
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
            int use_h2 = rt->spec.prof.enable_h2;
            int use_h3 = rt->spec.prof.enable_h3;
            const char *proto_desc = (use_h2 && use_h3) ? "双轨分流: TCP/H2 + UDP/H3" : (use_h2 ? "仅 TCP/H2" : "仅 UDP/H3");

            // 先尝试读取候选缓存 (按启用的协议走对应快路径)
            if (carrier_try_use_candidate_caches(rt)) {
                if (use_h2) rt->listen_fd = listen_tcp(rt->spec.addr);
                if (use_h3) rt->udp_listen_fd = listen_udp(rt->spec.addr);
                if ((use_h2 && cfnat_socket_invalid(rt->listen_fd)) ||
                    (use_h3 && cfnat_socket_invalid(rt->udp_listen_fd))) {
                    log_msg("[%s] 无法监听 %s (%s): %s", carrier_display_name(rt->spec.mode), rt->spec.addr, proto_desc, strerror(errno));
                    if (cfnat_socket_valid(rt->listen_fd)) { close(rt->listen_fd); rt->listen_fd = INVALID_SOCKET; }
                    if (cfnat_socket_valid(rt->udp_listen_fd)) { close(rt->udp_listen_fd); rt->udp_listen_fd = INVALID_SOCKET; }
                    free(rt->candidates.items);
                    rt->candidates.items = nullptr;
                    rt->candidates.len = 0;
                    free(rt->udp_candidates.items);
                    rt->udp_candidates.items = nullptr;
                    rt->udp_candidates.len = 0;
                    continue;
                }
                log_msg("[%s] 正在监听 %s (%s)，TLS目标端口：%d，非TLS目标端口：%d",
                        carrier_display_name(rt->spec.mode), rt->spec.addr, proto_desc,
                        rt->spec.prof.port, rt->spec.prof.http_port);
                if (carrier_start_threads(rt) == 0) {
                    started_count++;
                } else {
                    if (cfnat_socket_valid(rt->listen_fd)) { close(rt->listen_fd); rt->listen_fd = INVALID_SOCKET; }
                    if (cfnat_socket_valid(rt->udp_listen_fd)) { close(rt->udp_listen_fd); rt->udp_listen_fd = INVALID_SOCKET; }
                }
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
                    if (cfnat_socket_valid(rt->listen_fd)) { close(rt->listen_fd); rt->listen_fd = INVALID_SOCKET; }
                    if (cfnat_socket_valid(rt->udp_listen_fd)) { close(rt->udp_listen_fd); rt->udp_listen_fd = INVALID_SOCKET; }
                    continue;
                }
            } else {
                profile_ips = load_ip_list(cur_ipfile, rt->spec.prof.random_mode, cur_v6_split);
                if (profile_ips.len == 0) {
                    warn_msg("[%s] 没有可扫描的 IP (%s 为空)", carrier_display_name(rt->spec.mode), cur_ipfile);
                    if (cfnat_socket_valid(rt->listen_fd)) { close(rt->listen_fd); rt->listen_fd = INVALID_SOCKET; }
                    if (cfnat_socket_valid(rt->udp_listen_fd)) { close(rt->udp_listen_fd); rt->udp_listen_fd = INVALID_SOCKET; }
                    continue;
                }
            }

            /* 冷启动预监听：按启用的协议提前绑定端口，让客户端连接在内核队列排队，彻底杜绝 RST */
            if (use_h2 && cfnat_socket_invalid(rt->listen_fd)) {
                rt->listen_fd = listen_tcp(rt->spec.addr);
            }
            if (use_h3 && cfnat_socket_invalid(rt->udp_listen_fd)) {
                rt->udp_listen_fd = listen_udp(rt->spec.addr);
            }
            if ((use_h2 && cfnat_socket_valid(rt->listen_fd)) || (!use_h2 && use_h3 && cfnat_socket_valid(rt->udp_listen_fd))) {
                log_msg("[%s] 预绑定监听端口成功 %s (%s)",
                        carrier_display_name(rt->spec.mode), rt->spec.addr, proto_desc);
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
                if (cfnat_socket_valid(rt->listen_fd)) { close(rt->listen_fd); rt->listen_fd = INVALID_SOCKET; }
                if (cfnat_socket_valid(rt->udp_listen_fd)) { close(rt->udp_listen_fd); rt->udp_listen_fd = INVALID_SOCKET; }
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

            // 2. 设置 UDP 候选池 (仅在启用 H3 时执行)
            if (use_h3) {
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
                    if (rt->spec.use_baidu_proxy) {
                        int uport = (rt->spec.prof.port > 0) ? rt->spec.prof.port : (g_cfg.port > 0 ? g_cfg.port : 443);
                        int udelay = udp_probe_timeout_ms((rt->spec.prof.delay_ms > 0) ? rt->spec.prof.delay_ms : g_cfg.delay_ms);
                        ResultList fb = load_candidate_cache_for_profile(
                            candidate_cache_file_for_profile_udp("direct", rt->spec.prof.ips_type), &rt->spec.prof);
                        if (fb.len > 0 &&
                            cache_quick_check_parallel(rt, fb.items, fb.len, 1, uport, udelay) != (size_t)-1) {
                            rt->udp_candidates.items = fb.items;
                            rt->udp_candidates.len = fb.len;
                            carrier_set_current_udp_candidate(rt, 0);
                            atomic_store(&rt->udp_candidates.cache_valid, 1);
                            log_msg("[%s] 已复用直连 H3 候选缓存（本机直连 UDP 可达），共 %zu 个节点：百度前置仅代理 TCP，UDP 走直连",
                                    carrier_display_name(rt->spec.mode), fb.len);
                        } else {
                            free(fb.items);
                        }
                    }
                }
            }

            free(carrier_results.items);

            if (rt->candidates.len == 0 || !rt->candidates.current_ip[0]) {
                warn_msg("[%s] TCP 候选池初始化为空 (可能内存不足)，跳过启动", carrier_display_name(rt->spec.mode));
                if (cfnat_socket_valid(rt->listen_fd)) { close(rt->listen_fd); rt->listen_fd = INVALID_SOCKET; }
                if (cfnat_socket_valid(rt->udp_listen_fd)) { close(rt->udp_listen_fd); rt->udp_listen_fd = INVALID_SOCKET; }
                free(rt->candidates.items);
                rt->candidates.items = nullptr;
                rt->candidates.len = 0;
                free(rt->udp_candidates.items);
                rt->udp_candidates.items = nullptr;
                rt->udp_candidates.len = 0;
                continue;
            }

            if (use_h2 && cfnat_socket_invalid(rt->listen_fd)) {
                rt->listen_fd = listen_tcp(rt->spec.addr);
            }
            if (use_h3 && cfnat_socket_invalid(rt->udp_listen_fd)) {
                rt->udp_listen_fd = listen_udp(rt->spec.addr);
            }
            if ((use_h2 && cfnat_socket_invalid(rt->listen_fd)) ||
                (use_h3 && cfnat_socket_invalid(rt->udp_listen_fd))) {
                log_msg("[%s] 无法监听 %s (%s): %s", carrier_display_name(rt->spec.mode), rt->spec.addr, proto_desc, strerror(errno));
                if (cfnat_socket_valid(rt->listen_fd)) { close(rt->listen_fd); rt->listen_fd = INVALID_SOCKET; }
                if (cfnat_socket_valid(rt->udp_listen_fd)) { close(rt->udp_listen_fd); rt->udp_listen_fd = INVALID_SOCKET; }
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

            if (!use_h3) {
                log_msg("[%s] 正在监听 %s (%s)，TLS目标端口：%d，非TLS目标端口：%d\n"
                        "  └─ [TCP/H2] 最优 IP: %s (延迟 %d ms, 候选 %zu 个) | [UDP/H3] 已禁用",
                        carrier_display_name(rt->spec.mode), rt->spec.addr, proto_desc,
                        rt->spec.prof.port, rt->spec.prof.http_port,
                        rt->candidates.current_ip, tcp_lat, rt->candidates.len);
            } else if (!use_h2) {
                if (rt->udp_candidates.len > 0 && rt->udp_candidates.current_ip[0]) {
                    log_msg("[%s] 正在监听 %s (%s)，目标端口：%d\n"
                            "  └─ [UDP/H3] 最优 IP: %s (延迟 %d ms, 候选 %zu 个) | [TCP/H2] 已禁用",
                            carrier_display_name(rt->spec.mode), rt->spec.addr, proto_desc,
                            rt->spec.prof.port,
                            rt->udp_candidates.current_ip, udp_lat, rt->udp_candidates.len);
                } else {
                    log_msg("[%s] 正在监听 %s (%s)，目标端口：%d\n"
                            "  └─ [UDP/H3] 无可用节点 (0 个候选，等待空池退避自愈) | [TCP/H2] 已禁用",
                            carrier_display_name(rt->spec.mode), rt->spec.addr, proto_desc,
                            rt->spec.prof.port);
                }
            } else if (rt->udp_candidates.len > 0 && rt->udp_candidates.current_ip[0]) {
                log_msg("[%s] 正在监听 %s (%s)，TLS目标端口：%d，非TLS目标端口：%d\n"
                        "  ├─ [TCP/H2] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)\n"
                        "  └─ [UDP/H3] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)",
                        carrier_display_name(rt->spec.mode), rt->spec.addr, proto_desc,
                        rt->spec.prof.port, rt->spec.prof.http_port,
                        rt->candidates.current_ip, tcp_lat, rt->candidates.len,
                        rt->udp_candidates.current_ip, udp_lat, rt->udp_candidates.len);
            } else {
                log_msg("[%s] 正在监听 %s (%s)，TLS目标端口：%d，非TLS目标端口：%d\n"
                        "  ├─ [TCP/H2] 最优 IP: %s (延迟 %d ms, 候选 %zu 个)\n"
                        "  └─ [UDP/H3] 无可用节点 (0 个候选)",
                        carrier_display_name(rt->spec.mode), rt->spec.addr, proto_desc,
                        rt->spec.prof.port, rt->spec.prof.http_port,
                        rt->candidates.current_ip, tcp_lat, rt->candidates.len);
            }

            if (carrier_start_threads(rt) == 0) {
                started_count++;
            } else {
                if (cfnat_socket_valid(rt->listen_fd)) { close(rt->listen_fd); rt->listen_fd = INVALID_SOCKET; }
                if (cfnat_socket_valid(rt->udp_listen_fd)) { close(rt->udp_listen_fd); rt->udp_listen_fd = INVALID_SOCKET; }
            }
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
                pthread_mutex_destroy(&rt->maint_mu);
                pthread_cond_destroy(&rt->maint_cv);
                if (rt->proxy_pool) {
                    baidu_pool_free(rt->proxy_pool);
                    free(rt->proxy_pool);
                }
            }
            free(g_carrier_runtimes);
            g_carrier_runtimes = nullptr;
            g_carrier_runtime_count = 0;
            free(g_locations);
            g_locations = nullptr;
            g_location_count = 0;
            return 1;
        }
        long last_stats_ms = now_ms();
        while (atomic_load(&g_running)) {
            if (sleep_interruptible_ms(1000) != 0) break;
            if (g_cfg.stats_interval > 0) {
                long cur_ms = now_ms();
                if ((long long)(cur_ms - last_stats_ms) >= (long long)g_cfg.stats_interval * 1000LL) {
                    last_stats_ms = cur_ms;
                    log_runtime_stats();
                }
            }
        }
        /* 1. 广播唤醒维护线程 */
        for (size_t i = 0; i < g_carrier_runtime_count; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];
            pthread_mutex_lock(&rt->maint_mu);
            pthread_cond_broadcast(&rt->maint_cv);
            pthread_mutex_unlock(&rt->maint_mu);
        }
        /* 2. P1-4: 先 join 全部后台线程与监听接收线程，杜绝 close 后的 fd 被复用引起竞态 */
        for (size_t i = 0; i < g_carrier_runtime_count; i++) {
            CarrierRuntime *rt = &g_carrier_runtimes[i];
            if (rt->health_tid) pthread_join(rt->health_tid, nullptr);
            if (rt->udp_health_tid) pthread_join(rt->udp_health_tid, nullptr);
            if (rt->accept_tid) pthread_join(rt->accept_tid, nullptr);
            if (rt->udp_tid) pthread_join(rt->udp_tid, nullptr);
            if (rt->maint_tid) pthread_join(rt->maint_tid, nullptr);
        }
        /* 3. 监听线程均已停止，安全关闭监听套接字 */
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
        /* 4. 等待所有正在收尾的 TCP 活跃连接线程安全退出，覆盖最大超时时间 (5000ms)，杜绝 UAF */
        long drain_start = now_ms();
        while (atomic_load(&g_active_tcp_conns) > 0 && (now_ms() - drain_start) < 5000) {
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
            pthread_mutex_destroy(&rt->maint_mu);
            pthread_cond_destroy(&rt->maint_cv);
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
        free(g_locations);
        g_locations = nullptr;
        g_location_count = 0;
#ifdef _WIN32
        WSACleanup();
#endif
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
                    free(g_locations);
                return 1;
            }
            results = scan_ips(nullptr, &cidrs, &g_cfg, nullptr);
            cidrlist_destroy(&cidrs);
        } else {
            StringList ips = load_ip_list(cli_ipfile, g_cfg.random_mode, g_cfg.v6_split);
            if (ips.len == 0) {
                log_msg("没有可扫描的 IP (%s 为空)", cli_ipfile);
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
        print_results_table_ex(stdout, "TCP/H2", nullptr, results.items, results.len,
                               (now_ms() - start) / 1000);
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
    free(g_locations);
    g_locations = nullptr;
    g_location_count = 0;
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
