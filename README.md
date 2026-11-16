# cfnat C 版 (C23 纯静态现代平台版)

面向低内存环境的 **Cloudflare IP 扫描 + 单端口 TCP/UDP (H2/H3) 双轨透明转发** 工具。

本项目采用最新的 **C23 国际标准 (ISO/IEC 9899:2024)** 进行现代化重构，针对 **Linux、Windows 11 及 Android Termux 现代平台（amd64 / arm64）** 构建**纯静态（Pure Static）独立二进制**，彻底剥离 glibc 依赖，根除一切跨发行版兼容性问题。同时全面集成了 **HTTP/2 (TCP) 与 HTTP/3 (QUIC/UDP) 双轨独立测优、Xray XMUX 深度协同优化、首包快速熔断以及原子树状防打断日志系统（v0.0.18-c23）**。

核心目标是保留扫描、优选、转发、健康检查、百度前置代理和双方案监听等核心能力的同时，尽量压低常驻内存与 CPU 占用，非常适合 OpenWrt/软路由、手机 Termux、小内存 VPS 以及 Windows 11 设备。

---

## 目录

- [现代平台优化与支持说明](#现代平台优化与支持说明)
- [项目定位与转发链路](#项目定位与转发链路)
- [核心特性](#核心特性)
- [Xray XMUX 协同机制说明](#xray-xmux-协同机制说明)
- [快速开始与编译](#快速开始与编译)
- [Android Termux 运行指南](#android-termux-运行指南)
- [Systemd 生产服务部署指南](#systemd-生产服务部署指南)
- [运行参数](#运行参数)
- [常用示例](#常用示例)
- [构建与 GitHub Actions 发布](#构建与-github-actions-发布)
- [资源占用说明](#资源占用说明)
- [常见问题](#常见问题)
- [免责声明](#免责声明)

---

## ⚡ 现代平台优化与支持说明

### 1. 核心性能与传输层优化
- **双向转发线程合并减负（每连接线程数与虚拟内存立降 33%）**：
  - `relay_bidirectional()` 彻底废除创建 2 个子转发线程的传统模式；当前连接处理线程 `connection_thread` 直接就地接管反向转发（`u -> c`），仅派生 1 个轻量子线程负责正向转发（`c -> u`）；
  - 每条连接由 3 个线程压减至 2 个线程，降低 33% 的线程创建、销毁与上下文切换开销，并在等待对端终止时完全消除空闲等待线程的虚拟内存占用。
- **预解析二进制地址缓存（`sockaddr_storage` 热路径零解析）**：
  - 在 `Result`、`CandidatePool`、`ConnCtx` 及 `UdpSession` 中全量内置二进制网络地址 `struct sockaddr_storage addr` 与 `addr_len`；
  - 候选 IP 初筛入池或切换时即刻完成 `inet_pton` 解析，后续高并发建立 TCP 连接与 UDP 会话时全面走 `tcp_connect_sa` 与 `udp_connect_upstream_sa`，彻底消除热路径上反复 `strchr` 探测与字符串 IP 重复转换的 CPU 开销。
- **Linux 零拷贝栈保护（`pipe_worker_fallback` 强隔离 `noinline`）**：
  - 将 Linux `splice` 失败时的用户态回退拷贝函数显式标记为 `noinline`（`__attribute__((noinline))` / `__declspec(noinline)`）；
  - 彻底杜绝 GCC / Clang 自动将 16KB 回退缓冲区内联进主工作线程栈帧，保证走内核级零拷贝通道的线程栈干净轻巧，根除高并发小线程栈下的栈溢出风险。
- **扫描架构轻量化（彻底释放 400 个内核描述符，静态失效单轮熔断）**：
  - 废弃 `scan_worker` 中每线程创建独立 `EventLoop` 的开销，直接采用自适应超时 `recv_headers`，彻底消灭 400 个并发线程持有的 400 个内核 `epoll`/`kqueue` 句柄；
  - 静态特征即刻熔断：当遇到机房不匹配（`colo_skip`）、Cloudflare 限制（`cfray_miss`）或状态码不符（`http_code_mismatch`）时，立即 `break` 终止后续轮次，杜绝高达 5 倍的无谓 HTTP 探测重试。
- **QUIC 批量并发探测异常消费与特征校验**：
  - 接入 `POLLERR` 并捕获消费 `recvfrom` 返回的 ICMP 异步错误及 Windows `WSAECONNRESET`，彻底修复探测套接字在非阻塞模式下遭遇不可达错误时 0ms 陷入 CPU 100% 死循环的隐患；
  - 严格校验 QUIC 报文首字节长包头标志 `(resp[0] & 0x80) != 0`，有效过滤网络杂包与伪造报文。
- **零堆分配 CIDR 惰性遍历与 IPv6 容量预分配**：
  - 在 `-random=false` 顺序模式下全面启用 `CidrList` 二分定位前缀和流式生成 IP，消灭数百万个字符串堆内存分配（`malloc` / `realloc`），内存开销降低至 $O(1)$ 常数级；
  - `load_ip_list` 载入 IPv6 时单次预分配 40960 项指针容量，避免上万行 IPv6 CIDR 衍生时的数十次数组搬迁。
- **全链路禁用 Nagle 算法（`TCP_NODELAY`）**：在接入客户端连接以及拨号上游连接时全面注入，消除 40ms 交互粘滞延迟，显著提升 TLS 握手及多路复用首包响应速度。
- **TCP Keep-Alive 微参数深度对齐（45s 保活，根除僵尸连接）**：
  - 针对 Xray / Chrome 等主流客户端 H2 空闲保活周期（45 秒），显式配置操作系统内核保活参数：`TCP_KEEPIDLE = 45s`、`TCP_KEEPINTVL = 10s`、`TCP_KEEPCNT = 3`（Windows 平台通过 `SIO_KEEPALIVE_VALS` 同步对齐）；
  - 彻底杜绝中间防火墙/NAT 静默断开导致的连接死挂（从 Linux 默认挂死 **2 小时**缩减至 **75 秒**自动识别回收），加速释放转发线程与文件句柄。
- **UDP/H3 会话 $O(1)$ MRU 热点缓存与批量锁优化**：
  - 针对 QUIC/H3 多路复用流量高度集中于单个客户端源端口的特征，引入 8 字节极简 MRU 指针缓存，客户端高频连续发包时检索 $O(1)$ 瞬间命中（命中率 >95%）；
  - 批量接收客户端数据报时前置复用解析与批量外置加锁，消除逐包频繁争抢 `udp_mu` 的热路径锁开销。
- **UDP 套接字异常与黑洞即时驱逐自愈引擎**：
  - 接入 `POLLERR | POLLHUP` 事件主动回收，上游遭遇 ICMP 端口/主机不可达时立即关闭失效套接字并重置状态，彻底杜绝内核空转（100% CPU Spinning）；
  - 独立于空闲超时的快速黑洞感知：连接建立 $\ge$ 5 秒且已发包 $\ge$ 1200 字节但回包为零时，立即将黑洞感知周期从 60 秒缩短至 5 秒内，并将失效黑洞会话从链表即刻安全驱逐并释放，杜绝同一僵尸会话每 5 秒重复累加失效计数；
  - 双轨自愈充沛度判定：原地自愈必须满足 TCP 与 UDP 存活候选均达标，杜绝局部网络丢 UDP 包导致的候选池枯竭或容量萎缩。
- **TCP 连接跨候选池顺位轮换（杜绝单死 IP 原地死磕）**：
  - 连接建立阶段采用顺位梯队拨号：首轮拨号失败时不原地重复重试相同 IP，而是直接顺位尝试候选池中的备用最优节点（`try_idx = (current_index + i) % len`）；
  - 备用节点握手成功时实时且无缝提升为当前活跃主节点，故障转移时间从原本死磕 900ms 降至单次 RTT 级别（约 50~100ms）。
- **TLS 探针全套件扩展支持（ECDHE-ECDSA + Workers 证书完美兼容）**：
  - 在 ClientHello 中完整集成 `TLS_ECDHE_ECDSA` 与 `TLS_ECDHE_RSA` 密码套件，并补齐 `ec_point_formats`、`supported_groups`（x25519, secp256r1, secp384r1）和 `signature_algorithms` 扩展；
  - 完美解决针对 Cloudflare Workers / Pages 等默认采用 ECDSA 边缘证书时，探测被边缘网关返回 0x15（Alert 握手失败）导致的 SNI 故障转移误判。
- **高并发热路径无锁化加速（`carrier_choose_ip_fast` & 原子失效计数）**：
  - 新连接进入时，通过 `atomic_load_explicit(..., memory_order_acquire)` 原语判定缓存有效性，并使用直接内存复制替代格式化解析；
  - `fast_fail_count` 全面原子化（`atomic_int`），数据下行接收链路实现零锁重置，彻底消除高负载传输对候选池互斥锁的争抢。
- **探测系统调用减负与慢节点早剪枝（扫描速度再翻倍）**：
  - 探测链路采用单套接字 `cfnat_poll_single` 直接轮询，根除每轮探测对 `epoll_ctl(ADD/DEL)` 的无谓系统调用开销；
  - 首轮探测若发现往返延迟严重超标（如 $> 2 \times \text{delay\_ms}$ 且 $> 250\text{ms}$），立即执行早剪枝放弃后续轮次，节省多达 80% 的无效探测耗时；
  - 采用基于 C23 `thread_local` 的无锁 **SplitMix64** 极速随机数生成器，彻底消除多线程并发调用 `rand()` 时 C 运行库的全局互斥锁争抢。
- **优雅退出安全隔离与 UAF 彻底根除**：
  - 连接转发线程局部预缓存承载模式信息，并在销毁流程中强化 `g_running` 状态校验，防止服务关闭后访问已释放的全局运行时资源；
  - 统一规范 CLI 扫描模式的标准输出流，表格与最优节点评分全部对齐至 `stdout`，日志与告警归流 `stderr`。
- **Linux 内核级零拷贝加固（`splice`）**：
  - 消除无脑 `SPLICE_F_MORE` 导致的尾包延迟尖峰（规避最高 200ms 的交互卡顿）；
  - 优雅半关闭（Half-Close）：读到 EOF 时仅对对端执行 `shutdown(..., SHUT_WR)`，完美兼容 HTTP/1.1 等协议的单向收尾流；
  - 16 KB 回退缓冲区解耦，在走零拷贝时彻底杜绝无谓的栈内存分配，根除小线程栈下的栈溢出隐患。
- **自适应内核页安全栈（支持 64KB Page ARM64 内核）**：
  - 扫描线程栈安全设定为 512 KB，转发/服务常驻线程设定为 256 KB，并全面动态对齐 `#if defined(PTHREAD_STACK_MIN)`；
  - 规避 Armbian / 树莓派 64KB 页面大小内核下的段错误（`status=11/SEGV`），在 64 位 Linux 需求分页（Demand Paging）机制下，每线程真实物理内存（RSS）仅占约 8~12 KB。
- **主监听接入零阻塞（`carrier_accept_thread` 消除网络阻塞）**：
  - 重构主接入循环的节点获取逻辑，废除在 `carrier_accept_thread` 中同步执行网络探测（`carrier_health_check_ip`）的做法，改用对候选池的 $O(1)$ 快速只读复制；
  - 遇到节点需要切换或探测时，完全交由独立的 `connection_thread` 在后台按顺位轮换尝试，主监听循环保持**纯本地内存操作与零网络 I/O 阻塞**，从容应对每秒上千个 TCP 连接涌入。
- **内核超时直通转发（单连接系统调用开销直接减半）**：
  - 双向转发循环直接依托套接字已设置的内核级超时（`SO_RCVTIMEO` 300 秒），彻底废弃每轮 `recv` 前无谓的 `poll` / `WSAPoll` 预查询；
  - 数据转发路径的系统调用次数立减 50%，显著压降 CPU 上下文切换消耗；同时在 Linux 零拷贝模式遭遇不支持的套接字类型（`EINVAL` / `ENOSYS`）时自动无缝降级至用户态缓冲拷贝。
- **双向吞吐感知的节点淘汰（彻底杜绝 DoH / 短连接误判驱逐）**：
  - 彻底摒弃以连接存活时间（$< 3000\text{ms}$）简单粗暴断定节点故障的缺陷逻辑，重构为基于数据流吞吐感知的 `carrier_note_connection_success` 与 `carrier_note_connection_failed` 状态机；
  - 针对 DNS-over-HTTPS (DoH)、短 API 查询等在 100~500ms 内极速完成响应的合法短连接，只要检测到上游回包数据（`bytes > 0`）即判定为连接成功并重置失败计数，坚决捍卫延迟最低、响应最快的优质节点不被误杀。
- **双轨预解析二进制地址全链路同步（彻底根除“脑裂” Bug）**：
  - 针对 `tcp_connect_sa` 与 `udp_connect_upstream_sa` 直接使用二进制 `sockaddr_storage` 拨号的特性，在网段裂变衍生、原地测活自愈与全局自愈补充扫描等所有生成/重填路径中，严格同步更新字符串 IP 与二进制地址（`current_addr` / `current_addr_len`）；
  - 彻底根除因拷贝遗漏导致日志显示新衍生 IP 但底层仍向旧种子节点发包的“脑裂”故障。
- **128 KB 块级内存池（StringList Arena Chunk Allocation）**：
  - 候选 IP 列表解析全面改用分块连续内存分配，单次申请 128 KB 内存块存储字符串，将数万次高频小碎片的 `malloc`/`free` 压减为常数级块级管理，彻底消灭堆内存碎片并提升启动解析速度。
- **UDP/H3 热路径流水线优化（优先回包转发与惰性地址获取）**：
  - 在 `carrier_udp_thread` 中优先处理并派发来自 Cloudflare 上游的回程数据报，有效压缩 QUIC/H3 往返时延；
  - 客户端发包处理引入惰性目标地址获取，配合 MRU 命中机制使连续数据报转发达到近乎零锁与零地址解析开销；
  - 采用 C23 `thread_local` 静态收发缓冲区，彻底消除主循环内外的堆 `malloc` / `free`，杜绝小线程栈下的栈溢出隐患。
- **扫描上下文常量请求预构建（400 线程零重复解析）**：
  - 在主扫描调度前将 `domain` 域名路径拆分及 HEAD/GET HTTP 报文模板一次性预生成至 `ScanCtx`；
  - 400 个并发探测线程直接指针复用常量模板，彻底消灭每个线程启动时重复解析与 `snprintf` 格式化开销。
- **候选池 RCU 风格无缝指针替换（消除漂移与空指针窗口）**：
  - 在双轨自愈与全局补充扫描中，采用临界区内原子指针切换、临界区外延迟 `free` 的策略，并将磁盘持久化 `save_candidate_cache` 剥离至内存释放之后；
  - 并发连接线程在读取候选池时绝不遭遇空指针或已释放内存，且彻底杜绝磁盘 I/O 卡顿阻碍内存及时清理，保障数据转发面高并发下的绝对安全。
- **QUIC 探针静态模板与零清零发包**：
  - 采用 C23 `thread_local` 预初始化 1200 字节 QUIC 版本协商探针报文，仅原子更新 4 字节种子与 Connection ID，彻底消灭每轮批次探测 1200 字节的栈声明与 `memset` 清零开销。
- **日志系统紧凑栈帧设计**：
  - 将 `vlog_line` 栈缓冲区由 12 KB 大幅紧凑缩减至 3 KB，在兼顾长行格式化的同时降低 75% 栈空间开销，对小内存嵌入式设备和多线程环境更为安全友好。
- **跨平台轻量级非阻塞 I/O 轮询**：统一使用 `cfnat_poll_single`（跨平台基于 `poll` / Windows `WSAPoll`），彻底移除冗余的 `EventLoop` 堆分配及每个线程持有的额外内核描述符，支持 Linux、Windows 与 Android 下单套接字的高性能毫秒级事件等待，解决 HTTP 探测时的虚假超时与资源占用。
- **Android Termux 沙箱审计兼容**：在 Android 平台下自动隔离 `splice` 系统调用，避免触发 Android `seccomp` 过滤机制报 `signal 31 (SIGSYS)` 错误，确保转发稳定。

### 2. 目标平台支持矩阵（纯静态架构）
构建产物全面采用**纯静态（Pure Static）独立二进制**，无外部动态库依赖，开箱即用：
- **Linux amd64 (x86_64)**：musl 纯静态独立二进制（`cfnat-linux-amd64`），仅需 Linux 3.10+ 内核，无视发行版差异（Ubuntu / Debian / Alpine / CentOS / OpenWrt / Arch 均可直接运行，彻底告别 `GLIBC_xxx not found` 报错）
- **Linux arm64 (aarch64)**：musl 纯静态独立二进制（`cfnat-linux-arm64`），适配各类 ARM VPS、树莓派及各类 OpenWrt 软路由
- **Android Termux (arm64 & amd64)**：官方最新 NDK r27c (LTS) 编译（`cfnat-android-arm64` / `cfnat-android-amd64`），适配 Bionic libc 与 Android 沙箱 seccomp 审计，Termux 免 root 开箱即用
- **Windows 11 amd64 (x86_64)**：Win11 原生纯静态可执行文件（`cfnat-windows-amd64.exe`）
- **Windows 11 arm64 (aarch64)**：Surface / 骁龙 X Elite / ARM 笔记本原生运行（`cfnat-windows-arm64.exe`）

---

## 项目定位与转发链路

cfnat C 版做四件事：
1. **智能扫描与子网裂变优选**：扫描 Cloudflare IP，初筛精准 TCP (H2) 候选池，并结合同网段裂变衍生引擎精筛出 UDP (H3) 专用候选池。
2. **同端口 TCP/UDP 双轨并发监听**：在同一本地端口（如 `127.0.0.1:4443`）同时监听 TCP 与 UDP 数据报。
3. **精准双轨独立路由转发**：
   - TCP 连接（H2/TLS）转发至当前**TCP 优选 IP**（支持自动识别首字节 `0x16` 分流 443 或 80 端口）；
   - UDP 报文（H3/QUIC）转发至当前**UDP 优选 IP:443**，会话状态自动管理。
4. **双轨协同自愈与热替换**：任何一个池见底时，自动触发一次性双轨原地测活与增量补齐，绝不阻塞断网。

它只做纯粹的高性能传输层透明字节/报文转发，不是 HTTP 反向代理，也不会解密或篡改任何业务数据。

```text
               ┌── [TCP: H2/TLS] ────→  cfnat 本地 TCP 端口  ────→  TCP 优选 IP:443
               │
客户端单端口接入
 (127.0.0.1:4443)
               │
               └── [UDP: H3/QUIC] ───→  cfnat 本地 UDP 端口  ────→  UDP 优选 IP:443
```

---

## 核心特性

- **全面遵循 C23 现代语言标准与零开销契约（v0.0.18-c23）**：
  - 核心源码全面遵循 ISO/IEC 9899:2024 (C23) 标准规范，全面引入 `nullptr` 类型安全空指针、`constexpr` 编译期常量及数字分隔符；
  - 采用 C23 标称类型枚举（`enum : uint8_t`），精确压缩枚举变量的内存占用并改善 CPU 缓存命中率；
  - 注入 `[[nodiscard]]` 函数契约属性，严格杜绝关键资源、套接字与健康探测返回值被疏漏丢弃的潜在隐患；
  - 彻底剥离动态库，发布纯静态 Linux 二进制，极大简化在各类路由器与轻量容器上的部署难度。
- **死 IP 首包握手熔断机制（扫描提速 60%+）**：
  - 扫描引擎在首轮 TCP 握手（`attempt == 0`）超时或失败时立即跳出判定死节点，避免对不可达节点执行第 2、3 轮盲目重试等待；
  - 6500+ IPv4 候选 IP 扫描耗时从 80 多秒锐减至 **20~30 秒**左右；统计数字与死 IP 数量精准 1:1 对齐。
- **H2 (TCP) + H3 (QUIC/UDP) 双轨独立测优与透明分流**：
  - **痛点解决**：国内部分 ISP 对境外 UDP 443 存在严重 QoS 限制甚至黑洞，很多 TCP 延迟极佳的 IP 无法传输 QUIC；传统的“单优选 IP”会导致 H3 频繁断流或连不上。
  - **独立路由**：同一监听地址（如 `127.0.0.1:4443`）上，TCP 流量自动打向 TCP 最优节点，UDP/QUIC 流量自动打向 UDP 响应最优节点。
- **RFC 9000 规范的 1200 字节轻量 QUIC 版本协商探针（Version Negotiation Probe）**：
  - 发送带有保留版本号 `0x5A5A5A5A` 的 1200 字节 QUIC Initial 数据包，诱导 Cloudflare 边缘节点立即回复 27 字节的 Version Negotiation 报文。
  - **零加密算法库开销**（无需引入 BoringSSL/OpenSSL 等笨重依赖，保持纯单文件 C 极致轻量），**零 CPU 密钥计算消耗**，单包即可精确测得 UDP 443 真实往返 RTT，且完全符合 RFC 9000 防放大攻击要求（规避 Cloudflare 丢弃小包）。
- **网段裂变衍生与精准定额优选（Subnet Expansion & Fission Engine）**：
  - **彻底告别粗放 2× 过采样**：随着网段裂变机制落地，扫描阶段严格按照用户 `-ipnum` 精准采集最优前 N 个节点，初次启动扫描耗时降低 30%~50%，且彻底避免尾部高延迟节点的劣质填充；
  - **同网段极速裂变衍生**：UDP 精筛不再依赖漫灌盲测，只需从 TCP 结果中捕获 1~2 个响应正常的目标网段火种，即可在同 /24 (IPv4) 或 /64 (IPv6) 内毫秒级衍生出同机房相邻 IP 并行探针，快速补齐满额 UDP 池；
  - 若当地环境完全阻断 UDP 443，绝不降级伪造假节点，而是保持真实状态等待自愈重扫，杜绝静默黑洞。
- **双轨协同自愈机制（Coordinated Dual-Pool Self-Healing）**：
  - **统一自愈引擎**：无论 TCP 池见底还是 UDP 池见底（TCP 存活低于 60%、UDP 存活低于 25% 或顺位消耗达 70%），互斥锁保障仅触发一次双轨原地测活与增量补充；
  - **存活火种合并**：提取两池尚存活的 IP 与全新扫描结果统一重排，精准截取前 `ipnum` 补充 TCP 池与 UDP 池，原地测活并发量减半，自愈恢复收敛速度提升近一倍；双缓存文件（`direct-cache-v4.txt` 与 `direct-cache-v4-udp.txt`）同步沉淀持久化。
- **多行原子树状日志系统（绝对防并发撕裂打断）**：
  - **视觉锚点左前置与差异化配色**：所有双轨日志左置 `[TCP/H2]`（高亮青色）与 `[UDP/H3]`（高亮洋红），层次分明；
  - **原子树状启动与自愈汇报**：快速启动命中缓存与后台自愈完成采用树状结构输出：
    ```text
    2026/11/16 03:07:47 [INFO] [IPv6直连优选] 命中双轨候选缓存快速启动:
    2026/11/16 03:07:47 [INFO]   ├─ [TCP/H2] 最优 IP: 2a06:98c1:... (延迟 88 ms, 候选 20 个)
    2026/11/16 03:07:47 [INFO]   └─ [UDP/H3] 最优 IP: 2606:4700:... (延迟 78 ms, 候选 20 个)
    ```
  - **杜绝并发穿插打断**：底层 `vlog_line` 支持多行原子构建，整棵树在单一系统调用与互斥保护下输出；表格打印同样受锁保护并统一步调，杜绝被并发日志打碎。
- **IPv6 /48 智能切分与完全展开格式**：支持通过 `-v6-split`（默认 `/54`，即每个 `/48` 细分为 64 个子网切片）为庞大的 IPv6 地址块生成约 4 万个离散候选样本，大幅提升命中极速机房（如香港 HKG 80ms）的概率；生成的 IPv6 地址全部统一展开为 8 段完整 16 进制形式，杜绝 `::` 缩写歧义。
- **渐进式三级健康检查**（FULL → MEDIUM → LIGHT）：新节点 FULL 探测建立基线，连续成功即逐级降级，任意失败立即升级至 FULL，以最小开销保障候选池质量。
- **初筛 HTTP 200 深度状态校验**：延迟初筛后对可通 IP 执行完整的 HTTP 响应码（默认 200）验证，根除 Cloudflare IPv6 Anycast 伪通及 Error 1034（Edge IP Restricted）限制节点。
- **单端口同时承接 TLS 与非 TLS / HTTP 流量**：客户端只需连接一个本地端口，程序根据首字节（`0x16`）自动分流到 443 或 80 目标端口。
- **灵活的数据中心筛选与反选**：支持正选白名单，支持 `-HKG`、`^HKG`、`!HKG` 排除语法，并提供专用的 `-exclude-colo` 参数。
- **CIDR 惰性展开**：只存 CIDR 范围，按需计算 IP，KB 级内存即可处理百万级 IP 段。

---

## 🤝 Xray XMUX 协同机制说明

作为 Xray / Sing-box 等出站工具的前置中继，cfnat 与 Xray 的 **XMUX（H2/H3 多路复用控制器）** 特性完美互补：

| 维度 | Xray (应用层客户端) | cfnat (L4 传输层中继) |
| :--- | :--- | :--- |
| **定位分工** | 负责流控制、多路复用（将 16~32 个用户请求合并进 1 条连接）、消除流特征 | 负责全球 Anycast 路由优选、毫秒级测速、四层零拷贝中继、死节点故障自愈 |
| **TCP/H2 协同** | 开启 XMUX 避免频繁的三次握手与 TLS 协商 | 注入 `TCP_NODELAY` + 45s `TCP_KEEPIDLE`，消除 Nagle 粘滞，秒级清理静默断开的死连接 |
| **UDP/H3 协同** | 依赖 QUIC 在单个 UDP 端口上传输海量 H3 数据包 | 内置单级 MRU 热点缓存，会话查找降至 $O(1)$，消灭大吞吐时的链表遍历与 CPU 瓶颈 |
| **节点切换行为** | 依靠 `cMaxReuseTimes` / `hMaxReusableSecs` 定期温和轮换主连接 | **平滑收敛（Graceful Drain）**：切换 IP 时仅将新连接导向新 IP，绝不 RST 现有连接，保障已有 multiplexed 流传输完毕 |

> **提示**：无需（也不应）在 cfnat 中二次实现应用层复用。端到端保持 TLS 密文透明穿透，配合 Xray XMUX 既消除了特征，又享受到了最极致的物理链路延迟。

---

## 快速开始与编译

### 1. 本地编译 (C23 标准)

推荐使用 Zig (`zig cc`) 或现代 Clang 17+ / GCC 14+ 进行编译：

**Linux（musl 纯静态独立版，推荐任意 Linux 发行版及 OpenWrt）**：
```bash
zig cc -target x86_64-linux-musl -O2 -pipe -std=c23 \
  -Wall -Wextra -Wno-unused-parameter \
  ./cfnat.c -o ./cfnat-linux-amd64 -pthread -static -s
```

**Linux ARM64（musl 纯静态独立版，适用于 OpenWrt / 树莓派 / ARM VPS）**：
```bash
zig cc -target aarch64-linux-musl -O2 -pipe -std=c23 \
  -Wall -Wextra -Wno-unused-parameter \
  ./cfnat.c -o ./cfnat-linux-arm64 -pthread -static -s
```

**Windows 11（Zig 交叉编译）**：
```bash
zig cc -target x86_64-windows-gnu -O2 -pipe -std=c23 -D_WIN32_WINNT=0x0A00 \
  -finput-charset=UTF-8 -fexec-charset=UTF-8 \
  -Wall -Wextra -Wno-unused-parameter \
  ./cfnat.c -o ./cfnat-windows-amd64.exe -lws2_32 -ldnsapi -lwininet -static -s
```

### 2. 启动示例

```bash
# 启动直连优选监听
./cfnat -direct-listen=0.0.0.0:40000 -colo=HKG,SJC -delay=150

# 客户端统一连接
服务器IP:40000  (TLS 流量自动去 443，非 TLS 去 80)
```

---

## Android Termux 运行指南

1. **获取二进制**：从 GitHub Release 下载 `cfnat-android-arm64`（绝大多数现代手机为 ARM64 架构）。
2. **放入 Termux 私有目录执行**：
   ```bash
   cd ~
   chmod +x cfnat-android-arm64
   # 非 root 环境监听端口需大于 1024
   ./cfnat-android-arm64 -direct-listen=127.0.0.1:40000 -colo=HKG
   ```
3. **后台保活（防止手机锁屏杀进程）**：
   - 在 Termux 中执行 `termux-wake-lock`（获取 CPU 唤醒锁）；
   - 在手机系统设置中将 Termux 的省电策略设为 **“无限制 / 允许后台高耗电”**。

---

## 🛠 Systemd 生产服务部署指南

对于 Linux / Armbian / VPS 环境，推荐配置为 systemd 常驻守护服务。

新建 `/etc/systemd/system/cfnat.service`：
```ini
[Unit]
Description=Cloudflare Anycast IP Optimizer and Dual-Stack Proxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/etc/cf
ExecStartPre=/bin/sh -c 'unset http_proxy https_proxy'
ExecStart=/root/etc/cf/cfnat -baidu-listen=0.0.0.0:5443 -v4-listen=0.0.0.0:4443 -v6-listen=0.0.0.0:6443 -v6-code=200 -task=400 -num=3 -ipnum=20
Restart=always
RestartSec=10

# 关键配置：在高并发扫描（-task=400）时解除 cgroups 默认线程与描述符限制
TasksMax=infinity
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

生效并运行：
```bash
systemctl daemon-reload
systemctl enable --now cfnat
journalctl --output cat -f -u cfnat
```

---

## 运行参数

### 1. 监听模式参数

| 参数 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `-cli` / `-scan-only` | 显式开启 **单次 CLI 测速模式**。仅执行一次测速、在终端打印美化彩色候选 IP 表格并保存缓存文件后立即退出，绝不启动常驻转发监听服务。 | 留空不开启 (默认按监听参数启动常驻转发) |
| `-v4-listen[=addr]` | 开启 IPv4 转发本地监听（不带参数时默认 `0.0.0.0:4443`；若全部未指定，则默认开启此项） | 缺省未显式指定时默认 `0.0.0.0:4443` |
| `-v6-listen[=addr]` | 开启 IPv6 转发本地监听（不带参数时默认 `0.0.0.0:6443`） | 留空不开启 |
| `-baidu-listen[=addr]` | 开启百度前置优选本地监听（不带参数时默认 `0.0.0.0:5444`） | 留空不开启 |
| `-direct-listen[=addr]` | 兼容旧版参数：按 `-ips` 指定类型开启直连监听 | 留空不开启 |

> [!TIP]
> - 支持同时指定任意多个监听参数（例如 `-v4-listen -v6-listen`），即可**单进程同时开启 IPv4 与 IPv6 双转发**。
> - 若 `-v4-listen`、`-v6-listen`、`-baidu-listen`、`-direct-listen` 均未指定且未指定 `-cli` / `-scan-only`，程序默认自动开启 IPv4 转发监听 `0.0.0.0:4443`。

### 2. 通用参数与协议级前缀参数

所有常规参数均支持**全局通用**与**分流独立配置**：
- **不带前缀的参数**（如 `-delay=200`、`-task=300`、`-port=443`）作为基准默认配置，自动被所有实例继承；
- **带有 `-v4-` 或 `-v6-` 前缀的参数**（如 `-v6-code=200`、`-v4-delay=150`）仅对对应实例生效，享有最高优先级覆盖基准。

| 参数（通用 / v4专属 / v6专属） | 说明 | 默认值 |
| :--- | :--- | :--- |
| `-ips` | 全局指定 IP 类型：`4` (IPv4) 或 `6` (IPv6) | `4` |
| `-colo` / `-v4-colo` / `-v6-colo` | 匹配特定数据中心，支持反选 (前缀 `-` / `^` / `!`)，如 `HKG,SJC` 或 `-HKG,-SJC` | 留空全部匹配 |
| `-exclude-colo` / `-v4-exclude-colo` / `-v6-exclude-colo` | 显式排除的数据中心列表，如 `HKG,SJC`（支持与 `-colo` 自动合并） | 留空不排除 |
| `-domain` / `-v4-domain` / `-v6-domain` | 探测目标路径与 Host（用于状态码检测） | `cloudflaremirrors.com/debian` |
| `-code` / `-v4-code` / `-v6-code` | 期望的有效 HTTP 状态响应码。<br>**缺省/为 0 时：仅测连通性与延迟，跳过 HTTP 响应码检验（极大提速）；**<br>**显式指定（如 `-code=200` 或 `-v6-code=200`）时：测得延迟后进一步校验 HTTP 状态码（杜绝 IPv6 Error 1034 限制）。** | `0` (仅测连通性) |
| `-delay` / `-v4-delay` / `-v6-delay` | 有效延迟上限（毫秒） | `300` |
| `-task` / `-v4-task` / `-v6-task` | 扫描并发线程数 | `200` |
| `-ipnum` / `-v4-ipnum` / `-v6-ipnum` | 保留的最优候选 IP 数量上限（Top-N 截断）。同时作为后台实例 70% 消耗拦截与 25% 存活门槛的水位基准。 | `20` |
| `-num` / `-v4-num` / `-v6-num` | 单 IP 探测尝试次数（首包不通直接熔断，仅连通节点发满测定丢包与抖动） | `5` |
| `-port` / `-v4-port` / `-v6-port` | 上游 TLS 转发目标端口（注意区分本地监听与目标端口） | `443` |
| `-http-port` / `-v4-http-port` / `-v6-http-port` | 上游非 TLS 转发目标端口 | `80` |
| `-random` / `-v4-random` / `-v6-random` | 是否按 CIDR 随机抽样生成候选 IP | `true` |
| `-v6-split` | IPv6 /48 子网切分前缀掩码（有效范围 `48` ~ `64`）。<br>**默认 54：将每个 /48 切分为 64 个 /54 子网并在每个子网中随机抽样 1 个候选**（600+ 行衍生约 4 万个离散候选，大幅增强路由与机房多样性）；<br>若设为 `48` 则每个 /48 仅抽样 1 个。生成的 IPv6 统一展开为标准的 8 段无缩写形式。 | `54` (每个 /48 切分抽样 64 个) |
| `-baidu-resolver` | 针对 Fake-IP 的百度解析方式: `auto` / `udp://` / `doh://` | `auto` |
| `-bind-if` | 绑定出站物理网卡 (如 `eth0`、`en0`) | 留空使用默认路由 |
| `-health-log` | 定时输出健康检查日志的间隔秒数（仅在 `-log=debug` 时输出成功汇报，普通模式仅告警失败） | `60` |
| `-log` / `-log-level` | 日志级别：`silent` / `error` / `warn` / `info` / `debug`。<br>**`info`（默认）**：日常转发与周期健康检查完全静默，仅输出关键里程碑（启动树状日志、自愈树状日志、故障切换等），彻底杜绝连接建立/断开刷屏；终端下支持单行原地刷新扫描进度；<br>**`debug`**：开启全量调试模式，实时输出扫描发现的每个有效 IP 及位置信息、详细百分比进度、无论命中缓存还是新扫描均完整打印候选 IP 表格，支持全局 ANSI 语法高亮。 | `info` |

---

## 常用示例

### 1. 经典双栈双转发（单进程同时监听 IPv4 与 IPv6）
```bash
# 同时开启 IPv4（本地 4443）与 IPv6（本地 6443），IPv6 指定检测 HTTP 200 排除 1034，IPv4 追求极速仅测延迟
./cfnat -v4-listen -v6-listen -v6-code=200 -task=300 -exclude-colo=HKG
```

### 2. 自定义本地监听地址与目标端口
```bash
# IPv4 监听 127.0.0.1:1080，IPv6 监听 0.0.0.0:2080，上游 TLS 端口为 8443
./cfnat -v4-listen=127.0.0.1:1080 -v6-listen=2080 -port=8443
```

### 3. 仅测速扫描（CLI 单次测速模式，不监听端口）
```bash
# 执行单次测速，打印美化彩色候选表格并保存缓存后直接退出
./cfnat -cli -colo=HKG -delay=150 -ipnum=10
```

### 4. 排除特定数据中心（反选模式，如排除 HKG）
```bash
./cfnat -v6-listen -exclude-colo=HKG,SJC
```

### 5. 配合 Xray / Sing-box 出站优选（单端口 H2 + H3 全透明支持）
```bash
# 本地监听 127.0.0.1:4443，自动开启 TCP/H2 与 UDP/H3 双轨测优
./cfnat -v4-listen=127.0.0.1:4443 -colo=HKG,SJC -delay=200 -task=300
```
客户端配置：
- **服务器地址 (Address)**: `127.0.0.1`
- **端口 (Port)**: `4443`
- **协议说明**：客户端连接 `127.0.0.1:4443`。cfnat 自动在底层将 TCP 流量导入 TCP 优选节点，将 UDP/QUIC 流量导入 H3 优选节点。

---

## 构建与 GitHub Actions 发布

工作流文件位于 `.github/workflows/build.yml`：
- **自动构建产物（全部为纯静态或原生免外部依赖二进制）**：
  - `cfnat-linux-amd64` (Linux x86_64 musl 纯静态版)
  - `cfnat-linux-arm64` (Linux aarch64 musl 纯静态版)
  - `cfnat-android-arm64` / `cfnat-android-amd64` (Android NDK Termux 原生版)
  - `cfnat-windows-amd64.exe` / `cfnat-windows-arm64.exe` (Win11 纯静态版)
- **触发与发布方式**：
  - **推送 Tag 发布**：推送形如 `v0.0.18` 的标签时自动触发编译并发布到 Release。
  - **手动网页触发发布**：在 GitHub Actions 页面点击 **Run workflow**，支持输入版本号或自动从 `cfnat.c` 提取版本号，支持重复发布时强制覆盖更新 Release 资源。

---

## 资源占用说明

C 版的核心价值是降低常驻资源占用。相较于 Go 版，C 版没有 Go 运行时、GC 和 goroutine 调度器的额外常驻成本：
- 双向转发缓冲区固定为 `16 KB`，降低常驻内存。
- 线程虚拟栈采用按需分页（Demand Paging），每个并发线程物理内存仅 ~8~12 KB。
- UDP MRU 会话查找仅增加 8 字节指针开销，消除 $O(N)$ 循环遍历。
- 候选结果只保留必要字段，CIDR 惰性展开，KB 级内存即可处理百万级 IP 段。
- 连接级 IP 选择缓存（cache_valid）结合原子原语，避免连接建立时的高频加锁与健康检查。
- I/O 轮询基于轻量级 `cfnat_poll_single` 与批量 `poll` / `WSAPoll`，无多余事件循环对象分配与文件描述符占用，兼顾极简与并发效率。

---

## 常见问题

### 1. 为什么扫描统计里显示“连接失败”数万次，但输入文件只有几百或几千行？
这是两个机制协同作用的正常结果：
1. **探测重试与失败累加**：启动参数 `-num` 代表单个 IP 的最大探测次数。虽然未连通的死 IP 已经由首包握手熔断机制大幅规避了后续无效重试，但对于偶发丢包或超时节点，多次探测失败会进行人次累加；
2. **IPv6 的 `/48` 子网切分算法（`-v6-split=54`）**：`ips-v6.txt` 中每一行都是 `/48` 大段，每个大段包含 $2^{80}$ 个地址。代码默认将每个 `/48` 切分为 64 个 `/54` 子网各抽样 1 个 IP（633 行衍生出 40,512 个候选 IP）。因此实际扫描池规模在 4 万个以上，正是这种广泛的离散样本才使得在 16 秒内筛出 79ms 香港极速节点成为可能。

### 2. 为什么只监听一个端口，却能同时处理 TLS 和 HTTP？
程序读取客户端连接的首字节：首字节为 `0x16` 时判定为 TLS 握手，自动转发到 `-port`（443）；其他数据判定为 HTTP/非 TLS，自动转发到 `-http-port`（80）。

### 3. IP 发生故障切换时，会导致客户端断流或网络卡顿吗？
不会。cfnat 采用 **平滑收敛（Graceful Drain）** 机制：
1. 顺位切换时，仅原子切换全局指向的 `current_ip`（供新进连接使用）；
2. 绝不主动对现有活跃连接发送硬 RST/Close，客户端复用的长连接会继续安全传输直至完成。

### 4. 为什么需要将 H2 与 H3 独立测优并在同一端口分别转发？
国内部分宽带运营商对境外 UDP 443 存在 QoS 严重限速甚至丢包策略。传统的测优工具只测 TCP，选出的最优 IP 往往在 TCP 下延迟极低，但 UDP 443 根本无法握手。cfnat 自动在底层将 TCP 流量导入 TCP 优选节点，将 UDP/QUIC 流量导入 H3 优选节点，真正做到了“一个配置端口，TCP 极速低延迟，UDP 稳通不断流”。

---

## 免责声明

本工具仅用于网络测试与学习用途。请在合法、合规的网络环境下使用，使用者自行承担因配置或使用造成的后果。
