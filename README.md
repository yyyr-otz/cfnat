# cfnat C 版 (C23 纯静态现代平台版)

面向全平台与高性能转发场景的 **Cloudflare IP 扫描 + 单端口 TCP/UDP (H2/H3) 双轨透明转发** 工具。

本项目采用 **C23 国际标准 (ISO/IEC 9899:2024)** 进行现代化构建，针对 **Linux、Windows 11 及 Android Termux 现代平台（amd64 / arm64）** 生成**纯静态（Pure Static）独立二进制**，彻底剥离 glibc 依赖，根除跨发行版兼容性问题。同时全面集成了 **HTTP/2 (TCP) 与 HTTP/3 (QUIC/UDP) 双轨独立测优、四层高 BDP 缓冲区架构、Xray XMUX 与分片深度协同优化、首包快速熔断以及原子树状防打断日志系统**。

核心目标是完整提供扫描、优选、三栈（IPv4 / IPv6 / 百度前置）H2/H3 同端口转发、渐进式健康检查与双轨自愈能力，同时兼顾极致的单流大吞吐与低 CPU 系统调用开销，适用于 OpenWrt/软路由、手机 Termux、VPS 以及 Windows 11 设备。

## 现代平台优化与支持说明

### 1. 四层高吞吐缓冲区与跨平台 I/O 引擎优化

| 缓冲区层级 | 适用平台 | 容量配置 | 核心性能收益 |
| :--- | :--- | :--- | :--- |
| **TCP 内核套接字缓冲 (`SO_RCVBUF` / `SO_SNDBUF`)** | Windows / Linux / Android | `2 MB`（自适应回退 `1 MB` / `512 KB`） | 解除高 RTT（80~200ms）跨境链路的带宽时延积（BDP）窗口瓶颈，单流吞吐上限较 256KB 窗口提升 8 倍 |
| **UDP 内核套接字缓冲 (`SO_RCVBUF` / `SO_SNDBUF`)** | Windows / Linux / Android | `4 MB`（自适应回退 `2 MB` / `1 MB`） | 吸收 QUIC/H3 多路复用高并发突发流量，杜绝内核接收队列溢出导致的静默丢包 |
| **用户态 TCP 转发缓冲 (`COPY_BUF_SIZE`)** | Windows / Android（及 Linux 回退） | `128 KB`（虚拟线程栈 `512 KB`） | 单次 `recv`/`send` 可吞吐 8 个满载 16KB TLS 记录帧，系统调用次数减少 87.5%，且完美常驻 CPU 核心 L2 Cache |
| **Linux 零拷贝管道 (`F_SETPIPE_SZ` + `splice`)** | Linux (`amd64` / `arm64`) | `256 KB`（回退 `128 KB` / `64 KB`） | 单次 `splice` 零拷贝系统调用可转移 64 个内核页面引用，长流大吞吐系统调用开销降低 75% |
| **UDP/H3 批量收发队列 (`UDP_BATCH_SZ` + `recvmmsg`)** | 无 Root Android / Linux | 上下行双向 `32` 包（`64 KB`） | 上行（Xray $\to$ cfnat）与下行（Cloudflare $\to$ cfnat）双向启用 `recvmmsg`，单次系统调用即可吞吐整轮 QUIC 拥塞窗口突发 |

### 2. 核心性能与传输层优化

- **首包 `MSG_PEEK` 免缓冲直通（保留 Xray `finalmask` 分片特征 & 消除建连阻塞）**：
  - `connection_thread` 仅通过 1 字节 `MSG_PEEK` 嗅探识别 TLS（`0x16`）或明文 HTTP 以分流目标端口（`443` / `80`），绝不在用户态消费或重组 TLS ClientHello；
  - 彻底消除等待 Xray `finalmask`（`tlshello` 分片）收齐的 150~200ms 串行阻塞与 4KB 线程栈缓冲，完整保留客户端抗审查分片特征；在 Linux 下首包直接走 `splice` 内核零拷贝，在 Windows 与 Android 下直接走 `128 KB` 大缓冲直通转发。
- **双向转发线程合并减负（每连接线程数与虚拟内存立降 33%）**：
  - `relay_bidirectional()` 废除创建 2 个子转发线程的传统模式；当前连接处理线程 `connection_thread` 直接就地接管反向转发（`u -> c`），仅派生 1 个子线程负责正向转发（`c -> u`）；
  - 每条连接由 3 个线程压减至 2 个线程，降低 33% 的线程创建、销毁与上下文切换开销。
- **预解析二进制地址缓存（`sockaddr_storage` 热路径零解析）**：
  - 在 `Result`、`CandidatePool`、`ConnCtx`、`UdpSession` 及 `BaiduProxyNode` 中全量内置二进制网络地址 `struct sockaddr_storage` 与长度；
  - 候选节点与百度代理节点入池时即刻完成 `inet_pton` 解析，后续高并发建立 TCP 连接、百度 `CONNECT` 拨号与 UDP 会话时全面走二进制地址直连，消除热路径上重复字符串解析与转换的 CPU 开销。
- **UDP/H3 会话 $O(1)$ MRU 热点缓存与 `udp_dirty` 增量 `pollfd` 缓存**：
  - 针对 QUIC/H3 多路复用流量高度集中于单个客户端源端口的特征，引入单级 MRU 指针缓存，客户端连续发包时 $O(1)$ 瞬间命中（命中率 >95%）；
  - 引入 `udp_dirty` 会话表变更标记：当会话未发生增删或重连时，`carrier_udp_thread` 直接复用 `poll` / `WSAPoll` 描述符数组，免除每轮唤醒的链表遍历与互斥锁加解锁；且仅在会话首包下行（`bytes_down == 0`）时重置 `fast_fail_count`，消除逐包原子写引发的缓存行争抢。
- **Linux 与无 Root Android 上下行双向 `recvmmsg` 批量收包**：
  - 在 Linux musl 与 Android Bionic（seccomp 标准白名单系统调用）下，UDP 监听端与上游接收端全面启用 `recvmmsg()`，单次系统调用可批量收取最多 32 个 QUIC 数据报，使 H3 高频突发流量下的内核态切换开销降低最高 90%。
- **vDSO 单调时钟 `clock_gettime(CLOCK_MONOTONIC)` 与冗余系统调用去重**：
  - Linux 与 Android 采用 `CLOCK_MONOTONIC` 替代 `gettimeofday()`，通过内核 vDSO 页在用户态直接读取（约 3ns，零内核陷入），并与 Windows 的 `GetTickCount64()` 一样具备严格单调递增特性，彻底杜绝 NTP / 基站校时导致测速 RTT 异常或会话误超时；
  - 剔除每条 TCP 连接在 `accept`/`connect` 与 `connection_thread` 之间重复执行的 4 次 `setsockopt` 调用；连接正常关闭时通过 `fast_fail_count == 0` 原子无锁短路返回，99.9% 的正常连接关闭无需争抢候选池互斥锁。
- **Linux 零拷贝栈保护（`pipe_worker_fallback` 强隔离 `noinline`）**：
  - 将 Linux `splice` 失败时的用户态回退拷贝函数显式标记为 `noinline`（`__attribute__((noinline))` / `__declspec(noinline)`）；
  - 杜绝编译器自动将 `128 KB` 回退缓冲区内联进主工作线程栈帧，保证走内核级零拷贝通道的线程栈干净轻巧。
- **扫描架构轻量化（彻底释放 400 个内核描述符，静态失效单轮熔断）**：
  - 采用单套接字自适应超时 `recv_headers` 与 `cfnat_poll_single` 轮询，消灭 400 个并发线程持有的额外 `epoll`/`kqueue` 句柄；
  - 静态特征即刻熔断：遇到机房不匹配（`colo_skip`）、缺少 `CF-RAY`（`cfray_miss`）或状态码不符（`http_code_mismatch`）时立即终止后续轮次，且首轮延迟严重超标时直接早剪枝，搭配 C23 `thread_local` 无锁 **SplitMix64** 随机数生成器大幅提升扫描速度。
- **QUIC 批量并发探测异常消费与特征校验**：
  - 接入 `POLLERR` 并捕获消费 `recvfrom` 返回的 ICMP 异步错误及 Windows `WSAECONNRESET`，修复非阻塞探测套接字遭遇不可达错误时陷入 CPU 空转的隐患；
  - 严格校验 QUIC 报文首字节长包头标志 `(resp[0] & 0x80) != 0`，过滤网络杂包与伪造报文。
- **零堆分配 CIDR 惰性遍历与 128 KB 块级内存池**：
  - 在 `-random=false` 顺序模式下启用 `CidrList` 二分定位前缀和流式生成 IP，内存开销降至 $O(1)$ 常数级；
  - `StringList` 采用 128 KB 连续内存池分块分配（Arena Chunk Allocation），`load_ip_list` 载入 IPv6 时单次预分配 40960 项指针容量，消灭数万次碎片化 `malloc`/`free`。
- **全链路禁用 Nagle 算法（`TCP_NODELAY`）与 Windows 回环加速（`SIO_LOOPBACK_FAST_PATH`）**：
  - 在接入客户端连接及拨号上游连接时全面注入 `TCP_NODELAY`，消除 40ms 交互粘滞延迟；Windows 平台自动启用 `SIO_LOOPBACK_FAST_PATH`，免除本地 Xray 与 `cfnat` 间通信经过完整 TCP/IP 协议栈的开销。
- **TCP Keep-Alive 微参数深度对齐（45s 保活，根除僵尸连接）**：
  - 针对 Xray / Chrome 等主流客户端 H2 空闲保活周期（45 秒），显式配置操作系统内核保活参数：`TCP_KEEPIDLE = 45s`、`TCP_KEEPINTVL = 10s`、`TCP_KEEPCNT = 3`（Windows 平台通过 `SIO_KEEPALIVE_VALS` 同步对齐），将静默死连接回收时间从默认 2 小时缩减至 75 秒。
- **UDP 套接字异常与黑洞即时驱逐自愈引擎**：
  - 接入 `POLLERR | POLLHUP` 事件主动回收，上游遭遇 ICMP 端口/主机不可达时立即关闭失效套接字并触发顺位切换；
  - 独立于空闲超时的快速黑洞感知：连接建立 $\ge$ 5 秒且已发包 $\ge$ 1200 字节但回包为零时，在 5 秒内即时识别并驱逐黑洞会话。
- **TCP 连接跨候选池顺位轮换（杜绝单死 IP 原地死磕）**：
  - 连接建立阶段采用顺位梯队拨号：首轮拨号失败时不原地重复重试相同 IP，而是直接顺位尝试候选池中的备用最优节点（`try_idx = (current_index + i) % len`），备用节点握手成功时实时无缝提升为主节点。
- **双向吞吐感知的节点淘汰与 RCU 风格无缝指针替换**：
  - 基于真实数据吞吐感知（`bytes > 0`）判定连接成功，保护 DoH 与短 API 请求所使用的低延迟优质节点不被误杀；
  - 在双轨自愈与全局补充扫描中采用临界区内指针切换、临界区外延迟释放与脱锁落盘策略，确保并发转发面零阻塞。

### 3. 目标平台支持矩阵（纯静态架构）

构建产物全面采用**纯静态（Pure Static）独立二进制**或原生免外部依赖二进制，开箱即用：
- **Linux amd64 (x86_64)**：musl 纯静态独立二进制（`cfnat-linux-amd64`），仅需 Linux 3.10+ 内核，无视发行版差异（Ubuntu / Debian / Alpine / CentOS / OpenWrt / Arch 均可直接运行）
- **Linux arm64 (aarch64)**：musl 纯静态独立二进制（`cfnat-linux-arm64`），适配各类 ARM VPS、树莓派及 OpenWrt 软路由
- **Android Termux (arm64 & amd64)**：Android NDK 编译（`cfnat-android-arm64` / `cfnat-android-amd64`），适配 Bionic libc 与 Android 沙箱 seccomp 审计，Termux 免 root 开箱即用
- **Windows 11 amd64 (x86_64)**：Win11 原生纯静态可执行文件（`cfnat-windows-amd64.exe`）
- **Windows 11 arm64 (aarch64)**：Surface / 骁龙 X Elite / ARM 笔记本原生运行（`cfnat-windows-arm64.exe`）

## 项目定位与转发链路

cfnat C 版做四件事：
1. **智能扫描与子网裂变优选**：扫描 Cloudflare IP，初筛精准 TCP (H2) 候选池，并结合同网段裂变衍生引擎精筛出 UDP (H3) 专用候选池。
2. **三栈同端口 TCP/UDP 双轨并发监听**：在 IPv4（`-v4-listen`）、IPv6（`-v6-listen`）与百度前置（`-baidu-listen`）各监听端口上同时监听 TCP 与 UDP 数据报，保持三栈 H2/H3 行为完全一致。
3. **精准双轨独立路由转发**：
   - TCP 连接（H2/TLS）转发至当前 **TCP 优选 IP**（支持自动通过首字节 `0x16` `MSG_PEEK` 分流 443 或 80 端口）；
   - UDP 报文（H3/QUIC）转发至当前 **UDP 优选 IP:443**，会话状态自动管理。
4. **双轨协同自愈与热替换**：任一候选池见底时，自动触发一次性双轨原地测活与增量补齐，绝不阻塞断网。

它只做纯粹的高性能传输层透明字节/报文转发，不是 HTTP 反向代理，也不会解密或篡改任何业务数据。

```text
               ┌── [TCP: H2/TLS] ────→  cfnat 本地 TCP 端口  ────→  TCP 优选 IP:443
               │
客户端单端口接入
 (4443 / 5443 / 6443)
               │
               └── [UDP: H3/QUIC] ───→  cfnat 本地 UDP 端口  ────→  UDP 优选 IP:443
```

## 核心特性

- **全面遵循 C23 现代语言标准与零开销契约**：
  - 核心源码遵循 ISO/IEC 9899:2024 (C23) 标准规范，引入 `nullptr` 类型安全空指针、`constexpr` 编译期常量、`thread_local` 线程局部存储及数字分隔符（同时内置 C11/C17 兼容回退层）；
  - 采用 C23 标称类型枚举（`enum : uint8_t`），压缩枚举变量的内存占用并改善 CPU 缓存命中率；
  - 注入 `[[nodiscard]]` 函数契约属性，严格杜绝关键资源、套接字与健康探测返回值被疏漏丢弃的隐患。
- **死 IP 首包握手熔断机制（扫描提速 60%+）**：
  - 扫描引擎在首轮 TCP 握手（`attempt == 0`）超时或失败时立即跳出判定死节点，避免对不可达节点执行后续轮次盲目重试等待；
  - 6500+ IPv4 候选 IP 扫描耗时锐减至 **20~30 秒**左右，统计数字与死 IP 数量精准 1:1 对齐。
- **H2 (TCP) + H3 (QUIC/UDP) 双轨独立测优与三栈透明分流**：
  - **痛点解决**：国内部分 ISP 对境外 UDP 443 存在 QoS 限制甚至黑洞，很多 TCP 延迟极佳的 IP 无法传输 QUIC；传统的“单优选 IP”会导致 H3 频繁断流或连不上。
  - **独立路由与三栈统一**：在 `-v4-listen`、`-v6-listen` 与 `-baidu-listen` 监听端口上，TCP 流量自动导向 TCP 优选池，UDP/QUIC 流量自动导向 UDP 优选池；Xray 在三栈端口间切换时无需修改 H2/H3（`alpn`）配置。
- **RFC 9000 规范的 1200 字节轻量 QUIC 版本协商探针（Version Negotiation Probe）**：
  - 发送带有保留版本号 `0x5A5A5A5A` 的 1200 字节 QUIC Initial 数据包，触发 Cloudflare 边缘节点立即回复 27 字节的 Version Negotiation 报文；
  - **零加密算法库开销**（保持纯单文件 C 极致轻量），**零 CPU 密钥计算消耗**，单包即可精确测得 UDP 443 真实往返 RTT，且符合 RFC 9000 防放大攻击要求。
- **网段裂变衍生与精准定额优选（Subnet Expansion & Fission Engine）**：
  - **告别粗放过采样**：扫描阶段严格按照用户 `-ipnum` 精准采集最优前 N 个节点，初次启动扫描耗时降低 30%~50%；
  - **同网段极速裂变衍生**：只需从 TCP 结果中捕获 1~2 个响应正常的目标网段火种，即可在同 `/24` (IPv4) 或 `/64` (IPv6) 内毫秒级衍生出同机房相邻 IP 并行探针，快速补齐满额 UDP 池；若当地网络完全阻断 UDP 443，绝不伪造假节点降级，保持真实状态等待自愈重扫。
- **双轨协同自愈机制（Coordinated Dual-Pool Self-Healing）**：
  - **统一自愈引擎**：无论 TCP 池见底还是 UDP 池见底（TCP 存活低于 60%、UDP 存活低于 25% 或顺位消耗达 70%），互斥锁保障仅触发一次双轨原地测活与增量补充；
  - **存活火种合并**：提取两池尚存活的 IP 与全新扫描结果统一重排，精准截取前 `ipnum` 补充 TCP 池与 UDP 池，双缓存文件（如 `direct-cache-v4.txt` 与 `direct-cache-v4-udp.txt`）同步沉淀持久化。
- **多行原子树状日志系统（防并发撕裂打断）**：
  - **视觉锚点左前置与差异化配色**：所有双轨日志左置 `[TCP/H2]`（高亮青色）与 `[UDP/H3]`（高亮洋红），层次分明；
  - **原子树状启动与自愈汇报**：快速启动命中缓存与后台自愈完成采用树状结构在单一系统调用与互斥保护下原子输出：
    ```text
    2026/11/16 03:07:47 [INFO] [IPv6直连优选] 命中双轨候选缓存快速启动:
    2026/11/16 03:07:47 [INFO]   ├─ [TCP/H2] 最优 IP: 2a06:98c1:... (延迟 88 ms, 候选 20 个)
    2026/11/16 03:07:47 [INFO]   └─ [UDP/H3] 最优 IP: 2606:4700:... (延迟 78 ms, 候选 20 个)
    ```
- **IPv6 `/48` 智能切分与完全展开格式**：支持通过 `-v6-split`（默认 `/54`，即每个 `/48` 细分为 64 个子网切片）为 IPv6 地址块生成约 4 万个离散候选样本；生成的 IPv6 地址统一展开为 8 段完整 16 进制形式，杜绝 `::` 缩写歧义。
- **渐进式三级健康检查**（FULL → MEDIUM → LIGHT）：新节点 FULL 探测建立基线，连续成功即逐级降级，任意失败立即升级至 FULL，以最小开销保障候选池质量。
- **初筛 HTTP 状态校验**：支持通过 `-code` / `-v6-code` 对可通 IP 执行完整的 HTTP 响应码（如 200）验证，根除 Cloudflare IPv6 Anycast 伪通及 Error 1034（Edge IP Restricted）限制节点。

## Xray XMUX 协同机制说明

作为 Xray / Sing-box 等出站工具的前置中继，cfnat 与 Xray 的 **XMUX（H2/H3 多路复用控制器）** 及 `finalmask` 分片特性深度互补：

| 维度 | Xray (应用层客户端) | cfnat (L4 传输层中继) |
| :--- | :--- | :--- |
| **定位分工** | 负责流控制、多路复用（将 16~32 个请求合并进 1 条连接）、TLS 分片与消除流特征 | 负责全球 Anycast 路由优选、毫秒级测速、大缓冲/零拷贝中继、死节点故障自愈 |
| **TCP/H2 协同** | 开启 XMUX 与 `finalmask` 避免频繁握手并混淆特征 | 首包 `MSG_PEEK` 免重组透传分片 + `TCP_NODELAY` + 45s `TCP_KEEPIDLE` + `2 MB` 高 BDP 窗口 |
| **UDP/H3 协同** | 依赖 QUIC 在单个 UDP 端口上传输海量 H3 数据包 | 内置 MRU 热点缓存 + `udp_dirty` 描述符缓存 + `4 MB` 套接字缓冲 + 双向 32 包 `recvmmsg` |
| **节点切换行为** | 依靠 `cMaxReuseTimes` / `hMaxReusableSecs` 定期温和轮换主连接 | **平滑收敛（Graceful Drain）**：切换 IP 时仅将新连接导向新 IP，绝不 RST 现有连接，保障已有复用流传输完毕 |

> **提示**：无需（也不应）在 cfnat 中二次实现应用层复用。端到端保持 TLS 密文与分片透明穿透，配合 Xray XMUX 既消除了特征，又享受到了最低的物理链路延迟与高 BDP 吞吐。

## 快速开始与编译

### 1. 本地编译 (C23 标准)

推荐使用 Zig (`zig cc`) 或现代 Clang / GCC 进行编译：

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

**Windows 11（Zig 交叉编译，支持 amd64 与 arm64）**：
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

## Systemd 生产服务部署指南

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
> - 支持同时指定任意多个监听参数（例如 `-baidu-listen=0.0.0.0:5443 -v4-listen=0.0.0.0:4443 -v6-listen=0.0.0.0:6443`），即可**单进程同时开启三栈双轨转发**。
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
| `-v6-split` | IPv6 `/48` 子网切分前缀掩码（有效范围 `48` ~ `64`）。<br>**默认 54：将每个 `/48` 切分为 64 个 `/54` 子网并在每个子网中随机抽样 1 个候选**（600+ 行衍生约 4 万个离散候选，大幅增强路由与机房多样性）；<br>若设为 `48` 则每个 `/48` 仅抽样 1 个。生成的 IPv6 统一展开为标准的 8 段无缩写形式。 | `54` (每个 `/48` 切分抽样 64 个) |
| `-baidu-resolver` | 针对 Fake-IP 的百度解析方式: `auto` / `udp://` / `doh://` | `auto` |
| `-bind-if` | 绑定出站物理网卡 (如 `eth0`、`en0`) | 留空使用默认路由 |
| `-health-log` | 定时输出健康检查日志的间隔秒数（仅在 `-log=debug` 时输出成功汇报，普通模式仅告警失败） | `60` |
| `-log` / `-log-level` | 日志级别：`silent` / `error` / `warn` / `info` / `debug`。<br>**`info`（默认）**：日常转发与周期健康检查完全静默，仅输出关键里程碑（启动树状日志、自愈树状日志、故障切换等），彻底杜绝连接建立/断开刷屏；终端下支持单行原地刷新扫描进度；<br>**`debug`**：开启全量调试模式，实时输出扫描发现的每个有效 IP 及位置信息、详细百分比进度、无论命中缓存还是新扫描均完整打印候选 IP 表格，支持全局 ANSI 语法高亮。 | `info` |

## 常用示例

### 1. 经典双栈/三栈转发（单进程同时监听多个端口）
```bash
# 同时开启 IPv4（本地 4443）、IPv6（本地 6443）与百度前置（本地 5443），IPv6 指定检测 HTTP 200 排除 1034
./cfnat -baidu-listen=0.0.0.0:5443 -v4-listen=0.0.0.0:4443 -v6-listen=0.0.0.0:6443 -v6-code=200 -task=300 -exclude-colo=HKG
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

## 构建与 GitHub Actions 发布

工作流文件位于 `.github/workflows/build.yml`：
- **自动构建产物（全部为纯静态或原生免外部依赖二进制）**：
  - `cfnat-linux-amd64` (Linux x86_64 musl 纯静态版)
  - `cfnat-linux-arm64` (Linux aarch64 musl 纯静态版)
  - `cfnat-android-arm64` / `cfnat-android-amd64` (Android NDK Termux 原生版)
  - `cfnat-windows-amd64.exe` / `cfnat-windows-arm64.exe` (Win11 纯静态版)
- **触发与发布方式**：
  - **推送 Tag 发布**：推送形如 `v*` 的版本标签时自动触发编译并发布到 Release。
  - **手动网页触发发布**：在 GitHub Actions 页面点击 **Run workflow**，支持输入标签名称或自动从源码提取宏定义版本，支持重复发布时强制覆盖更新 Release 资源。

## 资源占用与缓冲区设计说明

C 版在消除 Go 运行时、GC 和协程调度器额外常驻成本的基础上，针对高带宽时延积（BDP）跨境转发做了分级缓冲区设计：
- **内核套接字窗口（`SO_RCVBUF` / `SO_SNDBUF`）**：TCP 优先设为 `2 MB`（回退 `1 MB` / `512 KB`），UDP 优先设为 `4 MB`（回退 `2 MB` / `1 MB`），充分跑满 100~200ms 高延迟跨境链路的单流带宽并吸收 QUIC 突发报文。
- **用户态转发缓冲（`COPY_BUF_SIZE = 128 KB`）**：在 Windows 11 与 Android Termux 上单次 `recv`/`send` 吞吐 8 个满载 16KB TLS 记录帧，同时 `128 KB` 容量严格控制在现代处理器核心 L2 Cache 热区内，避免冲刷缓存。
- **Linux 零拷贝管道（`F_SETPIPE_SZ = 256 KB`）**：单次 `splice()` 零拷贝系统调用可转移 64 个内核页面引用，且用户态回退函数通过 `noinline` 强隔离，走零拷贝通道时不占用用户态缓冲页。
- **按需分页虚拟线程栈（`512 KB`）**：扫描与转发线程虚拟栈设为 `512 KB`（动态对齐 `PTHREAD_STACK_MIN`），依托操作系统按需分页（Demand Paging）机制，未触碰的虚拟栈页不消耗物理内存（RSS）。
- **UDP/H3 批量队列与 $O(1)$ 检索**：Linux 与 Android 上下行双向启用 32 包 `recvmmsg`（`thread_local` 静态队列仅占 `64 KB`），配合 8 字节 MRU 指针缓存与 `udp_dirty` 描述符缓存，实现高吞吐下的极低系统调用开销。

## 常见问题

### 1. 为什么扫描统计里显示“连接失败”数万次，但输入文件只有几百或几千行？
这是两个机制协同作用的正常结果：
1. **探测重试与失败累加**：启动参数 `-num` 代表单个 IP 的最大探测次数。虽然未连通的死 IP 已经由首包握手熔断机制规避了后续无效重试，但对于偶发丢包或超时节点，多次探测失败会进行人次累加；
2. **IPv6 的 `/48` 子网切分算法（`-v6-split=54`）**：`ips-v6.txt` 中每一行都是 `/48` 大段，每个大段包含 $2^{80}$ 个地址。代码默认将每个 `/48` 切分为 64 个 `/54` 子网各抽样 1 个 IP（633 行衍生出 40,512 个候选 IP）。因此实际扫描池规模在 4 万个以上，正是这种广泛的离散样本才使得在短时间内筛出极速节点成为可能。

### 2. 为什么只监听一个端口，却能同时处理 TLS、HTTP 与 QUIC/H3？
在同一监听端口上，程序同时绑定了 TCP 与 UDP 套接字：TCP 流量通过 `MSG_PEEK` 窥探首字节（`0x16` 判定为 TLS 自动转发到 `-port` 443，其他判定为 HTTP 自动转发到 `-http-port` 80）；UDP 流量自动作为 QUIC/H3 数据报转发到 UDP 优选池节点的 443 端口。

### 3. IP 发生故障切换时，会导致客户端断流或网络卡顿吗？
不会。cfnat 采用 **平滑收敛（Graceful Drain）** 机制：
1. 顺位切换时，仅原子切换全局指向的 `current_ip`（供新进连接使用）；
2. 绝不主动对现有活跃连接发送硬 RST/Close，客户端复用的长连接会继续安全传输直至完成。

### 4. 为什么需要将 H2 与 H3 独立测优并在同一端口分别转发？
国内部分宽带运营商对境外 UDP 443 存在 QoS 限速甚至丢包策略。传统的测优工具只测 TCP，选出的最优 IP 往往在 TCP 下延迟极低，但 UDP 443 无法握手。cfnat 自动在底层将 TCP 流量导入 TCP 优选节点，将 UDP/QUIC 流量导入 H3 优选节点，真正做到了“一个配置端口，TCP 极速低延迟，UDP 稳通不断流”。

## 免责声明

本工具仅用于网络测试与学习用途。请在合法、合规的网络环境下使用，使用者自行承担因配置或使用造成的后果。
