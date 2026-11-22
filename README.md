# cfnat C 版 (C23 纯静态现代平台版)

面向全平台与高性能转发场景的 **Cloudflare IP 扫描 + 单端口 TCP/UDP (H2/H3) 双轨透明转发** 工具。

本项目采用 **C23 国际标准 (ISO/IEC 9899:2024)** 进行现代化构建，针对 **Linux、Windows 11 及 Android Termux 现代平台（amd64 / arm64）** 生成**纯静态（Pure Static）独立二进制**，彻底剥离 glibc 依赖，根除跨发行版兼容性问题。同时全面集成了 **HTTP/2 (TCP) 与 HTTP/3 (QUIC/UDP) 双轨独立测优、按栈协议开关、抗 QoS 节拍化 H3 探测、可选真实 QUIC v1 ClientHello 模拟、按活跃度自适应健康检查、自适应高 BDP 缓冲区架构、Xray XMUX 协同优化以及原子树状防打断日志系统**。

核心目标是完整提供扫描、优选、三栈（IPv4 / IPv6 / 百度前置）H2/H3 同端口（或单协议独立）转发、活跃态高灵敏测活与空池退避自愈能力，同时兼顾极致的单流大吞吐与低 CPU 系统调用开销，适用于 OpenWrt/软路由、手机 Termux、VPS 以及 Windows 11 设备。

## 现代平台优化与支持说明

### 1. 四层高吞吐缓冲区与跨平台 I/O 引擎优化

| 缓冲区层级 | 适用平台 | 容量配置 | 核心性能收益 |
| :--- | :--- | :--- | :--- |
| **TCP 内核套接字缓冲 (`SO_RCVBUF` / `SO_SNDBUF`)** | Windows / Linux / Android | Linux: 接收与发送交由内核 `tcp_moderate_rcvbuf` / `tcp_wmem` 动态调优 + `TCP_NOTSENT_LOWAT=64KB`；Windows: `2 MB`（自适应回退 `1 MB` / `512 KB`）+ `SIO_LOOPBACK_FAST_PATH` | 解除固定窗口对 BBR 高 BDP 跨境吞吐的钳制，兼顾极致单流大带宽、零 Bufferbloat 与低延迟本机回环 |
| **UDP 内核套接字缓冲 (`SO_RCVBUF` / `SO_SNDBUF`)** | Windows / Linux / Android | 监听 `4 MB`（回退 `2 MB` / `1 MB`） / 会话自适应（≤32 会话 `1 MB`→`512 KB`→`256 KB`；>32 会话 `256 KB`→`128 KB`→`64 KB`） | 吸收 QUIC/H3 多路复用高并发突发流量防丢包，同时防止多会话耗尽内核内存 |
| **用户态 TCP 转发缓冲 (`COPY_BUF_SIZE`)** | Windows / Android（及 Linux 回退） | `64 KB`（虚拟线程栈 `512 KB`） | 单次 `recv`/`send` 吞吐 4 个满载 16KB TLS 记录帧，命中 CPU 核心 L2 Cache，高并发下较 128KB 节省 50% 物理页占用 |
| **Linux 零拷贝管道 (`F_SETPIPE_SZ` + `splice`)** | Linux (`amd64` / `arm64`) | `256 KB`（回退 `128 KB` / `64 KB`） | 单次 `splice` 零拷贝系统调用可转移 64 个内核页面引用，长流大吞吐系统调用开销降低 75% |
| **UDP/H3 批量与逐包边界透传引擎** | Linux / 无 Root Android / Windows 11 | Linux & Android: 上下行双向 `32` 包 `recvmmsg`/`sendmmsg`（单包槽位 `4096 B`）；Windows 11: 非阻塞循环排空 `recvfrom`/`sendto` + 全量关闭 `SIO_UDP_CONNRESET` | Linux/Android 降低 32 倍系统调用开销；Windows 严格保持 QUIC 原始数据报边界，彻底规避部分网卡驱动 URO 合并缺失控制消息导致的握手截断问题 |

### 2. 核心性能与传输层优化

- **首包 `MSG_PEEK` 免缓冲直通（保留 Xray `finalmask` 分片特征 & 消除建连阻塞）**：
  - `connection_thread` 仅通过 1 字节 `MSG_PEEK` 嗅探识别 TLS（`0x16`）或明文 HTTP 以分流目标端口（`443` / `80`，非 TLS 80 失败自动回退 443），绝不在用户态消费或重组 TLS ClientHello；
  - 彻底消除等待 Xray `finalmask`（`tlshello` 分片）收齐的 150~200ms 串行阻塞与 4KB 线程栈缓冲，完整保留客户端抗审查分片特征；在 Linux 下首包直接走 `splice` 内核零拷贝，在 Windows 与 Android 下直接走 `64 KB` 缓冲直通转发。
- **双向转发线程合并减负（每连接线程数与虚拟内存立降 33%）**：
  - `relay_bidirectional()` 废除创建 2 个子转发线程的传统模式；当前连接处理线程 `connection_thread` 直接就地接管反向转发（`u -> c`），仅派生 1 个子线程负责正向转发（`c -> u`）。
- **预解析二进制地址缓存（`sockaddr_storage` 热路径零解析）**：
  - 在 `Result`、`CandidatePool`、`ConnCtx`、`UdpSession` 及 `BaiduProxyNode` 中全量内置二进制网络地址 `struct sockaddr_storage` 与长度，消除高并发建立 TCP 连接、百度 `CONNECT` 拨号与 UDP 会话时的重复字符串解析开销。
- **UDP/H3 1024 会话分实例限额、8 位哈希分桶 + MRU + 原子 `epoch` 热迁移**：
  - 单实例会话上限达 `1024`（各实例独立计数互不挤压），结合 8 位哈希分桶（`udp_hash[256]`）与单级 MRU 缓存，单客户端突发与多客户端并发均保持 $O(1)$ 检索；
  - **无锁 `epoch` 驱动动态热迁移**：UDP 优选池切换时仅原子递增 `udp_candidates.epoch`，`carrier_udp_thread` 在本线程内无锁感知变更并平滑重建上游套接字（自动换新源端口），零互斥锁争抢、零哈希表并发竞争。
- **Linux/Android 双向 `recvmmsg`/`sendmmsg` 与 Windows 稳定边界透传**：
  - Linux 与无 Root Android 上下行双向启用 32 包 `recvmmsg()` + `sendmmsg()` 批处理，严格过滤 `MSG_TRUNC` 截断残包，遭遇非阻塞部分发送（Partial Send）时精确回退逐包恢复；
  - Windows 11 上 `listen_tcp` 在 `bind()` 之前启用 `SIO_LOOPBACK_FAST_PATH` 加速本机与 Xray 的回环 TCP；UDP 全量关闭 `SIO_UDP_CONNRESET` 并采用严格保持数据报边界的循环排空收发，杜绝驱动级合并导致的 QUIC 握手异常。
- **BBR 拥塞控制、`TCP_NOTSENT_LOWAT` 与 `TCP_USER_TIMEOUT` 三重加固**：
  - Linux/Android 上游拨号优先启用 **BBR**（内核不支持时自动回退），有效抵抗 0.5%~2% 跨境随机丢包；
  - 配合 `TCP_NOTSENT_LOWAT = 64 KB` 消除大下载流引发的 Bufferbloat 延迟膨胀；
  - 取消转发路径的 300s `SO_RCVTIMEO` 硬超时，Linux/Android 死连接交由 45s `TCP_KEEPIDLE`（+10s×3）与 `TCP_USER_TIMEOUT = 25s` 判定，Windows 额外保留 90s `SO_SNDTIMEO` 兜底零窗口发送阻塞：保证单向大文件长传输永不中途误拆，又不产生僵尸线程。
- **`TCP_INFO` 内核高精度 `tcpi_rtt` 基准与高重传节点自动降权**：
  - 扫描探测优先读取 Linux 内核 `tcpi_rtt` 并叠加 `0.25×tcpi_rttvar` 抖动权重，消除多线程排队误差并优先挑选低抖动稳定节点；
  - 连接收尾采样内核总重传数 `tcpi_total_retrans` 并结合上行字节数估算重传率，大流量重传超过 15% 时温和抬高该节点的 `ewma_latency`（封顶 +100ms 且随正常连接自动衰减恢复），不触发 `fast_fail` 切换抖动。
- **异步后台维护线程（`carrier_maintenance_thread`）与全环形 30 秒冷却回灌**：
  - 节点顺位切换与自愈扫描全面解耦至独立后台维护线程，数据转发面零阻塞；
  - 采用按综合分升序 + 首波 2 路 / 后续 4 路并发探测搭配 30 秒失败冷却期与 `consecutive_fail` 指数惩罚（$50 \times 2^n$），短暂抖动的头部优质节点冷却后自动回灌复用。
- **高精度单调时钟、秒级时间戳缓存与无锁关闭快路径**：
  - Linux 与 Android 使用 `clock_gettime(CLOCK_MONOTONIC)`；Windows 使用以进程启动时刻为锚点的 `QueryPerformanceCounter` 提供 1ms 级单调时钟（既消除 15.6ms 粗粒度抖动，又避免系统快速启动开机超 24.85 天后的 32 位 `long` 溢出回绕）；
  - 日志采用 C23 `thread_local` 秒级缓存时间戳；连接正常关闭时通过原子无锁快路径返回。
- **冷启动按需端口预绑定（Early Binding）与优雅退出**：
  - 扫描前按各栈启用的协议提前绑定监听端口（TCP Backlog `4096`），客户端首包握手先入内核队列，消除冷启动初期 RST；
  - 扫描线程数依 CPU 核心自适应降载（`min(task, 64 × nproc)`），保护低配软路由。

### 3. 目标平台支持矩阵（纯静态架构）

构建产物全面采用**纯静态（Pure Static）独立二进制**或原生免外部依赖二进制，开箱即用：
- **Linux amd64 (x86_64)**：musl 纯静态独立二进制（`cfnat-linux-amd64`），无视发行版差异（Ubuntu / Debian / Alpine / CentOS / OpenWrt / Arch 均可直接运行）
- **Linux arm64 (aarch64)**：musl 纯静态独立二进制（`cfnat-linux-arm64`），适配各类 ARM VPS、树莓派及 OpenWrt 软路由
- **Android Termux (arm64 & amd64)**：Android NDK 编译（`cfnat-android-arm64` / `cfnat-android-amd64`），适配 Bionic libc 与 Android 沙箱 seccomp 审计，Termux 免 root 开箱即用
- **Windows 11 amd64 (x86_64)**：Win11 原生纯静态可执行文件（`cfnat-windows-amd64.exe`）
- **Windows 11 arm64 (aarch64)**：Surface / 骁龙 X Elite / ARM 笔记本原生运行（`cfnat-windows-arm64.exe`）

## 项目定位与转发链路

cfnat C 版做四件事：
1. **智能扫描与抗 QoS 子网裂变优选**：扫描 Cloudflare IP，筛选精准 TCP (H2) 候选池，并按低突发抗 QoS 节拍与同网段裂变引擎多轮测速生成 UDP (H3) 专用候选池。
2. **三栈灵活次序 + 单/双协议按需监听**：支持 IPv4（`-v4-listen`）、IPv6（`-v6-listen`）与百度前置（`-baidu-listen`）按命令行传参次序依次启动，并可按栈自由指定 **H2+H3 双轨 / 仅 H2 / 仅 H3**。
3. **精准双轨独立路由转发**：
   - TCP 连接（H2/TLS）转发至当前 **TCP 优选 IP**（通过首字节 `0x16` `MSG_PEEK` 自动分流 443 或 80 端口，80 失败自动回退 443）；
   - UDP 报文（H3/QUIC）转发至当前 **UDP 优选 IP:443**，自动执行黑洞剔除、窒息低速检测与空闲回收。
4. **活跃态高灵敏测活与空池退避自愈**：有真实客户端流量的协议栈自动提升健康检查频率与多包丢包检测；H3 因 QoS 暂时空池时自动按指数退避试探并无感热恢复，绝不阻塞转发。

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

### 1. 全面遵循 C23 现代语言标准与零开销契约
- 核心源码遵循 ISO/IEC 9899:2024 (C23) 标准，使用 `nullptr`、`constexpr`、`thread_local`、标称类型枚举（`enum : uint8_t`）与 `[[nodiscard]]` 属性（内置 C11/C17 回退层），且严格避免 `__DATE__`/`__TIME__` 以满足可复现构建要求。

### 2. 三栈独立判定口径与按传参顺序启动
- **直连栈（IPv4 / IPv6）**：统一以目标端口（默认 443）的 TLS 握手作为**唯一存活与延迟门槛**；首轮以短超时「尽力而为」地探测 80 端口 HTTP HEAD 提取 `CF-RAY` 机房标签，采集失败仅记为 `UNK` 而绝不淘汰 IP，避免 IPv6（:80 常被 ISP 过滤）被整批误杀。
- **百度前置栈**：`HTTP CONNECT` 隧道本身是两跳（耗时约 `90~1200ms`），因此隧道内沿用 `80` 端口 HTTP HEAD（`CONNECT` 独立保底 `1500ms` 预算，单节点失败自动换节点重试一次），全部无果时自动回退 443 TLS 兜底；443 真实可用性由健康检查（`HC_FULL`）复验。
- **按传参顺序初始化**：`-v4-listen`、`-v6-listen`、`-baidu-listen` 按命令行中出现的先后顺序依次完成扫描与监听；若同时启用 `v4` 与 `baidu` 且百度开启了 H3，只要 `-baidu-listen` 排在 `-v4-listen` 之前，程序会自动将 `v4` 提前到 `baidu` 之前，确保直连 H3 缓存已生成供百度兜底复用。

### 3. 分栈协议开关（`-h2` / `-h3`）与纯 H3 三级缓存快路径
- 支持全局 `-h2` / `-h3` 及分栈 `-v4-h2` / `-v4-h3` / `-v6-h2` / `-v6-h3` / `-baidu-h2` / `-baidu-h3`（默认均为 `true`）；同一启用实例不能同时关闭 H2 与 H3。
- **纯 H2 模式（`h2=1, h3=0`）**：跳过 H3 精筛、不读写 `-udp.txt` 缓存、不绑定 UDP 监听且不启动 UDP 转发/测活线程，彻底零 UDP 发包。
- **纯 H3 模式（`h2=0, h3=1`）**：不绑定 TCP `listen_fd`、不启 TCP 接收与测活线程，仅校验并启动 UDP 监听；冷启动与自愈遵循 **三级缓存流转**：
  1. **命中有效 `udpcache`**（如 `direct-cache-v6-udp.txt`）：跳过 TCP 扫描直接秒启；
  2. **无有效 `udpcache` 但有有效 `tcpcache`**：直接读取 `tcpcache` 当种子精筛 H3，免去全量 TCP 扫描；
  3. **两者皆无或失效**：先跑前置 TCP 扫描生成种子并写入 `tcpcache`，再精筛 H3 候选池。

### 4. 抗 QoS 多轮 H3 精筛、可选真实 ClientHello 探针与空池退避自愈
- **双模式 QUIC 探针（`-h3-client`）**：
  - **默认轻量 VN 探针（`-h3-client=0`）**：RFC 9000 规范的 1200 字节版本协商探针（头部 `0xC0 + 0x5A5A5A5A` + 8 字节 DCID/SCID + 1177 字节**全零载荷**），零加密开销、极速稳定。
  - **真实 QUIC v1 Initial 模拟（`-h3-client=1` / `true`）**：内联零外部依赖的 RFC 9000/9001 加密原语（SHA-256 + HKDF-SHA256 + AES-128-GCM + Header Protection），发送含合法 SNI、`ALPN=h3`、`x25519` KeyShare 与 `quic_transport_parameters` 的 1200 字节真实加密 ClientHello，用于排查或规避针对全零载荷的特征拦截。
- **四步抗 QoS 精筛节奏**：
  1. **扫后冷却**：TCP 扫描结束后先停 `500ms`，让路由器 conntrack 与出口突发配额回落；
  2. **金丝雀单点探路**：批量开测前先单发探测最多 3 个头部节点（间隔 `800ms`），连挂直接提前止损，绝不在 QoS 惩罚窗内盲目齐射；
  3. **小批次换源端口 + 节拍 + 自动降速自保**：金丝雀通过后间隔 `300ms`，按每批最多 `6` 个 IP、每批重建共享 UDP socket 轮换本地源端口、包间 `20ms` 节拍、轮间 `200ms` / 批间 `250ms` 间隔执行 `num` 轮测速（按平均延迟、抖动与丢包率综合评分）；若金丝雀连通但首批并发 0 回包，自动冷却 `1.2s` 切换为单点慢速节拍（每 IP 独立 socket + `150ms` 间隔）并兜底保留已验证的金丝雀节点；
  4. **原池子网循环裂变补齐**：合格节点不足 `ipnum` 个时，从原 `ipnum` 个 IP 的 IPv6 `/64` 或 IPv4 `/24` 子网每 IP 裂变 2 个循环补测（最多 6 轮，防阻断死循环），合并排序产出 H3 池。
- **H3 空池指数退避自愈**：启动期若因瞬时 QoS 导致 H3 池为空，`carrier_udp_health_thread` 按 **`30s → 60s → 120s → 240s → 300s`** 指数退避单发试探 1~2 个头部节点；一旦确认 QoS 解除，直接基于现有 TCP 种子池无感重建并热切换 H3 池（百度前置同步检测直连 H3 缓存是否恢复），全程不打扰 TCP 转发。

### 5. 多维度综合评分、冷却回灌与高重传降权算法
- **综合评分公式（`score_result`，分数越低越优）**：
  $$\text{Score} = 10 \times \text{EWMA\_Latency} + 25 \times \text{LossRate} + 5 \times \text{Jitter} + \text{FailPenalty}$$
  - 其中 `FailPenalty` 在连续失败 $n$ 次（上限 10 次）时按 $50 \times 2^n$ 指数增长；同分时依次按原始延迟与丢包率决胜。
- **全环形 30 秒冷却回灌与首波 2+4 并行切换**：
  - 节点切换时优先挑选无失败记录或失败冷却已满 **`30s`** 的候选，按综合分升序分波探测（**首波 2 路快探，后续每波 4 路并发**，择最低延迟胜出，收敛耗时约 1×RTT）；
  - 若全池均处于 30s 冷却期，自动放宽至冷却 ≥ **`5s`** 的候选兜底，避免池耗尽前过早触发重扫。
- **内核重传感知温和降权**：
  - Linux/Android 在 TCP 连接关闭时采样 `TCP_INFO` 的 `tcpi_total_retrans` 结合上行字节数估算重传率；大流量重传率超过 **15%** 时温和抬高该节点的 `ewma_latency`（封顶 +100ms 并随后续正常连接自动衰减恢复），既降低劣质节点权重又不引发切换震荡。

### 6. UDP/H3 会话管理、黑洞剔除、窒息低速检测、空闲超时与 LRU 淘汰算法
- **双条件黑洞剔除（每 `3s` 巡检，抓“完全断流”）**：
  - **初始握手黑洞**：下行 `bytes_down == 0`、会话已存活 `≥ 4s`，且累计上行 `≥ 1200 B`；
  - **传输中途黑洞**：曾有下行（`bytes_down > 0`），但连续 `≥ 4s` 无任何下行回包，且期间新增上行 `≥ 1200 B`；
  - 触发黑洞后立即关闭上游 socket、清理会话并递增目标 IP 的 `consecutive_fail`。
- **窒息低速检测（Stall Detection，抓“延迟极低但下载卡死”）**：
  - 专门应对运营商对 UDP 443 的令牌桶极低速限流（小包心跳与 3 包探针仍能 0% 丢包回包，但持续下行被压到几乎为 0）；
  - 每 **`≥ 5s`**（配合 `3s` 巡检实际每 ~`6s`）对活跃会话做一次收发字节滑动快照：若窗口内 **上行增量 `≥ 2.5 KB`**（覆盖 QUIC PTO 退避期重传）、**下行增量 `< 8 KB`** 且 **上行 `≥ 2 ×` 下行**（典型收发倒挂特征），记 1 次窒息告警；
  - **抗抖动保留计数**：仅当下行真正恢复（窗口内下行 `≥ 32 KB`）或客户端进入静默（上行 `= 0`）时才清零计数，避免 QUIC 退避期小包或偶发微量漏水把预警清零；
  - 同一会话累计 **2 次**窒息告警即判定「窒息低速剔除」，关闭上游 socket、计入节点失败并**直接触发顺位切换**（适配 Xray XMUX 单长连接复用场景，无需等待第二条会话）；黑洞剔除（`4s`）与内核 `POLLERR` / `POLLHUP` 事件仍保留累计 **2 次**触发切换，迁移时自动换新目标 IP 与新源端口并重置窒息窗口。
- **空闲超时回收（`60s`，抓“自然闲置”）**：
  - 距离最后一次收发包（`last_active_ms`）超过 **`60s`**（`UDP_SESSION_TIMEOUT_MS`）自动清理会话释放文件描述符；空闲回收**不计入节点失败、不触发 IP 切换**，避免误伤 Xray 正常保活的空闲隧道。
- **分实例 `1024` 会话上限与 LRU 淘汰**：
  - 每个监听实例独立维护最多 **`1024`** 条活跃 UDP 会话（不跨实例挤压），通过 8 位哈希分桶 + 单级 MRU 实现 $O(1)$ 查找；达到上限时按 `last_active_ms` 自动淘汰最久未活跃会话。

### 7. 按栈按协议「活跃态 / 闲置态」自适应健康检查
- **活跃态**（该栈该协议当前有活跃连接/会话，或近 `30s` 内有过收发流量）：
  - **UDP/H3**：周期锁定在 **`15s`**，每轮升级为 **3 包 × `50ms`** 测丢包——收到 ≥2/3 包视为健康（偶发丢 1 包仅记 debug 日志不误切），丢包 ≥2/3（67%）即记失败并在 `10s` 后复检，连续 2 次失败触发切换，专门抓出「单包延迟很低但实际高丢包/被软限速」的半死节点；
  - **TCP/H2**：周期锁定在 **`20s`**，配合首包实时回退与 `TCP_INFO` 重传降权。
- **闲置态**（无活跃流量超过 `30s`）：
  - 自动退避至 **`60s`** 低频单包轻检（TCP 检测级别由 `HC_FULL → HC_MEDIUM → HC_LIGHT` 逐级降载），任意失败立即回到 `10s` 快速双检确认，省资源且不打扰闲置链路。

### 8. TCP/H2 连接级容错、双轨缓存持久化与原地自愈
- **首包握手超时实时无缝回退 & 80→443 自动回退**：
  - 客户端建立 TCP 连接时若首选节点握手超时，当场顺位尝试备用候选 IP，拨通即无缝接管为当前最优 IP 并计入切换统计；非 TLS 明文流量尝试 `80` 端口失败时自动回退 `443` 目标端口。
- **三层漏斗架构（官方底座 → 分协议定容热库 → 战备缓存）**：
  - **原料层（`ips-v4.txt` / `ips-v6.txt`）**：始终保留官方全量网段底座，永不被云端订阅覆盖；
  - **记忆层（`ips-hotpool-v4.txt` / `ips-hotpool-v6.txt` / `ips-hotpool-v4-udp.txt` / `ips-hotpool-v6-udp.txt`）**：按协议物理拆分的本地定容热库（v4 上限 `250`，v6 上限 `450` 且 `/48` 上限 `50`），遵循 **24h 观察期 + 3 天半衰期 + 7 天硬 TTL + 10m 记分节流 + 12×2h 时段亲和**，结合实战转发正向晋升与黑洞/窒息对称重扣（`fail_ema ≥ 6` 即踢出）；云端 `-v4-url`/`-v6-url` 以观察期种子注入热库，热库成熟后按 **50% 黄金段 + 30% 观察/云端段 + 20% 官方随机探索** 抽样，将发包突发压到最低；
  - **战备层（`*-cache-*.txt`）与 5 路并发快检**：
  - 缓存文件（如 `direct-cache-v4.txt`、`direct-cache-v4-udp.txt`）记录延迟、丢包率、EWMA、抖动与失败次数，通过「临时文件 → `fsync`/`_commit` → 原子重命名」防损坏；启动时并发快检前 5 个候选，命中即秒启；缓存超过 `3600s`（1 小时）将在后续自愈时刷新。
- **原地测活 + 增量补扫（`carrier_rescan_dual_pools`）**：
  - 触发自愈时先对现有双池 IP 去重原地复测：若 TCP 存活 ≥ **60%** 且 UDP（若启用）存活 ≥ **25%**，直接原地重排装填、跳过全量扫描；否则仅增量补扫并合并去重。

### 9. IPv4 惰性二分扫描、IPv6 全前缀智能切分、百度抗 Fake-IP 解析与原子树状日志
- **IPv4 顺序模式 $O(1)$ 内存扫描**：关闭随机抽样（`-random=false`）时基于 CIDR 前缀和与二分定位惰性生成 IP，零全量展开内存开销，适配小内存软路由。
- **IPv6 全前缀智能切分与混合清单识别**：支持 `-v6-split` 扩展至 **`1` ~ `128`**（默认 `54`），`ips-v6.txt` 可混排任意完整 IPv6（含压缩/`[ip]`/`/128`）与每行不同前缀的子网；完整 IP 直接测优，文件子网小于参数子网（如参数 `/50`、文件 `/64`）时按文件子网展开，单行切分超 `1024` 自动按高 10 位分层封顶防 OOM，统一展开为 8 段完整 16 进制格式。
- **百度前置抗 Fake-IP 解析池**：支持 `auto` / `udp://` / `doh://` 解析器绕过本地 Fake-IP，内置 5 秒原子缓存最优代理节点，单节点失败自动换节点重试。
- **多行原子树状日志与周期运行指标**：所有双轨日志左置 `[TCP/H2]` 与 `[UDP/H3]`，启动与周期指标单次原子写入防并发打断；`-log=debug` 自动隐藏扫描百分比滚动行，避免与逐条探测明细穿插刷屏。

## Xray XMUX 协同机制说明

作为 Xray / Sing-box 等出站工具的前置中继，cfnat（L4 透传层）与 Xray（应用层 / QUIC 协议栈）各司其职、深度互补：

| 维度 | Xray (应用层客户端) | cfnat (L4 传输层中继) |
| :--- | :--- | :--- |
| **定位分工** | 负责流控制、XMUX 多路复用、隧道生命周期（`hMaxReusableSecs` / `cMaxReuseTimes`）、TLS 分片与 QUIC 断线重连 | 负责全球 Anycast 路由优选、毫秒级测速、零拷贝/大缓冲中继、活跃态丢包检测与死节点故障自愈 |
| **TCP/H2 协同** | 开启 XMUX 与 `finalmask` 避免频繁握手并混淆特征 | 首包 `MSG_PEEK` 免重组透传分片 + `TCP_NODELAY` + BBR + `TCP_NOTSENT_LOWAT=64KB` + 45s 保活 + 25s 死连快收 |
| **UDP/H3 协同** | 依赖 QUIC 在单个 UDP 端口上传输海量 H3 数据包并控制隧道平滑轮换 | MRU + 8 位哈希分桶 $O(1)$ 查找 + `epoch` 无锁热迁移换新源端口 + 4MB/1MB 分级缓冲 + Linux 双向 32 包 `recvmmsg`/`sendmmsg` |
| **节点切换行为** | 依靠 XMUX 参数定期温和轮换隧道，旧流异常时快速重建 | **TCP 平滑收敛（Graceful Drain）**：仅将新连接导向新 IP，绝不 RST 存量连接；**UDP 黑洞快切**：新包自动切至新 IP 与新源端口 |

> **提示**：无需（也不应）在 cfnat 中二次实现应用层复用。端到端保持 TLS/QUIC 密文与分片透明穿透，隧道时效与平滑轮换交由 Xray 管理，cfnat 专注 L4 选路、零拷贝转发与快速自愈。

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
zig cc -target x86_64-windows-gnu -O2 -pipe -std=c23 \
  -finput-charset=UTF-8 -fexec-charset=UTF-8 \
  -Wall -Wextra -Wno-unused-parameter \
  ./cfnat.c -o ./cfnat-windows-amd64.exe -lws2_32 -ldnsapi -lwininet -static -s
```

### 2. 启动示例

```bash
# 启动直连优选监听
./cfnat -direct-listen=0.0.0.0:40000 -colo=HKG,SJC -delay=150

# 客户端统一连接
服务器IP:40000  (TLS 流量自动去 443，非 TLS 去 80，UDP/QUIC 自动去 H3 优选池 443)
```

## Android Termux 运行指南

1. **获取二进制**：从 GitHub Release 下载 `cfnat-android-arm64`（绝大多数现代手机为 ARM64 架构）。
2. **放入 Termux 私有目录执行**：
   ```bash
   cd ~
   chmod +x cfnat-android-arm64
   # 非 root 环境监听端口需大于 1024
   ./cfnat-android-arm64 -v4-listen=127.0.0.1:40000 -colo=HKG
   ```
3. **后台保活（防止手机锁屏杀进程）**：
   - 在 Termux 中执行 `termux-wake-lock`（获取 CPU 唤醒锁）；
   - 在手机系统设置中将 Termux 的省电策略设为 **“无限制 / 允许后台高耗电”**。

## Systemd 生产服务部署指南

对于 Linux / Armbian / VPS 或内网多终端共用环境，推荐配置为 systemd 常驻守护服务。

新建 `/etc/systemd/system/cfnat.service`：
```ini
[Unit]
Description=Cloudflare Anycast IP Optimizer and Dual-Stack Proxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/etc/cf
Environment=FORCE_COLOR=1
ExecStartPre=/bin/sh -c 'unset http_proxy https_proxy'
ExecStart=/root/etc/cf/cfnat -v6-listen=0.0.0.0:6443 -v4-listen=0.0.0.0:4443 -baidu-listen=0.0.0.0:5443 -v6-code=200 -task=400 -num=3 -ipnum=20
Restart=always
RestartSec=10

# 关键配置：高并发扫描与多终端转发时解除 cgroups 默认线程与描述符限制
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

### 1. 监听模式参数（按传参顺序决定启动次序）

| 参数 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `-cli` / `-scan-only` | 显式开启 **单次 CLI 测速模式**。仅执行一次测速、在终端打印美化彩色候选 IP 表格并保存缓存文件后立即退出，绝不启动常驻转发监听服务。 | 留空不开启 (默认按监听参数启动常驻转发) |
| `-v4-listen[=addr]` | 开启 IPv4 转发本地监听（不带参数时默认 `0.0.0.0:4443`；若全部未指定，则默认开启此项） | 缺省未显式指定时默认 `0.0.0.0:4443` |
| `-v6-listen[=addr]` | 开启 IPv6 转发本地监听（不带参数时默认 `[::]:6443`） | 留空不开启 |
| `-baidu-listen[=addr]` | 开启百度前置优选本地监听（不带参数时默认 `0.0.0.0:5444`） | 留空不开启 |
| `-direct-listen[=addr]` | 兼容旧版参数：按 `-ips` 指定类型开启直连监听 | 留空不开启 |

> [!TIP]
> - 支持同时指定任意多个监听参数，**按命令行出现顺序依次完成初始化**（例如先写 `-v6-listen` 再写 `-v4-listen` 则先初始化 IPv6）。
> - 若同时启用了 `v4` 与 `baidu` 且百度前置开启了 H3，只要 `-baidu-listen` 出现在 `-v4-listen` 之前，程序会自动将 `v4` 提前到 `baidu` 之前，确保直连 H3 缓存已就绪供百度兜底复用；若百度设为纯 H2（`-baidu-h3=0`），则完全遵循传参顺序。
> - 若所有监听参数均未指定且未指定 `-cli` / `-scan-only`，默认自动开启 IPv4 转发监听 `0.0.0.0:4443`。

### 2. 协议开关与通用 / 分栈前缀参数

所有常规参数均支持**全局通用**与**分栈独立配置**：
- **不带前缀的参数**（如 `-delay=200`、`-h3=0`）作为基准默认配置，自动被所有实例继承；
- **带有 `-v4-` / `-v6-` / `-baidu-` 前缀的参数**（如 `-v6-code=200`、`-v4-h3=0`、`-v6-h2=0`）仅对对应实例生效，优先级高于全局默认值。

| 参数（通用 / 分栈专属） | 说明 | 默认值 |
| :--- | :--- | :--- |
| `-h2` / `-v4-h2` / `-v6-h2` / `-baidu-h2` | 启用或关闭 **TCP/H2** 监听、转发与测活（`1`/`true` 开启，`0`/`false` 关闭）。关闭时进入纯 H3 模式：不绑定 TCP 监听、不启 TCP 线程，冷启动按 `udpcache → tcpcache → 前置扫描` 三级流转。 | `true` |
| `-h3` / `-v4-h3` / `-v6-h3` / `-baidu-h3` | 启用或关闭 **UDP/H3** 测优、监听、转发与测活（`1`/`true` 开启，`0`/`false` 关闭）。关闭时进入纯 H2 模式：跳过 QUIC 探测与 `-udp.txt` 缓存，不绑定 UDP 监听。**注：同一启用实例不能同时关闭 H2 与 H3。** | `true` |
| `-h3-client` | H3 探测是否启用 **真实 RFC 9001 QUIC v1 Initial (TLS 1.3 ClientHello)** 模拟（`0`/`false` 使用轻量全零 VN 探针；`1`/`true` 或裸传 `-h3-client` 发送含 SNI、`ALPN=h3` 的加密 Initial 包，零外部库依赖）。 | `false` |
| `-ips` | 全局指定 IP 类型：`4` (IPv4) 或 `6` (IPv6) | `4` |
| `-colo` / `-v4-colo` / `-v6-colo` | 匹配特定数据中心，支持反选 (前缀 `-` / `^` / `!`)，如 `HKG,SJC` 或 `-HKG,-SJC` | 留空全部匹配 |
| `-exclude-colo` / `-v4-exclude-colo` / `-v6-exclude-colo` | 显式排除的数据中心列表，如 `HKG,SJC`（支持与 `-colo` 自动合并） | 留空不排除 |
| `-domain` / `-v4-domain` / `-v6-domain` | 探测目标路径与 Host（用于 TLS SNI、`-h3-client` SNI 与 HTTP 状态码检测） | `cloudflaremirrors.com/debian` |
| `-code` / `-v4-code` / `-v6-code` / `-baidu-code` | 期望的有效 HTTP 状态响应码。<br>**缺省/为 0 时**：直连栈在 443 目标端口做 TLS 握手作为存活与延迟门槛，80 端口仅尽力补充 `CF-RAY` 机房标签；百度前置栈隧道内以 80 端口 HTTP HEAD 作为存活门槛（全部无果时回退 443 TLS）。<br>**显式指定（如 `-code=200`）时**：在 80 端口严格校验状态码（405 自动回退 GET 确认）；若 80 整体不可达（IPv6 常见），则跳过校验并在扫描结束时提示一次。 | `0` (仅测连通性) |
| `-delay` / `-v4-delay` / `-v6-delay` | 有效往返延迟（1×RTT）上限（毫秒），同时作为 H3 多轮测速的延迟合格门槛。**注：百度前置 `CONNECT` 拨号另设 `1500ms` 独立下限预算。** | `300` |
| `-task` / `-v4-task` / `-v6-task` | 扫描并发线程数（上限 `2000`，并按 CPU 核心数自适应限制为 `64 × nproc`） | `200` |
| `-ipnum` / `-v4-ipnum` / `-v6-ipnum` | 保留的最优候选 IP 数量上限（Top-N 截断，上限 `1000`；H3 候选池上限 `64`），同时作为子网裂变补齐与原地自愈的目标水位 | `20` |
| `-num` / `-v4-num` / `-v6-num` | 单 IP 探测尝试次数（上限 `50`）：TCP 明文按 Keep-Alive 复用、TLS 自动收敛至最多 `2` 次；**H3 精筛与子网裂变均按 `num` 轮测速**计算平均延迟、抖动与丢包率（首轮无回包立即熔断） | `5` |
| `-port` / `-v4-port` / `-v6-port` | 上游 TLS / QUIC 转发目标端口（注意区分本地监听与目标端口） | `443` |
| `-http-port` / `-v4-http-port` / `-v6-http-port` | 上游非 TLS 转发目标端口 | `80` |
| `-random` / `-v4-random` / `-v6-random` | 是否按 CIDR 随机抽样生成候选 IP | `true` |
| `-v4-url` / `-v6-url` | 自定义云端优选源 URL（支持带参数订阅链接）。拉取并校验后**以观察期（`hits=1`）注入本地热库**，**绝不覆盖官方 `ips-v4.txt` / `ips-v6.txt`**；支持混排标准 CIDR、`ip:port#备注`、`[v6]:port#备注`、CSV 与非 IP 说明行（自动去 BOM、跳过非 IP 行并 O(1) 去重）。 | 不启用（仅用官方底座+本地热库） |
| `-update` / `-v4-update` / `-v6-update` | 云端外援源同步策略（支持全局统一 `-update` 与 `-v4-`/`-v6-` 覆盖）：`0`/`false` 仅热库为空时拉取；`1`/`true` 每次启动拉取；`*m`/`*h`/`*d`（如 `60m`、`6h`）按热库头部的独立同步时间戳超期自动拉取。**注：显式指定 `-v4-url`/`-v6-url` 且未关闭时默认 `true`；有新源时仍优先快检本地缓存秒启转发，再后台异步从热库无感刷新（内容无变化则不触发后台刷新）。** | `false`（指定 URL 时默认 `true`） |
| `-to-cidr` / `-v4-to-cidr` / `-v6-to-cidr` | 是否将列表中的单 IP（含 `/32`、`/128`）转换为网段并去重后再抽样/展开：`0`/`false` 关闭（直测原 IP，适配含反代 IP 清单）；`1`/`true` 转为默认 `/24`（v4）或 `/64`（v6）；`-v4-to-cidr`/`-v6-to-cidr` 还支持自定义前缀（如 `24`、`64`、`48`）。原有更宽 CIDR 保持不变。 | `false` |
| `-v6-split` | IPv6 子网切分前缀掩码（支持 **`1` ~ `128`**，可带或不带 `/`）。完整 IPv6（含压缩/`[ip]`/`/128`）直接测优；文件某行子网小于参数子网（如参数 `/50`、文件 `/64`）时按该行文件子网展开；文件子网更大时按参数切分（`/128` 可精确枚举小段全部 IP，单行上限 `1024` 分层采样防 OOM）。**默认 `54`**。 | `54` |
| `-baidu-resolver` | 针对 Fake-IP 的百度解析方式: `auto` / `udp://` / `doh://` | `auto` |
| `-bind-if` | 绑定出站物理网卡 (如 `eth0`、`en0`) | 留空使用默认路由 |
| `-health-log` | **健康状态行（`-log=debug` 级别明细）输出间隔**秒数，`0` = 关闭。只控制打印频率，**不影响健康检查本身的活跃态/闲置态自适应节奏**。 | `60` |
| `-log` / `-log-level` | 日志级别：`silent` / `error` / `warn` / `info` / `debug`。<br>**`info`（默认）**：日常转发静默，仅输出启动/自愈树状日志、故障切换与周期运行指标；<br>**`debug`**：输出逐条探测明细、连接日志与完整候选表格（自动隐藏扫描百分比滚动进度日志，避免穿插刷屏）。 | `info` |
| `-stats-interval`<br>（别名 `-log-interval`） | **三栈双协议运行指标汇报间隔（秒）**，`0` = 关闭。<br>每周期用**一次原子写入**输出树状摘要，汇总全局活跃 TCP 连接与 UDP 会话数，并展示各栈 H2/H3 的当前最优 IP、机房（colo）、延迟、候选池数、活跃 UDP 会话数、累计切换次数（含首包超时实时回退）与本周期 UDP 上行/下行丢包计数（主动关闭的协议明确显示 `已禁用`）。 | `300` |

## 常用示例

### 1. 三栈全开 + 自定义启动顺序（先 IPv6，再 IPv4，最后百度前置）
```bash
./cfnat -v6-listen=0.0.0.0:6443 -v4-listen=0.0.0.0:4443 -baidu-listen=0.0.0.0:5443 -v6-code=200 -task=300 -num=3 -ipnum=20 -exclude-colo=HKG
```

### 2. 分栈单协议精细组合（IPv6 专跑 H3，IPv4 专跑 H2，百度前置纯 H2）
```bash
# IPv6 仅监听 UDP/H3（不占 TCP 端口、不启 TCP 测活）；IPv4 与百度仅跑 TCP/H2（零 UDP 探测）
./cfnat -v6-listen=0.0.0.0:6443 -v6-h2=0 -v4-listen=0.0.0.0:4443 -v4-h3=0 -baidu-listen=0.0.0.0:5443 -baidu-h3=0 -num=3 -ipnum=20
```

### 3. 开启真实 QUIC v1 ClientHello 模拟探针（排查/绕过全零特征拦截）
```bash
./cfnat -v4-listen=127.0.0.1:4443 -v6-listen=[::1]:6443 -h3-client=true -num=3 -log=debug
```

### 4. 仅测速扫描（CLI 单次测速模式，不监听端口）
```bash
# 执行单次测速，打印美化彩色候选表格并保存缓存后直接退出
./cfnat -cli -colo=HKG -delay=150 -ipnum=10
```

### 5. 配合 Xray / Sing-box 出站优选（单端口 H2 + H3 全透明支持）
```bash
./cfnat -v4-listen=127.0.0.1:4443 -colo=HKG,SJC -delay=200 -task=300 -num=3
```
客户端配置：
- **服务器地址 (Address)**: `127.0.0.1`
- **端口 (Port)**: `4443`
- **协议说明**：客户端连接 `127.0.0.1:4443`。cfnat 自动在底层将 TCP 流量导入 TCP 优选节点，将 UDP/QUIC 流量导入 H3 优选节点。

## 构建与 GitHub Actions 发布

工作流文件位于 `.github/workflows/build.yml`，采用 **单 Job 6 路并发构建** 架构：
- 仅占用 **1 个 `ubuntu-latest` runner**，单次下载 Zig 与 Android NDK 后，按目标隔离 Zig 缓存与日志并 6 路后台并发编译，完成后在同机生成 `sha256sums.txt` 直接发布 GitHub Release（省去多容器启动与 Artifact 中转开销）。
- **自动构建产物（全部为纯静态或原生免外部依赖二进制）**：
  - `cfnat-linux-amd64` (Linux x86_64 musl 纯静态版)
  - `cfnat-linux-arm64` (Linux aarch64 musl 纯静态版)
  - `cfnat-android-arm64` / `cfnat-android-amd64` (Android NDK Termux 原生版)
  - `cfnat-windows-amd64.exe` / `cfnat-windows-arm64.exe` (Win11 纯静态版)
- **触发与发布方式**：
  - **推送 Tag 发布**：推送形如 `v*` 的标签时自动编译并发布到 Release。
  - **手动网页触发发布**：在 GitHub Actions 页面点击 **Run workflow**，支持输入标签名称或自动从源码提取版本，支持标记为 Pre-release。

## 资源占用与缓冲区设计说明

C 版在消除 Go 运行时、GC 和协程调度器额外常驻成本的基础上，针对高带宽时延积（BDP）跨境转发做了分级缓冲区设计：
- **内核套接字窗口（`SO_RCVBUF` / `SO_SNDBUF`）**：Linux TCP 接收与发送均交由内核自动调优并配合 `TCP_NOTSENT_LOWAT=64KB`；Windows TCP 设为 `2 MB`（自适应回退 `1 MB` / `512 KB`）并在 `bind()` 前开启 `SIO_LOOPBACK_FAST_PATH`；全平台 UDP 监听套接字设为 `4 MB`，会话套接字随并发数自适应分档（≤32 会话用 `1 MB` 档，>32 会话自动收敛至 `256 KB` 档），兼顾少会话高 BDP 吞吐与软路由防 OOM。
- **用户态转发缓冲（`COPY_BUF_SIZE = 64 KB`）**：在 Windows 11 与 Android Termux 上单次 `recv`/`send` 吞吐 4 个满载 16KB TLS 记录帧，在 CPU 核心 L2 Cache 命中率与高并发 RSS 内存占用之间取得最优平衡。
- **Linux 零拷贝管道（`F_SETPIPE_SZ = 256 KB`）**：单次 `splice()` 零拷贝系统调用可转移 64 个内核页面引用，且用户态回退函数通过 `noinline` 强隔离，走零拷贝通道时不占用用户态缓冲页。
- **按需分页虚拟线程栈（`512 KB`）**：扫描与转发线程虚拟栈设为 `512 KB`（动态对齐 `PTHREAD_STACK_MIN`），依托操作系统按需分页（Demand Paging）机制，未触碰的虚拟栈页不消耗物理内存（RSS）。
- **UDP/H3 批量队列与 $O(1)$ 检索**：Linux 与 Android 上下行双向启用 32 包 `recvmmsg` / `sendmmsg`（`thread_local` 静态队列占 `128 KB`，单包槽位 `4096 B` 防截断），配合 MRU + 8 位哈希分桶与原子 `epoch` 热迁移，实现高吞吐下的极低系统调用开销。

## 常见问题

### 1. 为什么扫描统计里显示“连接失败”数万次，但输入文件只有几百或几千行？
这是两个机制协同作用的正常结果：
1. **探测重试与失败累加**：启动参数 `-num` 代表单个 IP 的最大探测次数。虽然未连通的死 IP 已经由首包握手熔断机制规避了后续无效重试，但对于偶发丢包或超时节点，多次探测失败会进行人次累加；
2. **IPv6 混合清单与子网切分算法（`-v6-split=54`）**：`ips-v6.txt` 支持混排完整 IPv6 与任意前缀子网；默认 `-v6-split=54` 会将 `/48` 大段切分为 64 个 `/54` 子网各抽样 1 个 IP（633 行衍生出 40,512 个候选 IP），而比参数更小的子网（如 `/64`）或完整 IP 会按原粒度保留，既兼顾广泛离散采样又支持精准定向测优。

### 2. 为什么只监听一个端口，却能同时处理 TLS、HTTP 与 QUIC/H3？
在默认双协议模式下，同一监听端口会同时绑定 TCP 与 UDP 套接字：TCP 流量通过 `MSG_PEEK` 窥探首字节（`0x16` 判定为 TLS 自动转发到 `-port` 443，其他判定为 HTTP 自动转发到 `-http-port` 80，失败自动回退 443）；UDP 流量自动作为 QUIC/H3 数据报转发到 UDP 优选池节点的 443 端口。若通过 `-h2=0` 或 `-h3=0` 关闭某一协议，则仅绑定并监听启用的那一侧端口。

### 3. 为什么有时 H3 节点延迟很低但几乎没速度？现在怎么处理的？
运营商对境外 UDP 443 常见「软限速、极低速限流或高丢包」，小包心跳依然畅通、单包延迟极低，传统纯黑洞检测与单包测速很难抓出这类半死节点。现在已从三方面立体拦截：
1. **数据面窒息低速检测（Stall Detection）**：在真实转发流量上每 ~`6s` 统计一次收发增量，若上行 `≥ 2.5 KB`、下行 `< 8 KB` 且上行 `≥ 2 ×` 下行即记 1 次预警（仅在下行恢复 `≥ 32 KB` 或完全静默时清零，防止 QUIC 退避或微量漏水误重置），累计 **2 次**即触发「窒息低速剔除」并直接顺位切换至新 IP 与新源端口；
2. **活跃态 3 包丢包测活**：当某栈的 UDP/H3 正在转发真实客户端流量时，健康检查自动提速至 `15s` 并改为每轮发 `3` 个包（间隔 `50ms`），丢包 ≥ `2/3` 即记失败、`10s` 后复检仍差立即切走；
3. **更快黑洞剔除**：会话巡检缩至 `3s`，连续 `4s` 无下行且上行 ≥ `1200 B` 即判定黑洞剔除并触发切换。

### 4. 为什么启动时 H3 会被运营商 QoS 整段拦截？拦截后如何自动恢复？
家宽/出口对短时间大量境外 UDP 443 突发包非常敏感。当前采用「**冷却 `500ms` → 金丝雀单点探路 → ≤6 IP 小批次换源端口 + `20ms` 节拍 → 首批全挂自动降速为单点 `150ms` 节拍**」来避免触发限流；如果仍撞上运营商时段性封锁导致 H3 暂时空池，后台 UDP 健康检查会自动按 **`30s → 60s → 120s → 240s → 300s`** 退避单发试探，QoS 解除后直接无感重建 H3 池，无需重启进程。此外还可开启 `-h3-client=true` 验证是否为全零探针特征拦截。

### 5. 扫描到底以哪个端口为准？80 端口不通会不会导致选不出 IP？
**不会。** 判定链按「是否是代理隧道」分开：

| 栈 | 存活 + 延迟门槛 | `CF-RAY` 机房标签 | 失败后果 |
| :--- | :--- | :--- | :--- |
| 直连 IPv4 / IPv6 | 目标端口（默认 **443**）的 TLS 握手 | HTTP 端口（默认 **80**）HEAD，仅首轮一次、短超时 | TLS 失败 → 淘汰（唯一硬门槛）；80 失败 → 仅标记 `UNK` |
| 百度前置 | HTTP 端口（默认 **80**）HTTP HEAD（隧道内）；全部无果时**回退到 443 TLS 兜底** | 同一个 80 端口 HEAD（兜底命中时为 `UNK`） | 80 与 443 都不通 → 淘汰；443 真实质量由健康检查复验 |
| `-code` 状态码校验 | HTTP 端口（默认 **80**） | — | 有响应但不匹配 → 淘汰；端口整体不可达 → 跳过校验并提示一次 |

### 6. 为什么百度前置 / IPv6 的 H3 候选经常是 0 个？
UDP 无法经 HTTP `CONNECT` 代理转发，**三栈的 H3 通道始终是本机直连 UDP 443**：
1. 百度前置的 TCP 候选按代理出口可达性筛选，本机直连 UDP 未必通，因此首轮 H3 精筛无回包时会自动复用已验证的直连 H3 缓存（`direct-cache-*-udp.txt`）；若仅需要百度前置跑 H2，可直接传 `-baidu-h3=0` 关闭。
2. IPv6 的 UDP 443 在部分运营商被整体阻断时，程序绝不伪造假节点，保持 0 候选并由空池退避机制等待自愈（H2 仍正常可用）。
3. 排查时按 `-log=debug` 观察 `QUIC 批量探测汇总: 候选 N，成功发出 M，收到回包 R`：
   - `M < N` → 本机套接字/路由问题（fd 耗尽或无 IPv6 路由）；
   - `M = N` 且 `R = 0` → 探针已发出但确实无回包，属链路阻断或 QoS，可尝试开启 `-h3-client=true` 对比验证。

## 免责声明

本工具仅用于网络测试与学习用途。请在合法、合规的网络环境下使用，使用者自行承担因配置或使用造成的后果。
