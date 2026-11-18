# cfnat C 版 (C23 纯静态现代平台版)

面向全平台与高性能转发场景的 **Cloudflare IP 扫描 + 单端口 TCP/UDP (H2/H3) 双轨透明转发** 工具。

本项目采用 **C23 国际标准 (ISO/IEC 9899:2024)** 进行现代化构建，针对 **Linux、Windows 11 及 Android Termux 现代平台（amd64 / arm64）** 生成**纯静态（Pure Static）独立二进制**，彻底剥离 glibc 依赖，根除跨发行版兼容性问题。同时全面集成了 **HTTP/2 (TCP) 与 HTTP/3 (QUIC/UDP) 双轨独立测优、自适应高 BDP 缓冲区架构、Xray XMUX 与分片深度协同优化、首包快速熔断以及原子树状防打断日志系统**。

核心目标是完整提供扫描、优选、三栈（IPv4 / IPv6 / 百度前置）H2/H3 同端口转发、渐进式健康检查与双轨自愈能力，同时兼顾极致的单流大吞吐与低 CPU 系统调用开销，适用于 OpenWrt/软路由、手机 Termux、VPS 以及 Windows 11 设备。

## 现代平台优化与支持说明

### 1. 四层高吞吐缓冲区与跨平台 I/O 引擎优化

| 缓冲区层级 | 适用平台 | 容量配置 | 核心性能收益 |
| :--- | :--- | :--- | :--- |
| **TCP 内核套接字缓冲 (`SO_RCVBUF` / `SO_SNDBUF`)** | Windows / Linux / Android | Linux: 接收与发送交由内核 `tcp_moderate_rcvbuf` / `tcp_wmem` 动态调优 + `TCP_NOTSENT_LOWAT=64KB`；Windows: `2 MB`（自适应回退 `1 MB` / `512 KB`） | 解除固定窗口对 BBR 高 BDP 跨境吞吐的钳制，兼顾极致单流大带宽与零 Bufferbloat 延迟膨胀 |
| **UDP 内核套接字缓冲 (`SO_RCVBUF` / `SO_SNDBUF`)** | Windows / Linux / Android | 监听 `4 MB`（回退 `2 MB` / `1 MB`） / 会话自适应（≤32 会话 `1 MB`→`512 KB`→`256 KB`；>32 会话 `256 KB`→`128 KB`→`64 KB`） | 吸收 QUIC/H3 多路复用高并发突发流量防丢包，同时防止多会话耗尽内核内存 |
| **用户态 TCP 转发缓冲 (`COPY_BUF_SIZE`)** | Windows / Android（及 Linux 回退） | `64 KB`（虚拟线程栈 `512 KB`） | 单次 `recv`/`send` 吞吐 4 个满载 16KB TLS 记录帧，完美命中 CPU 核心 L2 Cache，高并发下较 128KB 节省 50% 物理页占用 |
| **Linux 零拷贝管道 (`F_SETPIPE_SZ` + `splice`)** | Linux (`amd64` / `arm64`) | `256 KB`（回退 `128 KB` / `64 KB`） | 单次 `splice` 零拷贝系统调用可转移 64 个内核页面引用，长流大吞吐系统调用开销降低 75% |
| **UDP/H3 批量收发队列 (`UDP_BATCH_SZ` + `recvmmsg` / `sendmmsg`)** | 无 Root Android / Linux | 上下行双向 `32` 包（单包槽位 `4096 B`，队列 `128 KB`） | 上行与下行双向批量收发，4KB 槽位承载大包 QUIC 与 Jumbo Frame 杜绝 `MSG_TRUNC` 截断 |

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
  - **无锁 `epoch` 驱动动态热迁移**：UDP 优选池切换时仅原子递增 `udp_candidates.epoch`，`carrier_udp_thread` 在本线程内无锁感知变更并平滑重绑新上游，零互斥锁争抢、零哈希表并发竞争。
- **Linux 与无 Root Android 上下行双向 `recvmmsg` / `sendmmsg` 批量收发**：
  - UDP 上行与下行双向启用 32 包 `recvmmsg()` + `sendmmsg()` 对称批处理（下行单会话突发下载系统调用 32→1）；严格过滤 `MSG_TRUNC` 截断残包，遭遇非阻塞部分发送（Partial Send）时精确回退逐包恢复。
- **BBR 拥塞控制、`TCP_NOTSENT_LOWAT` 与 `TCP_USER_TIMEOUT` 三重加固**：
  - Linux/Android 上游拨号优先启用 **BBR**（内核不支持时自动回退），有效抵抗 0.5%~2% 跨境随机丢包；
  - 配合 `TCP_NOTSENT_LOWAT = 64 KB` 消除大下载流引发的 Bufferbloat 延迟膨胀；
  - 取消转发路径的 300s `SO_RCVTIMEO` 硬超时，Linux/Android 死连接完全交由 45s `TCP_KEEPIDLE`（+10s×3）与 `TCP_USER_TIMEOUT = 25s` 判定，Windows 额外保留 90s `SO_SNDTIMEO` 兜底零窗口发送阻塞：既保证单向大文件长传输永不中途误拆，又绝不产生僵尸线程或空转。
- **`TCP_INFO` 内核高精度 `tcpi_rtt` 基准与高重传节点自动降权**：
  - 扫描探测优先读取 Linux 内核 `tcpi_rtt` 并叠加 `0.25×tcpi_rttvar` 抖动权重，消除多线程排队误差并优先挑选低抖动稳定节点；
  - 连接收尾采样内核总重传数 `tcpi_total_retrans` 并结合上行字节数估算重传率，大流量重传超过 15% 时仅温和抬高该节点的 `ewma_latency`（封顶 +100ms 且随正常连接自动衰减恢复），不触发 `fast_fail` 切换抖动。
- **异步后台维护线程（`carrier_maintenance_thread`）与全环形 30 秒冷却回灌**：
  - 节点顺位切换与双轨自愈扫描全面解耦至独立后台维护线程，数据转发面零阻塞；
  - 废除 70% 池容量硬截断，采用按综合分升序 + 4 路并发探测搭配 30 秒失败冷却期与 `consecutive_fail` 指数惩罚（$50 \times 2^n$），短暂抖动的头部优质节点冷却后自动回灌复用。
- **vDSO 单调时钟、秒级时间戳缓存与无锁关闭快路径**：
  - Linux 与 Android 使用 `clock_gettime(CLOCK_MONOTONIC)` 替代 `gettimeofday()`；日志采用 C23 `thread_local` 秒级缓存时间戳；连接正常关闭时通过 `fast_fail_count` 与 `has_node_fail` 原子无锁短路返回，99.9% 场景零锁开销。
- **冷启动端口预绑定（Early Binding）与优雅退出**：
  - 扫描前提前绑定监听端口（TCP Backlog `4096`），客户端首包握手先入内核队列，消除冷启动初期的 TCP RST；
  - 扫描线程数依 CPU 核心自适应降载（`min(task, 64 × nproc)`），保护低配软路由避免过度上下文切换。

### 3. 目标平台支持矩阵（纯静态架构）

构建产物全面采用**纯静态（Pure Static）独立二进制**或原生免外部依赖二进制，开箱即用：
- **Linux amd64 (x86_64)**：musl 纯静态独立二进制（`cfnat-linux-amd64`），无视发行版差异（Ubuntu / Debian / Alpine / CentOS / OpenWrt / Arch 均可直接运行）
- **Linux arm64 (aarch64)**：musl 纯静态独立二进制（`cfnat-linux-arm64`），适配各类 ARM VPS、树莓派及 OpenWrt 软路由
- **Android Termux (arm64 & amd64)**：Android NDK 编译（`cfnat-android-arm64` / `cfnat-android-amd64`），适配 Bionic libc 与 Android 沙箱 seccomp 审计，Termux 免 root 开箱即用
- **Windows 11 amd64 (x86_64)**：Win11 原生纯静态可执行文件（`cfnat-windows-amd64.exe`）
- **Windows 11 arm64 (aarch64)**：Surface / 骁龙 X Elite / ARM 笔记本原生运行（`cfnat-windows-arm64.exe`）

## 项目定位与转发链路

cfnat C 版做四件事：
1. **智能扫描与子网裂变优选**：扫描 Cloudflare IP，初筛精准 TCP (H2) 候选池，并结合同网段裂变衍生引擎精筛出 UDP (H3) 专用候选池。
2. **三栈同端口 TCP/UDP 双轨并发监听**：在 IPv4（`-v4-listen`）、IPv6（`-v6-listen`）与百度前置（`-baidu-listen`）各监听端口上同时监听 TCP 与 UDP 数据报，保持三栈 H2/H3 行为完全一致。
3. **精准双轨独立路由转发**：
   - TCP 连接（H2/TLS）转发至当前 **TCP 优选 IP**（支持通过首字节 `0x16` `MSG_PEEK` 自动分流 443 或 80 端口）；
   - UDP 报文（H3/QUIC）转发至当前 **UDP 优选 IP:443**，会话状态自动管理。
4. **双轨协同自愈与热替换**：候选池失效或冷却耗尽时，由独立维护线程异步触发双轨原地测活与增量补齐，绝不阻塞转发。

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
  - 采用 C23 标称类型枚举（`enum : uint8_t`）与 `[[nodiscard]]` 函数契约属性，压缩内存占用并杜绝关键资源返回值被疏漏丢弃。
- **TLS 真实端口直测与首包握手熔断**：
  - 未开启 `-colo` / `-code` 时直接在目标 TLS 端口（443）执行轻量 ClientHello 握手测速（严格对齐 1×RTT 物理口径），开启 `-colo` / `-code` 时则结合 HTTP HEAD 校验与首轮 TLS 握手验证；
  - 首轮握手失败即刻熔断死节点，大幅缩短扫描耗时。
- **H2 (TCP) + H3 (QUIC/UDP) 双轨独立测优与三栈透明分流**：
  - 在 `-v4-listen`、`-v6-listen` 与 `-baidu-listen` 监听端口上，TCP 流量导向 TCP 优选池，UDP/QUIC 流量导向 UDP 优选池；Xray 在三栈端口间切换时无需修改 H2/H3（`alpn`）配置。
- **RFC 9000 规范的 1200 字节轻量 QUIC 版本协商探针**：
  - 发送带保留版本号 `0x5A5A5A5A` 的 1200 字节 QUIC Initial 包，触发 Cloudflare 边缘节点立即回复 Version Negotiation 报文，零加密库依赖即可精准测得 UDP 443 真实延迟。
- **网段裂变衍生与双轨协同自愈**：
  - 捕获有效 UDP 种子网段后在同 `/24`（IPv4）或 `/64`（IPv6）内快速衍生相邻 IP 并发检验，补齐满额 H3 候选池；若本地网络完全阻断 UDP 443，绝不降级伪造假节点；
  - 双缓存文件（如 `direct-cache-v4.txt` 与 `direct-cache-v4-udp.txt`）采用临时文件 + `fsync` + 原子重命名安全落盘。
- **多行原子树状日志系统**：
  - 所有双轨日志左置 `[TCP/H2]`（高亮青色）与 `[UDP/H3]`（高亮洋红），启动与自愈汇报以树状结构原子输出，杜绝并发日志交错打断。
- **IPv6 `/48` 智能切分与完全展开格式**：
  - 支持通过 `-v6-split`（安全范围 `48` ~ `58`，默认 `54`，即每个 `/48` 切分为 64 个子网切片）生成高多样性离散候选，统一展开为 8 段完整 16 进制形式。
- **自适应渐进式健康检查**：
  - 节点稳定时检测间隔自动从 30s 退避至 60s（检测级别由 FULL 逐级降至 LIGHT），任意失败即刻回退至 10s 快速双检确认。

## Xray XMUX 协同机制说明

作为 Xray / Sing-box 等出站工具的前置中继，cfnat 与 Xray 的 **XMUX（H2/H3 多路复用控制器）** 及 `finalmask` 分片特性深度互补：

| 维度 | Xray (应用层客户端) | cfnat (L4 传输层中继) |
| :--- | :--- | :--- |
| **定位分工** | 负责流控制、多路复用（将 16~32 个请求合并进 1 条连接）、TLS 分片与消除流特征 | 负责全球 Anycast 路由优选、毫秒级测速、零拷贝/大缓冲中继、死节点故障自愈 |
| **TCP/H2 协同** | 开启 XMUX 与 `finalmask` 避免频繁握手并混淆特征 | 首包 `MSG_PEEK` 免重组透传分片 + `TCP_NODELAY` + BBR + `TCP_NOTSENT_LOWAT=64KB` + 45s 保活 + 25s 死连快收 |
| **UDP/H3 协同** | 依赖 QUIC 在单个 UDP 端口上传输海量 H3 数据包 | MRU + 8 位哈希分桶 $O(1)$ 查找 + `epoch` 无锁热迁移 + 4MB/1MB 分级缓冲 + 双向 32 包 `recvmmsg`/`sendmmsg` |
| **节点切换行为** | 依靠 `cMaxReuseTimes` / `hMaxReusableSecs` 定期温和轮换主连接 | **平滑收敛（Graceful Drain）**：TCP 切换时仅将新连接导向新 IP，绝不 RST 存量活跃连接 |

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
| `-v6-listen[=addr]` | 开启 IPv6 转发本地监听（不带参数时默认 `[::]:6443`） | 留空不开启 |
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
| `-domain` / `-v4-domain` / `-v6-domain` | 探测目标路径与 Host（用于 TLS SNI 与 HTTP 状态码检测） | `cloudflaremirrors.com/debian` |
| `-code` / `-v4-code` / `-v6-code` | 期望的有效 HTTP 状态响应码。<br>**缺省/为 0 时：直接走目标端口轻量握手测速（极大提速）；**<br>**显式指定（如 `-code=200` 或 `-v6-code=200`）时：结合 HTTP 响应码校验与 TLS 端口验证（杜绝 IPv6 Error 1034 限制）。** | `0` (仅测连通性) |
| `-delay` / `-v4-delay` / `-v6-delay` | 有效往返延迟（1×RTT）上限（毫秒），冷启动自动启用端口预绑定（Backlog `4096`）消除初期 RST | `300` |
| `-task` / `-v4-task` / `-v6-task` | 扫描并发线程数（上限 `2000`，并按 CPU 核心数自适应限制为 `64 × nproc`） | `200` |
| `-ipnum` / `-v4-ipnum` / `-v6-ipnum` | 保留的最优候选 IP 数量上限（Top-N 截断，上限 `1000`），同时作为原地自愈存活水位基准 | `20` |
| `-num` / `-v4-num` / `-v6-num` | 单 IP 探测尝试次数（上限 `50`；首包不通直接熔断，TLS 纯测速自动轻量化为最多 2 次） | `5` |
| `-port` / `-v4-port` / `-v6-port` | 上游 TLS 转发目标端口（注意区分本地监听与目标端口） | `443` |
| `-http-port` / `-v4-http-port` / `-v6-http-port` | 上游非 TLS 转发目标端口 | `80` |
| `-random` / `-v4-random` / `-v6-random` | 是否按 CIDR 随机抽样生成候选 IP | `true` |
| `-v6-split` | IPv6 `/48` 子网切分前缀掩码（安全范围 `48` ~ `58`，单段最多抽样 1024 个防 OOM）。<br>**默认 `54`：每个 `/48` 切分为 64 个 `/54` 子网各抽样 1 个**；统一展开为 8 段无缩写形式。 | `54` |
| `-baidu-resolver` | 针对 Fake-IP 的百度解析方式: `auto` / `udp://` / `doh://` | `auto` |
| `-bind-if` | 绑定出站物理网卡 (如 `eth0`、`en0`) | 留空使用默认路由 |
| `-health-log` | 定时输出健康检查日志的间隔秒数（仅在 `-log=debug` 时输出成功汇报，普通模式仅告警失败） | `60` |
| `-log` / `-log-level` | 日志级别：`silent` / `error` / `warn` / `info` / `debug`。<br>**`info`（默认）**：日常转发静默，仅输出关键里程碑（启动/自愈树状日志、故障切换）；<br>**`debug`**：输出每个有效 IP、详细进度、连接日志与完整候选表格。 | `info` |

## 常用示例

### 1. 经典双栈/三栈转发（单进程同时监听多个端口）
```bash
# 同时开启 IPv4（本地 4443）、IPv6（本地 6443）与百度前置（本地 5443），IPv6 指定检测 HTTP 200 排除 1034
./cfnat -baidu-listen=0.0.0.0:5443 -v4-listen=0.0.0.0:4443 -v6-listen=0.0.0.0:6443 -v6-code=200 -task=300 -exclude-colo=HKG
```

### 2. 自定义本地监听地址与目标端口
```bash
# IPv4 监听 127.0.0.1:1080，IPv6 监听 [::]:2080，上游 TLS 端口为 8443
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
- **内核套接字窗口（`SO_RCVBUF` / `SO_SNDBUF`）**：Linux TCP 接收与发送均交由内核自动调优并配合 `TCP_NOTSENT_LOWAT=64KB`；Windows TCP 设为 `2 MB`（自适应回退 `1 MB` / `512 KB`）；全平台 UDP 监听套接字设为 `4 MB`，会话套接字随并发数自适应分档（≤32 会话用 `1 MB` 档，>32 会话自动收敛至 `256 KB` 档），兼顾少会话高 BDP 吞吐与软路由防 OOM。
- **用户态转发缓冲（`COPY_BUF_SIZE = 64 KB`）**：在 Windows 11 与 Android Termux 上单次 `recv`/`send` 吞吐 4 个满载 16KB TLS 记录帧，在 CPU 核心 L2 Cache 命中率与高并发 RSS 内存占用之间取得最优平衡。
- **Linux 零拷贝管道（`F_SETPIPE_SZ = 256 KB`）**：单次 `splice()` 零拷贝系统调用可转移 64 个内核页面引用，且用户态回退函数通过 `noinline` 强隔离，走零拷贝通道时不占用用户态缓冲页。
- **按需分页虚拟线程栈（`512 KB`）**：扫描与转发线程虚拟栈设为 `512 KB`（动态对齐 `PTHREAD_STACK_MIN`），依托操作系统按需分页（Demand Paging）机制，未触碰的虚拟栈页不消耗物理内存（RSS）。
- **UDP/H3 批量队列与 $O(1)$ 检索**：Linux 与 Android 上下行双向启用 32 包 `recvmmsg` / `sendmmsg`（`thread_local` 静态队列占 `128 KB`，单包槽位 `4096 B` 防截断），配合 MRU + 8 位哈希分桶与原子 `epoch` 热迁移，实现高吞吐下的极低系统调用开销。

## 常见问题

### 1. 为什么扫描统计里显示“连接失败”数万次，但输入文件只有几百或几千行？
这是两个机制协同作用的正常结果：
1. **探测重试与失败累加**：启动参数 `-num` 代表单个 IP 的最大探测次数。虽然未连通的死 IP 已经由首包握手熔断机制规避了后续无效重试，但对于偶发丢包或超时节点，多次探测失败会进行人次累加；
2. **IPv6 的 `/48` 子网切分算法（`-v6-split=54`）**：`ips-v6.txt` 中每一行都是 `/48` 大段，每个大段包含 $2^{80}$ 个地址。代码默认将每个 `/48` 切分为 64 个 `/54` 子网各抽样 1 个 IP（633 行衍生出 40,512 个候选 IP）。因此实际扫描池规模在 4 万个以上，正是这种广泛的离散样本才使得在短时间内筛出极速节点成为可能。

### 2. 为什么只监听一个端口，却能同时处理 TLS、HTTP 与 QUIC/H3？
在同一监听端口上，程序同时绑定了 TCP 与 UDP 套接字：TCP 流量通过 `MSG_PEEK` 窥探首字节（`0x16` 判定为 TLS 自动转发到 `-port` 443，其他判定为 HTTP 自动转发到 `-http-port` 80，失败自动回退 443）；UDP 流量自动作为 QUIC/H3 数据报转发到 UDP 优选池节点的 443 端口。

### 3. IP 发生故障切换时，会导致客户端断流或网络卡顿吗？
不会。TCP 采用 **平滑收敛（Graceful Drain）** 机制，切换时仅将新连接导向新 IP，绝不 RST 存量活跃连接；UDP 在优选池 `epoch` 变更时随新包到达自动平滑重绑新上游，快速脱离劣化节点。

### 4. 为什么需要将 H2 与 H3 独立测优并在同一端口分别转发？
国内部分宽带运营商对境外 UDP 443 存在 QoS 限速甚至丢包策略。传统的测优工具只测 TCP，选出的最优 IP 往往在 TCP 下延迟极低，但 UDP 443 无法握手。cfnat 自动在底层将 TCP 流量导入 TCP 优选节点，将 UDP/QUIC 流量导入 H3 优选节点，真正做到了“一个配置端口，TCP 极速低延迟，UDP 稳通不断流”。

## 免责声明

本工具仅用于网络测试与学习用途。请在合法、合规的网络环境下使用，使用者自行承担因配置或使用造成的后果。
