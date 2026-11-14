# cfnat C 版 (C23 纯静态现代平台版)

面向低内存环境的 **Cloudflare IP 扫描 + 单端口 TCP/UDP (H2/H3) 双轨透明转发** 工具。

本项目采用最新的 **C23 国际标准 (ISO/IEC 9899:2024)** 进行现代化重构，针对 **Linux、Windows 11 及 Android Termux 现代平台（amd64 / arm64）** 构建**纯静态（Pure Static）独立二进制**，彻底剥离 glibc 依赖，根除一切跨发行版兼容性问题。同时全面集成了 **HTTP/2 (TCP) 与 HTTP/3 (QUIC/UDP) 双轨独立测优与协同转发机制（v0.0.17-c23）**。

核心目标是保留扫描、优选、转发、健康检查、百度前置代理和双方案监听等核心能力的同时，尽量压低常驻内存占用，非常适合 OpenWrt/软路由、手机 Termux、小内存 VPS 以及 Windows 11 设备。

---

## 目录

- [现代平台优化与支持说明](#现代平台优化与支持说明)
- [项目定位与转发链路](#项目定位与转发链路)
- [核心特性](#核心特性)
- [快速开始与编译](#快速开始与编译)
- [Android Termux 运行指南](#android-termux-运行指南)
- [运行参数](#运行参数)
- [常用示例](#常用示例)
- [构建与 GitHub Actions 发布](#构建与-github-actions-发布)
- [资源占用说明](#资源占用说明)
- [常见问题](#常见问题)
- [免责声明](#免责声明)

---

## ⚡ 现代平台优化与支持说明

### 1. 核心性能优化
- **全链路禁用 Nagle 算法（`TCP_NODELAY`）**：在接入客户端连接以及拨号上游连接时全面注入，消除 40ms 交互延迟，显著提升 TLS 握手及首包响应速度。
- **高并发热路径无锁化加速（`carrier_choose_ip_fast`）**：新连接进入时，通过 `atomic_load_explicit(..., memory_order_acquire)` 原语判定缓存有效性，并使用直接内存复制替代格式化解析，大幅消除连接建立时对全局互斥锁的争抢。
- **Linux 内核级零拷贝加固（`splice`）**：
  - 开启 `SPLICE_F_MORE` 提示内核聚合数据包，显著提升转发吞吐量；
  - 16 KB 回退缓冲区解耦，在走零拷贝时彻底杜绝无谓的栈内存分配，根除 64 KB 极小线程栈下的栈溢出隐患。
- **Windows 11 EventLoop 事件驱动补齐**：完善非 epoll 平台下的 `evloop_wait_select` 回退实现，支持 Windows 下单套接字的非阻塞异步事件等待，解决 HTTP 探测时的虚假超时。
- **Android Termux 沙箱审计兼容**：在 Android 平台下自动隔离 `splice` 系统调用，避免触发 Android `seccomp` 过滤机制报 `signal 31 (SIGSYS)` 错误，确保转发稳定。

### 2. 目标平台支持矩阵（纯静态架构）
构建产物全面采用**纯静态（Pure Static）独立二进制**，无外部动态库依赖，开箱即用：
- **Linux amd64 (x86_64)**：musl 纯静态独立二进制（`cfnat-linux-amd64`），仅需 Linux 3.10+ 内核，无视发行版差异（Ubuntu / Debian / Alpine / CentOS / OpenWrt / Arch 均可直接运行，彻底告别 `GLIBC_xxx not found` 动态库不兼容报错）
- **Linux arm64 (aarch64)**：musl 纯静态独立二进制（`cfnat-linux-arm64`），适配各类 ARM VPS、树莓派及各类 OpenWrt 软路由
- **Android Termux (arm64 & amd64)**：官方最新 NDK r27c (LTS) 编译（`cfnat-android-arm64` / `cfnat-android-amd64`），适配 Bionic libc 与 Android 沙箱 seccomp 审计，Termux 免 root 开箱即用
- **Windows 11 amd64 (x86_64)**：Win11 原生纯静态可执行文件（`cfnat-windows-amd64.exe`）
- **Windows 11 arm64 (aarch64)**：Surface / 骁龙 X Elite / ARM 笔记本原生运行（`cfnat-windows-arm64.exe`）

> **不再主动支持的平台**：
> - Windows 7 / XP 及 32 位系统（宏定义已升级为 `_WIN32_WINNT=0x0A00` Win10/11）。
> - 老旧 32 位嵌入式架构（ARMv5/ARMv6/ARMv7、MIPS、MIPSEL）。
> - 小众服务器架构（MIPS64、PowerPC、RISC-V 64、s390x）及 macOS。

---

## 项目定位与转发链路

cfnat C 版做四件事：
1. **智能扫描与两阶段过采样**：扫描 Cloudflare IP，初筛 TCP (H2) 候选池，并基于轻量 QUIC 探针精筛出 UDP (H3) 专用候选池。
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

- **全面遵循 C23 现代语言标准与零开销契约（v0.0.17-c23）**：
  - 核心源码全面遵循 ISO/IEC 9899:2024 (C23) 标准规范，全面引入 `nullptr` 类型安全空指针、`constexpr` 编译期常量及数字分隔符（如 `16'384`）；
  - 采用 C23 标称类型枚举（`enum : uint8_t`），精确压缩枚举变量的内存占用并改善 CPU 缓存命中率；
  - 注入 `[[nodiscard]]` 函数契约属性，严格杜绝关键资源、套接字与健康探测返回值被疏漏丢弃的潜在隐患；
  - 彻底剥离动态库，发布纯静态 Linux 二进制，极大简化在各类路由器与轻量容器上的部署难度。
- **H2 (TCP) + H3 (QUIC/UDP) 双轨独立测优与透明分流**：
  - **痛点解决**：国内部分 ISP 对境外 UDP 443 存在严重 QoS 限制甚至黑洞，很多 TCP 延迟极佳的 IP 无法传输 QUIC；传统的“单优选 IP”会导致 H3 频繁断流或连不上。
  - **独立路由**：同一监听地址（如 `127.0.0.1:4443`）上，TCP 流量自动打向 TCP 最优节点，UDP/QUIC 流量自动打向 UDP 响应最优节点。
- **RFC 9000 规范的 1200 字节轻量 QUIC 版本协商探针（Version Negotiation Probe）**：
  - 发送带有保留版本号 `0x5A5A5A5A` 的 1200 字节 QUIC Initial 数据包，诱导 Cloudflare 边缘节点立即回复 27 字节的 Version Negotiation 报文。
  - **零加密算法库开销**（无需引入 BoringSSL/OpenSSL 等笨重依赖，保持纯单文件 C 极致轻量），**零 CPU 密钥计算消耗**，单包即可精确测得 UDP 443 真实往返 RTT，且完全符合 RFC 9000 防放大攻击要求（规避 Cloudflare 丢弃小包）。
- **两阶段漏斗形 2× 过采样优选（Funnel Oversampling）**：
  - TCP 先在全量 IP 中并发扫描出 Top 候选节点；
  - 仅对 TCP 表现最好的前 `ipnum * 2` 个节点，以 25ms 间隔温和发送 QUIC 探针（避免并发激增被运营商 QoS 判定为扫描阻断），精选出延迟最佳的 `ipnum` 个节点建立 UDP 候选池；
  - 若当地环境完全阻断 UDP 443，自动优雅降级使用 TCP 最优 IP，确保可靠性。
- **双轨协同自愈机制（Coordinated Dual-Pool Self-Healing）**：
  - **统一自愈引擎**：无论 TCP 池见底还是 UDP 池见底（存活低于 25% 或顺位消耗达 70%），互斥锁保障仅触发一次双轨原地测活与增量补充。
  - **存活火种合并**：提取两池尚存活的 IP 与全新扫描结果统一排序重排，前 `ipnum` 补充 TCP 池，前 `2*ipnum` 精筛补充 UDP 池，双缓存文件（`direct-cache-v4.txt` 与 `direct-cache-v4-udp.txt`）同步沉淀持久化。
- **双轨独立健康检查守护线程**：
  - TCP 采用渐进式三级检测（FULL → MEDIUM → LIGHT）；
  - UDP 采用 30 秒定时间歇式轻量 QUIC 探针；
  - 任意轨道连续 2 次失败触发顺位切换，水位告警触发双轨协同自愈。
- **现代化分级与 ANSI 彩色日志系统（深度降噪与可视化）**：
  - **默认级别彻底降噪**：日常转发连接（`[CONN]`）与健康检查成功汇报默认保持静默，仅在发生故障切换或自愈时告警，控制台杂音降低 95% 以上；
  - **终端动态单行刷新**：扫描时在 TTY 终端下自动启用 `\r` 原地单行进度刷新，杜绝滚屏破坏终端历史；
  - **全量调试与结果表格（`-log=debug`）**：在 DEBUG 模式下，实时流式打印每个被发现的有效 IP（含位置与延迟）、详细百分比进度，且无论命中缓存还是全新扫描，均以 ANSI 彩色高亮输出规整的候选池明细表格（绿/黄/红直观标识延迟）。

- **渐进式三级健康检查**（FULL → MEDIUM → LIGHT）：新节点 FULL 探测建立基线，连续成功即逐级降级，任意失败立即升级至 FULL，以最小开销保障候选池质量。
- **初筛 HTTP 200 深度状态校验**：延迟初筛后对可通 IP 执行完整的 HTTP 响应码（默认 200）验证，根除 Cloudflare IPv6 Anycast 伪通及 Error 1034（Edge IP Restricted）毒丸节点。
- **单端口同时承接 TLS 与非 TLS / HTTP 流量**：客户端只需连接一个本地端口，程序根据首字节（`0x16`）自动分流到 443 或 80 目标端口。
- **灵活的数据中心筛选与反选**：支持正选白名单，支持 `-HKG`、`^HKG`、`!HKG` 排除语法，并提供专用的 `-exclude-colo` 参数。
- **启动自动打印全量生效配置**：启动瞬间以 INFO 级别详尽列出所有运行参数（包含隐藏的缺省默认值），便于排查。
- **EWMA 综合评分选优**：候选 IP 按 EWMA 平滑延迟（α=0.125）、丢包率、抖动和连续失败次数综合打分，始终使用当前 score 最低的最优 IP。
- **SNI 感知 IP 选择**：读取客户端 TLS ClientHello 中的 SNI，为不同域名选择独立的最优 IP；连接失败时自动回退。
- **候选缓存与快速启动**：默认启用缓存，二次启动时先对缓存 IP 做快速健康检查，命中后立即监听，秒级恢复。
- **候选池自愈与带电热替换（消灭断流卡顿）**：
  - **被动顺位切换（低开销）**：日常依赖真实连接质量被动触发切换，减少后台无意义的 TCP 探活握手；
  - **70% 消耗阈值拦截与原地自愈**：主 IP 闪断时顺位向后尝试；达到 70% 消耗阈值时自动拦截，花约 300ms 对现有池执行原地快速并发测活，存活数 $\ge \max(3, 25\%)$ 时自动切回极品低延迟节点，免除 90% 以上的全量大扫描阻塞；
  - **“带电作业”平滑补仓**：存活数量不足时绝不提前砸池断网，保留当前最优存活 IP 维持业务流量转发；后台温和并发补充扫描，双缓冲原子热替换新旧池，实现客户端不断流、不掉线的平滑体验。
- **优选网段资产沉淀 (`-env.txt`)**：每次扫描出连通合格的 IP 时，自动将其聚合为前缀（IPv4 为 `/24`，IPv6 为 `/48`）并附加对应机房（如 `104.16.2.0/24,SJC` 或 `2606:4700:4401::/48,NRT`），按整行字典序去重沉淀到 `ips-v4-env.txt` 与 `ips-v6-env.txt`，便于用户长期提炼归纳专属网络环境下的高质量段库。
- **IPv6 /48 智能切分与完全展开格式**：支持通过 `-v6-split`（默认 `/54`，即每个 `/48` 细分为 64 个子网切片）为庞大的 IPv6 地址块生成离散候选样本；生成的 IPv6 地址全部统一展开为 8 段完整 16 进制形式（如 `2606:4700:9a68:1591:f76d:d848:b5de:8e02`），杜绝 `::` 缩写歧义。
- **内置 DNS 系统**：内置 DoH（AliDNS、Cloudflare）与 UDP DNS 解析器，自动检测 198.18.0.0/15 Fake-IP 并回退。
- **CIDR 惰性展开**：只存 CIDR 范围，按需计算 IP，KB 级内存即可处理百万级 IP 段。

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

## 运行参数

### 1. 监听模式参数（用于开启本地端口转发与运行模式控制）

| 参数 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `-cli` / `-scan-only` | 显式开启 **单次 CLI 测速模式**。仅执行一次测速、在终端打印美化彩色候选 IP 表格并保存缓存文件后立即退出，绝不启动常驻转发监听服务。 | 留空不开启 (默认按监听参数启动常驻转发) |
| `-v4-listen[=addr]` | 开启 IPv4 转发本地监听（不带参数时默认 `0.0.0.0:4443`；若全部未指定，则默认开启此项） | 缺省未显式指定时默认 `0.0.0.0:4443` |
| `-v6-listen[=addr]` | 开启 IPv6 转发本地监听（不带参数时默认 `0.0.0.0:6443`） | 留空不开启 |
| `-baidu-listen[=addr]` | 开启百度前置优选本地监听（不带参数时默认 `0.0.0.0:5444`） | 留空不开启 |
| `-direct-listen[=addr]` | 兼容旧版参数：按 `-ips` 指定类型开启直连监听 | 留空不开启 |

> [!TIP]
> - 支持同时指定任意多个监听参数（例如 `-v4-listen -v6-listen`），即可**单进程同时开启 IPv4 与 IPv6 双转发**，彻底告别多开两个程序的繁琐配置！
> - 若 `-v4-listen`、`-v6-listen`、`-baidu-listen`、`-direct-listen` 均未指定且未指定 `-cli` / `-scan-only`，程序默认自动开启 IPv4 转发监听 `0.0.0.0:4443`。
> - 若仅需执行单次测速打印表格（不启动转发监听），请指定 `-cli` 或 `-scan-only`（如 `./cfnat -cli -colo=HKG`）。

### 2. 通用参数与协议级前缀参数

所有常规参数均支持**全局通用**与**分流独立配置**：
- **不带前缀的参数**（如 `-delay=200`、`-task=300`、`-port=443`）作为基准默认配置，自动被所有实例继承；
- **带有 `-v4-` 或 `-v6-` 前缀的参数**（如 `-v6-code=200`、`-v4-delay=150`）仅对对应实例生效，享有最高优先级覆盖基准；
- 未开启的转发实例会自动忽略对应的专属前缀参数。

| 参数（通用 / v4专属 / v6专属） | 说明 | 默认值 |
| :--- | :--- | :--- |
| `-ips` | 全局指定 IP 类型：`4` (IPv4) 或 `6` (IPv6) | `4` |
| `-colo` / `-v4-colo` / `-v6-colo` | 匹配特定数据中心，支持反选 (前缀 `-` / `^` / `!`)，如 `HKG,SJC` 或 `-HKG,-SJC` | 留空全部匹配 |
| `-exclude-colo` / `-v4-exclude-colo` / `-v6-exclude-colo` | 显式排除的数据中心列表，如 `HKG,SJC`（支持与 `-colo` 自动合并） | 留空不排除 |
| `-domain` / `-v4-domain` / `-v6-domain` | 探测目标路径与 Host（用于状态码检测） | `cloudflaremirrors.com/debian` |
| `-code` / `-v4-code` / `-v6-code` | 期望的有效 HTTP 状态响应码。<br>**缺省/为 0 时：仅测连通性与延迟，跳过 HTTP 响应码检验（极大提速）；**<br>**显式指定（如 `-code=200` 或 `-v6-code=200`）时：测得延迟后进一步校验 HTTP 状态码（杜绝 IPv6 Error 1034 限制）。** | `0` (仅测连通性) |
| `-delay` / `-v4-delay` / `-v6-delay` | 有效延迟上限（毫秒） | `300` |
| `-task` / `-v4-task` / `-v6-task` | 扫描并发线程数 | `200` |
| `-ipnum` / `-v4-ipnum` / `-v6-ipnum` | 保留的最优候选 IP 数量上限（Top-N 截断）。程序有多少保留多少，不强制要求凑满；同时作为后台实例 70% 消耗拦截与 25% 存活门槛的水位基准。 | `20` |
| `-num` / `-v4-num` / `-v6-num` | 单 IP 探测尝试次数 | `5` |
| `-port` / `-v4-port` / `-v6-port` | 上游 TLS 转发目标端口（注意区分本地监听与目标端口） | `443` |
| `-http-port` / `-v4-http-port` / `-v6-http-port` | 上游非 TLS 转发目标端口 | `80` |
| `-random` / `-v4-random` / `-v6-random` | 是否按 CIDR 随机抽样生成候选 IP | `true` |
| `-v6-split` | IPv6 /48 子网切分前缀掩码（有效范围 `48` ~ `64`）。<br>**默认 54：将每个 /48 切分为 64 个 /54 子网并在每个子网中随机抽样 1 个候选**（共生成约 4 万个离散候选，大幅增强路由与机房多样性）；<br>若设为 `48` 则每个 /48 仅抽样 1 个。生成的 IPv6 统一展开为标准的 8 段无缩写形式（如 `2606:4700:9a68:1591:f76d:d848:b5de:8e02`）。 | `54` (每个 /48 切分抽样 64 个) |
| `-baidu-resolver` | 针对 Fake-IP 的百度解析方式: `auto` / `udp://` / `doh://` | `auto` |
| `-bind-if` | 绑定出站物理网卡 (如 `eth0`、`en0`) | 留空使用默认路由 |
| `-health-log` | 定时输出健康检查日志的间隔秒数（仅在 `-log=debug` 时输出成功汇报，普通模式仅告警失败） | `60` |
| `-log` / `-log-level` | 日志级别：`silent` / `error` / `warn` / `info` / `debug`。<br>**`info`（默认）**：日常转发与周期健康检查完全静默，仅输出关键里程碑（启动、自愈、故障切换等），彻底杜绝连接建立/断开刷屏；终端下支持单行原地刷新扫描进度；<br>**`debug`**：开启全量调试模式，实时输出扫描发现的每个有效 IP 及位置信息、详细百分比进度、无论命中缓存还是新扫描均完整打印候选 IP 表格，支持全局 ANSI 语法高亮。 | `info` |

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
# 方式 A：直接在 -colo 参数中使用减号前缀
./cfnat -v6-listen -colo=-HKG

# 方式 B：使用专用的 -exclude-colo 参数（脚本/HTML/VBS 环境下最安全）
./cfnat -v6-listen -exclude-colo=HKG,SJC
```

### 5. 直连与百度前置同时监听
```bash
./cfnat -v4-listen=40000 -baidu-listen=40001 -colo=HKG
```

### 6. 配合 Xray / Sing-box 出站优选（单端口 H2 + H3 全透明支持）
```bash
# 本地监听 127.0.0.1:4443，自动开启 TCP/H2 与 UDP/H3 双轨测优
./cfnat -v4-listen=127.0.0.1:4443 -colo=HKG,SJC -delay=200 -task=300
```
客户端（如 Xray / v2rayN / Sing-box / Clash Verge）配置：
- **服务器地址 (Address)**: `127.0.0.1`
- **端口 (Port)**: `4443`
- **协议说明**：无论客户端走普通的 TCP (VLESS/VMess + H2/XTLS)，还是走基于 UDP 的 HTTP/3 (QUIC)，客户端均连接 `127.0.0.1:4443`。cfnat 自动在底层将 TCP 流量导入 TCP 优选节点，将 UDP/QUIC 流量导入 H3 优选节点，无需客户端配置复杂分流！

---

## 构建与 GitHub Actions 发布

工作流文件位于 `.github/workflows/build.yml`：
- **自动构建产物（全部为纯静态或原生免外部依赖二进制）**：
  - `cfnat-linux-amd64` (Linux x86_64 musl 纯静态版)
  - `cfnat-linux-arm64` (Linux aarch64 musl 纯静态版)
  - `cfnat-android-arm64` / `cfnat-android-amd64` (Android NDK Termux 原生版)
  - `cfnat-windows-amd64.exe` / `cfnat-windows-arm64.exe` (Win11 纯静态版)
- **触发与发布方式**：
  - **推送 Tag 发布**：推送形如 `v0.0.17` 的标签时自动触发编译并发布到 Release。
  - **手动网页触发发布**：在 GitHub Actions 页面点击 **Run workflow**，支持输入版本号或自动从 `cfnat.c` 提取版本号，支持重复发布时强制覆盖更新 Release 资源。

---

## 资源占用说明

C 版的核心价值是降低常驻资源占用。相较于 Go 版，C 版没有 Go 运行时、GC 和 goroutine 调度器的额外常驻成本：
- 双向转发缓冲区固定为 `16 KB`，降低常驻内存。
- 连接线程栈精简为 64 KB。
- 候选结果只保留必要字段，CIDR 惰性展开，KB 级内存即可处理百万级 IP 段。
- 连接级 IP 选择缓存（cache_valid）结合原子原语，避免连接建立时的高频加锁与健康检查。
- EventLoop 使用原生 epoll，select 回退，兼顾极简与并发效率。

---

## 常见问题

### 1. 为什么只监听一个端口，却能同时处理 TLS 和 HTTP？
程序读取客户端连接的首字节：首字节为 `0x16` 时判定为 TLS 握手，自动转发到 `-port`（443）；其他数据判定为 HTTP/非 TLS，自动转发到 `-http-port`（80）。

### 2. 运行时提示找不到数据文件？
程序启动时会查找同目录下的 `ips-v4.txt`、`ips-v6.txt` 和 `locations.json`。如文件不存在，程序会自动尝试联网下载；离线环境下请确保将这三个文件置于同级目录下。

### 3. Android Termux 下出现 `Permission denied`？
- 确保没有使用 `-bind-if`（普通非 root 应用无权绑定网卡设备）；
- 确保本地监听端口大于 1024（如 40000），避免特权端口绑定受阻。

### 4. 若单次扫描获得的符合要求的 IP 数量少于 `-ipnum`，程序会怎样处理？
`-ipnum` 是**保留上限（Top-N 截断）**，而非阻塞等待凑齐的下限：
- **CLI 测速模式**：直接输出已测出的合格 IP（即使只有 1~2 个）并保存退出，不循环重跑；
- **后台转发模式**：直接以现有可用 IP 启动服务；后续若发生故障切换，会根据前 70% 顺位切换、原地测活自愈与后台平滑增量补齐机制动态维护候选池，绝不会因为数量不足而死循环或清空中断服务。

### 5. IP 发生故障切换时，会导致客户端断流或网络卡顿吗？
针对传统代理“池子耗尽就全量阻塞重扫 10 秒导致完全断网”的痛点，现代版 cfnat 引入了**阶梯式自愈与带电补仓**：
1. **顺位切换几乎瞬间完成（~0ms）**；
2. **达到 70% 阈值时执行原地 300ms 快速并发测活**，只要有可用节点（$\ge 3$ 个或 $25\%$）即自动满血复原；
3. **即使存活极少，也会保留最优节点继续承接客户端流量**，后台温和补仓后原子替换，彻底消灭断流掉线与报错。

### 6. 为什么需要将 H2 与 H3 独立测优并在同一端口分别转发？
- **现实网络差异**：国内部分宽带运营商（如移动、部分省份电信/联通）对境外 UDP 443 存在 QoS 严重限速甚至丢包策略。传统的测优工具只测 TCP，选出的最优 IP 往往在 TCP 下延迟极低，但 UDP 443 根本无法握手。若客户端启用了 HTTP/3 (QUIC)，就会出现页面加载超时、回退延迟严重甚至断流现象。
- **单端口同构透明路由**：cfnat 在同一个本地监听地址（如 `127.0.0.1:4443`）上同时开启 TCP 与 UDP 监听。Xray / Sing-box / 浏览器等客户端只需将代理目标地址配置为 `127.0.0.1:4443`，无需在客户端上配置两套复杂的端口规则：
  - 发送 TCP 连接（H2/TLS）时，cfnat 自动转发至经由 TCP 测优出的最优 IP；
  - 发送 UDP 报文（H3/QUIC）时，cfnat 自动转发至经由 RFC 9000 QUIC 探针精选出的 H3 优选 IP；
  - 真正做到了“一个配置端口，TCP 极速低延迟，UDP 稳通不断流”。

---

## 免责声明

本工具仅用于网络测试与学习用途。请在合法、合规的网络环境下使用，使用者自行承担因配置或使用造成的后果。
