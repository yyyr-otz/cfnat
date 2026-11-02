# cfnat C 版 (现代平台优化版)

面向低内存环境的 **Cloudflare IP 扫描 + 单端口 TCP 转发** 工具。

当前版本针对 **Linux、Windows 11 及 Android Termux 现代平台（amd64 / arm64）** 进行了专项热路径优化、零拷贝吞吐提升、I/O 抽象层加固与 Android 沙箱兼容适配。

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

### 2. 目标平台支持矩阵
当前重点维护与构建以下现代主流平台：
- **Linux amd64 (x86_64)**：glibc 动态版 + musl 全静态独立版
- **Linux arm64 (aarch64)**：glibc 动态版 + musl 全静态独立版（OpenWrt/软路由/ARM VPS 推荐）
- **Android Termux (arm64 & amd64)**：官方 NDK r26b 编译，适配 Bionic libc 与 seccomp 审计，Termux 开箱即用
- **Windows 11 amd64 (x86_64)**：Win11 原生纯静态可执行文件
- **Windows 11 arm64 (aarch64)**：Surface / 骁龙 X Elite / ARM 笔记本原生运行

> **不再主动支持的平台**：
> - Windows 7 / XP 及 32 位系统（宏定义已升级为 `_WIN32_WINNT=0x0A00` Win10/11）。
> - 老旧 32 位嵌入式架构（ARMv5/ARMv6/ARMv7、MIPS、MIPSEL）。
> - 小众服务器架构（MIPS64、PowerPC、RISC-V 64、s390x）及 macOS。

---

## 项目定位与转发链路

cfnat C 版做三件事：
1. 扫描 Cloudflare IP，按数据中心、延迟、丢包率筛出候选节点。
2. 在本机监听一个 TCP 端口，自动识别 TLS / 非 TLS 流量。
3. 把客户端连接转发到当前可用的 Cloudflare 优选 IP，并在失败时自动切换。

它只做纯粹的高性能 TCP 字节转发，不是 HTTP 反向代理，也不会解密或篡改业务数据。

```text
客户端  ──→  cfnat 本地监听端口  ──→  Cloudflare 优选 IP:443 或 :80
                                  (可选) 百度前置节点(HTTP CONNECT)
```

---

## 核心特性

- **渐进式三级健康检查**（FULL → MEDIUM → LIGHT）：新节点 FULL 探测建立基线，连续成功即逐级降级，任意失败立即升级至 FULL，以最小开销保障候选池质量。
- **初筛 HTTP 200 深度状态校验**：延迟初筛后对可通 IP 执行完整的 HTTP 响应码（默认 200）验证，根除 Cloudflare IPv6 Anycast 伪通及 Error 1034（Edge IP Restricted）毒丸节点。
- **单端口同时承接 TLS 与非 TLS / HTTP 流量**：客户端只需连接一个本地端口，程序根据首字节（`0x16`）自动分流到 443 或 80 目标端口。
- **灵活的数据中心筛选与反选**：支持正选白名单，支持 `-HKG`、`^HKG`、`!HKG` 排除语法，并提供专用的 `-exclude-colo` 参数。
- **启动自动打印全量生效配置**：启动瞬间以 INFO 级别详尽列出所有运行参数（包含隐藏的缺省默认值），便于排查。
- **EWMA 综合评分选优**：候选 IP 按 EWMA 平滑延迟（α=0.125）、丢包率、抖动和连续失败次数综合打分，始终使用当前 score 最低的最优 IP。
- **SNI 感知 IP 选择**：读取客户端 TLS ClientHello 中的 SNI，为不同域名选择独立的最优 IP；连接失败时自动回退。
- **候选缓存与快速启动**：默认启用缓存，二次启动时先对缓存 IP 做快速健康检查，命中后立即监听，秒级恢复。
- **优选网段资产沉淀 (`-env.txt`)**：每次扫描出连通合格的 IP 时，自动将其聚合为前缀（IPv4 为 `/24`，IPv6 为 `/48`）并附加对应机房（如 `104.16.2.0/24,SJC` 或 `2606:4700:4401::/48,NRT`），按整行字典序去重沉淀到 `ips-v4-env.txt` 与 `ips-v6-env.txt`，便于用户长期提炼归纳专属网络环境下的高质量段库。
- **IPv6 CIDR 随机抽样**：IPv6 /64 及以上前缀范围使用随机采样，避免 IPv6 展开导致内存爆炸。
- **内置 DNS 系统**：内置 DoH（AliDNS、Cloudflare）与 UDP DNS 解析器，自动检测 198.18.0.0/15 Fake-IP 并回退。
- **CIDR 惰性展开**：只存 CIDR 范围，按需计算 IP，KB 级内存即可处理百万级 IP 段。

---

## 快速开始与编译

### 1. 本地编译

**Linux（glibc 动态版）**：
```bash
gcc -O2 -pipe -std=c11 -Wall -Wextra -Wno-unused-parameter \
  ./cfnat.c -o ./cfnat-linux -pthread
```

**Linux（musl 静态版，推荐给 OpenWrt / Alpine）**：
```bash
zig cc -target x86_64-linux-musl -O2 -pipe -std=c11 \
  -Wall -Wextra -Wno-unused-parameter \
  ./cfnat.c -o ./cfnat-linux-amd64-musl -pthread -static -s
```

**Windows 11（Zig 交叉编译）**：
```bash
zig cc -target x86_64-windows-gnu -O2 -pipe -std=c11 -D_WIN32_WINNT=0x0A00 \
  -Wall -Wextra -Wno-unused-parameter \
  ./cfnat.c -o ./cfnat.exe -lws2_32 -ldnsapi -lwininet -static -s
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

### 1. 监听模式参数（用于开启本地端口转发）

| 参数 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `-v4-listen[=addr]` | 开启 IPv4 转发本地监听（不带参数时默认 `0.0.0.0:4443`；若全部未指定，则默认开启此项） | 缺省未显式指定时默认 `0.0.0.0:4443` |
| `-v6-listen[=addr]` | 开启 IPv6 转发本地监听（不带参数时默认 `0.0.0.0:6443`） | 留空不开启 |
| `-baidu-listen[=addr]` | 开启百度前置优选本地监听（不带参数时默认 `0.0.0.0:5444`） | 留空不开启 |
| `-direct-listen[=addr]` | 兼容旧版参数：按 `-ips` 指定类型开启直连监听 | 留空不开启 |

> [!TIP]
> - 支持同时指定任意多个监听参数（例如 `-v4-listen -v6-listen`），即可**单进程同时开启 IPv4 与 IPv6 双转发**，彻底告别多开两个程序的繁琐配置！
> - 若 `-v4-listen`、`-v6-listen`、`-baidu-listen`、`-direct-listen` 均未指定，程序默认自动开启 IPv4 监听 `0.0.0.0:4443`。

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
| `-ipnum` / `-v4-ipnum` / `-v6-ipnum` | 保留的最优候选 IP 数量 | `20` |
| `-num` / `-v4-num` / `-v6-num` | 单 IP 探测尝试次数 | `5` |
| `-port` / `-v4-port` / `-v6-port` | 上游 TLS 转发目标端口（注意区分本地监听与目标端口） | `443` |
| `-http-port` / `-v4-http-port` / `-v6-http-port` | 上游非 TLS 转发目标端口 | `80` |
| `-random` / `-v4-random` / `-v6-random` | 是否按 CIDR 随机抽样生成候选 IP | `true` |
| `-baidu-resolver` | 针对 Fake-IP 的百度解析方式: `auto` / `udp://` / `doh://` | `auto` |
| `-bind-if` | 绑定出站物理网卡 (如 `eth0`、`en0`) | 留空使用默认路由 |
| `-health-log` | 定时输出健康检查日志的间隔秒数 | `60` |
| `-log` | 日志级别：`silent` / `error` / `warn` / `info` / `debug` | `info` |

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

### 3. 仅测速扫描（不监听）
```bash
./cfnat -colo=HKG -delay=150 -ipnum=10
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

### 6. 配合 Xray / Sing-box 出站优选
```bash
./cfnat -v6-listen=443 -port=443 -http-port=80 -v6-code=200 -task=300 -exclude-colo=HKG
```

---

## 构建与 GitHub Actions 发布

工作流文件位于 `.github/workflows/build.yml`：
- **自动构建产物**：
  - `cfnat-linux-amd64` / `cfnat-linux-arm64` (glibc 动态版)
  - `cfnat-linux-amd64-musl` / `cfnat-linux-arm64-musl` (musl 纯静态版)
  - `cfnat-android-arm64` / `cfnat-android-amd64` (Android NDK Termux 原生版)
  - `cfnat-windows-amd64.exe` / `cfnat-windows-arm64.exe` (Win11 纯静态版)
- **触发与发布方式**：
  - **推送 Tag 发布**：推送形如 `v0.0.15` 的标签时自动触发编译并发布到 Release。
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

---

## 免责声明

本工具仅用于网络测试与学习用途。请在合法、合规的网络环境下使用，使用者自行承担因配置或使用造成的后果。
