# RustProbe Rust 替代路线图

本文档聚焦一个具体问题：

> 当前 Android 侧引入了较多 C 代码与第三方网络组件，后续是否适合继续 Rust 化，以及应该怎样替代。

本文档不讨论“是否追求语言纯度”，而是讨论：

- 哪些 C 代码是项目核心风险
- 哪些组件适合优先替换
- 哪些第三方能力短期不值得重写
- 可以用哪些 Rust 技术框架承接

## 1. 当前现状判断

从仓库结构看，C 代码的主要来源并不是自研检测逻辑，而是 Android `jni` 目录下的第三方转发/网络栈：

- `hev-socks5-tunnel`
- `hev-socks5-server`
- `lwip`
- `hev-task-system`

而项目真正的核心价值已经明显在 Rust 侧：

- `rustprobe-parse`
- `rustprobe-flow`
- `rustprobe-metrics`
- `rustprobe-detect`
- `rustprobe-store`

这意味着：

- 当前“C 代码占比高”更多是运行时与网络基础设施问题
- 当前“Rust 代码占比低”并不等于核心能力没有 Rust 化

## 2. 总体结论

结论不是“要不要 Rust 化”，而是：

1. 值得继续 Rust 化
2. 但不建议一步到位全量替换
3. 应该优先替换控制面和可控边缘层
4. 数据面转发栈要最后动

一句话概括：

> 先把项目从“Rust 检测核心 + C 转发底座”收敛成“Rust 主体 + 少量第三方 C 黑盒”，再决定是否彻底替掉黑盒。

## 3. 现有 C 部分分层

建议先把现有 C 代码按职责拆成 4 层来看：

### A. JNI / 桥接层

这部分通常负责：

- Java/Kotlin 与 native 交互
- 启停 tunnel / proxy
- 传递 fd / config / stats

特点：

- 替换成本低
- 风险低
- 对项目控制力提升明显

判断：

- 这是最适合优先 Rust 化的部分

### B. 控制面逻辑

这部分通常包括：

- tunnel 配置拼装
- session 生命周期
- 代理链路参数传递
- 运行状态上报

特点：

- 复杂度中等
- 与项目业务逻辑关系强
- 非性能瓶颈

判断：

- 非常适合回收进 Rust

### C. 转发运行时 / 事件循环

这部分通常包括：

- socket 驱动
- UDP / TCP 转发调度
- 用户态任务调度
- 会话转发表

特点：

- 复杂度高
- 稳定性敏感
- 很容易引入性能/兼容性回退

判断：

- 可以替，但不适合作为第一阶段目标

### D. 用户态网络栈

例如：

- `lwip`

特点：

- 最难
- 最耗时
- 最容易重构失控

判断：

- 除非未来明确要完全掌控转发数据面，否则短期不建议碰

## 4. 可选 Rust 技术框架

下面按“替代哪层”给出更现实的候选。

### 4.1 `tun-rs`

用途：

- 替代 TUN/TAP 接口基础设施
- 统一跨平台 TUN 抽象
- Android 可通过 `VpnService` fd 接入

适合承接：

- 现有 native 层中与 TUN 设备读写、配置、包装相关的部分

优势：

- 明确支持 Android
- 提供同步/异步接口
- 更容易和 Rust 主链路打通

不解决的问题：

- 不直接替代整套 tun2socks / socks5 转发逻辑

建议优先级：

- 很高

参考：

- https://github.com/tun-rs/tun-rs

### 4.2 `tokio`

用途：

- 替代事件循环与任务系统
- 承接异步 socket、定时器、并发会话管理

适合承接：

- `hev-task-system` 这一类运行时职责

优势：

- Rust 生态成熟
- 与现有 Rust 分析链更自然
- 有利于后续做检测、流式上报、规则引擎

不解决的问题：

- 不提供 TCP/IP 栈
- 不直接等于 tun2socks

建议优先级：

- 很高

参考：

- https://github.com/tokio-rs/tokio

### 4.3 `tun2proxy`

用途：

- 直接承接 TUN 到 SOCKS/HTTP Proxy 的转发

适合承接：

- 现有 `hev-socks5-tunnel` 的很大一部分定位

优势：

- 这是最接近“现成替代品”的 Rust 项目
- 明确支持 Android
- 明确支持 per-app routing 场景

风险：

- 是否完全匹配你们当前行为、稳定性、日志、统计需求，需要实测
- 很可能不能 1:1 无缝替换，需要做适配层

建议优先级：

- 高

参考：

- https://github.com/tun2proxy/tun2proxy

### 4.4 `smoltcp`

用途：

- 作为用户态 TCP/IP 栈候选

适合承接：

- 如果未来要把 `lwip` 也整体 Rust 化

优势：

- 纯 Rust
- 协议栈可控
- 从长期架构角度看很有吸引力

风险：

- 这是架构级重写，不是库替换
- Android 真机稳定性、性能、边界行为都要重新验证
- 工程量远高于替换桥接层

建议优先级：

- 中长期

参考：

- https://github.com/smoltcp-rs/smoltcp
- https://docs.rs/smoltcp/

### 4.5 `rustls`

用途：

- TLS 能力
- 证书、握手、加密配置相关能力

适合承接：

- 未来做更深入 TLS 分析、证书画像、检测辅助

说明：

- 它不是 tun2socks 替代品
- 但对威胁检测方向非常有价值

参考：

- https://github.com/rustls/rustls

### 4.6 `quinn`

用途：

- QUIC 实现

适合承接：

- 未来 QUIC / HTTP3 更深入检测、回放、实验性代理能力

说明：

- 它不是现有 C 栈的直接替代
- 但对后续检测与实验环境很重要

参考：

- https://github.com/quinn-rs/quinn

### 4.7 `Hickory DNS`

用途：

- DNS client / server / resolver

适合承接：

- DNS 解析、DNS 画像、DoH/DoT 分析与检测扩展

说明：

- 它不是转发栈替代品
- 更偏检测辅助基础设施

参考：

- https://github.com/hickory-dns/hickory-dns

## 5. 推荐替代顺序

建议分 4 个阶段推进。

### Stage 1：最小化 C 边缘层

目标：

- 让 JNI / config / lifecycle / stats 逐步转入 Rust 主逻辑

动作：

- 减少 C 侧状态机
- 让 Kotlin 尽量只和 Rust FFI 交互
- 把 native bridge 收敛成最薄的一层

收益：

- 风险最低
- 立刻提升可维护性

### Stage 2：替换运行时与 TUN 接口层

目标：

- 用 Rust 承接 TUN 和异步调度

建议组合：

- `tun-rs + tokio`

动作：

- 新建 Rust 原型路径
- 从 Android `VpnService` fd 直接喂给 Rust
- 在 Rust 内做异步读取、会话控制、代理转发调度

收益：

- 逐步摆脱 `hev-task-system`
- 控制面与数据面开始统一语言

### Stage 3：评估 `tun2proxy` 替代现有 tunnel

目标：

- 以最小重写成本替换大块 tun2proxy/tun2socks 逻辑

动作：

- 做独立 PoC
- 在真机对比：
  - TCP 稳定性
  - UDP/QUIC 行为
  - per-app owner resolution
  - 功耗
  - 丢包 / 断流 / 重连表现

收益：

- 如果 PoC 成功，能快速砍掉一大块自带 C 依赖

风险：

- 行为不一定完全兼容

### Stage 4：决定是否进入“全 Rust 数据面”

目标：

- 判断是否需要进一步替掉 `lwip` 级别组件

动作：

- 只有在以下条件下才考虑：
  - 现有替代方案无法满足检测或控制需求
  - 真机稳定性已经有足够回归能力
  - 团队愿意承担长期网络栈维护成本

建议候选：

- `smoltcp`

收益：

- 完整自主可控

风险：

- 代价最大

## 6. 不同方案的现实性排序

按你们当前阶段，我会这样排：

1. `tun-rs`
2. `tokio`
3. `tun2proxy`
4. `rustls / quinn / Hickory DNS`
5. `smoltcp`

说明：

- 前三项更偏“替代现有 C 运行面”
- 中间三项更偏“增强后续检测和协议能力”
- `smoltcp` 是“长期完全 Rust 化”的终局候选，而不是短期替换工具

## 7. 下一步建议

如果要开始做 Rust 替代，我建议下一轮不是直接重写，而是先做一个小 PoC：

### PoC 目标

- Android `VpnService` fd
- Rust 直接读取 TUN
- 通过 Rust runtime 做基本转发
- 保留现有 analytics / detect 链路

### 推荐 PoC 方案

- `tun-rs + tokio`
- 如果需要快速验证代理转发，再评估接 `tun2proxy`

### PoC 验收

- 能在真机上稳定跑 10 分钟以上
- 能访问常见网站
- 不明显劣化当前归因与分析链路
- CPU / 内存 / 电池表现可接受

## 8. 最终建议

最终我对这个问题的建议是：

- 要继续 Rust 化
- 但优先级要服务于“威胁检测路线”，不要被“全仓库去 C”绑架
- 先去掉你们自己控制面和运行时中的 C 依赖
- 把第三方 C 网络栈收缩成可替换黑盒
- 最后再决定是否真的要重写整个转发数据面

一句话总结：

> 最值得先替的不是 `lwip`，而是 JNI / runtime / tunnel orchestration；最值得先验证的 Rust 框架不是 `smoltcp`，而是 `tun-rs + tokio`，以及在合适时机评估 `tun2proxy`。
