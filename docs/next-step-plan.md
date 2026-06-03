# RustProbe 下一阶段计划

本文档用于承接 `2026-06-03` 这一轮实现结果，聚焦后续可执行工作，而不是继续扩散需求范围。

## 1. 当前阶段结论

当前最关键的第一阶段目标已经基本达成：

- 非 Root 条件下的 `VPNService -> TUN -> Rust` 主链路已打通
- 真机上已经能够持续捕获真实网络流量
- 基础解析、流表聚合、对象聚合、JSONL 落盘已具备最小可用能力

因此下一阶段不再以“能不能抓到流量”为中心，而是转向：

1. 抓到的流量能否更稳定、更安静地运行
2. 抓到的流量能否还原出更高价值的应用层线索
3. 抓到的流量能否稳定归因到单应用 / 多应用

## 2. 下一阶段目标

下一阶段建议聚焦 4 条主线：

1. 完善应用归因链路
2. 接入最小应用层解析
3. 提升存储与观测质量
4. 为后续 UI 接入准备稳定输出

## 3. 优先级排序

### P0：稳定化与可观测性

目标：让当前真机运行结果更适合持续调试和后续开发。

任务：

- 下调 `WouldBlock` 空轮询日志频率，避免 `logcat` 被无效日志刷满
- 增加 capture 运行统计摘要，例如每秒包数、活动 flow 数、对象数
- 明确 JSONL 文件结构与落盘字段
- 增加 Android 侧运行状态日志：
  - capture running
  - packets seen
  - owner query count
  - owner resolution hit count

验收：

- `logcat` 中主要看到业务流量与关键状态，而不是空轮询噪音
- `flows.jsonl` 和 `objects.jsonl` 可以稳定生成并持续追加

### P1：应用归因打实

目标：把“抓到流量”升级成“知道是哪一个 App 的流量”。

任务：

- 给 owner query / owner resolution 增加更强的调试日志
- 记录每条 `FlowKey` 是否已发起 owner 查询
- 记录 Android `getConnectionOwnerUid(...)` 的成功 / 失败 / 返回值
- 统计：
  - pending owner queries
  - owner resolution 命中率
  - `unattributed` flow 比例
- 校正 tuple 方向问题，确认查询时使用的 `src/dst` 组合是否符合 Android API 预期
- 验证单应用模式与多应用模式的行为差异

验收：

- 单应用模式下，目标应用流量能稳定映射到正确包名
- 多应用模式下，至少一部分真实 flow 能命中正确 app
- `app=unattributed` 比例明显下降

### P2：应用层协议最小解析

目标：把当前“传输层探针”推进到“基础应用层线索探针”。

本阶段优先做：

1. DNS
2. TLS ClientHello / SNI
3. HTTP 明文

任务：

- 在 `ParsedPacket` 中补充应用层元数据字段
- `rustprobe-parse` 增加：
  - DNS query name / response record 最小解析
  - TLS ClientHello 中的 SNI / ALPN 最小解析
  - HTTP request line / `Host` 最小解析
- `rustprobe-flow` 将 `Domain` 对象纳入聚合
- capture 日志和 JSONL 输出应用层字段

验收：

- 访问普通网站时，日志中能看到 DNS 域名或 TLS SNI
- 明文 HTTP 请求可显示 `Host` 和基础 URL 线索
- `objects.jsonl` 中开始出现 `Domain` 类对象

### P3：为 UI 和分析扩展准备稳定输出

目标：后面接 UI 时，不再依赖临时日志字符串。

任务：

- 定义更稳定的 flow snapshot 输出结构
- 定义 object snapshot 输出结构
- 定义 app attribution snapshot 输出结构
- 明确 UI 首版消费字段：
  - app
  - dst ip
  - dst port
  - domain
  - protocol
  - packets
  - bytes
  - first seen / last seen
- 为后续本地 WebSocket / JNI IPC 预留统一事件格式

验收：

- UI 后续接入时，可以直接消费结构化输出，而不是重新解析 log 文本

## 4. 任务拆解建议

建议按下面顺序推进，不要并行分散太多：

1. 先做 `P0` 日志与观测整理
2. 再做 `P1` 应用归因强化
3. 然后做 `P2` DNS 与 TLS SNI
4. 最后再补 `P2` HTTP 明文和 `P3` UI 输出结构

## 5. 推荐的本轮开发顺序

### Step 1

收敛当前日志噪音：

- capture 轮询日志限频
- 增加 summary 日志
- 检查 JSONL 输出稳定性

### Step 2

打透应用归因：

- 增强调试日志
- 校正 owner query tuple
- 做单应用 / 多应用实测

### Step 3

接入域名线索：

- 先做 DNS 解析
- 再做 TLS SNI
- 最后做 HTTP 明文

### Step 4

把结构化输出整理出来，为 UI 铺路。

## 6. 暂不建议现在做的事

为了保持节奏，以下内容建议先不作为下一阶段核心：

- 恶意域名黑名单联动
- 挖矿规则检测
- 复杂 UI 页面
- MITM HTTPS 解密
- 大规模持久化索引
- QUIC 深层解析

这些方向都重要，但都应该排在“稳定捕获、稳定归因、最小应用层解析”之后。

## 7. 下一轮完成线

如果下一轮能做到下面这些，就算非常扎实：

- 真机稳定运行，不再被空轮询日志淹没
- JSONL 输出稳定
- 单应用模式下归因明显改善
- `DNS + TLS SNI` 最小解析接入主链路
- `Domain` 对象进入聚合结果

到那一步，RustProbe 就会从“能抓到流量的原型”进一步升级成“能看见域名线索、能部分归因到 App 的真实探针内核”。
