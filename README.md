# Redis 搜索工具与 CVE-2025-49844 漏洞说明

## 概述
本项目提供一个用于在给定 IP 或网段内快速识别可能存在的 Redis 服务并获取版本信息的 Python 并发扫描脚本，支持尝试常见“默认/弱口令”授权以辅助识别。
项目起源是为了排查近期 Redis 的高危漏洞 CVE-2025-49844在我单位的资产情况。

## CVE-2025-49844 漏洞简介
- 漏洞类型：Lua 脚本系统中的 Use-After-Free（UAF）内存破坏，可能导致远程代码执行（RCE）
- 认证要求：需“已认证用户”可触发（但现实中大量 Redis 实例未启用认证或使用弱口令，风险被显著放大）
- CVSS 评分：10.0（Critical）
- 触发机制：利用特制 Lua 脚本操控垃圾回收器，制造 UAF 并逃逸 Lua 沙箱，获得宿主机的任意代码执行
- 影响面：所有启用了 Lua 脚本的 Redis 版本（据公开资料，该缺陷在代码库中存在约 13 年）

参考：
- Redis 官方安全通告（修复版本与缓解建议）  
  https://redis.io/blog/security-advisory-cve-2025-49844/

## 影响范围与修复版本
- 受影响：所有启用 Lua 脚本的 Redis（含 OSS/CE/Stack/Enterprise），以及部分分支/衍生（如 Valkey，参考 Wiz）
- 修复版本（源自 Redis 官方通告，建议以官方最新为准）：
  - Redis OSS/CE/Stack：
    - OSS/CE：8.2.2 及以上，8.0.4 及以上，7.4.6 及以上，7.2.11 及以上
    - Stack：7.4.0-v7 及以上，7.2.0-v19 及以上
  - Redis Software（Enterprise/商业版）：
    - 7.22.2-20 及以上，7.8.6-207 及以上，7.4.6-272 及以上，7.2.4-138 及以上，6.4.2-131 及以上
- 云托管：Redis Cloud 已自动修补（参考官方通告）

## 缓解与整改建议
- 立即升级至官方修复版本或更高
- 启用并强制认证，避免默认/弱口令；开启 protected-mode（CE/OSS）
- 严格的网络访问控制，仅允许可信源访问；禁止公网暴露
- 最小权限原则，限制 Lua/EVAL/EVALSHA 的使用（ACL 可临时禁用相关命令）
- 非必需则禁用 Lua 脚本功能
- 运行时加固：非 root 运行、启用日志与监控、分段网络、限制危险命令

## 脚本使用说明（scan_redis.py）
功能：
- 输入 IP、CIDR 网段或起止范围，识别可能的 Redis 并输出版本
- 并发扫描端口（默认 6379），支持多端口与范围
- 在遇到 NOAUTH 时尝试常见默认/弱口令授权（可关闭或自定义）
- 输出格式支持 text 与 json；支持保存到文件

基础用法：

```bash
# 单个IP
python scan_redis.py 192.168.1.10

# CIDR网段
python scan_redis.py 192.168.1.0/24

# 起止范围
python scan_redis.py 192.168.1.10-192.168.1.50
```

常用参数：
- -p/--ports 指定端口，支持逗号与范围（如 6379,6380 或 6379-6382）
- -t/--timeout 连接与读写超时秒，默认 1.0
- -c/--concurrency 并发限制，默认 200
- -o/--output 输出格式 text 或 json，默认 text
- --no-default-auth 不尝试默认/弱口令授权
- -P/--passwords 自定义密码列表，逗号分隔（与默认集合合并去重）
- -O/--output-file 将扫描结果保存到指定文件
- --append 以追加模式写入文件

示例：

```bash
# 扫描网段，保存文本结果
python scan_redis.py 192.168.15.0/24 -O results_192.168.15.txt

# 追加写入同一文件
python scan_redis.py 172.16.72.0/24 -O results_all.txt --append

# 输出为JSON并保存
python scan_redis.py 10.0.0.0/24 -o json -O results_10.json

# 指定多端口与自定义密码
python scan_redis.py 10.0.1.10-10.0.1.200 -p 6379-6380 -P "redis,123456,admin"
```

输出示例（text）：
- 10.0.0.8:6379 可能为Redis 版本: 7.2.4 状态: 无需认证
- 10.0.0.9:6379 可能为Redis 版本: 未知 状态: 需认证
- 10.0.0.172:6379 可能为Redis 版本: 3.2.9 状态: 已使用默认密码授权

JSON 输出字段：
- ip, port, open, redis, auth_required, version, authed, password_used

## 免责声明
本工具与文档仅用于安全自查与教育目的。关于漏洞修复版本与风险评估，请以官方公告与权威来源的最新更新为准。

