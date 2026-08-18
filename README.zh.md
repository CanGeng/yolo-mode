# yolo-mode

[English](README.md) | 中文

DeepSeek Harness（`dsh`）的**无人值守全权限窗口**插件：当你要离开电脑、却希望 agent 长时间自主推进任务时，一条**人类专用**命令——`/yolo on`——即为该会话武装 `danger-full-access` 沙箱 + `never` 审批，并配上自动回退、灾难命令绊线与完成/异常通知。

> **先读这段。** yolo 模式下模型以**你的** uid 执行、可触达整个文件系统，任何操作都与你的手动操作等势。内置护栏是**防事故的尽力而为绊线，不是安全边界**（正则黑名单可被有意的混淆绕过）。只为你愿意亲自执行的任务武装会话。残余风险见[这里](#残余风险)。

## 为什么需要它

无人值守时，逐次审批和 workspace 沙箱会把每一堵墙变成卡顿。dsh 已内置 `danger-full-access` 权限预设，但无人值守场景还缺：

- 一个快而明确的**人类专用**开关（模型永远没有给自己授权的工具）；
- **自动退路**（限时到期、熔断）；
- 一个针对**任何沙箱模式都拦不住的操作**的护栏——dsh 沙箱只约束文件效果，fork 炸弹、关机、裸设备写入在 `workspace-write` 下同样畅通；
- 给你的回传信号（干完活 / 被拦截 / 已解除的通知）。

## 用法

| 命令 | 作用 |
|---|---|
| `/yolo on` | 武装（默认**无上限**，直到 `/yolo off`） |
| `/yolo on 4h` · `/yolo on 90m` · `/yolo on 1h30m` · `/yolo on 2d` · `/yolo on 45`（裸数字=分钟） | 武装并限时；到期自动回退 |
| `/yolo off` | 立即解除，回退到 arm 前的权限快照 |
| `/yolo status` | 武装状态、剩余时间、回退目标、护栏计数、通知通道 |

武装通过 dsh 规范 setter 写入 `sandbox/mode` 与 `approval/policy` 会话事件：模型可见的运行时上下文立即更新、状态随日志重放穿越重启、Web UI 权限选择器显示 `danger-full-access`。

## 工作原理

1. **权限真源只有规范事件。** `yolo/armed` / `yolo/disarmed` 是派生标注（到期时间、回退快照、审计），从不凌驾于规范开关之上——与 dsh 的 log-only + 重放哲学一致。
2. **只有人类能武装。** `/yolo` 走 UI 命令平面；模型没有武装 yolo 的工具，护栏熔断也只会*解除*。
3. **到期是惰性且抗重启的。** `expiresAt` 在每次工具调用、每 30 秒扫描、插件启动时各检查一次；带着过期窗口复活的会话立即回退。已启动的后台进程**不会**被追杀（长任务正是使用场景）——残余风险以通知代替。
4. **护栏对自身定位诚实。** 所有文案（包括模型可见文本）都自称绊线，不制造虚假安全感（避免风险补偿）；对同一命令的拒绝是终局的：不得改写、编码或重试。
5. **通知不过工具管道。** 桌面命令 / webhook / SMTP 邮件走直接的 `child_process` / `fetch` / socket，插件自己的护栏不可能拦截或递归触发它们。

## 护栏

- `tools/pre-execute` 监听器；`mode: always | yolo-only | off`（默认 `always`，原因见*为什么需要它*）。
- **灾难核心表**（刻意极小、无可争议）：fork 炸弹；`dd`/重定向写裸设备；`mkfs`/`wipefs`/`blkdiscard`；对裸 `/`、`/*`、`~`、`$HOME` 的 `rm -rf`（覆盖拆分旗标、引号、glob、`--no-preserve-root` 变体；子路径放行）；shutdown/poweroff/halt/reboot/`init 0|6`/`systemctl poweroff`（锚定命令位置，`echo reboot` 这类散文不误伤）；`chmod -R 777 /`。
- **保护路径**：`write`/`edit` 工具不得触碰 `~/.ssh`、`~/.gnupg`、`~/.aws`、`~/.config/gcloud`、`~/.kube`（词法前缀匹配，可配置）。
- **熔断**：武装期间护栏拒绝累计达到 `maxStrikes`（默认 3，`0` 关闭）自动解除 yolo 并通知。
- 自定义正则追加进 `guard.patterns`；编译失败的模式被跳过，不会导致插件故障。

## 模型体验

武装期间一段缓存稳定的运行时上下文（`yolo:policy`）告知模型：全权限窗口生效；用户不在——自主推进、做出并记录合理默认选择、真正阻塞的问题攒到最后一次性问；到期时刻；绊线的存在与终局性；后台进程越过到期点的残余风险；事后完整会话日志将被审查。未武装时该段为空——零 token。

## 通知（默认全部关闭）

| 事件 | 触发时机 |
|---|---|
| `armed` / `disarmed:manual` / `disarmed:expired` / `disarmed:strikes` | 开关与回退 |
| `guard-denied` | 护栏拦截（含命中模式名与累计计数） |
| `idle` | 武装期间 agent 转入 idle（干完活/需要人）；每会话 5 分钟限频 |

三通道可同时启用——全部字段见 [cordis.patch.yml](cordis.patch.yml)：

```yaml
notify:
  desktop:
    command: 'notify-send "dsh yolo" "{event}: {detail}"'   # {event} {detail} {sessionId} {time} 占位
  webhook:
    url: https://example.com/hook    # POST {event, detail, sessionId, at}（JSON）
  email:                             # 自带极简 SMTP 客户端（PLAIN 认证；465 隐式 TLS 或 STARTTLS）
    host: smtp.example.com
    port: 465
    secure: true
    user: bot@example.com
    pass: app-password
    from: bot@example.com
    to: me@example.com
```

## 残余风险

以自主性换来的、需要知情接受的风险：

- 正则绊线可被有意的混淆绕过（base64、变量拼接、先写脚本再执行）；它防**事故**，不防对手。
- 武装期间启动的子 agent / 后台进程保留其出生时的权限，越过到期点继续有效。
- 到期最多滞后约 30 秒加一次工具调用间隔；不会打断生成中的长回复。
- `danger-full-access` 下 `write`/`edit` 可达全盘——保护路径只覆盖配置里列出的那些。
- 若你的 dsh Web 端点无认证，能访问端口的本机进程/页面本就能操作 UI（dsh 部署层面的事实，非本插件引入）。
- 一切（每次工具调用、每次 guard 决定）都进入会话日志，供事后在 GUI 中完整审查。

## 会话可读性漂移（卸载本插件前必读）

dsh 的持久化层在加载会话日志时，会拒绝包含内置 `KNOWN_SESSION_EVENT_TYPES` 集合之外事件类型的日志（除非事件带 `ignorable:true`——而截至 0.1.0-rc.6，`Session.append()` 没有任何途径设置该字段）。`/yolo on|off` 会向日志写入 `yolo/armed` / `yolo/disarmed` 注记事件，因此本插件在加载时把这两个类型注册进该集合。后果：

- **插件在装时**，yolo 会话正常加载。
- **卸载插件后**（或禁用其加载），任何跑过 `/yolo` 的会话都会因 `SessionFormatUnsupportedError` 无法打开——除非恢复插件，或给日志里的 `yolo/*` 行补上 `"ignorable": true`（每个事件一行的 JSON 改动；`decodeStorageRecord` 对其原样透传）。

简言之：**会话可读性依赖插件在位**。这是 harness 侧的 API 缺口（写入路径来者不拒、读取路径校验封闭词表、`ignorable` 有读无写），在原版 dsh 上插件无法绕开。卸载前请先按上述方式修补日志（解压 `session.jsonl.zstd`，给 `yolo/*` 行加 `"ignorable": true`，再压回）。

## 安装

```sh
# 1. 克隆到任意位置，链接进 profile 的 node_modules
git clone https://github.com/CanGeng/yolo-mode.git
ln -sfn "$(pwd)/yolo-mode" ~/.dsh/profiles/node_modules/yolo-mode

# 2. 把本仓库 cordis.patch.yml 里的 insert 行追加到
#    ~/.dsh/profiles/web/cordis.patch.yml

# 3. 重启 dsh web，会话里 /yolo status 验证
```

## 配置

所有开关都在 profile `cordis.patch.yml` 的 `yolo-mode` 行里——带注释的默认配置见 [cordis.patch.yml](cordis.patch.yml)（`guard.*`、`notify.*`、`context.*`）。

## 测试

```sh
node test.mjs   # 22 项：时长解析 / 事件折叠 / 护栏正反例 / 路径保护 / 邮件报文 / 假 SMTP 对话
```

## 许可

[MIT](LICENSE)
