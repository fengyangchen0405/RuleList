# RuleList

自用规则集。`Surge/*.list` 每行只包含规则类型和匹配值，不包含策略。`AI.list` 为 Surge 与 Clash/Mihomo 共用的域名规则，`AI-Process.list` 为 Surge Mac 专用进程规则。

## 策略映射

| 规则集 | Surge 策略 |
| --- | --- |
| `Direct.list` | `DIRECT` |
| `Proxy.list` | `🚀 节点选择` |
| `AI.list` | `🤖 AI` |
| `AI-Process.list` | `🤖 AI`（仅 Surge Mac） |
| `JP.list` | `🇯🇵 日本节点` |
| `Singapore.list` | `🇸🇬 新加坡节点` |

## AI 规则引用

Surge Mac 在 `[Rule]` 中同时引用两个文件，放在通用代理规则之前：

```ini
RULE-SET,https://raw.githubusercontent.com/fengyangchen0405/RuleList/main/Surge/AI-Process.list,🤖 AI
RULE-SET,https://raw.githubusercontent.com/fengyangchen0405/RuleList/main/Surge/AI.list,🤖 AI
```

原来只引用 `AI.list` 的 Surge Mac 配置需要新增 `AI-Process.list` 引用，才能保留应用进程分流。Clash/Mihomo 路由器继续使用原有 `AI.list` URL，配合 `behavior: classical` 和 `format: text`，无需引用进程文件。

## 校验

```bash
python -m unittest discover -s tests -v
python scripts/validate.py
python scripts/validate.py --profile /path/to/Surge.conf
```

validator 会检查语法、重复、同文件冗余、跨策略语义冲突，以及可选的主配置引用关系。

`PROCESS-NAME` 只对 Surge Mac 有效。App Bundle 前缀路径必须以 `/` 结尾，例如 `PROCESS-NAME,"/Applications/ChatGPT.app/"`。
