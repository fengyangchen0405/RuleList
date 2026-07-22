# RuleList

自用 Surge 规则集。`Surge/*.list` 每行只包含规则类型和匹配值，不包含策略。

## 策略映射

| 规则集 | Surge 策略 |
| --- | --- |
| `Direct.list` | `DIRECT` |
| `Proxy.list` | `🚀 节点选择` |
| `AI.list` | `🤖 AI` |
| `JP.list` | `🇯🇵 日本节点` |
| `Singapore.list` | `🇸🇬 新加坡节点` |

## 校验

```bash
python -m unittest discover -s tests -v
python scripts/validate.py
python scripts/validate.py --profile /path/to/Surge.conf
```

validator 会检查语法、重复、同文件冗余、跨策略语义冲突，以及可选的主配置引用关系。

`PROCESS-NAME` 只对 Surge Mac 有效。App Bundle 前缀路径必须以 `/` 结尾，例如 `PROCESS-NAME,"/Applications/ChatGPT.app/"`。
