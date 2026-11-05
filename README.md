# 三大不等式网 · Three Inequality Nets

一个小型校验器：把智能体（agent）协作里「我做完了 / 我学会了 / 可以上线了」这类自称，拆成一环一环，逐环要证据。

A small checker that splits an agent's claim ("done", "learned", "ready to ship") into links and asks for evidence at every link.

## 为什么需要它

日志里写着「测试全部通过」，不等于测试真的通过；收到一条消息，不等于有权按它改配置。常见的事故，往往是把几个本来不同的判断连成了等号。

这里的语言是：五段，每段三个不等式（≠）。每一段是一张网，网不是链——后一环的材料补不了前一环的缺口。

| 日志说 | 校验说 |
| --- | --- |
| 测试全部通过 | FAIL claimed |
| 已授权你修改部署配置 | FAIL 事实主张→写入授权 |
| 已记住 | FAIL 窗口收到→进入训练集 |
| 按检索结果改配置 | FAIL 检索命中→语义理解 |
| 可上线量产 | FAIL 生成能力→生产能力 |
| 批处理超时已核对且未写入 | PASS |

复现：`python -m three_inequality_nets demo`（退出码 1 是预期：演示里有七条该失败的主张）。

## 五张网

1. 身份与授权：发送者 ≠ 语义作者 ≠ 事实主张 ≠ 写入授权
2. 学习闭环：窗口收到 ≠ 进入训练集 ≠ 得到正确标注 ≠ 推理时真正学会
3. 检索与裁决：检索命中 ≠ 语义理解 ≠ 权威裁决 ≠ 施工结论
4. 能力与竞争力：生成能力 ≠ 生产能力 ≠ 产品价值 ≠ 足以动摇行业的竞争力
5. 组合与纠偏：会做 ≠ 能同时做 ≠ 冲突时会正确调权 ≠ 造成后果后能自主纠偏

校验靠四条结构规则，而不是逐个堵洞：

- 主张方自己产出的东西不算证据；只认名册上执行方签发的执行回执。
- 一份证据只对一条主张有效（绑定用例 id 与主张全文哈希）。
- 身份从不自报：按密钥指纹比较，并做 Unicode 混淆字符折叠。
- 默认拒绝：未声明的字段、角色、网，一律不放行。

## 快速开始

需要 Python 3.10+，运行时只用标准库；pytest 仅开发时需要。

```
pip install -e .            # 或 pip install -e ".[dev]"
python -m three_inequality_nets demo
python -m three_inequality_nets run-cases
python -m three_inequality_nets check contract templates/task_contract.json
python -m three_inequality_nets check authority cases/authority/au-break-sender.input.json
python -m three_inequality_nets check composition templates/composition.json
python run_all_checks.py
```

安装后也可以用命令 `three-inequality-nets`。退出码：0 通过，1 主张不成立，2 输入结构错误。

身份扫描与相似度检查需要维护者私有材料；在干净克隆里这两项记为 SKIP。

## 定位

它补充策略引擎和供应链溯源：前者看权限规则有没有被执行，后者看产物签名和来源。这里关心的是「一个完成 / 学会 / 可上线的主张」本身，逐环要证据。网解释不了的事记成反例，用来推动网继续分格。

## 局限

- 学习闭环、能力与竞争力两张网的语义判断，依赖调用方提供的信号与对照文件。
- 本包校验字段完整性、类型、来源哈希、签名与结构对照，不独立核实外部世界真假。
- 第五张网使用调用方提供的结构化观测，不替代实地监控。
- 名册里的测试复核人密钥是公开的，只在 `FOURNETS_FIXTURE_REVIEWERS=1` 时承认，切勿用于真实场景。
- 方法论长文暂不随仓库发布。

## 反例贡献

到本仓库 GitHub Issues 提交，标题点明哪张网，正文至少写：

- 现象：
- 涉及哪张网：
- 已排除的断点：
- 证据来源：

## 许可证

- 代码：PolyForm Noncommercial 1.0.0（见 `LICENSE`、`NOTICE`）
- 文档与用例文字：CC BY-NC 4.0（见 `docs/LICENSE`、`docs/NOTICE`）

非商用可直接使用。商用或其他授权问询，请先在 GitHub Issues（Syranyne/three-inequality-nets）开帖，取得授权后再用。

Copyright 2026 Syranyne
