# three_inequality_nets.core

本目录保留合同、账本、收敛与回执等历史模块（`contract` / `ledger` / `convergence` / `receipt`），供 CLI 与既有模板继续使用。

五张网主路径（`three_inequality_nets.nets.*`）不依赖这些模块；网侧共用的是 `evidence`、`report`、`schema`。

处置选择（2026-11-04 本体返工）：**保留在 `three_inequality_nets/core/`，不移入 extras**。原因：CLI 入口仍引用；迁移会扩大无授权改动面。测试覆盖仍薄，后续若要加深覆盖再单开任务。
