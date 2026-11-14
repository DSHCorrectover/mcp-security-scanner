# Armory：资金安全 × 架构问题武器规则 v1.0（2026-11-14）

> 从 DPX Bounded Review 实战提炼，对 MCP Atlas Census 全量 229,827 条工具记录批量打分。
> 数据锚：SHA-256 `2350dc77…f5780f`（2026-10-12 冻结基线，Zenodo DOI 10.5281/zenodo.23333514）。
> 复算：`curl -L https://github.com/DSHCorrectover/mcp-atlas-census/releases/download/v1.0.0/server_tools.jsonl.gz | sha256sum` → `2350dc77…f5780f`；`zcat | wc -l` → `229827`。
> 合规：静态 schema 分析，零侵入；发现按 CVD 协调披露（见 `gtm/对外披露与销售合规守则-20261114.md`）。

## 武器规则（8 条 → v1.0 实现 5 条）

| 规则 | 含义 | 判据 | 加固方案 |
|---|---|---|---|
| R1 | 资金写动作 | 工具名/描述含 settle/transfer/pay/withdraw/execute/… | 两段式确认强绑定 |
| **R1b** | **资金写动作且 schema 无鉴权/确认/限额字段** | R1 命中 ∧ properties 无 auth/confirm/token/signature/whitelist/limit | 鉴权字段+白名单+限额三件套 |
| R5 | NL 直驱资金动作 | instruction/prompt/natural_language 类字段 | NL→结构化 intent→确认→执行 |
| R6 | Raw 直传（XML/payload） | xml/pain001/iso20022/raw 类参数且无 sandbox | XSD 校验+服务端金额复核 |
| R7 | 外呼端点无签名 | webhook/callback/subscribe 且无 sign/hmac/secret 参数 | 域名白名单+HMAC 签名+防重放 |

## v1.0 全量命中（2026-11-14 跑，第三次数值独立复算一致）

| 指标 | 命中 | 占比 |
|---|---|---|
| R1 资金写动作工具 | **14,928** | 6.5% |
| R1b 其中 schema 零鉴权/确认/限额 | **13,054** | **R1 的 87.5%** |
| R5 NL 直驱 | 1,508 | 0.7% |
| R6 Raw 直传 | 470 | 0.2% |
| R7 无签名外呼 | 4,911 | 2.1% |
| 受影响 server | **13,120** | 占 42,163 的 31% |

**一句话**：生态里每 8 个资金写动作工具，7 个在 schema 层无任何鉴权/确认/限额字段——「单条提示→资金动作」是生态级暴露面，不是个别现象。

## TOP 高危 server（得分=规则加权；个体报告按 CVD 先私下通知）

得分规则：R1=+2，R1b=+3，R5/R6/R7=+1。

| 分 | 规则 | 工具数 | server |
|---|---|---|---|
| 883 | R1,R1b,R5,R7 | 296 | io.github.moralito311-andr/andreax |
| 567 | R1,R1b | 279 | io.github.getgapup/gapup-mcp |
| 567 | R1,R1b | 279 | io.github.getgapup/mcp-knowledge |
| 370 | R1,R1b,R5,R6,R7 | 453 | ai.oobeprotocol.sap.mcp/sap-mcp |
| 334 | R1,R1b,R6,R7 | 214 | xyz.558686.gpt55/token-gateway |
| 306 | R1,R1b,R5,R6,R7 | 1068 | io.github.davidmosiah/delx-mcp-a2a |
| 240 | R1,R1b,R5,R6,R7 | 116 | io.github.untitledfinancial/dpx（已发协调披露信，窗口期至 2026-12-14） |
| 207 | R1,R1b,R5,R7 | 347 | co.lovie/company-formation |
| 202 | R1,R1b,R5,R6,R7 | 444 | cloud.theprotocol/registry |
| 193 | R1,R1b,R7 | 44 | com.payram/mcp |
| 185 | R1,R1b,R6,R7 | 247 | kr.xdata/xdata-mcp |
| 176 | R1,R1b | 139 | me.agentworld/agentworld-mcp |
| 176 | R1,R1b,R5 | 171 | xyz.apexfaucet/apex-x1 |
| 175 | R1,R1b,R5,R6 | 55 | xyz.solknife/toolkit |
| 172 | R1,R1b,R7 | 46 | ru.maxzoa/1cent |

## 用法（销售闭环）

1. 个体审查：对某 server 全量工具跑规则 → 确认级发现 → 加固配对（模板见 deliverables/bounded-review/report-cover-template-v1.md）
2. 协调披露：先私下通知+30 天窗口 → 公开只发脱敏案例
3. T1 Bounded Review 收费复测闭环
4. v1.1 待实现：R2 两段式配对检测（quote/execute 建模）、R3 收款方白名单检测、R8 sandbox 默认值声明检测

## 与 scanner 的关系
`npx correctover-scan` 面向单次扫描；本 armory 面向全量普查批量打分。检测器 `armory_rules.py` 输入 census jsonl，输出规则命中统计+server 风险分。规则升级走 census 复算锚，数字只增不改口径（追加新规则另列，不改历史数字）。
