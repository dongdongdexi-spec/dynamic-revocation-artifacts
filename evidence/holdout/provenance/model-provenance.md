# 24 题模型配置溯源与可固定版本复跑评估

## 实验记录核查

冻结文件中的 `gpt-6-luna` 和 `gpt-6.2-sol` 与 2026 年 11 月 25 日对应 Codex 子代理的实际运行上下文一致。已从 14 个相关会话提取字段，覆盖首轮的两种拓扑、共用六角色回传和事后诊断。对应 `session_meta` 均记录 `model_provider: openai` 和 `cli_version: 0.171.0-alpha.13.2`，对应 `turn_context` 对 Luna 记录 `effort: medium`，对 Sol 记录 `effort: low`。核查仅提取受审会话的运行元数据，不归档原始会话或其中的私人信息。

| 字段 | Luna | Sol | 可核实的来源 |
|---|---|---|---|
| 厂商路由 / 框架 | OpenAI / Codex 0.171.0-alpha.13.2 | OpenAI / Codex 0.171.0-alpha.13.2 | 子代理 `session_meta` |
| 运行时模型标识 | `gpt-6-luna` | `gpt-6.2-sol` | 子代理 `turn_context.model` 与冻结文件相符 |
| 推理档位 | `medium` | `low` | 子代理 `turn_context.effort` |
| 精确、不可变的服务端快照或公开 API ID 对照 | 未记录 | 未记录 | 当前记录只确认框架的运行时标识 |
| 温度、`top_p`、生成随机种子、生成 token 上限、后端模型参数量 | 未记录 | 未记录 | 冻结、启动参数及运行上下文均无可归因字段 |
| 角色输出约束 | 每题每角色 250 字符 | 每题每角色 250 字符 | 冻结任务说明及评分器断言 |
| 单智能体 | 同一会话完成六角色资料压缩及协调规划 | 独立单智能体会话完成资料压缩及协调规划 | 设计、会话、计划 JSON |
| 一主六下游 | 六个独立角色会话生成回传，另一个 Luna 会话协调 | Sol 协调员复用六份 Luna 回传 | 六个角色文件跨配置逐字节一致 |

角色输出的 250 字符上限是评价任务显式约束。整场重抽样所用固定种子是分析参数。二者都不能用于推定模型采样配置。两个模型标识和推理档位共同定义两种运行配置，比较时不能单独归因于模型版本。论文也无需称其为匿名化模型，记录不能确认发行身份时，按运行时标识和缺失字段报告即可。 [现有冻结记录](../frozen/scoring-lock.json) · [冻结任务指令](../frozen/planning-prompts.md) · 第二模型复验设计

## 归档一致性和离线评分

| 锁定项 | SHA-256（已重算） |
|---|---|
| 24 题题库 | `c18801f9e86e85945de6ef86ffaf7be541b9464c151a2f47ea2ca0efb67dc04d` |
| 主评测执行器 | `f6526d5204f965b3a87fa3ab941ef31eb34ede9f4d5287acb0d1d65bb659bfc4` |
| 角色压缩和协调规划的任务说明 | `fe3870048e8fa5e89236c587c349788d0e3170180e40a3712452bdfd3ea28d84` |

验证了 24 题每题六个角色、四个压缩快照和四种撤权时序各六题。首轮两种协调员的六份多代理回传逐字节一致，角色回传均在 250 字符内。事后诊断仍使用同一题库，只重做角色 B 和 F 并另作冻结。两边的四份保留角色文件、两份修正角色文件及协调员输入均匹配诊断锁记录。离线调用 `execute()` 复算首轮八组和诊断四组的泄露、任务完成，结果与档案一致。每个条件的同一计划分别交给核权开与关的执行器，回放无需重新请求模型。

| 阶段 | 工作流 | Luna 任意泄露 / 任务完成（关 → 开） | Sol 任意泄露 / 任务完成（关 → 开） |
|---|---|---|---|
| 冻结首轮 | 单智能体 | 0/24 → 0/24；24/24 → 24/24 | 18/24 → 0/24；24/24 → 24/24 |
| 冻结首轮 | 一主六下游 | 0/24 → 0/24；0/24 → 0/24 | 0/24 → 0/24；0/24 → 0/24 |
| 同题事后诊断 | 一主六下游 | 18/24 → 0/24；19/24 → 19/24 | 18/24 → 0/24；24/24 → 24/24 |

冻结首轮、同题事后诊断和将来的可公开快照新生成分别标记。已归档的角色输出取证说明模型部分支持对记录计划的测试，当前模型输出没有提供独立的拓扑因果比较。 首轮结果 · 事后诊断

## 可固定公开快照的新生成评估

离线验收已经通过。冻结题库、角色输入及提示词可用于再次生成计划，现有执行器可以对新计划做成对回放。新生成还需要有授权的运行环境和可证明为不可变发布版本的公开模型入口。候选可以是厂商文档有版本化 ID 且该账号可访问的模型，也可以是能固定权重提交号、分词器和推理框架的公开权重。模型入口的可公开性和可访问性在选型时核验，冻结新的运行条件后再生成。本轮完成配置溯源和复跑评估，原始记录不会填入推测的温度、公开模型 ID 或后端参数量。

一个已经核实文档的候选是 `gpt-5.4-mini-2026-03-17`。官方模型页列出该固定快照及结构化输出支持。可用它建立统一的角色反馈 JSON 约束，在新协议中锁定实际可提交的推理和解码参数，先做账号可访问性与少量角色交接的试跑。其结果属于与既有 Codex 运行配置平行的新生成研究。 [OpenAI GPT-5.4 mini 模型文档](https://developers.openai.com/api/docs/models/gpt-5.4-mini)

1. 以单一可固定版本同时执行两种拓扑，先验证成对的核权开关效应。每题两步单智能体处理、六次独立角色回传、一次多智能体协调，按逐题接口预计 216 次模型生成，工具调用和重试另计。复现两个配置且共享一份六角色情报时，逐题约 288 次生成；为两个模型各自重做下游时约 432 次。
2. 冻结模型发布 ID 或权重 digest、执行器/提示词/题库哈希、工具可见性、角色分配、输出协议和日志格式。写明所有实际提交的解码字段和服务端返回的标识，包括温度、`top_p`、长度上限、随机种子、推理档位各自的适用性和缺失情况。若公开端点不具备同一工具环境，把这项差别登记为新配置。
3. 预先规则化校验 B 和 F 的 JSON 交接结构及字段完整性，先在排除于冻结 24 题的样例做预检。正式 24 题保留解析失败、缺失和拒答，免于按观察到的泄露率选样或修补。两臂继续复用同一计划，报告四种撤权时序、授权任务完成、泄露、两者联合指标及逐题配对。
4. 新计划、收件账本和结果单独归档，保留冻结首轮和事后诊断。若公开快照、执行环境或调用授权不可核实，保留当前可复算的记录计划证据，并如实标注生成复现的限制。

## Suggested English Methods text

> The planning records were produced with the OpenAI Codex harness (CLI `0.171.0-alpha.13.2`). The recorded runtime configurations were `gpt-6-luna` at medium reasoning effort and `gpt-6.2-sol` at low reasoning effort. The archive preserves the harness model identifiers and recorded effort. Immutable serving revisions, temperature, `top_p`, the generation seed, and API token limits are unavailable in these records. Both topologies use a 250-character cap per task and role note. In the single-agent condition the same model session handles role compression and coordination. In the multi-agent condition, six independent Luna sessions generate role notes and the Luna and Sol coordinators read the same six notes. Each resulting plan is replayed unchanged with the delivery gate both disabled and enabled. The frozen initial run and the same-case post hoc handoff diagnostic are disclosed separately. The artifact supports exact re-scoring of recorded plans, while regeneration on a separately pinned public release would constitute a new experiment.

| Field | First recorded planning configuration | Second recorded planning configuration |
|---|---|---|
| Provider and harness | OpenAI Codex `0.171.0-alpha.13.2` | Same |
| Runtime identifier and recorded effort | `gpt-6-luna`, medium | `gpt-6.2-sol`, low |
| Role notes in the coordinated workflow | Six independent Luna role sessions | Reuses those six Luna notes |
| Immutable serving revision and decoding metadata | Unavailable in the preserved log | Unavailable in the preserved log |
