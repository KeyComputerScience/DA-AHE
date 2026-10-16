# 可核对的结构优势与尚未证明的性能收益

| 项目 | 当前实现与证据边界 |
|---|---|
| 单密文封装 | 当前 k=6 下原始双多项式密文载荷 14,336→7,168 bytes；不含票据、分片头和认证元数据，不等于完整通信开销减半 |
| Markov 预测 | RobustController、受控 HMM 与 DPP/HYS 可执行；合成控制模型未校准，140组独立运行未证明全面性能优势 |
| 扰动恢复与路由修复 | 有 repair 动作和消融接口；本次策略未触发修复，全部恢复记录右删失，不能宣称恢复时间收益 |
| 恶意网关下的聚合完整性 | signed exact roster、hidden linear tag、持久化源发送记录和 Seen；真实签名功能试验覆盖篡改与重放拒绝，仍以可信源/汇聚端及秘密不泄露为前提 |
| 安全约束优先 | SafetyFilter 绑定 action/profile/config 与证据摘要；摘要校验不验证证明真伪，合成 fixture 不构成完整安全证书 |
| 可复核记录 | 已公开20个配对种子、七方法、140组原始记录；可校验哈希并从原始记录重算指标，不能替代板端测量或原论文实验 |

详细数值见 [`INDEPENDENT_RESULTS_ZH.md`](INDEPENDENT_RESULTS_ZH.md)，公开归档及
核验步骤见 [`PUBLIC_EVIDENCE.md`](PUBLIC_EVIDENCE.md)。论文修订清单见
[`MANUSCRIPT_CORRECTIONS.md`](MANUSCRIPT_CORRECTIONS.md)。
