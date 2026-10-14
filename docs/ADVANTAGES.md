# 用可独立核对的证据突出优势

| 论文优势 | 本项目对应实现 | 
|---|---|---|---|
| 单密文封装 | profile-bound support + pack_values，raw 双多项式对照 | 
| Markov 预测的价值 | RobustController、受控HMM、DPP/HYS | 
| 扰动恢复能力 | 独立 repair 分量和 without_route_repair 实验项 | 
| 恶意网关下的聚合完整性 | signed exact roster + hidden linear tag + persistent Seen |
| 安全约束优先 | SafetyFilter + 完整action/profile/config摘要 | 
| 可复核统计 | 配对seed的均值比bootstrap，原始指标独立报告 | 
