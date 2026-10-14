# DA-AHE：可审计参考实现与审稿复现包

本项目依据所提供论文独立重建，包含完整的主机端算法代码、对照控制器、消融数据路径、统计分析与证据管理工具、便携 C 核心，以及 MIT License。**交付时未执行项目、测试、编译、训练、仿真或安全估计。**

它不是作者原始代码。论文未附原始 INET/Contiki 工程、校准数据、确定性支持集合和认证证书，因此不能仅凭这份 PDF 保证逐点复现论文图表，也不能宣称已经达到论文的安全等级、失效率、板端内存或性能。缺失项在实现和审稿流程中显式呈现，不能用示例参数替代实验证据。

## 已提供的代码

| 模块 | 实现内容 |
|---|---|
| `ring.py` / `mlwe.py` | 模 2^32 的负循环多项式运算，M-LWE 密钥生成、加密、同态相加、解密，4096 字节规范序列化与 32/64 字节分块 |
| `signal.py` / `profiles.py` | 两路 240 样本整数提升变换、固定支持选择、量化/重构、完整摘要绑定的不可变配置；明确标记论文缺失细节 |
| `derivation.py` / `signatures.py` | SHAKE256 有限域无偏扩展、16 维线性认证、ML-DSA-44 票据签名；缺少 PQ 依赖时拒绝处理 |
| `protocol.py` | 论文算法 1-3：源封装、分块 HMAC、精确参与名单聚合、网关传输认证、端到端线性标签验证、持久防重放 |
| `lightweight.py` | 轻量明文认证聚合路径，明确其信任网关的边界 |
| `control.py` / `safety.py` | 五状态受控 HMM、精确 L1 歧义优化、鲁棒 Lyapunov 筛选、DPP/HYS 对照、严格证据门控 |
| `ablations.py` / `integration.py` | 静态/禁用修复控制器、已审查动作与数据面票据的绑定，防止在线篡改认证动作元组 |
| `calibration.py` / `replay.py` | 训练/评估种子分离的校准入口、冻结模型、因果遥测回放；经验残差不冒充全域证书 |
| `statistics.py` / `evidence.py` | 配对种子 bootstrap、原始均值与均值比、删失恢复处理、SHA256 清单和缺失证据审计 |
| `embedded/` | 无堆分配 C 多项式、打包、标签、解码和按块累加核心；不是原始板端固件 |
| `tools/` / `experiments/` | 固定提交的 Lattice Estimator 入口、外部 OMNeT 指标导入、环境记录、实验矩阵、结果绘图工具 |

## 安装与未来验证命令

以下命令供用户或审稿人后续执行；本次未执行。

```bash
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
python -m daahe profiles --output runs/profiles.json
```

完整签名数据路径还需安装本地 liboqs 0.16.0 和 Python 包
liboqs-python 0.16.0.1。可参考 `Dockerfile`，或按 `docs/REPRODUCIBILITY.md`
手动安装。安装后：

```bash
python -m pip install -r requirements-pq.txt
python -m daahe demo --participants 3 --profile pi0 --output runs/demo
python -m daahe demo --profile without_intdb2 --output runs/raw
python -m daahe demo --profile without_hve --output runs/no-hve
```

`demo` 使用合成波形，仅验证参考数据路径，输出真实执行所得的报告；交付包不含预填结果。它会尝试修改聚合数据并重算合法网关 MAC，检验端到端标签的作用，再检查合法聚合与重放。`without_hve` 是明确标记的消融路径，不具有端到端完整性保证。

```bash
python -m daahe replay-control --config configs/control_synthetic.json \
  --telemetry examples/telemetry_synthetic.csv --method da-ahe \
  --allow-synthetic --output runs/control.json
python -m daahe stats external/metrics.csv --output runs/summary.json
python -m daahe manifest --root . --output manifest.json
python -m daahe verify-manifest manifest.json --root .
python -m daahe audit --root . --output runs/readiness.json
```

`audit` 在原始证据缺失时返回非零状态，这是预期行为；源码清单校验通过也不代表实验已复现。控制器默认严格校验，只有明确选择 `--allow-synthetic` 才允许合成模型演示，输出不得用于支持论文图表或稳定性证书。

## 审稿入口

1. 先读 `docs/IMPLEMENTATION_STATUS.md` 和 `docs/PARAMETERS_AND_GAPS.md`，了解论文值、重建选择和未验证项。
2. 按 `docs/REVIEWER_CHECKLIST.md` 验证算法、攻击情形、对照公平性、统计口径和证据。
3. 对照 `docs/CLAIM_TRACEABILITY.md`，逐项关联论文主张与代码、输入、日志和验证状态。
4. 按 `docs/DEPLOYMENT.md` 完成真实网络、板端密钥与资源测量接入；按 `docs/ADVANTAGES.md` 组织优势证据。

支持强项的证据应分别展示：单密文减少有效载荷、预测控制减少扰动代价、路由修复恢复连接、线性认证抵抗恶意网关篡改。不能从功能测试推导密码学安全证明，也不能用 100% 验证覆盖率代替攻击检出概率。

## 许可证与来源

原创代码和文档采用 MIT，见 `LICENSE`；第三方及论文边界见 `NOTICE` 与
`THIRD_PARTY.md`。论文未提供作者/DOI 元数据，`CITATION.cff` 不虚构作者、DOI
或仓库地址。交付来源记录在 `docs/PAPER_SOURCE.json`。此工程为可检查的参考基础，
生产接入和论文精确数值复现仍须补齐列明的原始材料并实测。

