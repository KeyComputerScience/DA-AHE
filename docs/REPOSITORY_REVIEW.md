# DA-AHE 仓库审查记录

基线：[f0a3647cea71515649f53dcdb9e0dc3fb22bf483](https://github.com/KeyComputerScience/DA-AHE/tree/f0a3647cea71515649f53dcdb9e0dc3fb22bf483)。
本记录区分远程基线事实、本地准备的修补、尚缺的原始证据。

## 结论和审查边界

GitHub API 获取了未截断递归树，并将其 63 个文件的 Git blob SHA 与上一轮交付归档逐一比对，
63 个均一致。原归档总 66 文件，其中 manifest 自身不列入校验，清单含 65 个对象。
远程漏掉三个对象：`.gitignore`、`.dockerignore`、`.github/workflows/reviewer.yml`。
本轮用 `.github/workflows/ci.yml` 提供更完整验证工作流。漏传原因未确定。

## 已确认问题与本地准备的修补

| 优先级 | 基线问题与影响 | 0.2.0 补充 | 
|---|---|---|
| P1 | 隐藏文件漏传，随包清单仍引用它们；CI未进入仓库 | 补 `.gitignore`、`.dockerignore` 和 push/PR/manual CI；固定 Action 和 liboqs 提交 | 
| P1 | L120 支持选择仅取两个通道各自前半段一级 approximation，裁掉时间窗尾部 | 两级全窗整数提升，先保留两个通道全部 coarsest 系数；变换版本参与完整 profile 摘要 | 
| P1 | 同票据同源重采样复用 affine tag offset，可被恶意网关线性组合 | 必需持久 SourceEmissionStore，先绑定原始窗口，缓存首个封装，重传同字节；改采样必须新票据 | 
| P1 | strict模型证据只核对文件hash，未核对报告身份，旧报告可能配新模型 | 机器可读 subject 绑定模型、动作库、context、状态域、controller参数和适应规则；资源报告同步绑定完整证书数值 | 
| P1 | 估计器将 coded-BKW 的合法派生样本当作超额独立样本，使完整估计一直缺失 | 区分独立/派生样本，核对固定上游放大规则、有效问题和增大噪声，保留完整成本元数据 | 
| P1/P2 | 当前观测噪声和本行动后噪声共用校准列，时序含混 | CSV分为obs/next噪声及next_loss；只用训练数据拟合signed DPP增量，校验Eq.4状态一致性 |
| P2 | 回放初始previous_action=None，首轮切换成本与论文初始化不一致 | 显式初始动作映射；首轮信念不提前预测、DPP不提前observe，但计算初始切换成本 | 
| P2 | stats结果与plotter输入schema不兼容 | 绘图直接读stats JSON，明确节点数、指标和归一化选择 | 
| P2 | 全丢包运行被拒收，可能删掉失败seed；缺聚合ID送达事件会缩小coverage分母 | 保留PLR=1及seed，无定义延迟/coverage显式为空并阻止该配对指标均值；要求完整聚合关联 | 
| P2 | 统计成功不代表7×5×20完整矩阵已经完成 | `stats --matrix` 检查所有预注册方法/规模/seed，缺失或多余组合报错 | 
| P2 | README先覆盖manifest再verify，会消去漏传对象 | 先验证发布清单；生成器拒绝覆盖；另存现场清单供差异核对 | 
| P2 | C标签接口要求完整16×240矩阵，单矩阵15,360 B | 新增按元素回调的流式标签接口，内部部分标签64 B；保留兼容接口并标明成本 |

### 压缩支持集问题的静态证据

基线 [signal.py 的支持选择](https://github.com/KeyComputerScience/DA-AHE/blob/f0a3647cea71515649f53dcdb9e0dc3fb22bf483/src/daahe/signal.py#L98-L104)
先构造240项 approximation 再截取L≤240，后面的detail永不入选。
L120仅保留每通道前60/120个 approximation。对常值100，基线一级变换给出
approximation=273、detail=0；量化不改变后半段被置零这一事实。
inverse 的局部依赖使最后118/240个样本必为零，仅这些位置便给出
`PRD >= 100*sqrt(118/240) ≈ 70.12%`。

### 同票据重采样的条件性完整性风险

基线 [encapsulate](https://github.com/KeyComputerScience/DA-AHE/blob/f0a3647cea71515649f53dcdb9e0dc3fb22bf483/src/daahe/protocol.py#L167-L192)
允许同票据同源产生两份不同报告。若标签为 `t1=K*x1+xi`、`t2=K*x2+xi`，
则网关对密文构造 `2*c1-c2` 后，标签仍满足 `2*t1-t2=K*(2*x1-x2)+xi`。
在正确解码且数据仍在界内的条件下，sink首次提交可能接受，sink Seen尚无法阻止。
攻击不需要K泄漏，触发条件是受信源的应用层允许同上下文重新采样。

修订API必须传 `source_store=SourceEmissionStore(path)`；持久状态应防删除/回滚，
并随纪元和密钥配置管理。源数据库不是公开实验输出，不应进入CI上传或源码归档。

### 估计器派生样本问题的依据

固定上游 [coded-BKW](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe_bkw.py#L270-L277)
调用 [amplify_m](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe_parameters.py#L81-L116)，
用原样本的带符号组合生成更多派生样本并放大噪声；不能把返回的m直接当成新增独立公钥样本需求。
修订保留required-attacks完整性门槛及原始768独立样本预算，并核对上游有效问题和放大规则。

## 新CI验证什么

- 普通Python不变量/拒绝测试，及提交manifest核验。
- 便携C核心编译与独立已知答案，包括流式标签的闭式预期和回调失败清零。
- 固定liboqs原生提交与wrapper版本的真实ML-DSA测试。
- pi0/pi1/pi2与raw数据路径demo；保留实际JUnit、环境和报告，不上传私有ledger/keys。

板端10KiB、安全估计128.1、批次失败2^-128或论文全部图表。
整个源码归档是复现入口；wheel主要提供Python API。

## 仍需作者/项目负责人补充的材料

| 材料/工程 | 最低要求 | 对应主张 |
|---|---|---|
| 原始网络实验工程 | 可构建OMNeT++6.0/INET4.4 NED/INI/C++、RPL实现、仪器化计数、通道/拓扑参数、独立RNG流 | 规模、时延、丢包、恢复、网络能耗 |
| 原始板端工程 | Contiki-NG源码、精确commit/编译器/flags、最终ELF/map、逐角色stack HWM、周期/电流原始记录 | MCU周期、Flash、10KiB workspace、整体SRAM |
| 数据与种子 | 原20评估seed、训练/holdout/评估分离清单、配对外生轨迹、源信号及物理单位、每run原始结果 | 图表数值、置信区间、保真度 |
| 不可变动作/配置库 | 原始support、transform、量化、Bx、完整joint tuple、容量与Pareto校准输入；解决step8/16差异 | 配置一致性与所有消融 |
| 完整认证证据 | 实际分布下batch尾界、缩放carry、no-wrap、资源和fallback证明、真实模型误差/转移/域证据 | 正确性、安全约束、条件稳定性 |
| 安全估计原始输出 | pinned estimator、Sage环境、每攻击成本/适用性/失败记录及全局最小值 | 128.1启发式估计，而非普适安全证明 |
| 真正的动作执行器 | rho采样计划、批次/名单规划、CoAP/RPL repair驱动，动作与票据原子切换 | 闭环落地，不由固定遥测回放替代 |
| 额外比较方法 | SLAP、PQC-DL、B-HE的实际实现与统一成本边界/原始结果 | 能耗图中的比较结论 |
| 容错与密钥管理 | 源ledger防回滚、密钥轮换、sink结果可靠投递/outbox、端点权限与备份策略 | 长期运行、重启恢复、完整性边界 |
| 独立执行证据 | 真正测试日志、CI run URL、环境/二进制/源码摘要、失败与删失保留、版本release归档 | 审稿人可独立核验 |
