# DA-AHE 独立复现与128.1位目标

采用新参数 **k=6、d=256、n=m=1536、q=2³²、p=65537、σkey=3.2**，固定官方 lattice-estimator 提交并完成全部七种攻击，最低估计为 **136.475 bits ≥128.1**。原论文k=3参数本次估计未达标；这次结果属于修改参数后的独立实现。

| 攻击 | 估计bits |
|---|---:|
| primal_uSVP | 136.475 |
| primal_BDD | 137.475 |
| primal_hybrid | 137.475 |
| primal_MITM_hybrid | 337.3651054 |
| dual | 139.125 |
| dual_hybrid | 138.5950049 |
| coded_BKW | 435.2999548 |

这是generic flattened-LWE、ADPS16量子归约成本模型下的启发式估计。估计器采用Gaussian-like分布及其支持、密度近似，没有直接读取实现的有限整数CDT；结果不是对实际采样器、模块结构、侧信道或所有攻击的严格安全证明。完整逐攻击stdout、环境、输入、源码哈希及独立记录核验均随包交付。

解密正确性另行使用实现的实际256-bit整数CDT、精确概率及Sage外向区间运算验证。σenc/Nmax为3.2/16、3.4/14、3.6/12时，双多项式失败概率的log₂上界分别为−134.8530523、−136.5817958、−142.3045558。42个配置的一次适应选择联合上界为 **−130.5101732 < −128**。范围是随机key生成与fresh honest batch的联合概率，要求动作及名单在当前批次噪声产生前确定；不保证每个固定key、任意已观察历史条件下或无限生命周期。

新密文 **7168 bytes**，比原4096增加75%；双多项式原始路径为14336 bytes。论文中的密文大小、网络开销、加密时间、完整认证耗时、能耗及工作区结论需要相应更新。仿真的0.004秒加密耗时是明确标注的运算量代理假设，不能作为板端测量。

主机功能测试实际466项通过、1项跳过，真实ML-DSA专项测试另1项通过；Sage区间与精确概率专项19项通过。20次fresh-key真实签名/聚合试验全部通过，包含合法聚合、具有有效传输MAC的网关篡改拒绝及持久化重放拒绝；私钥和重放数据库不发布。

仿真采用独立Python离散事件实现，3000个传感器、60个网关、90秒产生窗口加35秒排空，种子1000–1019、七种方法。原始队列、分片、重传、完整固定名单批次、丢失与恢复删失均记录。它不属于原始OMNeT++/INET工程；控制模型为未校准的合成fixture，不能据此宣称论文数值或稳定性定理已复现。实际完成状态与逐种子指标见证据索引。

固件已用Arm GNU14.3交叉编译并通过主机已知答案检查；选定k6固件的Flash加载段5624 bytes、静态RAM20608 bytes（含8192-byte PSP，另预留4096-byte MSP）。这些仅属于独立核心微基准，不是完整协议、10-KiB工作区或实测栈高水位。**实板样本为0；周期、栈与能耗尚未采集。** 已提供串口原始采集、固件身份绑定和核验流程。

这次20-seed、七方法、140组运行得到如下描述性均值。有效交付以所有产生机会为分母；残余损失和无效接受率以实际接纳报告为分母。两种分母不能混用，节点和数据包不作为独立统计重复。

| 方法 | 有效交付/机会 | 残余损失/接纳 | 无效接受/接纳 | 有效交付平均时延s |
|---|---:|---:|---:|---:|
| DA-AHE | 35.572% | 32.352% | 0% | 6.859 |
| DPP | 34.280% | 30.872% | 0% | 6.606 |
| HYS | 38.823% | 33.240% | 0% | 6.287 |
| without_hve | 35.572% | 30.265% | 2.087% | 6.859 |
| without_intdb2 | 33.395% | 36.508% | 0% | 3.625 |
| without_markov | 44.010% | 55.990% | 0% | 10.840 |
| without_route_repair | 35.572% | 32.352% | 0% | 6.859 |

全部140组恢复记录均右删失：截至125秒观察末端，未观察到满足阈值的恢复。**95秒是删失时长，不是恢复时间。** 当前策略未触发路由修复，因此该消融不能证明修复机制无效或有收益。关闭HVE的有效交付没有增加，但接受了污染，不能把表面loss下降解释为可靠性提高。本结果没有复现论文低丢包或全面性能优势，不能替代原论文图表。

原始仿真器、原始固件和历史数据未恢复。所有新增执行均明确为独立结果，安全估计和尾界的失败尝试也保留。根源码manifest和完整证据manifest分别验证源码与原始输出字节；哈希不证明测量真实性。

GitHub连接创建分支返回403（Resource not accessible by integration），本地Git缺少推送凭据，因此本次交付尚未上传到仓库。源码包及Git补丁可直接用于更新；完整证据包中的原始轨迹应上传到长期、可公开访问的存储，并在论文补充材料中给出固定版本和SHA256。GitHub Actions工作流也可生成新运行的可下载日志，但工作流存在不代表已执行，临时Actions制品不宜作为长期存档。

论文修订时，应把原k=3/768/4096-byte参数和相应性能图表一起更新，再报告新参数下实测或明确建模的结果。对本次证据可准确写为：

> The independent reference implementation uses module rank k=6 and flattened dimension n=m=1536. A pinned seven-attack Lattice Estimator run reports a minimum cost of 136.475 bits under the stated generic flattened-LWE and ADPS16 quantum model. This heuristic estimate exceeds the 128.1-bit target. Ciphertexts occupy 7,168 bytes. The accompanying synthetic packet simulation and core firmware build are independent artifacts; they do not validate the manuscript's original network or physical-board measurements.
