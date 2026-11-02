# PS-59: Short report for training data decision

ZiQi Chai | 30 September 2026

## English

### Data choice

Use CIC-IDS-2017 flow records for model training and labelled evaluation. Both models use the same 20 flow features. `prepared.npz` contains 1,867,149 training, 429,294 validation and 401,965 test records. The test partition stays outside model fitting.

`cic_test_dataset.csv` contains 400 records selected from that test partition, with 100 per class. It is a small repeatable Charts demonstration, not a representative traffic mix. Dashboard Test mode generates synthetic traffic rates; those values demonstrate the chart and cannot establish model accuracy or live detection performance.

### Random Forest

RF learns Benign, BruteForce, DoS and PortScan labels. Its final fit combines training and validation: 2,296,443 records, 100 trees and `min_samples_leaf=5`. Consequently, the original validation partition is not an independent evaluation of this final RF. Use the untouched 401,965-record test partition for the final comparison.

### Isolation Forest

IF and its Yeo-Johnson PowerTransformer fit on 300,000 Benign records sampled without replacement from the original training partition. The chosen forest has 100 trees and `max_samples=32768` per tree. The ONNX anomaly threshold is -0.15080632694939178. This normal-only training matches IF's task of finding unusual flows; it does not make the anomaly score an attack probability.

Selection used 359,750 validation Benign records, 69,544 validation known attacks and 132,220 novelty records. Novelty contains DDoS 128,027, WebAttack 2,180, Bot 1,966, Infiltration 36 and Heartbleed 11. Because novelty also guided tuning, its figures below are reused evaluation results, not independent unknown-attack test accuracy.

### Current model comparison

Measured on 30 September with the existing ONNX files and current `ModelCombinationService`. Test population: 342,307 Benign and 59,658 known-attack records. These are binary model decisions before PreFilter, policy thresholds and firewall execution.

| Combination | Benign FPR | Known-attack recall | Novelty flagged |
| --- | ---: | ---: | ---: |
| RF only | 0.229% | 97.368% | 61.493% |
| IF only | 0.109% | 1.312% | 23.641% |
| IF then RF | 0.109% | 1.312% | 23.641% |
| RF then IF | 0.327% | 97.248% | 44.688% |
| Parallel RF + IF | 0.338% | 97.370% | 61.506% |

RF only and Parallel accept RF's non-Benign winning label. RF then IF additionally requires RF confidence >= 0.6 before accepting that label. IF then RF rejects all IF-normal flows first, explaining its low recall. A flagged novelty record does not mean its attack family was classified correctly.

### Decision

Keep the existing RF-only default and the manual comparison modes. In this comparison, Parallel adds one known-attack detection and 17 novelty flags over RF only, with 371 additional Benign false positives. IF remains available for anomaly monitoring; `Unknown_Anomaly` never automatically blocks. No model retraining or feature expansion is needed today. Flow statistics cannot reliably identify attacks that depend on HTTP payload contents. Live capture performance still requires separate testing.

Evidence: current model metadata, `prepared.npz`, `novelty.npz`, `cic_test_dataset.csv`, `tune_if.py`, and the 30 September ONNX evaluation. See [verification record](sprint3-2026-09-30-verification.md).

## 中文

### 数据选择

模型训练和带标签评估使用 CIC-IDS-2017 流记录，RF 与 IF 共用相同的 20 维流统计特征。`prepared.npz` 分为训练集 1,867,149 行、验证集 429,294 行、测试集 401,965 行；测试集不参加拟合。

`cic_test_dataset.csv` 从测试集中每类抽取 100 行，共 400 行，用于 Charts 页可重复演示。均衡抽样不能代表真实流量比例。Dashboard 的 Test 模式生成模拟流量速率，只证明图表能显示，不能证明模型准确率或实时检测效果。

### Random Forest

RF 学习 Benign、BruteForce、DoS、PortScan 四类标签。最终拟合合并训练集和验证集，共 2,296,443 行，使用 100 棵树、`min_samples_leaf=5`。所以原验证集不能再作为最终 RF 的独立评估；最终对比使用未参加拟合的 401,965 行测试集。

### Isolation Forest

IF 及其 Yeo-Johnson PowerTransformer 使用原训练集中的 300,000 行良性记录拟合，抽样不放回。最终配置为 100 棵树、每棵树 `max_samples=32768`，ONNX 异常阈值为 -0.15080632694939178。只用良性数据拟合符合学习正常流量分布的任务；异常分数不是攻击概率。

模型选择使用验证集良性 359,750 行、已知攻击 69,544 行，以及 novelty 132,220 行。novelty 包含 DDoS 128,027、WebAttack 2,180、Bot 1,966、Infiltration 36、Heartbleed 11。它参与过调参，因此下面的 novelty 指标属于复用评估，不能称为独立未知攻击测试准确率。

### 当前模型对比

9/30 使用现有 ONNX 文件，按当前 `ModelCombinationService` 重算。测试集含良性 342,307 行、已知攻击 59,658 行。结果只表示模型层的良性/攻击判定，不包含 PreFilter、策略阈值和防火墙执行。

| 组合 | 良性误报率 | 已知攻击召回率 | Novelty 标记率 |
| --- | ---: | ---: | ---: |
| RF 单模型 | 0.229% | 97.368% | 61.493% |
| IF 单模型 | 0.109% | 1.312% | 23.641% |
| IF → RF | 0.109% | 1.312% | 23.641% |
| RF → IF | 0.327% | 97.248% | 44.688% |
| RF + IF 并联 | 0.338% | 97.370% | 61.506% |

RF 单模型和并联直接接受 RF 的非良性最高分类；RF → IF 还要求 RF 置信度至少 0.6，否则交给 IF。IF → RF 先放过 IF 判为正常的流，因此召回率明显下降。标记 novelty 为攻击不代表正确识别了攻击类别。

### 决定

保留现有 RF 单模型默认值和手动对比功能。本次并联比 RF 单模型多检出 1 条已知攻击、多标记 17 条 novelty，但增加 371 条良性误报。IF 保留为异常监控选项，`Unknown_Anomaly` 永不自动封禁。今天不重新训练或扩展特征。现有流统计特征难以可靠识别依赖 HTTP 载荷内容的攻击；实时抓包效果需要单独验证。

依据：当前模型元数据、两个 NPZ 数据集、400 行 CSV、`tune_if.py` 和 9/30 的 ONNX 评估。联调结果见[验证记录](sprint3-2026-09-30-verification.md)。
