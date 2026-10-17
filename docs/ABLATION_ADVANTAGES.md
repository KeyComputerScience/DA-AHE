# DA-AHE component contributions and paired calculations

The four panels are arranged horizontally and use the fixed rank-6 parameters
and the 20 paired seed records in evidence/independent/campaign-report.
DA denotes DA-AHE; Fixed is the without-Markov policy; -C, -R and -V remove
IntDb2, route repair and HVE, respectively.

| Panel | Quantity | DA-AHE | Comparison |
|---|---|---:|---:|
| (a) | Mean modeled CPU cost per valid report (mJ) | 0.771703 | Fixed nominal: 1.037129 |
| (b) | Protected ciphertext payload (bytes) | 7,168 | Raw two-polynomial: 14,336 |
| (c) | Valid delivery / source opportunity (%) | 35.571667 | Without IntDb2: 33.395000 |
| (d) | Modeled invalid acceptance / admitted (%) | 0.000000 | Without HVE: 2.086961 |

## How the components contribute

The evidence supports three complementary functions: compact protected
representation, lower modeled CPU cost per valid delivered report, and aggregate
validity checking. Their integration is the design contribution; each ablation
quantifies its own component effect and denominator.

| Component | Implemented mechanism | Supported contribution |
|---|---|---|
| Admission policy | Causal controlled-HMM belief, immutable actions and resource/robust gates | Complete-policy CPU cost per valid report decreases by 25.59% versus fixed nominal |
| IntDb2 and profile-bound packing | Select/quantize the declared support and pack its coefficients with aggregate tags | Exact protected payload halves; the recorded IntDb2 ablation gains 2.18 pp valid delivery |
| HVE and authorization lifecycle | Hidden aggregate tags, signed roster/context/profile binding, durable emission and replay state | Recorded modeled invalid acceptance is zero with verification enabled |

The CPU comparison does not isolate belief estimation from other admission
choices. The packing reduction is structural arithmetic, and HVE's modeled
acceptance result is separate from a cryptographic security probability.
Complete comparisons remain in [the all-method table](../experiments/CURRENT_RESULTS.md).

## Component contributions

DA-AHE lowers mean per-seed CPU energy per valid report from 1.037 to 0.772 mJ relative to the fixed nominal policy, a 25.59% reduction (95% paired-bootstrap CI: 24.22% to 26.95%). At the same cryptographic parameter tuple, one-polynomial packing halves the protected ciphertext payload from 14,336 to 7,168 bytes. The IntDb2-enabled configuration improves valid delivery by 2.18 percentage points over the variant without IntDb2 (95% CI: 1.77 to 2.61), while HVE reduces modeled invalid acceptance from 2.09% to zero. These complementary results support the integration of admission control, compact protected representation and aggregate verification. The fixed policy nevertheless delivers 44.01% of source opportunities versus 35.57% for DA-AHE, reflecting a service-cost tradeoff. Policy comparisons include different admission behavior and do not isolate HMM gains. The route-repair ablation has identical archived outcomes, and all 140 recovery observations are right-censored, so these records do not establish a recovery-time advantage. The payload reduction excludes tickets, MACs, headers and retransmissions, and invalid acceptance uses the service model's injected invalidity labels.

## CPU normalization and paired uncertainty

For method m and seed s, let E[m,s] be complete-run modeled CPU joules and
v[m,s] be valid delivery per source opportunity. With 3,000 opportunities:

    valid_reports[m,s] = 3000 * v[m,s]
    cpu_mJ_per_valid[m,s] = 1000 * E[m,s] / valid_reports[m,s]
    displayed_mean[m] = mean_s(cpu_mJ_per_valid[m,s])
    reduction_percent = 100 * (1 - displayed_mean[DA] / displayed_mean[fixed])

The reduction is 25.592363%, with paired-bootstrap 95% interval
[24.219165%, 26.947800%]. The fixed nominal policy admits 100% of opportunities;
DA-AHE admits 52.603333%. The quantity compares complete policies.

The mean valid-delivery gain over Without IntDb2 is 2.176667 percentage points,
with paired-bootstrap 95% interval [1.766667, 2.610000] percentage points.
The index bank contains 100,000 shared PCG64 seed resamples with random seed
20261017. Displayed intervals are pointwise percentile intervals.

## Payload

    packed_bytes = (module_rank + 1) * ring_degree * 4
                 = (6 + 1) * 256 * 4
                 = 7168
    raw_bytes = 2 * packed_bytes = 14336
    reduction_percent = 100 * (1 - packed_bytes / raw_bytes) = 50

These quantities cover protected ciphertext payload. Ticket, MAC, header and
retransmission bytes have separate accounting.

## Aggregate validity and recovery

Invalid acceptance uses admitted reports as the denominator and injected
invalidity labels from the service model. DA-AHE and Without route repair have
identical archived outcomes. All 140 recovery records are right-censored at
125 seconds, so the figure contains no recovery-time ranking.

## Figure caption

Fig. 6. DA-AHE component contributions at 3,000 source nodes. (a) Modeled CPU cost per valid report, normalized within each seed; (b) protected ciphertext payload for raw two-polynomial and packed one-polynomial representations at fixed rank 6, ring degree 256 and q = 2^32; (c) valid delivery per source opportunity; (d) modeled invalid acceptance per admitted report. Bars in (a), (c) and (d) show equally weighted means over 20 paired seeds; error bars are pointwise 95% percentile-bootstrap intervals from 100,000 shared seed resamples. Panel (b) is exact payload accounting and excludes tickets, MACs, headers and retransmissions. Fixed nominal is the without-Markov policy; its admission rate differs from DA-AHE, so panel (a) compares complete policies. Route-repair and full DA-AHE outcomes coincide in this archive. All recovery records are right-censored; no recovery-time ranking is shown. Modeled invalid acceptance does not estimate a cryptographic forgery probability.

## Export

~~~bash
python tools/plot_ablation_advantages.py \
  --csv evidence/independent/campaign-report/per-seed.csv \
  --config evidence/independent/campaign-report/config.json \
  --output runs/ablation-advantages/revised-ablationA \
  --resamples 100000 --seed 20261017
~~~

The output prefix supplies vector PDF/SVG, a 300-dpi PNG, numerical JSON and
a text caption and results paragraph in the requested run directory. The saved
[numerical results](../experiments/ablation-advantages.json) retain the calculation
inputs, statistics and comparison scope.
