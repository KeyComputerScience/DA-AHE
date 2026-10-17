# Ablation figure and calculations

The four panels use the fixed rank-6 parameters and the 20 paired seed records
in evidence/independent/campaign-report.

| Panel | Quantity | DA-AHE | Comparison |
|---|---|---:|---:|
| (a) | Mean modeled CPU cost per valid report (mJ) | 0.771703 | Fixed nominal: 1.037129 |
| (b) | Protected ciphertext payload (bytes) | 7,168 | Raw two-polynomial: 14,336 |
| (c) | Valid delivery / source opportunity (%) | 35.571667 | Without IntDb2: 33.395000 |
| (d) | Modeled invalid acceptance / admitted (%) | 0.000000 | Without HVE: 2.086961 |

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

## Export

~~~bash
python tools/plot_ablation_advantages.py \
  --csv evidence/independent/campaign-report/per-seed.csv \
  --config evidence/independent/campaign-report/config.json \
  --output runs/ablation-advantages/revised-ablationA \
  --resamples 100000 --seed 20261017
~~~

The output prefix supplies vector PDF/SVG, a 300-dpi PNG, numerical JSON and
a text caption. The figure is available at
[revised-ablationA.pdf](manuscript/figures/revised-ablationA.pdf).
