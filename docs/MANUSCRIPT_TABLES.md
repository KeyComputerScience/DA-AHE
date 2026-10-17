# Tables and calculations

| Quantity | Data | Calculation |
|---|---|---|
| Conditional delay, CPU, radio TX, wire bytes and recovery counts | [per-seed.csv](../evidence/independent/campaign-report/per-seed.csv) | [paired-statistics code](../tools/manuscript_table.py) |
| Effective delivery, conditional delay and invalid acceptance | [per-seed.csv](../evidence/independent/campaign-report/per-seed.csv) | [ablation calculations](ABLATION_ADVANTAGES.md), [numerical results](../experiments/ablation-advantages.json) |
| nRF52840 memory | [firmware_memory_nrf52840.json](../configs/firmware_memory_nrf52840.json) | [byte/KiB arithmetic](#memory) |
| Reconstruction fidelity | [reconstruction_fidelity.json](../configs/reconstruction_fidelity.json) | [metric formulas](#reconstruction) |

## Memory

One KiB is 1,024 bytes. Displayed KiB values are rounded to two decimal places.

| Quantity | Calculation | Bytes |
|---|---|---:|
| Flash | 90,104 + 1,084 | 91,188 |
| Static SRAM | 1,084 + 26,892 | 27,976 |
| Peak SRAM | 27,976 + 1,352 | 29,328 |
| SRAM headroom | 262,144 - 29,328 | 232,816 |

## Reconstruction

For a reference vector x and reconstructed vector x_hat of length n:

    squared_error = sum((x[k] - x_hat[k])**2 for k in range(n))
    RMSE = sqrt(squared_error / n)
    PRD_percent = 100 * sqrt(squared_error / sum(x[k]**2 for k in range(n)))

PRD requires nonzero reference energy. RMSE uses the mV/mA unit convention and
PRD uses percent. The tabulated plus/minus quantities are stored as spread.

## Paired-seed statistics

For each metric, the table uses the arithmetic mean of 20 seed values.
The 95% percentile interval uses the 2.5% and 97.5% quantiles of 100,000
bootstrap seed means. Every method and metric uses the same seed-index matrix,
with PCG64 seed 20261017. The cost table retains all seven methods; the ablation
figure selects DA-AHE and four component variants.

The export command is specified in
[ABLATION_EVALUATION.md](ABLATION_EVALUATION.md#coordinated-manuscript-fig-6-and-cost-table).
