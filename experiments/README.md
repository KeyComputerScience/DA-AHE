# Active independent k=6 evaluation

The current experimental tables are [CURRENT_RESULTS.md](CURRENT_RESULTS.md)
and [current-results.json](current-results.json). They describe the fixed rank-6 study and bind its source evidence.

```bash
python tools/build_current_evaluation.py --check experiments
python tools/build_current_evaluation.py --output-dir runs/current-evaluation
```

The exporter checks all 140 saved per-seed rows (seven methods and 20 paired
seeds) against the published summary, verifies k=6/7,168-byte identities, and
recomputes all 72 synthetic aggregate-fidelity cases and exact risk budgets.
It does not fit a simulator to the original paper's numbers. Modeled energy,
conditional delivered-report delay, sampling/admission and censored recovery
are identified explicitly. The underlying full raw archive and fresh campaign
commands are documented in [PUBLIC_EVIDENCE.md](../docs/PUBLIC_EVIDENCE.md).

See [the evaluation specification](../docs/EVALUATION.md). The current study is independent Python simulation and synthetic
signal arithmetic, not original OMNeT++/INET or physical-board measurements.

Historical external-import schemas are in
[the archive](../docs/archive/original-experiment-contract/README.md).
