# Historical external experiment contract

`paper_targets.json` records the original manuscript targets.
`matrix.json`, `configurations.csv` and `METRICS_SCHEMA.md` define a prospective
700-run OMNeT++/INET external-import workflow. They are not executed independent
measurements. Hashes are bound in `configs/manuscript_alignment.json`.

For an external import, pass this `matrix.json` explicitly to the statistics
tool and use the associated schema. Historical relative paths retain their
original context. The independent Python study has a separate schema and is
reported in `experiments/current-results.json` and `CURRENT_RESULTS.md`.
