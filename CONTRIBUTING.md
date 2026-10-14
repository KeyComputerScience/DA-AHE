# Contribution and review workflow

Keep original-source code under MIT with an SPDX identifier. Do not copy author
or upstream code without preserving its actual license. Keep private keys,
restricted sensor data, and live replay databases out of source releases.

For an algorithm change, identify the paper equation or explain the completion
choice. Update parameter/profile/context hashes whenever the bound assumptions
change. Do not weaken strict evidence checks to make a demo pass. Add a meaningful
test for a new failure boundary or protocol attack and record its actual execution
status; do not mark unexecuted tests passed.

For an experiment, freeze the action library/model before evaluation; separate
calibration and evaluation seeds; retain failed/censored runs; use matched traffic,
disturbance and energy boundaries across methods. Publish raw metrics and the
corresponding config/trace hashes before computing normalized comparisons.

Before a release, execute the reviewer checklist with authorization, retain logs,
capture the environment, audit provenance, and regenerate the content manifest.
Package code plus permitted evidence only. Avoid claims stronger than the evidence.

