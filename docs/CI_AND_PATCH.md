# Hidden files, current CI and historical patch

The current workflow is `.github/workflows/reproduce.yml`. Every push to main,
pull request and manual trigger runs all nine substantive jobs: source bytes,
real-provider functional/native tests, ARM build, small replay, published
historical 140-case raw recomputation on Linux and strict frozen-source replay
on macOS ARM64/Python 3.12.10, fresh full 140-case generation/replay,
paired performance-matrix integration and statistical/figure exports,
and fresh seven-attack security estimates plus exact-CDT decoding checks. The
final coverage job fails on any missing, skipped, failed or cancelled job.
The observed historical floating-point portability failure and unchanged exact
replay requirement are documented in `REPLAY_PORTABILITY.md`.
See `PUBLIC_EVIDENCE.md` for immutable historical inputs and
`REPRODUCTION_COVERAGE.md` for what these checks can establish.

The instructions below refer only to an earlier patch; do not reapply it to a
current checkout merely to run the current workflow.

The patch targets GitHub commit `f0a3647cea71515649f53dcdb9e0dc3fb22bf483`.
The full reviewed source archive includes hidden files. Browser folder uploads
may omit them; use Git and inspect the staged paths explicitly.

From a local checkout of the target repository, first preserve your existing
uncommitted changes. Review the patch and check it against your current tree:

```bash

git rev-parse HEAD
git status --short
git apply --check /path/to/DA-AHE-f0a3647.patch
git apply /path/to/DA-AHE-f0a3647.patch
git status --short
git add -A
git diff --cached --stat
git ls-files .gitignore .dockerignore .github/workflows/ci.yml
```

`.gitignore` prevents keys, private ledgers, generated runs and build outputs
from being added as new files. It cannot remove secrets already committed to
history. `.dockerignore` removes private/generated files from the build context.

Install/build and test failures must fail their job. Missing original-author
evidence is separately reported by `daahe audit`; complete independent software
CI does not change that evidence state or create physical-board measurements.
