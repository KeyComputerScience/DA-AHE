# Hidden files, CI and patch application

The patch targets GitHub commit `f0a3647cea71515649f53dcdb9e0dc3fb22bf483`.
The full reviewed source archive includes hidden files. Browser folder uploads
may omit them; use Git and inspect the staged paths explicitly.

From a local checkout of the target repository, first preserve your existing
uncommitted changes. Review the patch and check it against your current tree:

###bash

git rev-parse HEAD
git status --short
git apply --check /path/to/DA-AHE-f0a3647.patch
git apply /path/to/DA-AHE-f0a3647.patch
git status --short
git add -A
git diff --cached --stat
git ls-files .gitignore .dockerignore .github/workflows/ci.yml

`.gitignore` prevents keys, private ledgers, generated runs and build outputs
from being added as new files. It cannot remove secrets already committed to
history. `.dockerignore` removes private/generated files from the build context.

Two jobs cover ordinary Python tests + portable C known answers, and explicit
real-ML-DSA tests + data-path demos including profile capacities. Install/build
and test failures must fail their job. Missing author evidence is separately
reported by `daahe audit`s.
