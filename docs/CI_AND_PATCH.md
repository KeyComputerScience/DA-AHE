# Hidden files, CI and patch application

The patch targets GitHub commit `f0a3647cea71515649f53dcdb9e0dc3fb22bf483`.
The full reviewed source archive includes hidden files. Browser folder uploads
may omit them; use Git and inspect the staged paths explicitly.
No command below was executed when preparing this delivery.

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

The last command should list all three paths. If a patch conflict is reported,
review the later changes; do not overwrite them or force-apply blindly. This
package does not create a commit, push, PR or workflow run on your behalf.

`.gitignore` prevents keys, private ledgers, generated runs and build outputs
from being added as new files. It cannot remove secrets already committed to
history. `.dockerignore` removes private/generated files from the build context;
it is not an application permission or encryption policy.

The workflow runs on future pushes to main, PRs and manual dispatch. It uses
read-only token permissions, immutable Action commits and a pinned native
liboqs commit. It retains only named public reports and environment/test logs,
never complete `runs/` directories or source emission databases.

Two jobs cover ordinary Python tests + portable C known answers, and explicit
real-ML-DSA tests + data-path demos including profile capacities. Install/build
and test failures must fail their job. Missing author evidence is separately
reported by `daahe audit`; it is not converted into a passing paper-reproduction
claim by these CI jobs.

The workflow verifies the committed source manifest before generating evidence.
After a later intentional code change, the release maintainer must review the
source diff, create a fresh manifest under a new filename, replace the committed
manifest deliberately, and publish the resulting archive checksum separately.
Never generate over a received release manifest before first verifying it.

The Docker base image and apt/transitive dependency graph are not a complete
archival environment lock. Capture the actual image digest, native binary hashes,
packages and compiler when a verified run is made. Workflow source alone is not
an execution log or a successful badge.

