#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the paper-to-evidence index without treating an index as a proof."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from daahe.evidence import _safe_path  # noqa: E402

STATUSES = {"reproduced_independent_scope", "implemented_not_original_measurement",
            "requires_original_data", "requires_hardware", "requires_proof"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular(root, name):
    path = _safe_path(root, name)
    require(path.is_file(), f"missing indexed file: {name}")
    return path


def verify(root=ROOT):
    root = Path(root).resolve()
    index = json.loads(regular(root, "configs/paper_claims.json").read_text())
    alignment = json.loads(regular(root, "configs/manuscript_alignment.json").read_text())
    require(index.get("schema_version") == 1, "unsupported paper evidence index")
    paper = index["manuscript"]
    require(paper == alignment["received_pdf"], "received PDF identity/scope drift")
    require(re.fullmatch(r"[0-9a-f]{64}", paper["sha256"]) is not None,
            "invalid manuscript hash")
    require(paper["pages"] == 14 and paper["editable_source_available"] is False,
            "unsupported manuscript source claim")
    require(index.get("paper_reproduced") is False and
            index.get("full_system_certified") is False, "unsupported global claim")
    claims = index["claims"]
    require(isinstance(claims, list) and claims, "empty paper claim index")
    seen, paths, counts = set(), set(), Counter()
    for claim in claims:
        identity = claim["id"]
        require(isinstance(identity, str) and identity and identity not in seen,
                "duplicate or empty claim identifier")
        seen.add(identity)
        require(claim["status"] in STATUSES, f"unsupported status: {identity}")
        counts[claim["status"]] += 1
        for field in ("paper_reference", "statement", "scope"):
            require(isinstance(claim[field], str) and claim[field].strip(),
                    f"missing {field}: {identity}")
        for field in ("implementation_paths", "evidence_paths", "verification_commands",
                      "required_for_original_claim"):
            require(isinstance(claim[field], list) and
                    all(isinstance(v, str) and v.strip() for v in claim[field]),
                    f"invalid {field}: {identity}")
        require(claim["implementation_paths"] and claim["verification_commands"],
                f"claim has no implementation or verification entry point: {identity}")
        if claim["status"] == "reproduced_independent_scope":
            require(claim["evidence_paths"], f"independent result has no evidence: {identity}")
        if claim["status"].startswith("requires_"):
            require(claim["required_for_original_claim"], f"missing gap description: {identity}")
        for name in claim["implementation_paths"] + claim["evidence_paths"]:
            regular(root, name)
            paths.add(name)
    records = index.get("generated_evidence_records", [])
    require(isinstance(records, list), "invalid evidence digest list")
    digests = set()
    for record in records:
        name, digest = record["path"], record["sha256"]
        require(name not in digests and name in paths, "duplicate or unindexed evidence digest")
        digests.add(name)
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "invalid evidence digest")
        require(hashlib.sha256(regular(root, name).read_bytes()).hexdigest() == digest,
                f"evidence hash mismatch: {name}")
    return {"status": "passed_paper_evidence_index", "claims": len(seen),
            "indexed_files": len(paths), "hash_bound_records": len(digests),
            "status_counts": dict(sorted(counts.items())),
            "manuscript_sha256": paper["sha256"], "paper_reproduced": False,
            "full_system_certified": False,
            "scope": "Identity, paths, declared scope and byte integrity. Experiment execution evidence is supplied by the evidence reproducer."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        result = verify(args.root)
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(json.dumps({"status": "failed_paper_evidence_index", "error": str(error)}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
