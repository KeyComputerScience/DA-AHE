# SPDX-License-Identifier: MIT
"""Evidence indices must reject scope inflation, drift and unsafe paths."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("paper_evidence_checker", ROOT / "tools/check_paper_evidence.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class PaperEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "configs").mkdir()
        self.paper = {"filename": "TSMC_DA (1).pdf", "sha256": "a" * 64,
                      "pages": 14, "editable_source_available": False,
                      "text_same_as_previous": True}
        self.index = {"schema_version": 1, "manuscript": self.paper,
                      "paper_reproduced": False, "full_system_certified": False,
                      "claims": [{"id": "fidelity", "paper_reference": "p.13 Table III",
                                  "statement": "Aggregate fidelity", "scope": "synthetic only",
                                  "status": "requires_original_data",
                                  "implementation_paths": ["tool.py"], "evidence_paths": [],
                                  "verification_commands": ["python tool.py"],
                                  "required_for_original_claim": ["original sensor corpus"]}]}
        (self.root / "tool.py").write_text("# fixture\n")
        self.write()

    def write(self):
        (self.root / "configs/paper_claims.json").write_text(json.dumps(self.index))
        (self.root / "configs/manuscript_alignment.json").write_text(
            json.dumps({"received_pdf": self.paper}))

    def test_index_pass_is_not_paper_reproduction(self):
        result = checker.verify(self.root)
        self.assertEqual(result["claims"], 1)
        self.assertFalse(result["paper_reproduced"])
        self.assertFalse(result["full_system_certified"])

    def test_original_paper_claim_cannot_be_inflated(self):
        self.index["paper_reproduced"] = True
        self.write()
        with self.assertRaisesRegex(ValueError, "unsupported global"):
            checker.verify(self.root)

    def test_pdf_hash_drift_fails(self):
        self.index["manuscript"] = dict(self.paper, sha256="b" * 64)
        self.write()
        with self.assertRaisesRegex(ValueError, "PDF identity"):
            checker.verify(self.root)

    def test_path_cannot_read_outside_repository(self):
        self.index["claims"][0]["implementation_paths"] = ["../private.py"]
        self.write()
        with self.assertRaisesRegex(ValueError, "unsafe manifest path"):
            checker.verify(self.root)

    def test_dangling_evidence_is_rejected(self):
        self.index["claims"][0]["evidence_paths"] = ["missing.json"]
        self.write()
        with self.assertRaisesRegex(ValueError, "missing indexed file"):
            checker.verify(self.root)

    def test_hash_mismatch_is_rejected(self):
        self.index["claims"][0]["evidence_paths"] = ["tool.py"]
        self.index["generated_evidence_records"] = [{"path": "tool.py", "sha256": "0" * 64}]
        self.write()
        with self.assertRaisesRegex(ValueError, "evidence hash mismatch"):
            checker.verify(self.root)

    def test_missing_gap_cannot_disappear(self):
        self.index["claims"][0]["required_for_original_claim"] = []
        self.write()
        with self.assertRaisesRegex(ValueError, "missing gap"):
            checker.verify(self.root)


if __name__ == "__main__":
    unittest.main()
