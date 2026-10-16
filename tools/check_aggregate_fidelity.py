#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute and recompute synthetic aggregate-domain integer-lifting fidelity cases.

No sensor corpus, physical units, original Table III result, encryption run or
deployment certificate is inferred from these experiments. Batch sizes above a
profile's nmax are retained as explicitly inadmissible mathematical diagnostics.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import platform
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from daahe.mlwe import DEFAULT_PARAMETERS  # noqa: E402
from daahe.profiles import example_profiles  # noqa: E402
from daahe.signal import (  # noqa: E402
    TRANSFORM_ID, encode_channels, forward_channel, inverse_channel,
    reconstruct_channels, round_div,
)

FAMILIES = {
    "smooth_triangle": "Integer triangle waves with source/channel-specific phase, amplitude and DC offset; period 120 samples.",
    "sparse_pulses": "Three signed integer impulses per channel with deterministic locations and amplitudes; no DC offset.",
    "mixed_step_noise": "Integer DC plus a step at sample 120 and bounded SHA256-derived noise in [-12,12].",
    "constant": "Source/channel-specific integer DC values, constant over the complete window.",
    "alternating": "Source/channel-specific integer alternating-sign high-frequency sequence.",
    "zero": "All-zero reference; PRD is undefined because reference energy is zero.",
}
DEFAULT_FAMILIES = ("smooth_triangle", "sparse_pulses", "mixed_step_noise")
SOURCE_FILES = (
    "tools/check_aggregate_fidelity.py", "src/daahe/__init__.py", "src/daahe/signal.py",
    "src/daahe/profiles.py", "src/daahe/mlwe.py", "src/daahe/ring.py",
)
SCOPE = "Declared synthetic integer-count signals only; not original Table III reproduction, physical measurements, encryption/decryption evidence or a full-system certificate."


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
        stream.write("\n")


def draw(seed, source, channel, label, modulus):
    """Integer-only deterministic generator; independent of Python's random module."""
    material = f"daahe-aggregate-fidelity-v1/{seed}/{source}/{channel}/{label}".encode()
    return int.from_bytes(hashlib.sha256(material).digest(), "big") % modulus


def generate_sources(family, seed, count):
    if family not in FAMILIES or type(seed) is not int or seed < 0:
        raise ValueError("unknown family or invalid nonnegative integer seed")
    if type(count) is not int or not 1 <= count <= 16:
        raise ValueError("batch size must be an integer in [1,16]")
    sources = []
    for source in range(count):
        channels = []
        for channel in range(2):
            base = 40 + draw(seed, source, channel, "base", 81)
            amplitude = 10 + draw(seed, source, channel, "amplitude", 31)
            phase = draw(seed, source, channel, "phase", 120)
            if family == "smooth_triangle":
                values = [base + amplitude * (60 - abs((t + phase) % 120 - 60)) // 30
                          for t in range(240)]
            elif family == "sparse_pulses":
                values = [0] * 240
                for pulse in range(3):
                    position = draw(seed, source, channel, f"pulse-{pulse}", 240)
                    values[position] += amplitude * (1 if pulse % 2 == 0 else -1)
            elif family == "mixed_step_noise":
                values = [base + (amplitude if t >= 120 else -amplitude)
                          + draw(seed, source, channel, f"noise-{t}", 25) - 12
                          for t in range(240)]
            elif family == "constant":
                values = [base] * 240
            elif family == "alternating":
                values = [amplitude * (1 if (t + phase) % 2 == 0 else -1) for t in range(240)]
            else:
                values = [0] * 240
            channels.append(values)
        sources.append(channels)
    return sources


def add_vectors(vectors):
    return [sum(column) for column in zip(*vectors)]


def subtract(left, right):
    return [a - b for a, b in zip(left, right)]


def inverse_flat(coefficients):
    return list(inverse_channel(coefficients[:240]) + inverse_channel(coefficients[240:]))


def scatter(values, support):
    coefficients = [0] * 480
    for position, value in zip(support, values):
        coefficients[position] = value
    return coefficients


def metrics(error, reference):
    def part(e, r):
        squared_error = sum(value * value for value in e)
        energy = sum(value * value for value in r)
        return {"samples": len(e), "squared_error": squared_error, "reference_energy": energy,
                "rmse_integer_counts": math.sqrt(squared_error / len(e)),
                "mae_integer_counts": sum(abs(value) for value in e) / len(e),
                "max_absolute_error_integer_counts": max(abs(value) for value in e),
                "bias_integer_counts": sum(e) / len(e),
                "prd_percent": 100 * math.sqrt(squared_error / energy) if energy else None,
                "prd_status": "defined" if energy else "undefined_zero_reference_energy"}
    return {"combined": part(error, reference),
            "channels": [part(error[:240], reference[:240]), part(error[240:], reference[240:])]}


def evaluate_case(sources, profile):
    """Telescoping vector attribution in a declared order; errors need not be orthogonal."""
    if not sources or len(sources) > 16 or any(len(source) != 2 for source in sources):
        raise ValueError("one to sixteen sources required")
    transformed = [list(forward_channel(source[0]) + forward_channel(source[1]))
                   for source in sources]
    truth = add_vectors([source[0] + source[1] for source in sources])
    if add_vectors([inverse_flat(coefficients) for coefficients in transformed]) != truth:
        raise ValueError("single-source exact-inversion invariant failed")
    summed_coefficients = add_vectors(transformed)
    full = inverse_flat(summed_coefficients)
    selected = inverse_flat(scatter([summed_coefficients[p] for p in profile.support], profile.support))
    quantized = [list(encode_channels(source, profile.support, profile.delta_q,
                                     profile.coefficient_bound)) for source in sources]
    summed_quantized = add_vectors(quantized)
    if any(abs(value) > 32768 for value in summed_quantized):
        raise ValueError("actual aggregate data coefficients exceed centered plaintext range")
    aggregate = list(sum(reconstruct_channels(summed_quantized, profile.support, profile.delta_q), ()))
    individual = add_vectors([list(sum(reconstruct_channels(q, profile.support, profile.delta_q), ()))
                              for q in quantized])
    # Full-support quantization is a mathematical diagnostic, not a 480-coefficient ciphertext.
    full_quantized_coefficients = add_vectors([
        [profile.delta_q * round_div(value, profile.delta_q) for value in row]
        for row in transformed])
    full_quantized = inverse_flat(full_quantized_coefficients)
    errors = {"integer_lifting_aggregation": subtract(full, truth),
              "selection_increment_after_lifting": subtract(selected, full),
              "quantization_increment_after_selection": subtract(aggregate, selected),
              "total_selected_quantized_aggregate": subtract(aggregate, truth),
              "sum_individual_selected_quantized": subtract(individual, truth),
              "aggregate_minus_sum_individual": subtract(aggregate, individual),
              "full_support_quantization_increment": subtract(full_quantized, full)}
    components = [errors[name] for name in ("integer_lifting_aggregation",
                  "selection_increment_after_lifting", "quantization_increment_after_selection")]
    if add_vectors(components) != errors["total_selected_quantized_aggregate"]:
        raise ValueError("error attribution identity failed")
    energies = [sum(v * v for v in component) for component in components]
    cross = sum(sum(a * b for a, b in zip(components[i], components[j]))
                for i in range(3) for j in range(i + 1, 3))
    return {"sources": sources, "profile": {**asdict(profile), "support": list(profile.support)},
            "profile_digest": profile.digest,
            "batch_size": len(sources), "profile_capacity_admissible": len(sources) <= profile.nmax,
            "capacity_scope": "Sizes exceeding profile nmax are inadmissible diagnostics; no protocol admission is claimed.",
            "actual_aggregate_data_no_wrap": True,
            "max_source_quantized_coefficient": max(abs(v) for row in quantized for v in row),
            "max_aggregate_quantized_coefficient": max(abs(v) for v in summed_quantized),
            "vectors": {"true_source_integer_sum": truth, "summed_full_transform": summed_coefficients,
                        "inverse_summed_full_transform": full, "inverse_selected_unquantized_sum": selected,
                        "source_quantized_selected_coefficients": quantized,
                        "inverse_selected_quantized_sum": aggregate,
                        "sum_individual_selected_quantized_reconstructions": individual,
                        "inverse_full_support_quantized_sum": full_quantized},
            "errors": errors, "metrics": {name: metrics(error, truth) for name, error in errors.items()},
            "attribution": {"order": ["integer_lifting_aggregation", "selection", "quantization"],
                            "telescoping_vector_identity": True, "component_squared_errors": energies,
                            "twice_pairwise_error_inner_products": 2 * cross,
                            "total_squared_error": sum(energies) + 2 * cross,
                            "scope": "Exact vector decomposition in this order; RMSE/PRD or squared errors must not be added without cross terms."}}


def source_records(root):
    return [{"path": name, "sha256": digest(root / name)} for name in SOURCE_FILES]


def summary_records(index, cases):
    rows = []
    for profile in index["profiles"]:
        for size in index["batch_sizes"]:
            selected = [case for case in cases if case["profile"]["name"] == profile
                        and case["batch_size"] == size]
            summaries = {}
            for name in selected[0]["metrics"]:
                values = [case["metrics"][name]["combined"] for case in selected]
                prds = [value["prd_percent"] for value in values if value["prd_percent"] is not None]
                summaries[name] = {"case_rmse_mean_integer_counts": sum(v["rmse_integer_counts"] for v in values) / len(values),
                                   "case_prd_mean_percent": sum(prds) / len(prds) if prds else None,
                                   "defined_prd_cases": len(prds),
                                   "max_absolute_error_integer_counts": max(v["max_absolute_error_integer_counts"] for v in values)}
            rows.append({"profile": profile, "batch_size": size, "cases": len(selected),
                         "profile_capacity_admissible": selected[0]["profile_capacity_admissible"],
                         "admissible_cases": len(selected) if selected[0]["profile_capacity_admissible"] else 0,
                         "inadmissible_diagnostic_cases": 0 if selected[0]["profile_capacity_admissible"] else len(selected),
                         "metrics": summaries})
    return {"schema_version": 1, "rows": rows, "scope": SCOPE,
            "estimand": "Descriptive equal-case means over declared synthetic family/seed cases, with no confidence interval, independent-sample or population-performance claim."}


def run_experiment(output, seeds=(1000, 1001), families=DEFAULT_FAMILIES,
                   batch_sizes=(1, 12, 14, 16), profiles=("pi0", "pi1", "pi2")):
    output = Path(output)
    choices = {"seeds": list(seeds), "families": list(families),
               "batch_sizes": list(batch_sizes), "profiles": list(profiles)}
    if any(not values or len(values) != len(set(values)) for values in choices.values()):
        raise ValueError("experiment dimensions must be nonempty and duplicate-free")
    if any(type(seed) is not int or seed < 0 for seed in seeds):
        raise ValueError("seeds must be nonnegative integers")
    if any(f not in FAMILIES for f in families) or any(p not in ("pi0", "pi1", "pi2") for p in profiles):
        raise ValueError("unknown family or compression profile")
    if any(type(n) is not int or not 1 <= n <= 16 for n in batch_sizes):
        raise ValueError("batch sizes must be integers in [1,16]")
    output.mkdir(parents=True, exist_ok=False)
    sources = source_records(ROOT)
    for name in SOURCE_FILES:
        target = output / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    index = {"schema_version": 1, "origin": "independent_synthetic_aggregate_fidelity",
             "paper_table_iii_reproduced": False, "physical_measurements": False,
             "full_system_certified": False, "scope": SCOPE, **choices,
             "signal_family_definitions": {name: FAMILIES[name] for name in families},
             "signal_units": "arbitrary integer counts; both channels use the same declared synthetic unit",
             "signal_generator": "SHA256 integer generator v1; no floating-point waveform generation",
             "comparison_paths": {
                 "full_support": "Inverse of the summed 480 full integer transforms, before selection or quantization; mathematical diagnostic.",
                 "selected_unquantized": "Select the declared profile support from summed transforms, scatter omitted coefficients to zero, then invert.",
                 "selected_quantized": "Quantize each source on the declared support using the actual reference encoder, sum retained coefficients and reconstruct once; no encryption is executed.",
                 "sum_individual": "Reconstruct each source's selected/quantized coefficients separately, then sum in the signal domain.",
                 "full_support_quantized": "Quantize all 480 coefficients per source before summation and inversion; this diagnostic exceeds the single-polynomial payload and is not a protocol action."},
             "metric_normalization": "Errors are measured against the actual aggregate source sum without division by N. PRD uses its squared energy; zero/cancelled reference energy yields null, never 0 percent.",
             "transform_id": TRANSFORM_ID, "encryption_parameters": asdict(DEFAULT_PARAMETERS),
             "python_version": platform.python_version(), "created_utc": datetime.now(timezone.utc).isoformat(),
             "command": ["python", "tools/check_aggregate_fidelity.py", "--output", "<new-evidence-dir>",
                         "--seeds", *map(str, seeds), "--families", *families,
                         "--batch-sizes", *map(str, batch_sizes), "--profiles", *profiles],
             "source_files": sources, "source_digest": hashlib.sha256(canonical(sources)).hexdigest(),
             "cases": []}
    library = {profile.name: profile for profile in example_profiles()}
    cases = []
    for seed in seeds:
        for family in families:
            for size in batch_sizes:
                signals = generate_sources(family, seed, size)
                for name in profiles:
                    case = evaluate_case(signals, library[name])
                    case.update(seed=seed, family=family)
                    filename = f"cases/{name}-n{size}-{family}-seed{seed}.json"
                    write_json(output / filename, case)
                    index["cases"].append({"path": filename, "seed": seed, "family": family,
                                           "batch_size": size, "profile": name})
                    cases.append(case)
    if source_records(ROOT) != sources:
        raise ValueError("source changed during execution; evidence retained but not finalized")
    write_json(output / "index.json", index)
    write_json(output / "summary.json", summary_records(index, cases))
    files = [{"path": p.relative_to(output).as_posix(), "size": p.stat().st_size, "sha256": digest(p)}
             for p in sorted(output.rglob("*")) if p.is_file()]
    write_json(output / "manifest.json", {"schema_version": 1, "algorithm": "SHA256", "files": files,
                                         "scope": "Byte integrity only; verify additionally recomputes every case."})
    return {"status": "executed_synthetic_fidelity", "cases": len(cases), "scope": SCOPE}


def safe_path(root, name):
    if not isinstance(name, str) or "\\" in name or "\x00" in name:
        raise ValueError("unsafe evidence path")
    parts = PurePosixPath(name)
    if parts.is_absolute() or any(p in ("", ".", "..") for p in name.split("/")):
        raise ValueError("unsafe evidence path")
    path = root / name
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("evidence path escapes root")
    for parent in (path, *path.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError("evidence symlink forbidden")
    return path


def equal_values(left, right):
    if isinstance(right, float):
        return (type(left) in (float, int)
                and math.isclose(left, right, rel_tol=1e-12, abs_tol=1e-12))
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(equal_values(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(equal_values(a, b) for a, b in zip(left, right))
    return left == right


def verify_evidence(root):
    root = Path(root).resolve()
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("schema_version") != 1 or manifest.get("algorithm") != "SHA256":
        raise ValueError("invalid evidence manifest")
    listed = set()
    for record in manifest["files"]:
        path = safe_path(root, record["path"])
        if record["path"] in listed:
            raise ValueError("duplicate evidence path")
        listed.add(record["path"])
        if not path.is_file() or path.stat().st_size != record["size"] or digest(path) != record["sha256"]:
            raise ValueError("evidence hash mismatch: " + record["path"])
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*")
              if p.is_file() and p != root / "manifest.json" and "__pycache__" not in p.parts}
    if actual != listed:
        raise ValueError("unlisted or missing evidence file")
    index = json.loads((root / "index.json").read_text())
    if index.get("schema_version") != 1 or index.get("transform_id") != TRANSFORM_ID:
        raise ValueError("unsupported evidence transform/schema")
    for claim in ("paper_table_iii_reproduced", "physical_measurements", "full_system_certified"):
        if index.get(claim) is not False:
            raise ValueError("unsupported evidence claim")
    if index["encryption_parameters"] != asdict(DEFAULT_PARAMETERS):
        raise ValueError("encryption tuple changed; use the archived source")
    if index["source_files"] != source_records(ROOT):
        raise ValueError("source drift; use source/tools/check_aggregate_fidelity.py from the evidence bundle")
    if index["source_digest"] != hashlib.sha256(canonical(index["source_files"])).hexdigest():
        raise ValueError("invalid source digest")
    for record in index["source_files"]:
        if digest(safe_path(root, "source/" + record["path"])) != record["sha256"]:
            raise ValueError("archived source mismatch")
    library = {profile.name: profile for profile in example_profiles()}
    expected = {(seed, family, size, profile) for seed in index["seeds"] for family in index["families"]
                for size in index["batch_sizes"] for profile in index["profiles"]}
    seen = set()
    cases = []
    for record in index["cases"]:
        key = record["seed"], record["family"], record["batch_size"], record["profile"]
        if key not in expected or key in seen:
            raise ValueError("unexpected or duplicate case")
        seen.add(key)
        case = json.loads(safe_path(root, record["path"]).read_text())
        computed = evaluate_case(generate_sources(key[1], key[0], key[2]), library[key[3]])
        computed.update(seed=key[0], family=key[1])
        if not equal_values(case, computed):
            raise ValueError("case recomputation mismatch: " + record["path"])
        cases.append(computed)
    if seen != expected or not seen:
        raise ValueError("incomplete experiment matrix")
    if not equal_values(json.loads((root / "summary.json").read_text()), summary_records(index, cases)):
        raise ValueError("summary recomputation mismatch")
    return {"status": "verified_and_recomputed", "cases": len(cases), "integer_arrays": "exact",
            "floating_metric_tolerance": 1e-12, "paper_table_iii_reproduced": False, "scope": SCOPE}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--output", type=Path, help="new evidence directory; overwrites forbidden")
    operation.add_argument("--verify", type=Path, help="hash-check and recompute an existing bundle")
    parser.add_argument("--seeds", type=int, nargs="+", default=[1000, 1001])
    parser.add_argument("--families", choices=tuple(FAMILIES), nargs="+", default=list(DEFAULT_FAMILIES))
    parser.add_argument("--batch-sizes", type=int, nargs="+", default=[1, 12, 14, 16])
    parser.add_argument("--profiles", choices=("pi0", "pi1", "pi2"), nargs="+", default=["pi0", "pi1", "pi2"])
    args = parser.parse_args(argv)
    try:
        result = (verify_evidence(args.verify) if args.verify else
                  run_experiment(args.output, args.seeds, args.families, args.batch_sizes, args.profiles))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        # Do not echo filesystem exception paths or other local identifiers into published logs.
        print(json.dumps({"status": "failed_synthetic_fidelity", "error_type": type(error).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
