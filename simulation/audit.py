"""Recompute outcomes from raw logs without trusting simulator accumulators."""
from __future__ import annotations

from collections import Counter, defaultdict
from bisect import bisect_left
import json
import math
from pathlib import Path
import statistics

from . import STATUS
from .io import digest, file_hash, read_jsonl


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    i = math.floor(position)
    return ordered[i] + (ordered[min(i + 1, len(ordered) - 1)] - ordered[i]) * (position - i)


def unique_frame_counts(offered, terminal_status_counts):
    """Count unique hop-local model frames, never transmission attempts.

    An exhausted retry, queue overflow or deadline is an observed final loss.
    Administrative censoring and missing terminal outcomes remain unresolved.
    ACK bytes belong to wire accounting, not additional model frame identities.
    """
    if type(offered) is not int or offered < 0:
        raise ValueError("offered frame count must be a nonnegative integer")
    for status, count in terminal_status_counts.items():
        if type(count) is not int or count < 0:
            raise ValueError("terminal frame counts must be nonnegative integers")
        if status not in {"received", "queue_overflow", "deadline", "administratively_censored"} and not status.startswith("retry_exhausted:"):
            raise ValueError("unknown terminal frame status")
    terminal = sum(terminal_status_counts.values())
    if terminal > offered:
        raise ValueError("terminal frames exceed unique offered frames")
    delivered = terminal_status_counts.get("received", 0)
    censored = terminal_status_counts.get("administratively_censored", 0)
    return {"offered": offered, "delivered": delivered,
            "lost": terminal - delivered - censored,
            "unresolved": censored + offered - terminal}


def recovery_observation(recovery):
    """Separate observed durations, administrative censoring and no excursion."""
    observed = recovery["status"] == "observed_recovery"
    censored = recovery["status"] == "right_censored"
    followup = recovery["observation_end_s"] - recovery["disturbance_onset_s"]
    return {"event_observed": observed, "analysis_eligible": observed or censored,
            "observed_duration_s": recovery["elapsed_from_onset_s"] if observed else None,
            "censor_duration_s": followup if censored else None,
            "time_to_event_or_censor_s": recovery["elapsed_from_onset_s"] if observed else
                followup if censored else None,
            "followup_from_onset_s": followup,
            "duration_origin": "disturbance_onset",
            "no_excursion_policy": "separate category; excluded from recovery-event risk set"}


def verification_report_counts(report_counts, enabled):
    """Model feature coverage over accepted reports, including invalid accepts.

    This records whether the sink validity decision is enabled. It is not an
    empirical attack-detection rate or a cryptographic forgery probability.
    """
    if type(enabled) is not bool:
        raise ValueError("verification availability must be boolean")
    accepted = report_counts.get("delivered_valid", 0) + report_counts.get("delivered_invalid", 0)
    return {"enabled": enabled, "accepted_reports": accepted,
            "verification_enabled_accepted_reports": accepted if enabled else 0,
            "invalid_accepted_reports": report_counts.get("delivered_invalid", 0),
            "integrity_rejected_reports": report_counts.get("integrity_rejected", 0),
            "scope": "measurement-window accepted reports, including lightweight reports",
            "semantics": "modeled sink validity-decision availability; not cryptographic detection"}


def repair_activity_counts(epochs, method, started, completed, failed):
    """Distinguish a selected repair action from a triggered repair round."""
    selected = sum(bool(row["decision"]["action"] and row["decision"]["action"]["repair"] > 0)
                   for row in epochs)
    if any(type(value) is not int or value < 0 for value in (started, completed, failed)) or completed + failed > started:
        raise ValueError("repair terminal counts exceed started rounds")
    return {"selected_control_epochs": selected,
            "enabled_control_epochs": selected if method != "without_route_repair" else 0,
            "actuations_started": started, "actuations_completed": completed,
            "actuations_failed": failed, "actuations_unresolved": started - completed - failed}


def recovery_from_epochs(rows, config):
    """Operational threshold recovery with explicit administrative censoring.

    An excursion must first be observed at/after disturbance onset. Empty windows
    cannot demonstrate recovery. Recovery is the END of the required consecutive
    sufficiently populated good windows. Censoring uses the common run horizon.
    No-excursion runs are separately labeled, with elapsed=0 for paired summaries.
    """
    threshold = config["recovery"]
    onset = config["disturbance"]["start_s"]
    excursion = None
    consecutive = 0
    for row in rows:
        if row["time_s"] < onset:
            continue
        y = row["telemetry"]
        good = (y[0] <= threshold["queue_max"] and y[1] <= threshold["observed_loss_max"] and
                y[2] <= threshold["delay_max_s"])
        if not good and excursion is None:
            excursion = row["time_s"]
        if excursion is not None:
            enough = row["completed_reports"] >= threshold["minimum_completed_reports"]
            consecutive = consecutive + 1 if good and enough else 0
            if consecutive >= threshold["consecutive_windows"]:
                return {"status": "observed_recovery", "right_censored": False,
                        "disturbance_onset_s": onset, "first_observed_excursion_s": excursion,
                        "elapsed_from_onset_s": row["time_s"] - onset,
                        "recovery_completion_s": row["time_s"],
                        "observation_end_s": config["duration_s"] + config["drain_s"]}
    horizon = config["duration_s"] + config["drain_s"]
    return {"status": "no_observed_excursion" if excursion is None else "right_censored",
            "right_censored": excursion is not None,
            "disturbance_onset_s": onset, "first_observed_excursion_s": excursion,
            "elapsed_from_onset_s": 0.0 if excursion is None else horizon - onset,
            "recovery_completion_s": None, "observation_end_s": horizon}


def recompute_run(run_dir, config, verify_hashes=True, *, include_ablation=None):
    run_dir = Path(run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    instrumentation_version = manifest.get("ablation_instrumentation_version")
    if instrumentation_version not in {None, 1}:
        raise ValueError("unsupported ablation instrumentation version")
    instrumented = instrumentation_version == 1
    if include_ablation is None:
        include_ablation = instrumented
    if type(include_ablation) is not bool:
        raise ValueError("include_ablation must be boolean or None")
    if manifest.get("protocol_model_version") != 2 or config.get("protocol_model_version") != 2:
        raise ValueError("only fixed-preauthorized-roster model version 2 is reportable")
    if manifest["config_digest"] != digest(config):
        raise ValueError("run configuration identity mismatch")
    if verify_hashes:
        for name, expected in manifest["raw_files"].items():
            if file_hash(run_dir / name) != expected:
                raise ValueError(f"raw artifact checksum mismatch: {name}")
    reports, packets, attempts = Counter(), Counter(), Counter()
    epochs = list(read_jsonl(run_dir / "epochs.jsonl.gz"))
    cutoffs = [(row["time_s"], row["emission_order"]) for row in epochs]
    valid_delays, accepted_delays = [], []
    report_ids, packet_ids = set(), set()
    report_by_id = {}
    report_by_window = Counter()
    accepted_by_window = Counter()
    delay_by_window = Counter()
    tamper_by_window = Counter()
    metric_reports = Counter()
    verification_enabled = manifest["method"] != "without_hve"
    admitted_by_window, skipped_by_window = Counter(), Counter()
    def window_end(time, order=math.inf):
        index = bisect_left(cutoffs, (time, order))
        if index >= len(cutoffs):
            raise ValueError("observable raw outcome after final controller cutoff")
        return cutoffs[index][0]
    for row in read_jsonl(run_dir / "reports.jsonl.gz"):
        if row["id"] in report_ids:
            raise ValueError("duplicate source opportunity terminal outcome")
        report_ids.add(row["id"])
        report_by_id[row["id"]] = row
        applied = verification_enabled and row["status"] in {"delivered_valid", "integrity_rejected"}
        for key, expected_value in (("modeled_verification_enabled", verification_enabled),
                                    ("modeled_validity_check_applied", applied)):
            if (instrumented and key not in row) or (key in row and
                    (type(row[key]) is not bool or row[key] != expected_value)):
                raise ValueError("report validity-check label disagrees with the declared method")
        reports["opportunities"] += 1
        reports[row["status"]] += 1
        generated_end = window_end(row["generated_s"])
        if row["admitted"]:
            reports["admitted"] += 1
            admitted_by_window[generated_end] += 1
            report_by_window[window_end(row["outcome_s"], row["emission_order"])] += 1
            if row["outcome_s"] > row["generated_s"] + config["report_deadline_s"] + 1e-8:
                if row["status"] != "administratively_censored":
                    raise ValueError("report completion after its hard deadline")
        else:
            skipped_by_window[generated_end] += 1
        if row["generated_s"] >= config.get("metric_start_s", 0.0):
            metric_reports["opportunities"] += 1
            metric_reports[row["status"]] += 1
            metric_reports["admitted"] += bool(row["admitted"])
        if row["status"] in {"delivered_valid", "delivered_invalid"}:
            accepted_delays.append(row["delay_s"])
            end = window_end(row["outcome_s"], row["emission_order"])
            accepted_by_window[end] += 1
            delay_by_window[end] += row["delay_s"]
        if row["status"] == "delivered_valid" and row["generated_s"] >= config.get("metric_start_s", 0.0):
            valid_delays.append(row["delay_s"])
    packet_attempts = 0
    packet_counts_by_transfer, packet_failures_by_transfer = Counter(), Counter()
    packet_ids_by_transfer = defaultdict(set)
    packet_status_by_hop = defaultdict(Counter)
    packet_hops_by_transfer = defaultdict(set)
    for row in read_jsonl(run_dir / "packets.jsonl.gz"):
        if row["id"] in packet_ids:
            raise ValueError("duplicate frame terminal outcome")
        packet_ids.add(row["id"])
        packet_ids_by_transfer[row["transfer"]].add(row["id"])
        packet_status_by_hop[row["hop"]][row["status"]] += 1
        packet_hops_by_transfer[row["transfer"]].add(row["hop"])
        packet_counts_by_transfer[row["transfer"]] += 1
        packet_failures_by_transfer[row["transfer"]] += row["status"] != "received"
        packets[row["status"]] += 1
        packet_attempts += row["attempts"]
        if not 0 <= row["attempts"] <= config["max_retries"] + 1:
            raise ValueError("frame exceeds common retry budget")
        if row["wire_bytes_per_attempt"] > config["max_psdu_bytes"] + config["phy_bytes"]:
            raise ValueError("modeled frame exceeds PHY/PSDU limit")
    wire_bytes = 0
    cpu_energy, tx_energy = 0.0, 0.0
    attempts_by_window, failures_by_window = Counter(), Counter()
    repair_starts, repair_completed, repair_failed = 0, 0, 0
    repair_started_ids, repair_terminal_ids = set(), set()
    attempts_by_hop, offered_frames_by_hop = defaultdict(Counter), Counter()
    noise_by_window = Counter()
    authorized_batches, authorizations, received_members = {}, {}, {}
    terminal_batches, created_transfers, finished_transfers = {}, {}, set()
    for row in read_jsonl(run_dir / "events.jsonl.gz"):
        if row["event"] == "tx_attempt":
            attempts[row["outcome"]] += 1
            attempts_by_hop[row["hop"]][row["outcome"]] += 1
            wire_bytes += row["wire_bytes"]
            tx_energy += row["modeled_energy_j"]
            end = window_end(row["time_s"], row["emission_order"])
            attempts_by_window[end] += 1
            failures_by_window[end] += row["outcome"] != "ok"
            tamper_by_window[end] += row["outcome"] == "block_auth_reject"
            if row["packet"] not in packet_ids:
                raise ValueError("transmission missing packet terminal outcome")
            if row["time_s"] < row["start_s"]:
                raise ValueError("negative transmission duration")
        elif row["event"] == "cpu_reservation":
            cpu_energy += row["modeled_energy_j"]
        elif row["event"] == "repair_started":
            if row["round"] in repair_started_ids:
                raise ValueError("duplicate repair-round start")
            repair_started_ids.add(row["round"])
            repair_starts += 1
        elif row["event"] == "repair_completed":
            if row["round"] not in repair_started_ids or row["round"] in repair_terminal_ids:
                raise ValueError("unknown or duplicate repair-round outcome")
            repair_terminal_ids.add(row["round"])
            repair_completed += 1
        elif row["event"] == "repair_failed":
            if row["round"] not in repair_started_ids or row["round"] in repair_terminal_ids:
                raise ValueError("unknown or duplicate repair-round outcome")
            repair_terminal_ids.add(row["round"])
            repair_failed += 1
        elif row["event"] == "batch_authorized":
            bid = row["batch_id"]
            roster = row["roster"]
            if bid in authorized_batches or not roster or len(roster) != len(set(roster)):
                raise ValueError("duplicate or empty preauthorized roster")
            if tuple(roster) != tuple(sorted(roster)) or len(roster) > row["selected_maximum_batch_size"]:
                raise ValueError("invalid preauthorized roster cardinality/order")
            if row["authorized_s"] != row["time_s"]:
                raise ValueError("authorization timestamp differs from its event")
            planned = {r["id"]: r["time_s"] for r in row["planned_samples"]}
            if set(planned) != set(roster) or any(t < row["time_s"] or
                    t >= min(row["time_s"] + config["control_interval_s"], config["duration_s"])
                    for t in planned.values()):
                raise ValueError("authorization must precede every member's public schedule")
            if row["deadline_s"] != min(planned.values()) + config["report_deadline_s"]:
                raise ValueError("whole-roster deadline is inconsistent")
            authorized_batches[bid] = row
            received_members[bid] = set()
            for rid in roster:
                if rid in authorizations:
                    raise ValueError("source opportunity belongs to two authorized rosters")
                authorizations[rid] = bid
        elif row["event"] == "authorized_member_received":
            bid, rid = row["batch_id"], row["report"]
            if bid not in authorized_batches or rid not in authorized_batches[bid]["roster"]:
                raise ValueError("source contribution is not in its original authorized roster")
            if row["roster"] != authorized_batches[bid]["roster"] or rid in received_members[bid]:
                raise ValueError("modified roster or duplicate source contribution")
            if "source/" + rid not in finished_transfers or packet_failures_by_transfer["source/" + rid]:
                raise ValueError("source contribution registered before complete successful frame reception")
            received_members[bid].add(rid)
        elif row["event"] == "aggregate_received":
            for key in ("modeled_verification_enabled", "modeled_validity_check_applied"):
                if (instrumented and key not in row) or (key in row and
                        (type(row[key]) is not bool or row[key] != verification_enabled)):
                    raise ValueError("aggregate validity-check label disagrees with the declared method")
            bid = row["batch_id"]
            if bid not in authorized_batches or row["reports"] != authorized_batches[bid]["roster"]:
                raise ValueError("sink received a shrunken or modified authorized roster")
            if row["transfer"] not in finished_transfers or packet_failures_by_transfer[row["transfer"]]:
                raise ValueError("sink accepted an incomplete aggregate transfer")
            if bid in terminal_batches:
                raise ValueError("authorized batch has two terminal outcomes")
            terminal_batches[bid] = (row["status"], row["time_s"])
            if row["status"] == "integrity_rejected":
                tamper_by_window[window_end(row["time_s"], row["emission_order"])] += 1
        elif row["event"] == "authorized_batch_expired":
            bid = row["batch_id"]
            if bid not in authorized_batches or row["roster"] != authorized_batches[bid]["roster"]:
                raise ValueError("expired batch roster changed after authorization")
            if row["missing_members"] != sorted(set(row["roster"]) - received_members[bid]):
                raise ValueError("missing authorized-member list disagrees with received contributions")
            if row["time_s"] != authorized_batches[bid]["deadline_s"] or bid in terminal_batches:
                raise ValueError("invalid whole-batch expiration")
            terminal_batches[bid] = ("deadline_expired", row["time_s"])
        elif row["event"] == "batch_formed":
            bid = row["batch_id"]
            if bid not in authorized_batches or row["reports"] != authorized_batches[bid]["roster"]:
                raise ValueError("batch formed with a shrunken or modified roster")
            if received_members[bid] != set(row["reports"]):
                raise ValueError("batch formed before all preauthorized members arrived")
            end = window_end(row["time_s"], row["emission_order"])
            expected_noise = len(row["reports"]) * config["noise_proxy_per_batch_member"]
            if row["noise_proxy"] != expected_noise:
                raise ValueError("batch noise proxy disagrees with explicit assumption")
            noise_by_window[end] = max(noise_by_window[end], expected_noise)
        elif row["event"] == "transfer_created":
            tid = row["transfer"]
            if tid in created_transfers:
                raise ValueError("transfer created twice")
            created_transfers[tid] = row
            hop = {"source": "uplink", "aggregate": "backhaul", "repair": "repair"}[row["kind"]]
            offered_frames_by_hop[hop] += row["frames"]
            if packet_hops_by_transfer[tid] != {hop}:
                raise ValueError("terminal frame hop disagrees with its transfer kind")
            if (instrumented and "frame_ids" not in row) or "frame_ids" in row:
                frame_ids = row.get("frame_ids", [])
                if len(frame_ids) != row["frames"] or len(set(frame_ids)) != len(frame_ids) or set(frame_ids) != packet_ids_by_transfer[tid]:
                    raise ValueError("unique generated-frame identities disagree with terminal frame records")
            if row["frames"] != packet_counts_by_transfer[tid]:
                raise ValueError("planned frame count differs from all terminal frame outcomes")
            members = len(row["ticket_roster"])
            ticket = 0 if row["kind"] == "repair" else (config["ticket_signature_bytes"] +
                config["ticket_fixed_bytes"] + members * config["ticket_member_id_nonce_bytes"])
            if row["ticket_bytes"] != ticket:
                raise ValueError("transfer ticket overhead was not included consistently")
            if row["kind"] != "repair" and row["payload_bytes"] <= ticket:
                raise ValueError("ticket is not part of the transmitted application payload")
            if row["kind"] != "repair":
                bid = row["batch_id"]
                if bid not in authorized_batches or row["ticket_roster"] != authorized_batches[bid]["roster"]:
                    raise ValueError("source/aggregate ticket differs from prior whole-roster authorization")
                if row["expiry_s"] != authorized_batches[bid]["deadline_s"]:
                    raise ValueError("source/aggregate validity interval differs from its ticket")
                if row["kind"] == "source":
                    if len(row["reports"]) != 1 or authorizations.get(row["reports"][0]) != bid:
                        raise ValueError("source uses a ticket for an unauthorized contribution")
                elif row["reports"] != authorized_batches[bid]["roster"] or received_members[bid] != set(row["reports"]):
                    raise ValueError("aggregate roster was modified or missing a preauthorized member")
        elif row["event"] == "transfer_done":
            tid = row["transfer"]
            if tid not in created_transfers or tid in finished_transfers:
                raise ValueError("unknown or duplicate transfer terminal outcome")
            if row["failed"] != bool(packet_failures_by_transfer[tid]):
                raise ValueError("transfer success disagrees with its terminal packet outcomes")
            finished_transfers.add(tid)
    if set(created_transfers) != set(packet_counts_by_transfer) or set(created_transfers) != finished_transfers:
        raise ValueError("transfer/frame terminal outcomes are not conserved")
    if set(terminal_batches) != set(authorized_batches):
        raise ValueError("a fixed authorized batch has no terminal whole-roster decision")
    if set(authorizations) != {rid for rid, row in report_by_id.items() if row["admitted"]}:
        raise ValueError("admitted report set differs from fixed sampling-plan authorizations")
    for bid, authorization in authorized_batches.items():
        status, time = terminal_batches[bid]
        planned = {r["id"]: r["time_s"] for r in authorization["planned_samples"]}
        for rid in authorization["roster"]:
            report = report_by_id[rid]
            if (report["batch_id"] != bid or report["status"] != status or
                    report["outcome_s"] != time or report["generated_s"] != planned[rid] or
                    report["batch_deadline_s"] != authorization["deadline_s"]):
                raise ValueError("authorized roster was partially accepted, shrunk, or expired inconsistently")
    if sum(attempts.values()) != packet_attempts:
        raise ValueError("packet attempt counts disagree with transmission events")
    expected = manifest["runtime_counts"]
    if any(dict(actual) != expected[name] for actual, name in
           ((reports, "reports"), (packets, "packets"), (attempts, "attempt_outcomes"))):
        raise ValueError("independent raw counts disagree with simulator accumulators")
    if wire_bytes != expected["wire_bytes"] or not math.isclose(cpu_energy, expected["modeled_cpu_energy_j"], abs_tol=1e-12):
        raise ValueError("raw wire/CPU accounting disagrees with simulator")
    if not math.isclose(tx_energy, expected["modeled_radio_tx_energy_j"], abs_tol=1e-12):
        raise ValueError("raw modeled radio energy disagrees with simulator")
    if not epochs or epochs[0]["time_s"] != 0:
        raise ValueError("missing initial causal decision")
    for i, row in enumerate(epochs):
        action = row["decision"]["action"]
        repair_selected = bool(action and action["repair"] > 0)
        for key, expected_value in (("repair_selected", repair_selected),
                                    ("repair_enabled", repair_selected and manifest["method"] != "without_route_repair")):
            if (instrumented and key not in row) or (key in row and
                    (type(row[key]) is not bool or row[key] != expected_value)):
                raise ValueError("repair selection label disagrees with the controller decision")
        if row["observation_cutoff_s"] != row["time_s"] or (i and row["observation_start_s"] != epochs[i-1]["time_s"]):
            raise ValueError("invalid observation-window chronology")
        if row["certified"] or row["decision"]["certified"]:
            raise ValueError("synthetic experiment must never claim certification")
        end = row["time_s"]
        expected_counts = (report_by_window[end], accepted_by_window[end],
                           attempts_by_window[end], failures_by_window[end], tamper_by_window[end])
        actual_counts = tuple(row[k] for k in ("completed_reports", "accepted_reports",
                              "transmission_attempts", "failed_attempts", "tamper_detections"))
        if actual_counts != expected_counts:
            raise ValueError("controller observation contains noncausal or inconsistent raw outcomes")
        if not math.isclose(row["delay_sum_s"], delay_by_window[end], abs_tol=1e-9):
            raise ValueError("controller delay observation disagrees with prior accepted reports")
        y = row["telemetry"]
        completed, accepted, count, failed, tamper = expected_counts
        expected_y = [row["queue_bytes_max"] / config["queue_bytes_per_transmitter"],
                      1 - accepted / completed if completed else 0.0,
                      delay_by_window[end] / accepted if accepted else 0.0,
                      failed / count if count else 0.0,
                      min(1.0, y[0] + (failed / count if count else 0.0)),
                      float(tamper > 0), noise_by_window[end]]
        if any(not math.isclose(a, b, abs_tol=1e-10) for a, b in zip(y, expected_y)):
            raise ValueError("telemetry differs from causal raw-window measurements")
    if sum(row["completed_reports"] for row in epochs) != reports["admitted"]:
        raise ValueError("causal window report counts do not conserve admitted reports")
    if sum(row["transmission_attempts"] for row in epochs) != sum(attempts.values()):
        raise ValueError("causal window attempts do not conserve raw transmission events")
    admitted = metric_reports["admitted"]
    opportunities = metric_reports["opportunities"]
    accepted = metric_reports["delivered_valid"] + metric_reports["delivered_invalid"]
    valid = metric_reports["delivered_valid"]
    result = {"schema_version": 1, "status": STATUS, "seed": manifest["seed"],
            "method": manifest["method"], "config_digest": manifest["config_digest"],
            "exogenous_digest": manifest["exogenous_digest"],
            "protocol_model_version": 2,
            "raw_counts": {"reports": dict(reports), "packets": dict(packets),
                           "attempt_outcomes": dict(attempts), "wire_bytes": wire_bytes,
                           "repair_started": repair_starts, "repair_completed": repair_completed,
                           "authorized_batches": len(authorized_batches),
                           "whole_batch_outcomes": dict(Counter(value[0] for value in terminal_batches.values()))},
            "measurement_window": {"source_generated_start_s": config.get("metric_start_s", 0.0),
                                   "source_generated_end_s": config["duration_s"]},
            "metric_report_counts": dict(metric_reports),
            "metrics": {"accepted_delivery_fraction_per_admitted": accepted / admitted if admitted else None,
                        "valid_delivery_fraction_per_admitted": valid / admitted if admitted else None,
                        "valid_delivery_fraction_per_opportunity": valid / opportunities if opportunities else None,
                        "observed_residual_loss_fraction": 1 - accepted / admitted if admitted else None,
                        "invalid_acceptance_fraction_per_admitted": metric_reports["delivered_invalid"] / admitted if admitted else None,
                        "source_admission_fraction": admitted / opportunities if opportunities else None,
                        "valid_delay_mean_s": statistics.fmean(valid_delays) if valid_delays else None,
                        "valid_delay_p95_s": percentile(valid_delays, .95),
                        "wire_bytes_per_source_opportunity_all_run": wire_bytes / reports["opportunities"] if reports["opportunities"] else None,
                        "modeled_cpu_energy_j_all_run": cpu_energy,
                        "modeled_radio_tx_energy_j_all_run": tx_energy},
            "recovery": recovery_from_epochs(epochs, config),
            "decision_counts": dict(Counter(row["decision"]["action"]["id"] if row["decision"]["action"] else
                                             "fail_closed" for row in epochs)),
            "all_decisions_certified": False,
            "limitations": ["Independent synthetic model, not OMNeT++/INET or manuscript-result reproduction.",
                            "Controller model/certificates are artificial and uncalibrated; no security/stability certificate.",
                            "RF contention is a serialized-domain/collision approximation, not a CSMA/RPL implementation.",
                            "Runtime executes byte counts and validity labels, not lattice cryptography or sensor reconstruction.",
                            "Modeled energy and noise proxies are assumptions, not measured values.",
                            "Sampling suppression is reported separately; admitted-only loss does not measure data completeness."]}
    if include_ablation or instrumented:
        data_status = packet_status_by_hop["uplink"] + packet_status_by_hop["backhaul"]
        frames = {"all": unique_frame_counts(sum(offered_frames_by_hop.values()), packets),
                  "data": unique_frame_counts(offered_frames_by_hop["uplink"] + offered_frames_by_hop["backhaul"], data_status),
                  "repair": unique_frame_counts(offered_frames_by_hop["repair"], packet_status_by_hop["repair"]),
                  "by_hop": {hop: unique_frame_counts(offered_frames_by_hop[hop], packet_status_by_hop[hop])
                             for hop in ("uplink", "backhaul", "repair")}}
        repair = repair_activity_counts(epochs, manifest["method"], repair_starts, repair_completed, repair_failed)
        if instrumented and (expected.get("unique_frames") != frames["all"] or
                             expected.get("repair_activity") != repair):
            raise ValueError("independent ablation counters disagree with simulator diagnostics")
        if include_ablation:
            data_attempts = attempts_by_hop["uplink"] + attempts_by_hop["backhaul"]
            attempt_total = sum(data_attempts.values())
            channel_failures = sum(data_attempts[k] for k in ("channel_error", "collision", "link_down"))
            verification = verification_report_counts(metric_reports, verification_enabled)
            data = frames["data"]
            result["ablation_counts"] = {
                "schema_version": 1,
                "network_frames": {"unit": "network_frame", "counting_policy": "terminal_after_retries",
                    "scope": "source_and_aggregate_transfers_all_run", **data},
                "frame_cohorts": frames,
                "frame_semantics": "Unique hop-local fragment identities; retries reuse an identity. Queue/deadline/retry-exhausted outcomes are final losses; administrative censoring is unresolved. ACK bytes are wire overhead, not additional frame identities.",
                "data_attempts": {"completed": attempt_total, "channel_failures": channel_failures,
                    "authentication_rejections": data_attempts["block_auth_reject"],
                    "all_failures": attempt_total - data_attempts["ok"], "outcomes": dict(data_attempts)},
                "attempt_semantics": "Completed source/aggregate frame attempts; channel failure means channel_error, collision or link_down, separately from block-auth rejection. This is not bit-level BER.",
                "verification": verification, "repair": repair,
                "repair_semantics": "Selected/enabled control epochs include initial and draining epochs; actuation counts actual alternate-route repair rounds, not RPL operations.",
            }
            result["ablation_metrics"] = {
                "final_fragment_loss_fraction": data["lost"] / data["offered"] if data["offered"] else None,
                "fragment_unresolved_fraction": data["unresolved"] / data["offered"] if data["offered"] else None,
                "per_attempt_channel_loss_fraction": channel_failures / attempt_total if attempt_total else None,
                "per_attempt_failure_fraction": (attempt_total - data_attempts["ok"]) / attempt_total if attempt_total else None,
                "verification_enabled_report_coverage_fraction": verification["verification_enabled_accepted_reports"] / accepted if accepted else None,
            }
            result["recovery"].update(recovery_observation(result["recovery"]))
    return result


def paired_campaign_summary(summaries, methods):
    by_method = {method: sorted((s for s in summaries if s["method"] == method),
                               key=lambda s: s["seed"]) for method in methods}
    seeds = [s["seed"] for s in by_method[methods[0]]]
    if any([s["seed"] for s in rows] != seeds for rows in by_method.values()):
        raise ValueError("campaign is not paired over identical seed sets")
    results = {}
    for method, rows in by_method.items():
        metric_names = rows[0]["metrics"] if rows else []
        metrics = {}
        for name in metric_names:
            values = [row["metrics"][name] for row in rows if row["metrics"][name] is not None]
            metrics[name] = {"mean_over_seeds": statistics.fmean(values) if values else None,
                             "sd_over_seeds": statistics.stdev(values) if len(values) > 1 else None,
                             "seeds_with_defined_metric": len(values)}
        results[method] = {"metrics": metrics,
                           "recovery_right_censored_seeds": sum(r["recovery"]["right_censored"] for r in rows),
                           "recovery_no_excursion_seeds": sum(r["recovery"]["status"] == "no_observed_excursion" for r in rows)}
    paired = {}
    if "da-ahe" in by_method:
        base = {row["seed"]: row for row in by_method["da-ahe"]}
        for method, rows in by_method.items():
            if method == "da-ahe":
                continue
            differences = {}
            for name in rows[0]["metrics"]:
                deltas = [{"seed": row["seed"], "difference": row["metrics"][name] - base[row["seed"]]["metrics"][name]}
                          for row in rows if row["metrics"][name] is not None and base[row["seed"]]["metrics"][name] is not None]
                values = [value["difference"] for value in deltas]
                differences[name] = {"direction": "method minus da-ahe", "per_seed": deltas,
                                     "mean_difference": statistics.fmean(values) if values else None,
                                     "sd_difference": statistics.stdev(values) if len(values) > 1 else None}
            paired[method] = differences
    return {"status": STATUS, "paired_evaluation_seeds": seeds, "methods": results,
            "paired_differences": paired,
            "recovery_note": "Right-censored recovery times are not treated as observed durations or averaged. See per-seed records.",
            "inference_note": "Means/SD describe this synthetic seed population; no paper performance or statistical significance claim."}
