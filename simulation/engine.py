"""Packet/fragment discrete-event simulator with endogenous queueing feedback.

Two-hop sensor--gateway--sink topology, per-transmitter byte queues, serialized
contention domains, independent frame retries, finite report deadlines, gateway
batching, and observed-failure-triggered alternate-route repair. This deliberately
simplified model does not implement INET, RPL, RF propagation, real lattice
arithmetic, or the original authors' unavailable simulator. All time/energy/noise
values are declared assumptions. The noise value is an operational proxy only.
"""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
import heapq
import math
from pathlib import Path

from . import METHODS, STATUS
from .exogenous import read_exogenous, validate_config
from .io import JsonlWriter, digest, file_hash, uniform, write_json
from .policy import Policy


def fragment_block(payload_bytes, c):
    """Return actual on-air frame sizes, including explicitly modeled headers.

    PSDU excludes PHY. 6LoWPAN fragmentation repeats MAC/PHY/lowpan/fragment
    headers. UDP/CoAP/block-HMAC occur once per block datagram. Each fragment is
    queued/retried independently. This is a declared wire model, not packet capture.
    """
    datagram = payload_bytes + sum(c[k] for k in
        ("compressed_ipv6_bytes", "udp_bytes", "coap_bytes", "block_option_bytes", "block_auth_bytes"))
    capacity = c["max_psdu_bytes"] - c["mac_bytes"] - c["lowpan_bytes"]
    if capacity <= c["fragment_header_bytes"]:
        raise ValueError("header configuration leaves no fragment payload")
    fragmented = datagram > capacity
    capacity -= c["fragment_header_bytes"] if fragmented else 0
    overhead = c["phy_bytes"] + c["mac_bytes"] + c["lowpan_bytes"]
    overhead += c["fragment_header_bytes"] if fragmented else 0
    return [(min(capacity, datagram - pos), overhead + min(capacity, datagram - pos))
            for pos in range(0, datagram, capacity)]


@dataclass
class Frame:
    id: str
    transfer: str
    owner: int
    gateway: int
    hop: str
    domain: int
    created: float
    expiry: float
    fragment_bytes: int
    wire_bytes: int
    block: int
    fragment: int
    attempts: int = 0
    queued_s: float = 0.0
    queue_wait_s: float = 0.0
    done: bool = False


@dataclass
class Transfer:
    id: str
    kind: str
    gateway: int
    reports: tuple[str, ...]
    remaining: int
    created: float
    corrupt: bool = False
    batch_id: str | None = None
    ticket_roster: tuple[str, ...] = ()
    failed: bool = False
    failure_reasons: Counter = field(default_factory=Counter)


class Simulator:
    def __init__(self, config, seed, method, exogenous_dir, output_dir, controller_path):
        self.c = c = validate_config(config)
        if method not in METHODS:
            raise ValueError("unknown method")
        self.seed, self.method = seed, method
        topology, self.traffic, self.environment, self.exogenous_manifest = read_exogenous(exogenous_dir)
        if topology["seed"] != seed:
            raise ValueError("seed and exogenous inputs disagree")
        self.nodes = topology["nodes"]
        if len(self.nodes) != c["nodes"] or len(topology["gateways"]) != c["gateways"]:
            raise ValueError("topology and simulation configuration disagree")
        self.policy = Policy(controller_path, method)
        if {key: action.batch_size for key, action in self.policy.actions.items()} != c["profile_batch_caps"]:
            raise ValueError("controller action capacities differ from the bound simulation profile caps")
        if self.policy.data.get("cryptographic_parameters") != c["cryptographic_parameters"]:
            raise ValueError("controller fixture and simulation cryptographic tuples disagree")
        if self.policy.data.get("bound_evidence_artifacts") != c["bound_evidence_artifacts"]:
            raise ValueError("controller fixture and simulation evidence bindings disagree")
        self.controller_path = Path(controller_path)
        self.output = Path(output_dir)
        self.output.mkdir(parents=True, exist_ok=True)
        self.events_log = JsonlWriter(self.output / "events.jsonl.gz")
        self.packets_log = JsonlWriter(self.output / "packets.jsonl.gz")
        self.reports_log = JsonlWriter(self.output / "reports.jsonl.gz")
        self.epochs_log = JsonlWriter(self.output / "epochs.jsonl.gz")
        self.now = 0.0
        self.sequence = 0
        self.emission_order = 0
        self.events = []
        domains = c["local_contention_domains"] + c["backhaul_contention_domains"]
        self.queues = [deque() for _ in range(domains)]
        self.active_owners = [Counter() for _ in range(domains)]
        self.busy = [False] * domains
        self.owner_bytes = Counter()
        self.frames = {}
        self.transfers = {}
        self.reports = {}
        self.batches = {}
        self.authorization_by_report = {}
        self.traffic_cursor = 0
        self.cpu_until = Counter()
        self.alternate_ready = [math.inf] * c["gateways"]
        self.repair_inflight = [False] * c["gateways"]
        self.repair_sequence = [0] * c["gateways"]
        self.repair_rounds = {}
        self.window = self.empty_window()
        self.previous_cutoff = 0.0
        self.epoch_rows = []
        self.report_count = Counter()
        self.attempt_count = Counter()
        self.wire_bytes = 0
        self.cpu_energy = 0.0
        self.tx_energy = 0.0
        self.packet_count = Counter()

    def empty_window(self):
        return {"completed": 0, "accepted": 0, "valid": 0, "delays": [], "attempts": 0,
                "failed_attempts": 0, "tamper_detected": 0, "noise_proxy_max": 0.0,
                "gateway_failures": Counter(), "admitted": 0, "skipped": 0}

    def schedule(self, time, callback, *args, priority=10):
        if time < self.now - 1e-12:
            raise ValueError("cannot schedule an event in the past")
        self.sequence += 1
        heapq.heappush(self.events, (time, priority, self.sequence, callback, args))

    def log(self, event, **value):
        self.emit(self.events_log, {"time_s": self.now, "event": event, **value})

    def emit(self, stream, value):
        self.emission_order += 1
        stream.write({"emission_order": self.emission_order, **value})

    def ticket_bytes(self, members):
        return (self.c["ticket_signature_bytes"] + self.c["ticket_fixed_bytes"] +
                members * self.c["ticket_member_id_nonce_bytes"])

    def source_payload(self, report):
        data = self.c["lightweight_payload_bytes"]
        if report["protected"]:
            data = self.c["protected_ciphertext_bytes"] * (2 if self.method == "without_intdb2" else 1)
        roster = self.batches[report["batch_id"]]["roster"]
        return data + self.ticket_bytes(len(roster))

    def authorize_window(self):
        """Sink authorizes a frozen roster from the public schedule, never arrivals.

        The controller never receives this future schedule as telemetry and never
        sees future channel/attack outcomes. Final partial groups are fixed at
        authorization with size <= selected maximum N, not trimmed on reception.
        """
        if self.now >= self.c["duration_s"]:
            return
        end = min(self.now + self.c["control_interval_s"], self.c["duration_s"])
        action = self.policy.current
        groups = {}
        while self.traffic_cursor < len(self.traffic):
            opportunity = self.traffic[self.traffic_cursor]
            if opportunity["time_s"] >= end:
                break
            self.traffic_cursor += 1
            if opportunity["time_s"] < self.now:
                raise ValueError("public schedule authorization fell behind source arrival")
            if action is None or opportunity["sampling_uniform"] >= action.rho:
                continue
            node = self.nodes[opportunity["node"]]
            groups.setdefault((node["gateway"], node["protected"]), []).append(opportunity)
        epoch = round(self.now / self.c["control_interval_s"])
        for (gateway, protected), opportunities in sorted(groups.items()):
            for group, first in enumerate(range(0, len(opportunities), action.batch_size)):
                planned = opportunities[first:first + action.batch_size]
                roster = tuple(sorted(row["id"] for row in planned))
                bid = f"batch/e{epoch}/g{gateway}/p{int(protected)}/k{group}"
                deadline = min(row["time_s"] for row in planned) + self.c["report_deadline_s"]
                self.batches[bid] = {"id": bid, "roster": roster, "gateway": gateway,
                    "protected": protected, "action": action, "authorized_s": self.now,
                    "deadline_s": deadline, "received": set(), "source_failed": set(),
                    "state": "authorized"}
                for rid in roster:
                    if rid in self.authorization_by_report:
                        raise ValueError("source opportunity authorized twice")
                    self.authorization_by_report[rid] = bid
                self.log("batch_authorized", batch_id=bid, roster=list(roster), gateway=gateway,
                         protected=protected, action_id=action.id,
                         authorized_s=self.now, deadline_s=deadline,
                         planned_samples=[{"id": row["id"], "time_s": row["time_s"]} for row in planned],
                         selected_maximum_batch_size=action.batch_size,
                         ticket_bytes=self.ticket_bytes(len(roster)))
                self.schedule(deadline, self.expire_batch, bid, priority=0)

    def cpu(self, owner, duration, kind, callback, *args):
        start = max(self.now, self.cpu_until[owner])
        self.cpu_until[owner] = start + duration
        energy = duration * self.c["cpu_power_w"]
        self.cpu_energy += energy
        self.log("cpu_reservation", owner=owner, kind=kind, start_s=start,
                 duration_s=duration, modeled_energy_j=energy)
        self.schedule(start + duration, callback, *args)

    def generate(self, opportunity):
        rid, node_id = opportunity["id"], opportunity["node"]
        node = self.nodes[node_id]
        action = self.policy.current
        self.report_count["opportunities"] += 1
        if action is None or opportunity["sampling_uniform"] >= action.rho:
            status = "controller_stopped" if action is None else "sampling_skipped"
            self.report_count[status] += 1
            self.window["skipped"] += 1
            self.emit(self.reports_log, {"id": rid, "node": node_id, "gateway": node["gateway"],
                "generated_s": self.now, "outcome_s": self.now, "status": status,
                "admitted": False, "protected": node["protected"],
                "action_id": action.id if action else None, "batch_id": None, "delay_s": None})
            return
        bid = self.authorization_by_report.get(rid)
        if bid is None:
            raise ValueError("source cannot send without a previously authorized roster ticket")
        batch = self.batches[bid]
        if batch["action"].id != action.id or batch["authorized_s"] > self.now:
            raise ValueError("source action/ticket disagrees with prior authorization")
        report = {"id": rid, "node": node_id, "gateway": node["gateway"],
                  "generated_s": self.now, "expiry_s": batch["deadline_s"], "batch_id": bid,
                  "protected": node["protected"], "action": action, "final": False,
                  "failure_reasons": Counter()}
        self.reports[rid] = report
        self.report_count["admitted"] += 1
        self.window["admitted"] += 1
        duration = (self.c["source_encrypt_s"] * (2 if self.method == "without_intdb2" else 1) +
                    (0 if self.method == "without_intdb2" else self.c["source_compress_s"]))
        if not node["protected"]:
            duration = self.c["source_lightweight_s"]
        duration += self.c["source_ticket_verify_s"]
        duration += self.c["source_tag_s"] if node["protected"] else 0.0
        duration += (math.ceil(self.source_payload(report) / action.block_bytes) *
                     self.c["source_block_mac_s_per_block"])
        self.cpu(node_id, duration, "source_processing", self.source_ready, rid)

    def source_ready(self, rid):
        report = self.reports[rid]
        if report["final"]:
            return
        payload = self.source_payload(report)
        self.create_transfer("source/" + rid, "source", report["gateway"], (rid,),
                             report["node"], payload, report["action"].block_bytes, report["expiry_s"],
                             batch_id=report["batch_id"],
                             ticket_roster=self.batches[report["batch_id"]]["roster"])

    def create_transfer(self, tid, kind, gateway, reports, owner, payload, block_size, expiry,
                        corrupt=False, batch_id=None, ticket_roster=()):
        if tid in self.transfers:
            raise ValueError("duplicate transfer identity")
        frames = []
        for block, pos in enumerate(range(0, payload, block_size)):
            block_payload = min(block_size, payload - pos)
            for fragment, (fragment_bytes, wire_bytes) in enumerate(fragment_block(block_payload, self.c)):
                hop = "uplink" if kind == "source" else "repair" if kind == "repair" else "backhaul"
                domain = (gateway % self.c["local_contention_domains"] if hop == "uplink" else
                          self.c["local_contention_domains"] + gateway % self.c["backhaul_contention_domains"])
                frames.append(Frame(f"{tid}/b{block}/f{fragment}", tid, owner, gateway, hop,
                                    domain, self.now, expiry, fragment_bytes, wire_bytes, block, fragment))
        if kind != "repair":
            batch = self.batches[batch_id]
            if ticket_roster != batch["roster"] or expiry != batch["deadline_s"]:
                raise ValueError("transfer cannot change the preauthorized roster or deadline")
            if kind == "aggregate" and (reports != ticket_roster or batch["received"] != set(ticket_roster)):
                raise ValueError("cannot aggregate an incomplete or modified authorized roster")
        self.transfers[tid] = Transfer(tid, kind, gateway, reports, len(frames), self.now,
                                       corrupt, batch_id, ticket_roster)
        self.log("transfer_created", transfer=tid, kind=kind, reports=list(reports),
                 gateway=gateway, payload_bytes=payload, block_bytes=block_size, frames=len(frames),
                 expiry_s=expiry,
                 batch_id=batch_id, ticket_roster=list(ticket_roster),
                 ticket_bytes=0 if kind == "repair" else self.ticket_bytes(len(ticket_roster)),
                 ticket_signature_bytes=0 if kind == "repair" else self.c["ticket_signature_bytes"])
        for frame in frames:
            self.frames[frame.id] = frame
            self.enqueue(frame)

    def enqueue(self, frame):
        if frame.done:
            return
        if self.now >= frame.expiry:
            self.finish_frame(frame, "deadline")
            return
        if self.owner_bytes[frame.owner] + frame.wire_bytes > self.c["queue_bytes_per_transmitter"]:
            self.finish_frame(frame, "queue_overflow")
            return
        frame.queued_s = self.now
        self.owner_bytes[frame.owner] += frame.wire_bytes
        self.queues[frame.domain].append(frame)
        self.active_owners[frame.domain][frame.owner] += 1
        if not self.busy[frame.domain]:
            self.busy[frame.domain] = True
            self.schedule(self.now, self.start_frame, frame.domain)

    def start_frame(self, domain):
        queue = self.queues[domain]
        if not queue:
            self.busy[domain] = False
            return
        frame = queue.popleft()
        contenders = len(self.active_owners[domain])
        self.active_owners[domain][frame.owner] -= 1
        if not self.active_owners[domain][frame.owner]:
            del self.active_owners[domain][frame.owner]
        self.owner_bytes[frame.owner] -= frame.wire_bytes
        frame.queue_wait_s += self.now - frame.queued_s
        if self.now >= frame.expiry:
            self.finish_frame(frame, "deadline")
            self.schedule(self.now, self.start_frame, domain)
            return
        frame.attempts += 1
        backoff = int(uniform(self.seed, "backoff", frame.id, frame.attempts) * self.c["backoff_slots"])
        duration = (frame.wire_bytes * 8 / self.c["bit_rate_bps"] + self.c["ack_wait_s"] +
                    backoff * self.c["backoff_slot_s"])
        self.schedule(self.now + duration, self.end_frame, frame, self.now, contenders)

    def environment_at(self, gateway, time):
        e, d = self.environment, self.c["disturbance"]
        affected = gateway in e["affected_gateways"]
        disturbed = affected and e["start_s"] <= time < e["end_s"]
        b = min(int(time / e["bin_s"]), len(e["interference_multipliers"][gateway]) - 1)
        ber = d["disturbed_ber"] if disturbed else d["baseline_ber"]
        ber *= e["interference_multipliers"][gateway][b]
        tamper = d["disturbed_external_tamper_probability"] if disturbed else d["baseline_external_tamper_probability"]
        return disturbed, ber, tamper, e["forgery_active"][gateway][b]

    def end_frame(self, frame, start, contenders):
        # Channel conditions at the transmission instant are external. The action
        # affects backlog/contenders, route availability, and traffic, not the RNG.
        disturbed, ber, tamper, _ = self.environment_at(frame.gateway, start)
        link_down = (frame.hop == "backhaul" and disturbed and
                     start < self.alternate_ready[frame.gateway])
        collision_p = min(1.0, max(0, contenders - 1) * self.c["contention_collision_per_extra_sender"])
        error_p = -math.expm1(frame.wire_bytes * 8 * math.log1p(-min(ber, 1 - 1e-15)))
        if link_down:
            outcome = "link_down"
        elif uniform(self.seed, "collision", frame.id, frame.attempts) < collision_p:
            outcome = "collision"
        elif uniform(self.seed, "frame_error", frame.id, frame.attempts) < error_p:
            outcome = "channel_error"
        elif uniform(self.seed, "external_tamper", frame.id, frame.attempts) < tamper:
            outcome = "block_auth_reject"
        else:
            outcome = "ok"
        self.window["attempts"] += 1
        self.attempt_count[outcome] += 1
        wire = frame.wire_bytes + (self.c["ack_wire_bytes"] if outcome == "ok" else 0)
        self.wire_bytes += wire
        energy = wire * 8 * self.c["tx_j_per_wire_bit"]
        self.tx_energy += energy
        self.log("tx_attempt", packet=frame.id, transfer=frame.transfer, hop=frame.hop,
                 gateway=frame.gateway, owner=frame.owner, start_s=start, attempt=frame.attempts,
                 outcome=outcome, wire_bytes=wire, data_wire_bytes=frame.wire_bytes,
                 contenders=contenders, collision_probability=collision_p, bit_error_probability=ber,
                 link_down=link_down, modeled_energy_j=energy)
        if outcome != "ok":
            self.window["failed_attempts"] += 1
            if outcome == "block_auth_reject":
                self.window["tamper_detected"] += 1
        if self.now >= frame.expiry:
            self.finish_frame(frame, "deadline")
        elif outcome == "ok":
            self.finish_frame(frame, "received")
        elif frame.attempts > self.c["max_retries"]:
            self.finish_frame(frame, "retry_exhausted:" + outcome)
        else:
            self.enqueue(frame)
        self.schedule(self.now, self.start_frame, frame.domain)

    def finish_frame(self, frame, status):
        if frame.done:
            raise ValueError("packet terminal outcome emitted twice")
        frame.done = True
        # Route discovery is prompted by exhausted retransmissions, not by the
        # simulator's hidden outage bit or isolated ordinary radio errors.
        if frame.hop == "backhaul" and status.startswith("retry_exhausted:"):
            self.window["gateway_failures"][frame.gateway] += 1
        self.packet_count[status] += 1
        self.emit(self.packets_log, {"id": frame.id, "transfer": frame.transfer, "owner": frame.owner,
            "gateway": frame.gateway, "hop": frame.hop, "block": frame.block, "fragment": frame.fragment,
            "created_s": frame.created, "expiry_s": frame.expiry, "outcome_s": self.now,
            "status": status, "attempts": frame.attempts, "queue_wait_s": frame.queue_wait_s,
            "fragment_bytes": frame.fragment_bytes, "wire_bytes_per_attempt": frame.wire_bytes})
        transfer = self.transfers[frame.transfer]
        if status != "received":
            transfer.failed = True
            transfer.failure_reasons[status] += 1
        transfer.remaining -= 1
        if transfer.remaining == 0:
            self.transfer_done(transfer)

    def transfer_done(self, transfer):
        self.log("transfer_done", transfer=transfer.id, kind=transfer.kind,
                 failed=transfer.failed, failure_reasons=dict(transfer.failure_reasons))
        if transfer.kind == "repair":
            round_id = transfer.id.rsplit("/m", 1)[0]
            state = self.repair_rounds[round_id]
            state["remaining"] -= 1
            state["failed"] |= transfer.failed
            if state["remaining"] == 0:
                if state["failed"]:
                    self.repair_inflight[transfer.gateway] = False
                    self.log("repair_failed", gateway=transfer.gateway, round=round_id)
                else:
                    self.schedule(max(self.now, state["ready_s"]), self.finish_repair, transfer.gateway, round_id)
            return
        if transfer.failed:
            for rid in transfer.reports:
                self.reports[rid]["failure_reasons"].update(transfer.failure_reasons)
            return
        if transfer.kind == "source":
            report = self.reports[transfer.reports[0]]
            blocks = math.ceil(self.source_payload(report) / report["action"].block_bytes)
            duration = blocks * self.c["gateway_block_mac_verify_s_per_block"]
            self.cpu(self.c["nodes"] + transfer.gateway, duration,
                     "gateway_received_envelope_block_auth", self.add_batch, transfer.reports[0])
        else:
            batch = self.batches[transfer.batch_id]
            if batch["state"] == "deadline_expired" or self.now >= batch["deadline_s"]:
                return
            if transfer.reports != batch["roster"] or any(self.reports[rid]["final"] for rid in transfer.reports):
                raise ValueError("sink processing cannot prune expired authorized members")
            duration = self.c["sink_ticket_verify_s"]
            duration += len(transfer.reports) * self.c["sink_verify_s_per_report"] if self.method != "without_hve" else 0
            self.cpu(self.c["nodes"] + self.c["gateways"], duration, "sink_verification",
                     self.accept_aggregate, transfer.id)

    def add_batch(self, rid):
        report = self.reports[rid]
        batch = self.batches[report["batch_id"]]
        if report["final"] or self.now >= batch["deadline_s"]:
            return
        if rid not in batch["roster"] or rid in batch["received"]:
            raise ValueError("duplicate or unauthorized source contribution")
        batch["received"].add(rid)
        self.log("authorized_member_received", batch_id=batch["id"], report=rid,
                 roster=list(batch["roster"]))
        if batch["received"] != set(batch["roster"]):
            return
        if batch["state"] != "authorized":
            raise ValueError("authorized batch completed twice")
        batch["state"] = "all_members_received"
        reports = batch["roster"]
        self.window["noise_proxy_max"] = max(self.window["noise_proxy_max"],
                                              len(reports) * self.c["noise_proxy_per_batch_member"])
        self.log("batch_formed", batch_id=batch["id"], reports=list(reports),
                 gateway=batch["gateway"],
                 noise_proxy=len(reports) * self.c["noise_proxy_per_batch_member"])
        # The configurable hold begins only after all preauthorized members have
        # arrived. It can never justify flushing or shrinking a partial roster.
        self.schedule(self.now + self.c["batch_ready_hold_s"],
                      self.aggregate_processing, batch["id"])

    def aggregate_processing(self, bid):
        batch = self.batches[bid]
        if self.now >= batch["deadline_s"] or batch["state"] != "all_members_received":
            return
        self.cpu(self.c["nodes"] + batch["gateway"],
                 len(batch["roster"]) * self.c["gateway_aggregate_s_per_report"],
                 "gateway_aggregation", self.aggregate_ready, bid)

    def aggregate_ready(self, bid):
        batch = self.batches[bid]
        if self.now >= batch["deadline_s"] or batch["state"] != "all_members_received":
            return
        reports = batch["roster"]
        if batch["received"] != set(reports) or any(self.reports[rid]["final"] for rid in reports):
            raise ValueError("whole-roster aggregation requires every unexpired member")
        payload = self.c["lightweight_payload_bytes"]
        if batch["protected"]:
            payload = self.c["protected_ciphertext_bytes"] * (2 if self.method == "without_intdb2" else 1)
        payload += self.c["aggregate_roster_fixed_bytes"] + len(reports) * self.c["aggregate_roster_per_member_bytes"]
        payload += self.ticket_bytes(len(reports))
        # This offline audit label never reaches a controller without HVE.
        _, _, _, corrupt = self.environment_at(batch["gateway"], self.now)
        tid = "aggregate/" + bid
        batch["state"] = "aggregate_sent"
        self.create_transfer(tid, "aggregate", batch["gateway"], reports,
                             self.c["nodes"] + batch["gateway"], payload, batch["action"].block_bytes,
                             batch["deadline_s"], corrupt=corrupt, batch_id=bid, ticket_roster=reports)

    def accept_aggregate(self, tid):
        transfer = self.transfers[tid]
        batch = self.batches[transfer.batch_id]
        if self.now >= batch["deadline_s"] or batch["state"] == "deadline_expired":
            return
        if batch["state"] != "aggregate_sent" or transfer.reports != batch["roster"]:
            raise ValueError("sink must accept or reject the exact original authorized roster")
        if any(self.reports[rid]["final"] for rid in batch["roster"]):
            raise ValueError("sink cannot accept a batch after any member has expired")
        status = ("integrity_rejected" if self.method != "without_hve" else "delivered_invalid") if transfer.corrupt else "delivered_valid"
        if status == "integrity_rejected":
            self.window["tamper_detected"] += 1
        batch["state"] = status
        self.log("aggregate_received", transfer=tid, batch_id=batch["id"],
                 reports=list(batch["roster"]), status=status)
        for rid in batch["roster"]:
            self.finish_report(rid, status)

    def expire_batch(self, bid):
        batch = self.batches[bid]
        if batch["state"] in {"delivered_valid", "delivered_invalid", "integrity_rejected", "deadline_expired"}:
            return
        missing = sorted(set(batch["roster"]) - batch["received"])
        batch["state"] = "deadline_expired"
        self.log("authorized_batch_expired", batch_id=bid, roster=list(batch["roster"]),
                 missing_members=missing,
                 reason="authorized_member_missing" if missing else "aggregate_deadline_expired")
        for rid in batch["roster"]:
            report = self.reports.get(rid)
            if report is None:
                raise ValueError("batch validity ended before a preauthorized source's public schedule")
            if not report["final"]:
                report["failure_reasons"]["authorized_member_missing" if missing else
                                          "aggregate_deadline_expired"] += 1
                self.finish_report(rid, "deadline_expired")

    def finish_report(self, rid, status):
        report = self.reports[rid]
        report["final"] = True
        self.report_count[status] += 1
        self.window["completed"] += 1
        accepted = status in {"delivered_valid", "delivered_invalid"}
        if accepted:
            self.window["accepted"] += 1
            self.window["delays"].append(self.now - report["generated_s"])
        self.window["valid"] += status == "delivered_valid"
        self.emit(self.reports_log, {"id": rid, "node": report["node"], "gateway": report["gateway"],
            "generated_s": report["generated_s"], "outcome_s": self.now, "status": status,
            "admitted": True, "protected": report["protected"], "action_id": report["action"].id,
            "batch_id": report["batch_id"], "batch_deadline_s": report["expiry_s"],
            "delay_s": self.now - report["generated_s"] if accepted else None,
            "failure_reasons": dict(report["failure_reasons"])})

    def start_repair(self, gateway):
        if self.repair_inflight[gateway] or self.now >= self.alternate_ready[gateway]:
            return
        self.repair_inflight[gateway] = True
        self.repair_sequence[gateway] += 1
        rid = f"repair/g{gateway}/r{self.repair_sequence[gateway]}"
        count = self.c["repair_control_messages"]
        self.repair_rounds[rid] = {"remaining": count, "failed": False,
                                  "ready_s": self.now + self.c["repair_latency_s"]}
        self.log("repair_started", gateway=gateway, round=rid, messages=count,
                 earliest_ready_s=self.now + self.c["repair_latency_s"])
        for m in range(count):
            self.create_transfer(f"{rid}/m{m}", "repair", gateway, (), self.c["nodes"] + gateway,
                                 self.c["control_message_bytes"], self.c["control_message_bytes"],
                                 self.now + self.c["report_deadline_s"])

    def finish_repair(self, gateway, rid):
        self.alternate_ready[gateway] = self.now
        self.repair_inflight[gateway] = False
        self.log("repair_completed", gateway=gateway, round=rid)

    def control_epoch(self, initial=False):
        w = self.window
        active_bytes = [value for value in self.owner_bytes.values() if value > 0]
        queue = max(active_bytes, default=0) / self.c["queue_bytes_per_transmitter"]
        observed_loss = 1 - w["accepted"] / w["completed"] if w["completed"] else 0.0
        mean_delay = sum(w["delays"]) / len(w["delays"]) if w["delays"] else 0.0
        failure_fraction = w["failed_attempts"] / w["attempts"] if w["attempts"] else 0.0
        # The BER coordinate is a causal per-attempt error-rate proxy, explicitly
        # not an oracle read of environment_at() or the latent outage schedule.
        telemetry = (queue, observed_loss, mean_delay, failure_fraction,
                     min(1.0, queue + failure_fraction), float(w["tamper_detected"] > 0), w["noise_proxy_max"])
        decision = self.policy.choose(telemetry, initial=initial)
        row = {"time_s": self.now, "observation_start_s": self.previous_cutoff,
               "observation_cutoff_s": self.now, "completed_reports": w["completed"],
               "accepted_reports": w["accepted"], "admitted_reports": w["admitted"],
               "skipped_opportunities": w["skipped"], "transmission_attempts": w["attempts"],
               "failed_attempts": w["failed_attempts"], "queue_bytes_max": max(active_bytes, default=0),
               "queue_bytes_total": sum(active_bytes), "delay_sum_s": sum(w["delays"]),
               "tamper_detections": w["tamper_detected"], **decision}
        self.emit(self.epochs_log, row)
        self.epoch_rows.append(row)
        self.authorize_window()
        action = self.policy.current
        if action is not None and action.repair > 0 and self.method != "without_route_repair":
            # Triggered solely by completed previous-window frame outcomes.
            for gateway, failures in sorted(w["gateway_failures"].items()):
                if failures >= self.c["repair_failures_to_trigger"]:
                    self.start_repair(gateway)
        self.window = self.empty_window()
        self.previous_cutoff = self.now

    def run(self):
        horizon = self.c["duration_s"] + self.c["drain_s"]
        self.schedule(0, self.control_epoch, True, priority=5)
        step = self.c["control_interval_s"]
        for i in range(1, math.floor(horizon / step) + 1):
            self.schedule(i * step, self.control_epoch, priority=5)
        if horizon % step:
            self.schedule(horizon, self.control_epoch, priority=5)
        for opportunity in self.traffic:
            self.schedule(opportunity["time_s"], self.generate, opportunity)
        while self.events and self.events[0][0] <= horizon:
            self.now, _, _, callback, args = heapq.heappop(self.events)
            callback(*args)
        self.now = horizon
        pending = [frame for frame in self.frames.values() if not frame.done]
        # Normally none remain because drain covers the report lifetime. Explicit
        # terminal labels prevent silent denominator loss if a model changes.
        for frame in pending:
            self.finish_frame(frame, "administratively_censored")
        for rid, report in self.reports.items():
            if not report["final"]:
                self.finish_report(rid, "administratively_censored")
        for stream in (self.events_log, self.packets_log, self.reports_log, self.epochs_log):
            stream.close()
        raw = {name: file_hash(self.output / name) for name in
               ("events.jsonl.gz", "packets.jsonl.gz", "reports.jsonl.gz", "epochs.jsonl.gz")}
        counts = {"reports": dict(self.report_count), "packets": dict(self.packet_count),
                  "attempt_outcomes": dict(self.attempt_count), "wire_bytes": self.wire_bytes,
                  "modeled_cpu_energy_j": self.cpu_energy, "modeled_radio_tx_energy_j": self.tx_energy}
        manifest = {"schema_version": 1, "status": STATUS, "seed": self.seed, "method": self.method,
                    "config_digest": digest(self.c), "controller_sha256": file_hash(self.controller_path),
                    "exogenous_digest": self.exogenous_manifest["exogenous_digest"],
                    "raw_files": raw, "runtime_counts": counts,
                    "stop_time_s": horizon, "all_decisions_certified": False,
                    "protocol_model_version": 2,
                    "label": "independent fixed-preauthorized-roster closed-loop synthetic packet experiment, not original OMNeT++/INET"}
        write_json(self.output / "manifest.json", manifest)
        from .audit import recompute_run
        summary = recompute_run(self.output, self.c)
        write_json(self.output / "summary.json", summary)
        return summary


def run_one(config, seed, method, exogenous_dir, output_dir, controller_path):
    return Simulator(config, seed, method, exogenous_dir, output_dir, controller_path).run()
