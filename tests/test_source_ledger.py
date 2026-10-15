# SPDX-License-Identifier: MIT
"""Durable one-report source invariants; execution receipts are recorded separately.

Encryption is replaced with deliberately changing canonical ciphertext bytes to
isolate persistence/race behavior. This is not an encryption or ML-DSA test.
The HMAC signer below is a test double only and is never a production provider.
"""
from concurrent.futures import ThreadPoolExecutor
import hmac
from threading import Barrier, Lock
from types import SimpleNamespace

import pytest

import daahe.protocol as protocol
from daahe.mlwe import Ciphertext
from daahe.profiles import Profile, ProfileLibrary
from daahe.protocol import (Contributor, SourceEmissionStore, Ticket,
                            encapsulate, issue_ticket)
from daahe.signal import support_for_length


class TestOnlySigner:
    __test__ = False

    def sign(self, message):
        return hmac.digest(b"test-source-ledger-key" * 2, message, "sha3_256")

    def verify(self, message, signature):
        return hmac.compare_digest(self.sign(message), signature)


@pytest.fixture
def report_context(tmp_path, monkeypatch):
    signer = TestOnlySigner()
    profile = Profile("source-ledger", 120, 16, 3.2, 1, support_for_length(120), 2048)
    library = ProfileLibrary([profile])
    source = Contributor("sensor-a", b"n" * 16)
    ticket = Ticket(0, 1, "source-ledger-test", profile.profile_id, profile.digest,
                    (source,), b"b" * 32)
    signed = issue_ticket(ticket, signer)
    calls = []
    lock = Lock()

    def changing_ciphertext(pk, message, sigma):
        with lock:
            calls.append(tuple(message))
            ordinal = len(calls)
        return Ciphertext(((0,) * 256,) * pk.params.k, (ordinal,) + (0,) * 255, pk.params)

    monkeypatch.setattr(protocol, "encrypt", changing_ciphertext)
    return {"signer": signer, "library": library, "source": source, "signed": signed,
            "path": tmp_path / "source.sqlite", "calls": calls,
            "encrypt": changing_ciphertext}


def emit(context, channels, store):
    return encapsulate(channels, context["signed"], context["source"],
                       SimpleNamespace(params=context["signed"].ticket.encryption_parameters),
                       b"e" * 32, b"k" * 32, context["signer"], context["library"],
                       source_store=store)


def test_source_store_is_mandatory_and_must_be_durable(report_context):
    context = report_context
    with pytest.raises(TypeError, match="source_store"):
        encapsulate(((100,) * 240,) * 2, context["signed"], context["source"], object(),
                    b"e" * 32, b"k" * 32, context["signer"], context["library"])
    with pytest.raises(ValueError, match="SourceEmissionStore"):
        emit(context, ((100,) * 240,) * 2, None)
    with pytest.raises(ValueError, match="durable"):
        SourceEmissionStore(":memory:")
    assert not context["calls"]


def test_identical_retransmission_and_restart_return_original_ciphertext(report_context):
    context = report_context
    channels = ((100,) * 240,) * 2
    first = emit(context, channels, SourceEmissionStore(context["path"]))
    retry = emit(context, channels, SourceEmissionStore(context["path"]))
    assert retry == first
    assert len(context["calls"]) == 1


def test_same_ticket_cannot_be_used_to_resample_before_or_after_restart(report_context):
    context = report_context
    channels = ((100,) * 240,) * 2
    first = emit(context, channels, SourceEmissionStore(context["path"]))
    changed = (channels[0][:-1] + (101,), channels[1])
    for store in (SourceEmissionStore(context["path"]), SourceEmissionStore(context["path"])):
        with pytest.raises(ValueError, match="different raw payload"):
            emit(context, changed, store)
    assert emit(context, channels, SourceEmissionStore(context["path"])) == first
    assert len(context["calls"]) == 1
    # Reusing an affine offset for two reports would permit 2*c1-c2 forgery.
    # The source prevents the second distinct report from being emitted at all.


def test_crash_after_binding_allows_only_same_payload_to_resume(report_context, monkeypatch):
    context = report_context
    channels = ((100,) * 240,) * 2

    def interrupted_encryption(*args, **kwargs):
        raise RuntimeError("simulated crash before any ciphertext release")

    monkeypatch.setattr(protocol, "encrypt", interrupted_encryption)
    with pytest.raises(RuntimeError, match="simulated crash"):
        emit(context, channels, SourceEmissionStore(context["path"]))
    reopened = SourceEmissionStore(context["path"])
    with pytest.raises(ValueError, match="different raw payload"):
        emit(context, ((101,) * 240,) * 2, reopened)
    monkeypatch.setattr(protocol, "encrypt", context["encrypt"])
    first = emit(context, channels, reopened)
    assert emit(context, channels, SourceEmissionStore(context["path"])) == first
    assert len(context["calls"]) == 1


def test_crash_after_cache_commit_recovers_original_bytes(report_context, monkeypatch):
    context = report_context
    store = SourceEmissionStore(context["path"])
    cache_first = store._cache_first

    def interrupted_delivery(*args, **kwargs):
        cache_first(*args, **kwargs)
        raise RuntimeError("simulated crash after cache commit")

    monkeypatch.setattr(store, "_cache_first", interrupted_delivery)
    channels = ((100,) * 240,) * 2
    with pytest.raises(RuntimeError, match="after cache commit"):
        emit(context, channels, store)
    recovered = emit(context, channels, SourceEmissionStore(context["path"]))
    first_v_block = context["signed"].ticket.encryption_parameters.k * 256 * 4 // 64
    assert recovered.blocks[first_v_block].payload[:4] == (1).to_bytes(4, "little")
    assert len(context["calls"]) == 1
    assert emit(context, channels, SourceEmissionStore(context["path"])) == recovered


def test_raw_payload_binding_rejects_even_when_quantized_values_would_match(report_context):
    context = dict(report_context)
    profile = Profile("raw-collision", 480, 16, 3.2, 1, tuple(range(480)), 2048, "raw")
    context["library"] = ProfileLibrary([profile])
    ticket = Ticket(0, 2, "source-ledger-test", profile.profile_id, profile.digest,
                    (context["source"],), b"c" * 32)
    context["signed"] = issue_ticket(ticket, context["signer"])
    store = SourceEmissionStore(context["path"])
    first = emit(context, ((100,) * 240,) * 2, store)
    # Both 100 and 101 round to 6 at step 16. Source authorization binds raw data.
    with pytest.raises(ValueError, match="different raw payload"):
        emit(context, ((101,) * 240,) * 2, store)
    assert len(context["calls"]) == 2  # the first raw report has two polynomials
    assert emit(context, ((100,) * 240,) * 2, store) == first


def test_concurrent_same_payload_returns_one_committed_envelope(report_context, monkeypatch):
    context = report_context
    store = SourceEmissionStore(context["path"])
    barrier = Barrier(2)

    def simultaneous_encryption(*args, **kwargs):
        result = context["encrypt"](*args, **kwargs)
        barrier.wait(timeout=15)
        return result

    monkeypatch.setattr(protocol, "encrypt", simultaneous_encryption)
    channels = ((100,) * 240,) * 2
    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = list(pool.map(lambda _: emit(context, channels, store), range(2)))
    assert len(context["calls"]) == 2  # both drafts differ, only one is ever released
    assert first == second
    assert emit(context, channels, SourceEmissionStore(context["path"])) == first
