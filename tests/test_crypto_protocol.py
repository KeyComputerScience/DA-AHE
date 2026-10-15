# SPDX-License-Identifier: MIT
"""Meaningful reference invariants and adversarial rejection cases; execution receipts are recorded separately.

The deterministic HMAC signer below is a test double for protocol framing only.
It is never exported as a production ticket provider or a PQ signature claim.
Random(seed) is injected only into cryptographic unit-test fixtures.
"""
from dataclasses import replace
import hashlib
import hmac
import random
import struct

import pytest

from daahe.derivation import derive_matrix, derive_offset, linear_tag
from daahe.mlwe import DEFAULT_PARAMETERS, Ciphertext, decrypt, encrypt, iter_ciphertext_blocks, keygen
from daahe.profiles import Profile, ProfileLibrary
from daahe.protocol import (Block, Contributor, ReplayStore, Sink, SourceEnvelope, Ticket,
                            aggregate, aggregate_message, block_mac, issue_ticket, pack_values,
                            unpack_values, verify_ticket)
from daahe.ring import centered, negacyclic_mul
from daahe.signal import forward_channel, inverse_channel, support_for_length


class TestOnlySigner:
    __test__ = False
    def sign(self, message):
        return hmac.digest(b"unit-test-only-key"*2,message,"sha3_256")
    def verify(self, message, signature):
        return hmac.compare_digest(self.sign(message),signature)


def test_negacyclic_wrap_has_negative_sign_and_exact_large_integer_arithmetic():
    q = 2**32
    assert negacyclic_mul((0,0,0,1),(0,1,0,0),q) == (q-1,0,0,0)
    assert negacyclic_mul((q-1,0,0,0),(q-1,0,0,0),q) == (1,0,0,0)
    assert centered(32768,65537) == 32768
    assert centered(32769,65537) == -32768


def test_packing_boundary_yields_one_or_two_polynomials():
    assert len(pack_values([1]*240,[2]*16)) == 1
    assert len(pack_values([1]*480,[2]*16)) == 2
    polys = pack_values([1]*240,[2]*16)
    assert unpack_values(polys,240) == ((1,)*240,(2,)*16)
    with pytest.raises(ValueError, match="noncanonical"):
        pack_values([65537],[0]*16)
    with pytest.raises(ValueError, match="unused"):
        unpack_values(((0,)*17+(1,)+(0,)*238,),1)


def test_profile_defensively_freezes_support_and_enforces_no_wrap_boundary():
    positions = list(range(240))
    profile = Profile("boundary",240,8,3.2,16,positions,2048)
    original_digest = profile.digest
    positions[0] = 479
    assert profile.support == tuple(range(240))
    assert profile.digest == original_digest
    with pytest.raises((AttributeError,TypeError)):
        profile.support[0] = 10
    with pytest.raises(ValueError,match="no-wrap"):
        Profile("overflow",240,8,3.2,16,tuple(range(240)),2049)


def test_raw_profile_requires_all_480_values_and_exact_order():
    profile = Profile("raw",480,16,3.2,16,tuple(range(480)),2048,"raw")
    assert profile.polynomial_count == 2
    with pytest.raises(ValueError):
        Profile("incomplete-raw",240,16,3.2,16,tuple(range(240)),2048,"raw")
    with pytest.raises(ValueError):
        Profile("reordered-raw",480,16,3.2,16,tuple(reversed(range(480))),2048,"raw")


def test_illustrative_integer_lifting_is_reversible_but_not_an_original_trace():
    rng = random.Random(71)
    values = tuple(rng.randrange(-10000,10000) for _ in range(240))
    assert inverse_channel(forward_channel(values)) == values
    support = support_for_length(240)
    assert len(support) == len(set(support)) == 240
    assert all(0 <= index < 480 for index in support)


@pytest.fixture(scope="module")
def keys():
    return keygen(random.Random(991))


def test_additive_encryption_and_parameter_derived_transport(keys):
    x = (5,65530,11)+(0,)*253
    y = (7,9,65534)+(0,)*253
    a = encrypt(keys.pk,x,rng=random.Random(101))
    b = encrypt(keys.pk,y,rng=random.Random(102))
    assert decrypt(keys.sk,a+b) == tuple((left+right)%65537 for left,right in zip(x,y))
    wire = a.to_bytes()
    assert len(wire) == keys.pk.params.ciphertext_bytes
    assert Ciphertext.from_bytes(wire) == a
    assert b"".join(iter_ciphertext_blocks(a,64)) == wire
    assert len(tuple(iter_ciphertext_blocks(a,32))) == keys.pk.params.ciphertext_bytes // 32
    with pytest.raises(ValueError):
        Ciphertext.from_bytes(wire[:-1])


@pytest.fixture
def batch(keys):
    signer = TestOnlySigner()
    profile = Profile("test-support",2,1,3.2,2,(0,1),100)
    library = ProfileLibrary([profile])
    contributors = (Contributor("sensor-a",b"a"*16),Contributor("sensor-b",b"b"*16))
    ticket = Ticket(0,1,"test-protocol",profile.profile_id,profile.digest,contributors,b"n"*32)
    signed = issue_ticket(ticket,signer)
    secret, gateway_key = b"e"*32,b"g"*32
    block_keys = {s.source_id:hashlib.sha256(s.source_id.encode()).digest() for s in contributors}
    matrix = derive_matrix(secret,ticket.digest,2)
    envelopes = []
    for i,source in enumerate(contributors):
        values = (2+2*i,3+2*i)
        offset = derive_offset(secret,ticket.digest,source.source_id,source.nonce)
        plaintext = pack_values(values,linear_tag(matrix,values,offset))[0]
        ciphertext = encrypt(keys.pk,plaintext,rng=random.Random(500+i))
        payloads = tuple(iter_ciphertext_blocks(ciphertext,64))
        blocks = tuple(Block(j,len(payloads),payload,block_mac(block_keys[source.source_id],ticket,source,j,len(payloads),payload))
                       for j,payload in enumerate(payloads))
        envelopes.append(SourceEnvelope(signed,source,blocks))
    result = aggregate(envelopes,signed,block_keys,gateway_key,signer,library)
    return keys,signer,profile,library,contributors,signed,secret,gateway_key,block_keys,envelopes,result


def sink_for(batch,tmp_path,name):
    keys,signer,_,library,_,_,secret,gateway_key,_,_,_ = batch
    return Sink(keys.sk,secret,gateway_key,signer,library,ReplayStore(tmp_path/name),
                epoch=0,context="test-protocol")


def test_honest_exact_roster_aggregate_accepts_once_with_durable_replay(batch,tmp_path):
    result = batch[-1]
    sink = sink_for(batch,tmp_path,"seen.sqlite")
    accepted = sink.accept(result)
    assert accepted is not None and accepted.integrity_verified
    assert accepted.quantized_aggregate == (6,8)
    assert sink.accept(result) is None
    assert sink_for(batch,tmp_path,"seen.sqlite").accept(result) is None


def test_gateway_rejects_missing_duplicate_reordered_or_reassigned_blocks(batch):
    _,signer,_,library,_,signed,_,gateway_key,block_keys,envelopes,_ = batch
    for invalid in (envelopes[:1],envelopes+[envelopes[0]],list(reversed(envelopes))):
        with pytest.raises(ValueError):
            aggregate(invalid,signed,block_keys,gateway_key,signer,library)
    # Valid MAC for source A is not reusable for source B, even at same position.
    changed = replace(envelopes[1],blocks=(envelopes[0].blocks[0],)+envelopes[1].blocks[1:])
    with pytest.raises(ValueError,match="invalid block"):
        aggregate([envelopes[0],changed],signed,block_keys,gateway_key,signer,library)


def test_signed_ticket_binds_full_profile_digest_and_roster(batch):
    _,signer,_,library,contributors,signed,_,_,_,_,_ = batch
    changed = replace(signed,ticket=replace(signed.ticket,roster=contributors[:1]))
    with pytest.raises(ValueError,match="invalid ticket"):
        verify_ticket(changed,signer,library)
    digest = signed.ticket.profile_digest
    changed_digest = digest[:-1]+("0" if digest[-1] != "0" else "1")
    changed = replace(signed,ticket=replace(signed.ticket,profile_digest=changed_digest))
    with pytest.raises(ValueError,match="invalid ticket"):
        verify_ticket(changed,signer,library)


def forge_gateway_transport(result,gateway_key,**changes):
    changed = replace(result,**changes)
    mac = hmac.digest(gateway_key,aggregate_message(changed.signed_ticket,changed.contributors,changed.ciphertext),"sha3_256")
    return replace(changed,transport_mac=mac)


@pytest.mark.parametrize("plaintext_index",[0,2])
def test_compromised_gateway_recomputed_transport_mac_does_not_bypass_linear_tag(batch,tmp_path,plaintext_index):
    # Change data coefficient (0) or tag coefficient (L=2), preserve signed roster,
    # and recompute the gateway-held HMAC. Rejection must come from end-to-end checks.
    result,gateway_key = batch[-1],batch[7]
    wire = bytearray(result.ciphertext)
    position = DEFAULT_PARAMETERS.k*256*4+plaintext_index*4  # v component, after all u polynomials
    old = struct.unpack_from("<I",wire,position)[0]
    struct.pack_into("<I",wire,position,(old+(2**32//65537)) & 0xffffffff)
    forged = forge_gateway_transport(result,gateway_key,ciphertext=bytes(wire))
    assert sink_for(batch,tmp_path,"forgery.sqlite").accept(forged) is None
    # A rejected forgery does not reserve the honest batch's replay identity.
    assert sink_for(batch,tmp_path,"forgery.sqlite").accept(result) is not None


def test_sink_rejects_false_declared_roster_despite_gateway_transport_mac(batch,tmp_path):
    result,gateway_key = batch[-1],batch[7]
    forged = forge_gateway_transport(result,gateway_key,contributors=result.contributors[:1])
    assert sink_for(batch,tmp_path,"roster.sqlite").accept(forged) is None


def test_sink_malformed_inputs_share_one_rejection_outcome(batch,tmp_path):
    sink = sink_for(batch,tmp_path,"malformed.sqlite")
    for invalid in (None,{},b"garbage",replace(batch[-1],ciphertext=b"short"),
                    replace(batch[-1],transport_mac=b"wrong")):
        assert sink.accept(invalid) is None


def test_replay_store_requires_persistence(tmp_path):
    with pytest.raises(ValueError,match="durable"):
        ReplayStore(":memory:")
    path = tmp_path/"replay.sqlite"
    assert ReplayStore(path).reserve(b"a"*32)
    assert not ReplayStore(path).reserve(b"a"*32)
