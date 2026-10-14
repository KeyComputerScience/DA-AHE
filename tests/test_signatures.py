# SPDX-License-Identifier: MIT
"""Optional real-provider tests, all authored and unexecuted at delivery."""
import pytest
from types import SimpleNamespace

import daahe.signatures as signatures


def test_absent_native_provider_fails_before_import_or_network_bootstrap(monkeypatch):
    monkeypatch.setattr(signatures.importlib.metadata,"version",lambda _:signatures.PYTHON_PROVIDER_VERSION)
    monkeypatch.setattr(signatures.importlib.util,"find_spec",lambda _:object())
    monkeypatch.setattr(signatures,"_native_library_available",lambda:False)
    with pytest.raises(signatures.ProviderUnavailable,match="automatic installation is disabled"):
        signatures.MLDSA44Signer.keygen()


@pytest.mark.parametrize("existing",[None,"caller-version"])
def test_provider_import_failure_restores_callers_environment_and_blocks_bootstrap(monkeypatch,existing):
    monkeypatch.setattr(signatures.importlib.metadata,"version",lambda _:signatures.PYTHON_PROVIDER_VERSION)
    monkeypatch.setattr(signatures.importlib.util,"find_spec",lambda _:object())
    monkeypatch.setattr(signatures,"_native_library_available",lambda:True)
    if existing is None:
        monkeypatch.delenv("PYOQS_VERSION",raising=False)
    else:
        monkeypatch.setenv("PYOQS_VERSION",existing)
    def import_failure(name):
        assert signatures.os.environ["PYOQS_VERSION"] == signatures._NO_INSTALL_SENTINEL
        raise ImportError("unit-test provider failure")
    monkeypatch.setattr(signatures.importlib,"import_module",import_failure)
    with pytest.raises(signatures.ProviderUnavailable,match="automatic installation is disabled"):
        signatures._provider()
    assert signatures.os.environ.get("PYOQS_VERSION") == existing


def test_provider_installer_hook_is_replaced_with_explicit_refusal(monkeypatch):
    monkeypatch.setattr(signatures.importlib.metadata,"version",lambda _:signatures.PYTHON_PROVIDER_VERSION)
    monkeypatch.setattr(signatures.importlib.util,"find_spec",lambda _:object())
    monkeypatch.setattr(signatures,"_native_library_available",lambda:True)
    monkeypatch.delenv("PYOQS_VERSION",raising=False)
    wrapper = SimpleNamespace(oqs_version=lambda:signatures.NATIVE_PROVIDER_VERSION,
                              get_enabled_sig_mechanisms=lambda:[signatures.ALGORITHM])
    implementation = SimpleNamespace(_install_liboqs=lambda:pytest.fail("installer must never run"),OQS_VERSION="original")
    def fake_import(name):
        assert signatures.os.environ["PYOQS_VERSION"] == signatures._NO_INSTALL_SENTINEL
        return wrapper if name == "oqs" else implementation
    monkeypatch.setattr(signatures.importlib,"import_module",fake_import)
    assert signatures._provider() is wrapper
    assert implementation.OQS_VERSION == signatures._NO_INSTALL_SENTINEL
    assert "PYOQS_VERSION" not in signatures.os.environ
    with pytest.raises(signatures.ProviderUnavailable,match="download and installation are disabled"):
        implementation._install_liboqs()


@pytest.mark.pq
def test_real_ml_dsa_44_roundtrip_message_binding_and_key_restore(request):
    # Explicit selection is required even on machines where a provider exists.
    if request.config.option.markexpr.strip() != "pq":
        pytest.skip("explicit reviewer command pytest -m pq required")
    with signatures.MLDSA44Signer.keygen() as signer:
        verifier = signatures.MLDSA44Verifier(signer.public_key)
        message = b"DA-AHE real-provider test, not experimental data"
        signature = signer.sign(message)
        assert len(signer.public_key) == signatures.PUBLIC_KEY_BYTES
        assert len(signature) == signatures.SIGNATURE_BYTES
        assert verifier.verify(message,signature)
        assert not verifier.verify(message+b"altered",signature)
        corrupted = bytes([signature[0]^1])+signature[1:]
        assert not verifier.verify(message,corrupted)
        secret = signer.export_secret_key()
        with signatures.MLDSA44Signer.from_secret_key(signer.public_key,secret) as restored:
            assert verifier.verify(message,restored.sign(message))
    with pytest.raises(RuntimeError,match="closed"):
        signer.sign(message)
