# SPDX-License-Identifier: MIT
"""Fail-closed ML-DSA-44 tickets through the optional official liboqs provider.

API: ``MLDSA44Signer.keygen()``, ``signer.public_key``, ``signer.sign(bytes)``,
``signer.export_secret_key()``, ``MLDSA44Signer.from_secret_key(pk, sk)``, and
``MLDSA44Verifier(pk).verify(message, signature)``. Use a signer as a context
manager (or call close) so liboqs cleanses its native secret buffer. Exported
Python secret-key bytes cannot be reliably wiped and require external key
management. No classical, mock or HMAC signature fallback is implemented.

The official wrapper may download/build a missing native library during import.
This adapter requires liboqs-python 0.16.0.1 and native liboqs 0.16.0, mirrors the
pinned wrapper's search order, and disables its bootstrap using an invalid
PYOQS_VERSION sentinel during import. In that pinned version the installer
validates this value before creating its build directory or launching Git/CMake.
Thus a preflight/import lookup mismatch fails before download or installation.
The caller's environment value is restored after import. Afterwards the pinned
implementation's installer is replaced with a refusal, including when another
caller already imported the wrapper. This is a guard for the trusted pinned
wrapper, not a sandbox for malicious replacement packages or native libraries.
Official loader: https://github.com/open-quantum-safe/liboqs-python/blob/0.16.0.1/oqs/oqs.py
"""

from __future__ import annotations

import ctypes
import ctypes.util
import importlib
import importlib.metadata
import importlib.util
import os
import platform
from pathlib import Path
from threading import RLock
from types import ModuleType
from typing import Any

ALGORITHM = "ML-DSA-44"
PUBLIC_KEY_BYTES = 1312
SECRET_KEY_BYTES = 2560
SIGNATURE_BYTES = 2420
PYTHON_PROVIDER_VERSION = "0.16.0.1"
NATIVE_PROVIDER_VERSION = "0.16.0"
_NO_INSTALL_SENTINEL = "daahe-no-automatic-installation"
_PROVIDER_IMPORT_LOCK = RLock()


class ProviderUnavailable(RuntimeError):
    """Required optional post-quantum provider is not installed or enabled."""


def _native_library_available() -> bool:
    # Match _load_shared_obj / _load_liboqs in pinned liboqs-python exactly.
    # An explicit OQS_INSTALL_PATH replaces, rather than supplements, _oqs.
    root = (
        Path(os.environ["OQS_INSTALL_PATH"])
        if "OQS_INSTALL_PATH" in os.environ else Path.home() / "_oqs"
    )
    system = platform.system()
    directories = (
        (root / "bin", root / "bin")
        if system == "Windows" else (root / "lib", root / "lib64")
    )
    filenames = ("oqs.dll", "liboqs.dll") if system == "Windows" else (
        "liboqs.dylib" if system == "Darwin" else "liboqs.so",
    )
    candidates = [
        str(directory.absolute() / filename)
        for directory in directories for filename in filenames
    ]
    for name in ("oqs", "liboqs"):
        try:
            found = ctypes.util.find_library(name)
        except (OSError, RuntimeError):
            found = None
        if found:
            candidates.insert(0, found)
    loader = ctypes.windll.LoadLibrary if system == "Windows" else ctypes.cdll.LoadLibrary
    for candidate in candidates:
        try:
            native = loader(candidate)
        except OSError:
            continue
        # The wrapper returns its first loadable library, even if its version is
        # wrong. Do not accept a later candidate the wrapper would never choose.
        try:
            native.OQS_version.restype = ctypes.c_char_p
            native.OQS_version.argtypes = []
            version = native.OQS_version()
            return version == NATIVE_PROVIDER_VERSION.encode("ascii")
        except (AttributeError, OSError):
            return False
    return False


def _installation_disabled(*args: object, **kwargs: object) -> None:
    raise ProviderUnavailable("automatic liboqs download and installation are disabled")


def _provider() -> ModuleType:
    try:
        installed_version = importlib.metadata.version("liboqs-python")
    except importlib.metadata.PackageNotFoundError as error:
        raise ProviderUnavailable(
            "install the optional liboqs-python dependency and native liboqs first"
        ) from error
    if installed_version != PYTHON_PROVIDER_VERSION:
        raise ProviderUnavailable("this adapter requires pinned liboqs-python 0.16.0.1")
    if importlib.util.find_spec("oqs") is None:
        raise ProviderUnavailable("install the optional liboqs-python dependency and native liboqs first")
    if not _native_library_available():
        raise ProviderUnavailable(
            "a loadable native liboqs 0.16.0 is required; automatic installation is disabled"
        )
    with _PROVIDER_IMPORT_LOCK:
        previous_version = os.environ.get("PYOQS_VERSION")
        os.environ["PYOQS_VERSION"] = _NO_INSTALL_SENTINEL
        try:
            module = importlib.import_module("oqs")
            implementation = importlib.import_module("oqs.oqs")
            # The sentinel blocks fresh-import bootstrap before this assignment.
            # Replacing the private hook additionally covers an earlier import.
            implementation._install_liboqs = _installation_disabled
            implementation.OQS_VERSION = _NO_INSTALL_SENTINEL
        except (ImportError, OSError, RuntimeError, ValueError, AttributeError) as error:
            raise ProviderUnavailable(
                "the installed liboqs provider could not be loaded; "
                "automatic installation is disabled"
            ) from error
        finally:
            if previous_version is None:
                os.environ.pop("PYOQS_VERSION", None)
            else:
                os.environ["PYOQS_VERSION"] = previous_version
    if module.oqs_version() != NATIVE_PROVIDER_VERSION:
        raise ProviderUnavailable("the loaded liboqs provider must be version 0.16.0")
    if ALGORITHM not in module.get_enabled_sig_mechanisms():
        raise ProviderUnavailable("the installed liboqs provider does not enable ML-DSA-44")
    return module


def _bytes(value: bytes, label: str, expected: int | None = None) -> None:
    if not isinstance(value, bytes) or (expected is not None and len(value) != expected):
        raise ValueError(f"{label} must be bytes of the expected length")


class MLDSA44Signer:
    """Own one native signing context; use ``with MLDSA44Signer.keygen() as s``."""

    def __init__(self, native: Any, public_key: bytes) -> None:
        _bytes(public_key, "public key", PUBLIC_KEY_BYTES)
        self._native = native
        self._public_key = public_key

    @classmethod
    def keygen(cls) -> MLDSA44Signer:
        provider = _provider()
        native = provider.Signature(ALGORITHM)
        try:
            public_key = native.generate_keypair()
            return cls(native, public_key)
        except Exception:
            native.free()
            raise

    @classmethod
    def from_secret_key(cls, public_key: bytes, secret_key: bytes) -> MLDSA44Signer:
        _bytes(public_key, "public key", PUBLIC_KEY_BYTES)
        _bytes(secret_key, "secret key", SECRET_KEY_BYTES)
        provider = _provider()
        return cls(provider.Signature(ALGORITHM, secret_key), public_key)

    @property
    def public_key(self) -> bytes:
        return self._public_key

    def _open(self) -> Any:
        if self._native is None:
            raise RuntimeError("signing context has been closed")
        return self._native

    def sign(self, message: bytes) -> bytes:
        _bytes(message, "message")
        signature = self._open().sign(message)
        _bytes(signature, "signature", SIGNATURE_BYTES)
        return signature

    def verify(self, message: bytes, signature: bytes) -> bool:
        return MLDSA44Verifier(self.public_key).verify(message, signature)

    def export_secret_key(self) -> bytes:
        """Export for external secret storage; Python bytes cannot be securely wiped."""
        return self._open().export_secret_key()

    def close(self) -> None:
        if self._native is not None:
            self._native.free()
            self._native = None

    def __enter__(self) -> MLDSA44Signer:
        self._open()
        return self

    def __exit__(self, *exception: object) -> None:
        self.close()

    generate = keygen


class MLDSA44Verifier:
    def __init__(self, public_key: bytes) -> None:
        _bytes(public_key, "public key", PUBLIC_KEY_BYTES)
        self.public_key = public_key

    def verify(self, message: bytes, signature: bytes) -> bool:
        if not isinstance(message, bytes) or not isinstance(signature, bytes):
            return False
        if len(signature) != SIGNATURE_BYTES:
            return False
        provider = _provider()
        with provider.Signature(ALGORITHM) as verifier:
            try:
                return bool(verifier.verify(message, signature, self.public_key))
            except (ValueError, RuntimeError):
                return False
