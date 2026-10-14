# Third-party provenance and license boundaries

No third-party source is vendored. Dependencies retain their upstream licenses;
archive the actual installed revision's LICENSE/NOTICE in a release environment.
The MIT license in this package only covers its original files.

| Project | Role | Version / provenance |
|---|---|---|
| [CPython](https://www.python.org/downloads/) | host runtime | proposed3.11.11; actual capture required |
| [NumPy](https://numpy.org/) | paired bootstrap arrays | direct pin2.2.4 |
| [pytest](https://docs.pytest.org/) | reviewer tests | direct pin8.3.5 |
| [liboqs-python](https://github.com/open-quantum-safe/liboqs-python/releases/tag/0.16.0.1) | ML-DSA-44 wrapper | pin0.16.0.1, upstream MIT |
| [liboqs](https://github.com/open-quantum-safe/liboqs/releases/tag/0.16.0) | native signature provider | proposed tag0.16.0; capture full commit/binary hash |
| [lattice-estimator](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84) | fixed-instance attack estimates | paper-pinned exact commit |
| [SageMath](https://www.sagemath.org/) | estimator execution | original version unavailable, record actual |
| [OMNeT++](https://omnetpp.org/) / [INET](https://inet.omnetpp.org/) | original external packet-level experiments | paper6.0/4.4; original model absent |
| [Contiki-NG](https://github.com/contiki-ng/contiki-ng) | original external firmware | paperv4.8 / short commit9771e9a; original image absent |

Native provider usage follows the [official Python Signature API](https://github.com/open-quantum-safe/liboqs-python/blob/main/examples/sig.py).
The wrapper can bootstrap a missing native library; the adapter performs a local
availability check first, and deployment instructions require explicit install.
The precise native loader/version must be verified in the execution environment.

OMNeT++ licensing and any third-party data rights are not transferred by this
artifact. Do not redistribute the supplied manuscript, original datasets or
upstream firmware under this package's MIT license without the corresponding
rights. 

