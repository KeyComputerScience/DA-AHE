# SPDX-License-Identifier: MIT
# A version-selected fallback. Supply a verified image digest for immutable CI.
ARG SAGE_IMAGE=sagemath/sagemath:10.6
FROM ${SAGE_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/malb/lattice-estimator.git /opt/lattice-estimator \
    && git -C /opt/lattice-estimator checkout --detach 53da5982597709ba0fdf94ea37a84d822310fd84
COPY tools/estimate_security.sage tools/estimator_result_adapter.py tools/estimate_security_parameters.py tools/search_security_parameters.py /opt/daahe/tools/
COPY security/container-entrypoint.sh /opt/daahe/security/container-entrypoint.sh
RUN chmod +x /opt/daahe/security/container-entrypoint.sh
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/daahe
ENTRYPOINT ["/opt/daahe/security/container-entrypoint.sh"]
