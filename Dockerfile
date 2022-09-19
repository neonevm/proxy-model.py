ARG NEON_EVM_COMMIT

FROM neonlabsorg/evm_loader:${NEON_EVM_COMMIT} AS spl
# FROM neonlabsorg/evm_loader:ci-proxy-caller-program AS proxy_program

FROM solanalabs/rust:1.61.0 AS builder
RUN rustup toolchain install nightly
RUN rustup component add clippy --toolchain nightly
WORKDIR /opt
RUN sh -c "$(curl -sSfL https://release.solana.com/stable/install)" && \
    /root/.local/share/solana/install/active_release/bin/sdk/bpf/scripts/install.sh
ENV PATH=/root/.local/share/solana/install/active_release/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

COPY ./proxy_program/ /opt/proxy_program/
WORKDIR /opt/proxy_program
RUN cargo +nightly clippy &&  cargo build-bpf

FROM ubuntu:20.04

COPY ./requirements.txt /opt

WORKDIR /opt

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y git software-properties-common openssl curl parallel netcat-openbsd \
                                                  ca-certificates python3-pip python3-venv postgresql-client && \
    python3 -m venv venv && \
    pip3 install --upgrade pip && \
    /bin/bash -c "source venv/bin/activate" && \
    pip install -r requirements.txt && \
    pip3 install py-solc-x && \
    python3 -c "import solcx; solcx.install_solc(version='0.7.6')" && \
    apt remove -y git && \
    rm -rf /var/lib/apt/lists/*

COPY --from=spl /opt/solana/bin/solana \
                /opt/solana/bin/solana-keygen \
                /cli/bin/

COPY --from=spl /opt/spl-token \
                /opt/create-test-accounts.sh \
                /opt/neon-cli \
                /opt/evm_loader-keypair.json \
                /spl/bin/

COPY --from=spl /opt/contracts/contracts/ /opt/contracts/

COPY --from=spl /opt/neon-cli /spl/bin/emulator
COPY --from=builder /opt/proxy_program/proxy_program-keypair.json /spl/bin/
COPY --from=builder /opt/proxy_program/proxy_program-keypair.json /opt
COPY --from=builder /opt/proxy_program/target/deploy/proxy_program.so /opt
COPY --from=builder /opt/proxy_program/deploy-proxy_program.sh /opt

COPY proxy/operator-keypairs/id.json /root/.config/solana/

COPY . /opt
ARG PROXY_REVISION
ARG PROXY_LOG_CFG
RUN (cp -f /opt/${PROXY_LOG_CFG} /opt/log_cfg.json || true)
RUN sed -i 's/NEON_PROXY_REVISION_TO_BE_REPLACED/'"$PROXY_REVISION"'/g' /opt/proxy/neon_rpc_api_model/neon_rpc_api_worker.py

COPY ./proxy/solana-py.patch /opt
RUN cd /usr/local/lib/python3.8/dist-packages/ && patch -p0 </opt/solana-py.patch

ENV PATH /venv/bin:/cli/bin/:/spl/bin/:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV CONFIG="devnet"

EXPOSE 9090/tcp
ENTRYPOINT [ "./proxy/run-proxy.sh" ]
