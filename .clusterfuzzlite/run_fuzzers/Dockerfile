FROM neonlabsorg/evm_loader AS spl
FROM neonlabsorg/evm_loader:ci-proxy-caller-program AS proxy_program
FROM gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers:v1
ARG SOLANA_URL
ENV FUZZING_LANGUAGE="python"

ENV PATH "$PATH:/cli/bin/:/spl/bin/"

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
COPY --from=proxy_program /opt/proxy_program-keypair.json /spl/bin/

COPY proxy/operator-keypairs/id.json /root/.config/solana/
COPY proxy/operator-keypairs/ /opt/proxy/operator-keypairs/
RUN apt install -y ca-certificates && update-ca-certificates --fresh
ENV SSL_CERT_DIR=/etc/ssl/certs
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
RUN solana config set --keypair ~/.config/solana/id.json && \
    solana config set -u $SOLANA_URL && \
    ln -s /opt/proxy/operator-keypairs/id?*.json /root/.config/solana/ && \
    /spl/bin/create-test-accounts.sh 30
