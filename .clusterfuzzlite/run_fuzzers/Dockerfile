FROM neonlabsorg/evm_loader AS spl
FROM neonlabsorg/evm_loader:ci-proxy-caller-program AS proxy_program
FROM gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers:v1

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
RUN solana config set --keypair ~/.config/solana/id.json && ln -s /opt/proxy/operator-keypairs/id?*.json /root/.config/solana/
