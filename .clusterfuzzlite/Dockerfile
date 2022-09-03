FROM neonlabsorg/evm_loader AS spl
FROM neonlabsorg/evm_loader:ci-proxy-caller-program AS proxy_program
FROM gcr.io/oss-fuzz-base/base-builder-python

ENV FUZZING_LANGUAGE="python"
COPY . $SRC/
WORKDIR $SRC
COPY .clusterfuzzlite/build.sh $SRC/