FROM gcr.io/oss-fuzz-base/base-builder-python

COPY . $SRC/
WORKDIR $SRC
COPY .clusterfuzzlite/build.sh $SRC/
ENV PYTHONPATH=$PYTHONPATH:$SRC
