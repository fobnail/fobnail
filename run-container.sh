#!/bin/bash

dir=$(dirname $(readlink -f ${BASH_SOURCE[0]}))

docker run --privileged \
    --rm -it \
    -v $dir:/home/build/fobnail \
    -v /dev:/dev \
    -w /home/build/fobnail \
    --net=host \
    3mdeb/fobnail-sdk /bin/bash