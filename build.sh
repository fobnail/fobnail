#!/bin/bash

usage() {
    echo "Usage: $0 -t TARGET [--run] [--release] -- [cargo flags]"
    echo "  -t           Either pc or nrf (default pc)"
    echo "  --run        Build and run"
    echo "  --release    Do release instead of debug build"
    echo ""
    echo "Examples"
    echo "  env FOBNAIL_LOG=trace ./build.sh --run"
    echo "  ./build.sh -t nrf --run"

    exit 1
}

die() {
    [ $# -ne 0 ] && echo "$@"
    exit 1
}

target=""
run=""
do_release_build=""
extra_args=""

while true; do
    case "$1" in
        -t | --target)
            shift
            target="$1"
            shift
            ;;
        --run)
            run="1"
            shift
            ;;
        --release)
            do_release_build="1"
            shift
            ;;
        --)
            extra_args="1"
            shift
            break
            ;;
        *)
            break
            ;;
    esac
done

[ -n "${target}" ] || target="pc"

cargo_command="build"

if [ "${target}" == "pc" ]; then
    cargo_target="x86_64-unknown-linux-gnu"
    if [ -n "${run}" ]; then
        cargo_command="run"
    fi
elif [ "${target}" == "nrf" ]; then
    cargo_target="thumbv7em-none-eabihf"
    if [ -n "${run}" ]; then
        cargo_command="embed"
    fi
else
    die "Unsupported target ${target}"
fi

if [ -n "${do_release_build}" ]; then
    cargo_release_flag="--release"
else
    cargo_release_flag=""
fi

if [ -n "${extra_args}" ]; then
    cargo_extra_args="$@"
fi

full_cmd="cargo ${cargo_command} --target ${cargo_target} ${cargo_release_flag} ${cargo_extra_args}"

dir=$(dirname $(readlink -f ${BASH_SOURCE[0]}))

mkdir -p $dir/.temp/cargo

docker run --privileged \
    --rm -it \
    -v $dir:/home/build/fobnail \
    -v /dev:/dev \
    -v $dir/.temp/cargo:/home/build/.cargo \
    -w /home/build/fobnail \
    -e FOBNAIL_LOG=$FOBNAIL_LOG \
    --net=host \
    --init \
    3mdeb/fobnail-sdk \
    /bin/bash -i -c "${full_cmd}"
