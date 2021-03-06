#!/usr/bin/env bash

set -euo pipefail

install() {
(
    cd "${root_dir}"
    cat > .git/hooks/pre-commit <<-EOF
#!/usr/bin/env bash
set -euo pipefail

ARGS=(hook-impl --config=.pre-commit-config.yaml --hook-type=pre-commit)

ARGS+=(--color always --hook-dir "/build" -- "\$@")

# git always calls us from repo root directory
FOBNAIL_SDK_DOCKER_EXTRA_OPTS="-v \$PWD/.temp/pre-commit:/home/builder/.cache/pre-commit"
export FOBNAIL_SDK_DOCKER_EXTRA_OPTS

if [ ! -d ".temp/pre-commit" ]; then
    mkdir -p .temp/pre-commit
fi

# pre-commit will fail if Docker is called with -it flag set.
export CI=true
exec run-fobnail-sdk.sh pre-commit "\${ARGS[@]}"
EOF
    chmod +x .git/hooks/pre-commit
)
}

root_dir=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")

precommit_run() {
    if [ ! -d "${root_dir}/.temp/pre-commit" ]; then
        mkdir -p "${root_dir}/.temp/pre-commit"
    fi

    # pre-commit will fail if Docker is called with -it flag set.
    export CI=true
    FOBNAIL_SDK_DOCKER_EXTRA_OPTS="-e PRE_COMMIT_COLOR=always -v $root_dir/.temp/pre-commit:/home/builder/.cache/pre-commit"
    export FOBNAIL_SDK_DOCKER_EXTRA_OPTS
    (
        cd "${root_dir}"
        exec run-fobnail-sdk.sh pre-commit "$@"
    )
}

if [ "$#" -eq "0" ]; then
    # run pre-commit without args
    precommit_run
else
    if [ "$1" == "install" ]; then
        install
    else
        precommit_run "$@"
    fi
fi
