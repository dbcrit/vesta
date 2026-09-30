# SPDX-License-Identifier: Apache-2.0
# Helpers for the e2e scripts. Sourced, not executed.
# shellcheck shell=bash

set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC2034 # used by the scripts that source this file
REPO_ROOT="$(cd "${E2E_DIR}/../.." && pwd)"
# shellcheck source=test/e2e/env.sh
source "${E2E_DIR}/env.sh"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die() {
	printf '\033[1;31merror:\033[0m %s\n' "$*" >&2
	exit 1
}

# Runs a command as root (the scripts are meant for a disposable test host).
as_root() {
	if [[ "$(id -u)" == 0 ]]; then
		"$@"
	else
		sudo "$@"
	fi
}

need() {
	local c
	for c in "$@"; do
		command -v "${c}" >/dev/null 2>&1 || die "missing tool: ${c}"
	done
}

kc() { kubectl "$@"; }

# retry <seconds> <description> <command...>: runs the command every 2s until
# it succeeds or the time is up.
retry() {
	local timeout="$1" what="$2"
	shift 2
	local deadline=$((SECONDS + timeout))
	until "$@" >/dev/null 2>&1; do
		if ((SECONDS >= deadline)); then
			warn "timed out after ${timeout}s waiting for ${what}"
			"$@" || true
			return 1
		fi
		sleep 2
	done
}

node_name() { kc get nodes -o jsonpath='{.items[0].metadata.name}'; }

node_has_label() { # <label>=<value>
	local key="${1%%=*}" want="${1#*=}"
	[[ "$(kc get node "$(node_name)" -o "jsonpath={.metadata.labels.${key//./\\.}}")" == "${want}" ]]
}

# The node's primary IPv4 address (the API server's advertise address).
node_ip() { kc get node "$(node_name)" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'; }
