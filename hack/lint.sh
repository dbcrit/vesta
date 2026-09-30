#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs shellcheck (shell scripts), hadolint (Dockerfiles) and actionlint (GitHub
# workflows), each in a pinned container.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

shellcheck_image="koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d"
hadolint_image="hadolint/hadolint:v2.14.0@sha256:27086352fd5e1907ea2b934eb1023f217c5ae087992eb59fde121dce9c9ff21e"
actionlint_image="rhysd/actionlint:1.7.8@sha256:96d4a8c87dbbfb3bdd324f8fdc285fc3df5261e2decc619a4dd7e8ee52bbfd46"

prune=(-path ./.git -o -path ./images/guest/out -o -path ./guest/target -o -path ./bpf/.output)

# Portable to bash 3.2 (macOS): no mapfile.
scripts=()
while IFS= read -r f; do scripts+=("${f}"); done < <(find . \( "${prune[@]}" \) -prune -o -type f -name '*.sh' -print | LC_ALL=C sort)
echo "shellcheck: ${#scripts[@]} scripts"
docker run --rm -v "${repo_root}:/mnt:ro" -w /mnt "${shellcheck_image}" \
	--external-sources --source-path=SCRIPTDIR --severity=style "${scripts[@]}"

dockerfiles=()
while IFS= read -r f; do dockerfiles+=("${f}"); done < <(find . \( "${prune[@]}" \) -prune -o -type f \( -name 'Dockerfile' -o -name '*.Dockerfile' -o -name 'Dockerfile.*' \) ! -name '*.dockerignore' -print | LC_ALL=C sort)
echo "hadolint: ${#dockerfiles[@]} Dockerfiles"
for f in "${dockerfiles[@]}"; do
	docker run --rm -i -v "${repo_root}/hack/hadolint.yaml:/.config/hadolint.yaml:ro" "${hadolint_image}" hadolint --config /.config/hadolint.yaml - <"${f}" ||
		{ echo "hadolint failed: ${f}" >&2; exit 1; }
done

if [[ -d .github/workflows ]]; then
	echo "actionlint"
	docker run --rm -v "${repo_root}:/repo:ro" -w /repo "${actionlint_image}" -color
fi
echo "lint: OK"
