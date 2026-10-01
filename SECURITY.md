# Security policy

vesta runs privileged code on Kubernetes nodes and inside Kata guest VMs, so we treat security reports as a priority.

The STRIDE threat model, with trust boundaries, known open risks and planned mitigations, is in [docs/threat-model.md](docs/threat-model.md). Issues listed there as open are known; reports that go beyond them are especially welcome.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it privately through GitHub's private vulnerability reporting ("Report a vulnerability" under the repository's Security tab). _Placeholder: a dedicated security contact address will be published here before the first release._

Please include:

- the affected component (`vesta-agent`, `vesta-install`, `vesta-guestd`, BPF programs, guest kernel config, Helm chart) and version or commit;
- the Kata Containers, containerd and guest kernel versions;
- steps to reproduce, and the impact you observed or expect.

## What happens next

_Placeholder timelines, to be confirmed by the maintainers:_

1. We acknowledge the report within 3 working days.
2. We confirm or reject it, with an initial severity, within 10 working days.
3. We agree on a disclosure date with the reporter. The default embargo is 90 days or the release of a fix, whichever is sooner.
4. We publish a GitHub security advisory and request a CVE when appropriate, crediting the reporter unless they ask us not to.

## Scope

The threat model is in [docs/ARCHITECTURE.md §1.4](docs/ARCHITECTURE.md). These are in scope:

- a guest (including root in the guest) affecting the host, vesta-agent or other sandboxes through the vesta channel (boundary B2);
- root in the guest silently disabling enforcement without the host noticing (goal G2);
- policy bypass by a workload within the guest (boundary B1);
- privilege problems in the Helm chart, RBAC, the admission policy or the node installer.

Upstream Kata Containers, containerd and Linux kernel issues should go to those projects. Tell us as well if they affect vesta.

## Supported versions

vesta is pre-release. Only the `main` branch receives security fixes.
