/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * vesta kernel <-> userspace ABI.
 *
 * Shared by the BPF programs (bpf/) and vesta-guestd (guest/, mirrored with
 * #[repr(C)]). Layout rules, see docs/abi.md:
 *   - fixed-width types only, guest host byte order unless a field says
 *     otherwise (__be16 / network-order byte arrays);
 *   - every struct is explicitly padded; padding fields are named _padN and
 *     MUST be zero when written by userspace (hash/LPM keys compare them);
 *   - sizes and offsets are pinned by _Static_assert below; changing any of
 *     them requires bumping VESTA_ABI_VERSION and shipping a new guest image.
 */
#ifndef VESTA_ABI_H
#define VESTA_ABI_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#include <stddef.h>
#endif

#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

#define VESTA_ABI_VERSION 1

/* ---- Limits ---------------------------------------------------------- */

#define VESTA_COMM_LEN   16   /* TASK_COMM_LEN */
#define VESTA_PATH_MAX   256  /* exe path bytes incl. NUL; longer paths are truncated + flagged */
#define VESTA_ARGV_MAX   1024 /* argv bytes, NUL-separated; longer argv is truncated + flagged */
#define VESTA_TAG_LEN    8    /* BPF_TAG_SIZE */

#define VESTA_MAX_CGROUPS    4096
#define VESTA_MAX_EXEC_RULES 65536
#define VESTA_MAX_NET_RULES  16384 /* per address family */
#define VESTA_MAX_POLICIES   1024  /* valid policy_id: 1..VESTA_MAX_POLICIES; 0 = none */

/* Default ring buffer size; guestd may resize before load (power of two, page multiple). */
#define VESTA_RINGBUF_DEFAULT_BYTES (4U << 20)

/* Prefix bits of the fixed (non-address) part of a net rule key: policy_id(32) + proto(8) + _pad0(8) + port(16). */
#define VESTA_NET_KEY_FIXED_BITS 64

/* ---- Enums (stored as the integer width of the field that holds them) - */

enum vesta_event_type {
	VESTA_EVENT_UNSPEC      = 0,
	VESTA_EVENT_EXEC        = 1,
	VESTA_EVENT_CONNECT     = 2,
	VESTA_EVENT_SENDMSG     = 3,  /* reserved, Phase 4 */
	VESTA_EVENT_BIND        = 4,  /* reserved, Phase 4 */
	VESTA_EVENT_DNS         = 5,  /* reserved, Phase 4 */
	VESTA_EVENT_FILE_OPEN   = 6,  /* reserved, Phase 4 */
	VESTA_EVENT_FILE_MODIFY = 7,  /* reserved, Phase 4 */
	VESTA_EVENT_PTRACE      = 8,  /* reserved, Phase 3 */
	VESTA_EVENT_USERNS      = 9,  /* reserved, Phase 3 */
	VESTA_EVENT_MOUNT       = 10, /* reserved, Phase 4 */
	VESTA_EVENT_SETUID      = 11, /* reserved, Phase 4 */
	VESTA_EVENT_MEMFD       = 12, /* reserved, Phase 4 */
	VESTA_EVENT_UNSHARE     = 13, /* reserved, Phase 4 */
	VESTA_EVENT_DUP_SOCKET  = 14, /* reserved, Phase 4 */
	VESTA_EVENT_TAMPER      = 15, /* reserved, Phase 3 */
	VESTA_EVENT_TYPE_MAX    = 16, /* array bound for drop_counters */
};

/* Numbering matches vesta.event.v1.Action. */
enum vesta_action {
	VESTA_ACTION_UNSPEC  = 0,
	VESTA_ACTION_AUDITED = 1,
	VESTA_ACTION_DENIED  = 2,
	VESTA_ACTION_ALLOWED = 3,
};

/* Program that produced an event. Numbering matches vesta.event.v1.Hook. */
enum vesta_hook {
	VESTA_HOOK_UNSPEC              = 0,
	VESTA_HOOK_SCHED_PROCESS_EXEC  = 1, /* P1 tp/sched/sched_process_exec */
	VESTA_HOOK_BPRM_CHECK_SECURITY = 2, /* P2 lsm/bprm_check_security */
	VESTA_HOOK_CGROUP_CONNECT4     = 3, /* N1 cgroup/connect4 */
	VESTA_HOOK_CGROUP_CONNECT6     = 4, /* N1 cgroup/connect6 */
};

/* Per-policy mode. Zero value is the safe default (never deny). */
enum vesta_mode {
	VESTA_MODE_AUDIT   = 0,
	VESTA_MODE_ENFORCE = 1,
};

enum vesta_failure_policy {
	VESTA_FAILURE_OPEN   = 0,
	VESTA_FAILURE_CLOSED = 1,
};

/* Global kill switch. Zero value = normal operation. */
enum vesta_global_mode {
	VESTA_GLOBAL_NORMAL     = 0,
	VESTA_GLOBAL_AUDIT_ONLY = 1, /* programs never deny */
	VESTA_GLOBAL_DETACHED   = 2, /* guestd detaches all but self-protection; programs emit nothing */
};

/* Rule verdict. Numbering matches vesta.channel.v1.Verdict. 0 = no rule. */
enum vesta_verdict {
	VESTA_VERDICT_NONE  = 0,
	VESTA_VERDICT_ALLOW = 1,
	VESTA_VERDICT_DENY  = 2,
};

/* Numbering matches vesta.channel.v1.RootfsType. */
enum vesta_rootfs_type {
	VESTA_ROOTFS_UNKNOWN       = 0,
	VESTA_ROOTFS_GUEST_OVERLAY = 1,
	VESTA_ROOTFS_VIRTIO_FS     = 2,
	VESTA_ROOTFS_BLOCK         = 3,
};

/* vesta_event_header.flags. Bit positions match vesta.event.v1.EventFlag - 1. */
#define VESTA_EVF_PATH_TRUNCATED   (1U << 0)
#define VESTA_EVF_ARGV_TRUNCATED   (1U << 1)
#define VESTA_EVF_CGROUP_UNBOUND   (1U << 2) /* no cgroup_policy entry */
#define VESTA_EVF_POLICY_PENDING   (1U << 3) /* entry exists but VESTA_CGF_PENDING, or policy_ready == 0 */
#define VESTA_EVF_WOULD_DENY       (1U << 4) /* deny verdict not enforced (audit mode or AUDIT_ONLY) */
#define VESTA_EVF_GLOBAL_AUDIT_ONLY (1U << 5)
#define VESTA_EVF_EXE_UNLINKED     (1U << 6) /* exe has no link left (deleted, memfd, O_TMPFILE) or is a pseudo file */
#define VESTA_EVF_EXE_OUTSIDE_ROOT (1U << 7) /* exe not reachable from the task's root: path is from the global root */

/* vesta_cgroup_policy.flags */
#define VESTA_CGF_PENDING (1U << 0) /* bound, policy not yet applied: failure policy decides */

/* vesta_config.flags */
#define VESTA_CFG_EXEC_ARGV (1U << 0) /* capture argv in exec events */

/* ---- Ring buffer records ---------------------------------------------- */

/*
 * Every record starts with this header. `size` is the full record size
 * (header + payload); consumers MUST check size >= sizeof(header), then
 * size == sizeof(struct for `type`) before reading the payload.
 */
struct vesta_event_header {
	__u16 abi_version;        /* VESTA_ABI_VERSION */
	__u16 type;               /* enum vesta_event_type */
	__u16 size;               /* total record bytes */
	__u8  action;             /* enum vesta_action */
	__u8  hook;               /* enum vesta_hook */
	__u64 ktime_boot_ns;      /* bpf_ktime_get_boot_ns() */
	__u64 cgroup_id;          /* bpf_get_current_cgroup_id() */
	__u64 policy_generation;  /* vesta_cgroup_policy.generation, 0 if unbound */
	__u32 pid;                /* kernel tid */
	__u32 tgid;               /* kernel tgid */
	__u32 ppid;               /* real_parent->tgid */
	__u32 uid;                /* current euid (init user ns) */
	__u32 gid;                /* current egid (init user ns) */
	__u32 policy_id;          /* 0 if unbound */
	__u32 rule_id;            /* matching rule, 0 if none */
	__u32 flags;              /* VESTA_EVF_* */
	char  comm[VESTA_COMM_LEN];
	__u32 ns_tgid;            /* tgid in the task's own pid namespace */
	__u32 _pad0;
};

struct vesta_exec_payload {
	__u32 exe_dev;            /* kernel s_dev encoding: (major << 20) | minor */
	__u32 argc;               /* original argc (not truncated) */
	__u64 exe_ino;
	__u16 path_len;           /* bytes in path, excluding NUL */
	__u16 argv_len;           /* valid bytes in argv */
	__u32 _pad0;
	char  path[VESTA_PATH_MAX];  /* resolved exe path, NUL-terminated */
	char  argv[VESTA_ARGV_MAX];  /* NUL-separated arguments */
};

struct vesta_exec_event {
	struct vesta_event_header hdr;
	struct vesta_exec_payload exec;
};

struct vesta_connect_payload {
	__u16 family;             /* AF_INET (2) or AF_INET6 (10) */
	__u8  protocol;           /* IPPROTO_TCP (6), IPPROTO_UDP (17), ... */
	__u8  verdict;            /* enum vesta_verdict of the matching rule/default */
	__be16 dport;             /* network byte order */
	__u16 _pad0;
	__u8  daddr[16];          /* network byte order; IPv4 uses bytes 0..3, rest zero */
	__u64 sock_cookie;        /* bpf_get_socket_cookie() */
};

struct vesta_connect_event {
	struct vesta_event_header hdr;
	struct vesta_connect_payload connect;
};

/* ---- Map keys / values -------------------------------------------------- */

/* config: ARRAY[1], frozen after guestd writes it at boot. */
struct vesta_config {
	__u32 abi_version;          /* VESTA_ABI_VERSION */
	__u32 flags;                /* VESTA_CFG_* */
	__u64 guestd_cgroup_id;
	__u64 guestd_exe_ino;
	__u32 guestd_exe_dev;       /* s_dev encoding */
	__u32 heartbeat_interval_ms;
};

/* global_mode: ARRAY[1]. */
struct vesta_global_mode_value {
	__u32 mode;                 /* enum vesta_global_mode */
	__u32 _pad0;
};

/* policy_ready: ARRAY[1]. */
struct vesta_policy_ready_value {
	__u64 generation;           /* 0 = no policy applied yet */
};

/* cgroup_policy: HASH, key = __u64 cgroup id. */
struct vesta_cgroup_policy {
	__u64 generation;           /* ApplyPolicy generation this binding refers to */
	__u32 policy_id;
	__u8  mode;                 /* enum vesta_mode */
	__u8  failure;              /* enum vesta_failure_policy */
	__u8  rootfs_type;          /* enum vesta_rootfs_type */
	__u8  flags;                /* VESTA_CGF_* */
	__u8  exec_default;         /* enum vesta_verdict when no exec rule matches */
	__u8  net_default;          /* enum vesta_verdict when no net rule matches */
	__u16 _pad0;
	__u32 _pad1;
};

/* exec_rules: HASH. */
struct vesta_exec_key {
	__u32 policy_id;
	__u32 dev;                  /* s_dev encoding of the file's superblock */
	__u64 ino;
};

/* Value for exec_rules, net_rules_v4 and net_rules_v6. */
struct vesta_rule_value {
	__u32 verdict;              /* enum vesta_verdict */
	__u32 rule_id;              /* echoed in events; assigned by the host */
};

/*
 * net_rules_v4 / net_rules_v6: LPM_TRIE (BPF_F_NO_PREALLOC).
 * prefixlen = VESTA_NET_KEY_FIXED_BITS + CIDR prefix length. Fields before
 * addr are matched exactly. port 0 = any port, protocol 0 = any protocol:
 * lookups try (proto, port), (proto, 0), (0, port), (0, 0) in that order.
 */
struct vesta_net_key_v4 {
	__u32 prefixlen;
	__u32 policy_id;            /* host order; exact-match part, only needs to be consistent */
	__u8  protocol;
	__u8  _pad0;
	__be16 port;
	__u8  addr[4];
};

struct vesta_net_key_v6 {
	__u32 prefixlen;
	__u32 policy_id;            /* host order */
	__u8  protocol;
	__u8  _pad0;
	__be16 port;
	__u8  addr[16];
};

/* drop_counters: PERCPU_ARRAY[VESTA_EVENT_TYPE_MAX], value = __u64 count of failed ringbuf reserves. */

/* ---- Layout pins ---------------------------------------------------------- */

_Static_assert(sizeof(struct vesta_event_header) == 88, "vesta_event_header size");
_Static_assert(offsetof(struct vesta_event_header, ktime_boot_ns) == 8, "hdr.ktime_boot_ns");
_Static_assert(offsetof(struct vesta_event_header, pid) == 32, "hdr.pid");
_Static_assert(offsetof(struct vesta_event_header, comm) == 64, "hdr.comm");
_Static_assert(offsetof(struct vesta_event_header, ns_tgid) == 80, "hdr.ns_tgid");
_Static_assert(sizeof(struct vesta_exec_payload) == 1304, "vesta_exec_payload size");
_Static_assert(offsetof(struct vesta_exec_payload, path) == 24, "exec.path");
_Static_assert(offsetof(struct vesta_exec_payload, argv) == 280, "exec.argv");
_Static_assert(sizeof(struct vesta_exec_event) == 1392, "vesta_exec_event size");
_Static_assert(sizeof(struct vesta_connect_payload) == 32, "vesta_connect_payload size");
_Static_assert(offsetof(struct vesta_connect_payload, daddr) == 8, "connect.daddr");
_Static_assert(offsetof(struct vesta_connect_payload, sock_cookie) == 24, "connect.sock_cookie");
_Static_assert(sizeof(struct vesta_connect_event) == 120, "vesta_connect_event size");
_Static_assert(sizeof(struct vesta_config) == 32, "vesta_config size");
_Static_assert(sizeof(struct vesta_global_mode_value) == 8, "vesta_global_mode_value size");
_Static_assert(sizeof(struct vesta_policy_ready_value) == 8, "vesta_policy_ready_value size");
_Static_assert(sizeof(struct vesta_cgroup_policy) == 24, "vesta_cgroup_policy size");
_Static_assert(offsetof(struct vesta_cgroup_policy, exec_default) == 16, "cgp.exec_default");
_Static_assert(sizeof(struct vesta_exec_key) == 16, "vesta_exec_key size");
_Static_assert(sizeof(struct vesta_rule_value) == 8, "vesta_rule_value size");
_Static_assert(sizeof(struct vesta_net_key_v4) == 16, "vesta_net_key_v4 size");
_Static_assert(offsetof(struct vesta_net_key_v4, addr) == 12, "net4.addr");
_Static_assert(sizeof(struct vesta_net_key_v6) == 28, "vesta_net_key_v6 size");
_Static_assert(offsetof(struct vesta_net_key_v6, addr) == 12, "net6.addr");
_Static_assert(VESTA_NET_KEY_FIXED_BITS == 8 * (offsetof(struct vesta_net_key_v4, addr) - sizeof(__u32)),
	       "fixed LPM bits");

#endif /* VESTA_ABI_H */
