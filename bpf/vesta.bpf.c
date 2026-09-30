// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * vesta MVP programs (ARCHITECTURE §2.4, docs/abi.md "Decision logic"):
 *   P1 tp_btf/sched_process_exec   exec audit
 *   P2 lsm/bprm_check_security     exec allow/deny
 *   N1 cgroup/connect4, connect6   egress connect allow/deny
 *
 * Enforcement never depends on event delivery: a failed ringbuf reserve
 * only bumps drop_counters[type].
 */
/* 6.18's BTF has `typedef struct config_s config`, which clashes with the ABI map name. */
#define config vmlinux_config
#include "vmlinux.h"
#undef config
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "vesta_abi.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EPERM 1
#define AF_INET 2
#define AF_INET6 10

/* Deepest cgroup level searched for a bound ancestor (root is level 0). */
#define MAX_CGROUP_LEVEL 16
/* Path components walked for the exe path (mount crossings count too). */
#define MAX_PATH_COMPONENTS 32
#define NAME_MAX_BYTES 255
/* Path scratch: built right-to-left ending at SCRATCH_HALF, masked for the verifier. */
#define SCRATCH_HALF 512
#define SCRATCH_SIZE (2 * SCRATCH_HALF)

/* Set by vesta-guestd before load. */
const volatile __u32 vesta_abi_version = VESTA_ABI_VERSION;
/* Emit P1 exec events for cgroups with no cgroup_policy entry (CGROUP_UNBOUND). */
const volatile bool audit_unbound_exec = false;

/* ---- ABI maps (docs/abi.md). Policy maps are read-only for programs. ---- */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct vesta_config);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct vesta_global_mode_value);
} global_mode SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct vesta_policy_ready_value);
} policy_ready SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VESTA_MAX_CGROUPS);
	__uint(map_flags, BPF_F_RDONLY_PROG | BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, struct vesta_cgroup_policy);
} cgroup_policy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VESTA_MAX_EXEC_RULES);
	__uint(map_flags, BPF_F_RDONLY_PROG | BPF_F_NO_PREALLOC);
	__type(key, struct vesta_exec_key);
	__type(value, struct vesta_rule_value);
} exec_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, VESTA_MAX_NET_RULES);
	__uint(map_flags, BPF_F_RDONLY_PROG | BPF_F_NO_PREALLOC);
	__type(key, struct vesta_net_key_v4);
	__type(value, struct vesta_rule_value);
} net_rules_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, VESTA_MAX_NET_RULES);
	__uint(map_flags, BPF_F_RDONLY_PROG | BPF_F_NO_PREALLOC);
	__type(key, struct vesta_net_key_v6);
	__type(value, struct vesta_rule_value);
} net_rules_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, VESTA_RINGBUF_DEFAULT_BYTES);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, VESTA_EVENT_TYPE_MAX);
	__type(key, __u32);
	__type(value, __u64);
} drop_counters SEC(".maps");

/* ---- Internal (not part of the ABI, not pinned). ---- */

struct scratch {
	char buf[SCRATCH_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch);
} path_scratch SEC(".maps");

/* ---- Helpers ---- */

static __always_inline __u32 get_global_mode(void)
{
	__u32 zero = 0;
	struct vesta_global_mode_value *gm = bpf_map_lookup_elem(&global_mode, &zero);

	return gm ? gm->mode : VESTA_GLOBAL_NORMAL;
}

static __always_inline __u64 get_policy_ready(void)
{
	__u32 zero = 0;
	struct vesta_policy_ready_value *pr = bpf_map_lookup_elem(&policy_ready, &zero);

	return pr ? pr->generation : 0;
}

static __always_inline __u32 get_config_flags(void)
{
	__u32 zero = 0;
	struct vesta_config *cfg = bpf_map_lookup_elem(&config, &zero);

	return cfg ? cfg->flags : 0;
}

static __always_inline void count_drop(__u32 type)
{
	__u64 *cnt = bpf_map_lookup_elem(&drop_counters, &type);

	if (cnt)
		*cnt += 1;
}

/*
 * Finds the policy for the current task: its own cgroup, else the nearest
 * bound ancestor. Tasks in a child of a container cgroup (kata-agent's
 * "init" sub-cgroup, or a cgroup the workload created) keep the container's
 * policy. *cgid is set to the bound cgroup's id (the current one if unbound).
 */
static __always_inline struct vesta_cgroup_policy *lookup_binding(__u64 *cgid)
{
	__u64 id = bpf_get_current_cgroup_id();
	struct vesta_cgroup_policy *cgp;

	*cgid = id;
	cgp = bpf_map_lookup_elem(&cgroup_policy, &id);
	if (cgp)
		return cgp;

	for (int level = MAX_CGROUP_LEVEL - 1; level > 0; level--) {
		__u64 anc = bpf_get_current_ancestor_cgroup_id(level);

		if (!anc || anc == id)
			continue;
		cgp = bpf_map_lookup_elem(&cgroup_policy, &anc);
		if (cgp) {
			*cgid = anc;
			return cgp;
		}
	}
	return NULL;
}

struct decision {
	__u32 rule_id;
	__u32 flags;
	__u8 verdict;
	__u8 action;
	bool deny;
};

/*
 * docs/abi.md steps 3-5. A deny is enforced only for ENFORCE policies while
 * global_mode is NORMAL; otherwise it is audited with WOULD_DENY.
 */
static __always_inline void decide(struct decision *d, const struct vesta_cgroup_policy *cgp,
				   __u32 gmode, bool pending, const struct vesta_rule_value *rule,
				   __u8 default_verdict)
{
	if (pending) {
		d->flags |= VESTA_EVF_POLICY_PENDING;
		d->verdict = cgp->failure == VESTA_FAILURE_CLOSED ? VESTA_VERDICT_DENY : VESTA_VERDICT_NONE;
	} else if (rule) {
		d->verdict = rule->verdict;
		d->rule_id = rule->rule_id;
	} else {
		d->verdict = default_verdict;
	}

	if (d->verdict == VESTA_VERDICT_DENY) {
		if (cgp->mode == VESTA_MODE_ENFORCE && gmode == VESTA_GLOBAL_NORMAL) {
			d->deny = true;
			d->action = VESTA_ACTION_DENIED;
		} else {
			d->action = VESTA_ACTION_AUDITED;
			d->flags |= VESTA_EVF_WOULD_DENY;
			if (cgp->mode == VESTA_MODE_ENFORCE && gmode == VESTA_GLOBAL_AUDIT_ONLY)
				d->flags |= VESTA_EVF_GLOBAL_AUDIT_ONLY;
		}
	} else {
		d->action = cgp->mode == VESTA_MODE_ENFORCE ? VESTA_ACTION_ALLOWED : VESTA_ACTION_AUDITED;
	}
}

static __always_inline bool is_pending(const struct vesta_cgroup_policy *cgp)
{
	return (cgp->flags & VESTA_CGF_PENDING) || get_policy_ready() == 0;
}

/* tgid as seen from the task's own pid namespace. */
static __always_inline __u32 task_ns_tgid(struct task_struct *task)
{
	struct pid *pid = BPF_CORE_READ(task, group_leader, thread_pid);
	unsigned int level = BPF_CORE_READ(pid, level);
	int nr = 0;

	if (level >= 32) /* MAX_PID_NS_LEVEL */
		return 0;
	bpf_core_read(&nr, sizeof(nr), &pid->numbers[level].nr);
	return nr;
}

static __always_inline void fill_header(struct vesta_event_header *h, __u16 type, __u16 size,
					__u8 hook, __u64 cgid, const struct vesta_cgroup_policy *cgp,
					const struct decision *d)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	h->abi_version = VESTA_ABI_VERSION;
	h->type = type;
	h->size = size;
	h->action = d->action;
	h->hook = hook;
	h->ktime_boot_ns = bpf_ktime_get_boot_ns();
	h->cgroup_id = cgid;
	h->pid = (__u32)pid_tgid;
	h->tgid = pid_tgid >> 32;
	h->ppid = BPF_CORE_READ(task, real_parent, tgid);
	h->uid = BPF_CORE_READ(task, cred, euid.val);
	h->gid = BPF_CORE_READ(task, cred, egid.val);
	h->rule_id = d->rule_id;
	h->flags = d->flags;
	h->ns_tgid = task_ns_tgid(task);
	bpf_get_current_comm(h->comm, sizeof(h->comm));
	if (cgp) {
		h->policy_generation = cgp->generation;
		h->policy_id = cgp->policy_id;
	} else {
		h->flags |= VESTA_EVF_CGROUP_UNBOUND;
	}
}

/*
 * Writes the path of `file` relative to the current task's root into
 * ev->path, the way d_path() would for a reachable file. bpf_d_path() is not
 * available to tp_btf programs, so this walks dentries and mounts, bounded
 * by MAX_PATH_COMPONENTS. On overflow the deepest components are kept and
 * PATH_TRUNCATED is set. Where d_path() would mark the path, flags say so
 * instead: EXE_UNLINKED for a file with no link left (d_path's " (deleted)")
 * or a pseudo file, EXE_OUTSIDE_ROOT when the walk ends at the global root
 * without meeting the task's root.
 */
static __always_inline void read_exe_path(struct file *file, struct vesta_exec_payload *ev,
					  __u32 *flags)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 zero = 0;
	struct scratch *s = bpf_map_lookup_elem(&path_scratch, &zero);
	struct dentry *root_dentry, *dentry;
	struct vfsmount *root_mnt, *vfsmnt;
	struct mount *mnt;
	int off = SCRATCH_HALF;
	int len;

	if (!s)
		return;

	root_dentry = BPF_CORE_READ(task, fs, root.dentry);
	root_mnt = BPF_CORE_READ(task, fs, root.mnt);
	dentry = BPF_CORE_READ(file, f_path.dentry);
	vfsmnt = BPF_CORE_READ(file, f_path.mnt);
	mnt = (void *)vfsmnt - bpf_core_field_offset(struct mount, mnt);

	/* d_unlinked(): unhashed and not its own parent; or no links left. */
	if (BPF_CORE_READ(dentry, d_inode, i_nlink) == 0 ||
	    (!BPF_CORE_READ(dentry, d_hash.pprev) && BPF_CORE_READ(dentry, d_parent) != dentry))
		*flags |= VESTA_EVF_EXE_UNLINKED;

	for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
		struct dentry *mnt_root, *parent;
		struct qstr name;
		bool last = false;
		__u32 nlen;

		if (dentry == root_dentry && vfsmnt == root_mnt)
			break;
		mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
		parent = BPF_CORE_READ(dentry, d_parent);
		if (dentry == mnt_root) {
			struct mount *mnt_parent = BPF_CORE_READ(mnt, mnt_parent);

			if (mnt == mnt_parent) {
				/* Global root or a detached mount, not the task's root. */
				*flags |= VESTA_EVF_EXE_OUTSIDE_ROOT;
				break;
			}
			dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
			mnt = mnt_parent;
			vfsmnt = (void *)mnt + bpf_core_field_offset(struct mount, mnt);
			continue;
		}
		/* Pseudo files (memfd, anon inodes) are their own parent: emit the name and stop. */
		if (dentry == parent) {
			last = true;
			*flags |= VESTA_EVF_EXE_UNLINKED;
		}

		name = BPF_CORE_READ(dentry, d_name);
		nlen = name.len;
		if (nlen > NAME_MAX_BYTES)
			nlen = NAME_MAX_BYTES;
		if (off - (int)nlen - 1 < SCRATCH_HALF - (VESTA_PATH_MAX - 1)) {
			*flags |= VESTA_EVF_PATH_TRUNCATED;
			break;
		}
		off -= nlen;
		bpf_probe_read_kernel(&s->buf[off & (SCRATCH_HALF - 1)], nlen & NAME_MAX_BYTES, name.name);
		off -= 1;
		s->buf[off & (SCRATCH_HALF - 1)] = '/';
		if (last)
			break;
		dentry = parent;
	}

	if (off == SCRATCH_HALF) {
		off -= 1;
		s->buf[off & (SCRATCH_HALF - 1)] = '/';
	}
	len = SCRATCH_HALF - off;
	if (len > VESTA_PATH_MAX - 1)
		len = VESTA_PATH_MAX - 1;
	len &= VESTA_PATH_MAX - 1;
	if (bpf_probe_read_kernel(ev->path, len, &s->buf[off & (SCRATCH_HALF - 1)]))
		len = 0;
	ev->path[len] = 0;
	ev->path_len = len;
}

/* argv of the new image from mm->arg_start..arg_end (valid right after exec). */
static __always_inline void read_argv(struct vesta_exec_payload *ev, __u32 *flags)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	unsigned long start, end;
	__u64 len;

	if (!mm)
		return;
	start = BPF_CORE_READ(mm, arg_start);
	end = BPF_CORE_READ(mm, arg_end);
	if (end <= start)
		return;
	len = end - start;
	if (len > VESTA_ARGV_MAX) {
		len = VESTA_ARGV_MAX;
		*flags |= VESTA_EVF_ARGV_TRUNCATED;
	}
	if (bpf_probe_read_user(ev->argv, len, (const void *)start) == 0)
		ev->argv_len = len;
}

static __always_inline void read_exe_id(struct file *file, struct vesta_exec_key *key)
{
	struct inode *inode = BPF_CORE_READ(file, f_inode);

	key->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	key->ino = BPF_CORE_READ(inode, i_ino);
}

static __always_inline void emit_exec(struct linux_binprm *bprm, struct file *file,
				      const struct vesta_exec_key *id, __u8 hook, __u64 cgid,
				      const struct vesta_cgroup_policy *cgp, struct decision *d,
				      bool with_argv)
{
	struct vesta_exec_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);

	if (!ev) {
		count_drop(VESTA_EVENT_EXEC);
		return;
	}
	/*
	 * Ringbuf memory is not zeroed and 1392 bytes is too large to memset
	 * inline. Zero the header and scalars; readers bound path/argv by
	 * path_len/argv_len (docs/abi.md).
	 */
	__builtin_memset(&ev->hdr, 0, sizeof(ev->hdr));
	ev->exec._pad0 = 0;
	ev->exec.path_len = 0;
	ev->exec.argv_len = 0;
	ev->exec.path[0] = 0;
	ev->exec.argv[0] = 0;
	ev->exec.exe_dev = id->dev;
	ev->exec.exe_ino = id->ino;
	ev->exec.argc = BPF_CORE_READ(bprm, argc);
	read_exe_path(file, &ev->exec, &d->flags);
	if (with_argv)
		read_argv(&ev->exec, &d->flags);
	fill_header(&ev->hdr, VESTA_EVENT_EXEC, sizeof(*ev), hook, cgid, cgp, d);
	bpf_ringbuf_submit(ev, 0);
}

/* ---- P1: exec audit ---- */

SEC("tp_btf/sched_process_exec")
int BPF_PROG(vesta_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct decision d = { .action = VESTA_ACTION_AUDITED };
	struct vesta_cgroup_policy *cgp;
	struct vesta_exec_key id = {};
	struct file *file;
	__u64 cgid;

	if (get_global_mode() == VESTA_GLOBAL_DETACHED)
		return 0;
	cgp = lookup_binding(&cgid);
	if (!cgp && !audit_unbound_exec)
		return 0;

	file = BPF_CORE_READ(bprm, file);
	read_exe_id(file, &id);
	if (cgp) {
		if (is_pending(cgp)) {
			d.flags |= VESTA_EVF_POLICY_PENDING;
		} else {
			struct vesta_rule_value *rule;

			id.policy_id = cgp->policy_id;
			rule = bpf_map_lookup_elem(&exec_rules, &id);
			if (rule)
				d.rule_id = rule->rule_id;
		}
	}
	/* P1 only records that the exec happened; decisions are P2's events. */
	emit_exec(bprm, file, &id, VESTA_HOOK_SCHED_PROCESS_EXEC, cgid, cgp, &d,
		  get_config_flags() & VESTA_CFG_EXEC_ARGV);
	return 0;
}

/* ---- P2: exec allow/deny ---- */

SEC("lsm/bprm_check_security")
int BPF_PROG(vesta_bprm_check, struct linux_binprm *bprm, int ret)
{
	struct decision d = {};
	struct vesta_cgroup_policy *cgp;
	struct vesta_rule_value *rule = NULL;
	struct vesta_exec_key id = {};
	struct file *file;
	bool pending;
	__u32 gmode;
	__u64 cgid;

	if (ret)
		return ret;
	gmode = get_global_mode();
	if (gmode == VESTA_GLOBAL_DETACHED)
		return 0;
	cgp = lookup_binding(&cgid);
	if (!cgp)
		return 0;

	file = BPF_CORE_READ(bprm, file);
	read_exe_id(file, &id);
	pending = is_pending(cgp);
	if (!pending) {
		id.policy_id = cgp->policy_id;
		rule = bpf_map_lookup_elem(&exec_rules, &id);
	}
	decide(&d, cgp, gmode, pending, rule, cgp->exec_default);
	if (d.verdict != VESTA_VERDICT_DENY)
		return 0;

	/* argv of the new image is not in the current mm yet. */
	emit_exec(bprm, file, &id, VESTA_HOOK_BPRM_CHECK_SECURITY, cgid, cgp, &d, false);
	return d.deny ? -EPERM : 0;
}

/* ---- N1: egress connect ---- */

static __always_inline struct vesta_rule_value *lookup_net4(__u32 policy_id, __u8 proto,
							    __be16 port, __u32 addr)
{
	struct vesta_net_key_v4 key = {
		.prefixlen = VESTA_NET_KEY_FIXED_BITS + 32,
		.policy_id = policy_id,
	};
	struct vesta_rule_value *v;

	__builtin_memcpy(key.addr, &addr, sizeof(key.addr));
	/* (proto, port), (proto, any), (any, port), (any, any) */
	for (int i = 0; i < 4; i++) {
		key.protocol = i < 2 ? proto : 0;
		key.port = (i & 1) ? 0 : port;
		v = bpf_map_lookup_elem(&net_rules_v4, &key);
		if (v)
			return v;
	}
	return NULL;
}

static __always_inline struct vesta_rule_value *lookup_net6(__u32 policy_id, __u8 proto,
							    __be16 port, const __u32 addr[4])
{
	struct vesta_net_key_v6 key = {
		.prefixlen = VESTA_NET_KEY_FIXED_BITS + 128,
		.policy_id = policy_id,
	};
	struct vesta_rule_value *v;

	__builtin_memcpy(key.addr, addr, sizeof(key.addr));
	for (int i = 0; i < 4; i++) {
		key.protocol = i < 2 ? proto : 0;
		key.port = (i & 1) ? 0 : port;
		v = bpf_map_lookup_elem(&net_rules_v6, &key);
		if (v)
			return v;
	}
	return NULL;
}

static __always_inline int handle_connect(struct bpf_sock_addr *ctx, bool v6)
{
	struct decision d = {};
	struct vesta_cgroup_policy *cgp;
	struct vesta_rule_value *rule = NULL;
	struct vesta_connect_event *ev;
	__u32 addr[4] = {};
	__u8 proto;
	__be16 port;
	bool pending, mapped4 = false;
	__u32 gmode;
	__u64 cgid;

	gmode = get_global_mode();
	if (gmode == VESTA_GLOBAL_DETACHED)
		return 1;
	cgp = lookup_binding(&cgid);
	if (!cgp)
		return 1;

	proto = ctx->protocol;
	port = (__be16)ctx->user_port;
	if (v6) {
		addr[0] = ctx->user_ip6[0];
		addr[1] = ctx->user_ip6[1];
		addr[2] = ctx->user_ip6[2];
		addr[3] = ctx->user_ip6[3];
		/* ::ffff:a.b.c.d is IPv4 on a dual-stack socket: IPv4 rules apply. */
		mapped4 = addr[0] == 0 && addr[1] == 0 && addr[2] == bpf_htonl(0x0000ffff);
	} else {
		addr[0] = ctx->user_ip4;
	}

	pending = is_pending(cgp);
	if (!pending) {
		if (!v6)
			rule = lookup_net4(cgp->policy_id, proto, port, addr[0]);
		else if (mapped4)
			rule = lookup_net4(cgp->policy_id, proto, port, addr[3]);
		else
			rule = lookup_net6(cgp->policy_id, proto, port, addr);
	}
	decide(&d, cgp, gmode, pending, rule, cgp->net_default);

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (ev) {
		__builtin_memset(ev, 0, sizeof(*ev));
		ev->connect.family = v6 ? AF_INET6 : AF_INET;
		ev->connect.protocol = proto;
		ev->connect.verdict = d.verdict;
		ev->connect.dport = port;
		__builtin_memcpy(ev->connect.daddr, addr, sizeof(ev->connect.daddr));
		ev->connect.sock_cookie = bpf_get_socket_cookie(ctx);
		fill_header(&ev->hdr, VESTA_EVENT_CONNECT, sizeof(*ev),
			    v6 ? VESTA_HOOK_CGROUP_CONNECT6 : VESTA_HOOK_CGROUP_CONNECT4, cgid, cgp, &d);
		bpf_ringbuf_submit(ev, 0);
	} else {
		count_drop(VESTA_EVENT_CONNECT);
	}
	return d.deny ? 0 : 1;
}

SEC("cgroup/connect4")
int vesta_connect4(struct bpf_sock_addr *ctx)
{
	return handle_connect(ctx, false);
}

SEC("cgroup/connect6")
int vesta_connect6(struct bpf_sock_addr *ctx)
{
	return handle_connect(ctx, true);
}
