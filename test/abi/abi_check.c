// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* Compile-only check: the ABI header builds for both userspace and BPF targets
 * with no implicit padding (-Wpadded -Werror). */
#include "vesta_abi.h"

struct vesta_abi_all {
	struct vesta_exec_event exec;
	struct vesta_connect_event connect;
	struct vesta_config config;
	struct vesta_global_mode_value global_mode;
	struct vesta_policy_ready_value policy_ready;
	struct vesta_cgroup_policy cgroup_policy;
	struct vesta_exec_key exec_key;
	struct vesta_rule_value rule;
	struct vesta_net_key_v4 net4;
	struct vesta_net_key_v6 net6;
	__u32 _pad_tail;
};

struct vesta_abi_all vesta_abi_instance;
