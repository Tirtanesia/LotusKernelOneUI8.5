/*
 *  Security Server implementation for SELinux
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "security.h"
#include "services.h"
#include "policydb.h"

/*
 * Policy capability names array.
 * Đăng ký cgroup_seclabel để cho phép SELinux policy kích hoạt tính năng gán nhãn cgroup.
 */
const char *selinux_policycap_names[__POLICYDB_CAPABILITY_MAX] = {
	"network_peer_controls",
	"open_perms",
	"extended_socket_class",
	"always_check_network",
	"cgroup_seclabel",
	"nnp_nosuid_transition",
	"genfs_seclabel_symlinks"
};

/*
 * Kiểm tra xem policy capability có được enable trong policy hiện tại hay không.
 */
int security_policycap_supported(struct selinux_state *state, unsigned int req_cap)
{
	struct policydb *policydb = &state->ss->policydb;

	if (req_cap >= __POLICYDB_CAPABILITY_MAX)
		return 0;

	return ebitmap_get_bit(&policydb->policycaps, req_cap);
}
