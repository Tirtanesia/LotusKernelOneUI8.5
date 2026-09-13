/*
 *  SELinux LSM module implementation
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/selinux.h>
#include <linux/cgroup.h>
#include <linux/bpf.h>

#include "security.h"
#include "objsec.h"

/*
 * Thiết lập thuộc tính mount/superblock cho hệ thống tập tin
 */
static int selinux_set_mnt_opts(struct super_block *sb,
				struct fs_context *fc,
				unsigned long kern_flags,
				unsigned me_flags)
{
	struct superblock_security_struct *sbsec = sb->s_security;
	struct selinux_state *state = &selinux_state;
	int rc = 0;

	if (!sbsec)
		return -EINVAL;

	/*
	 * Xử lý gán nhãn đặc thù cho cgroup2 và bpf (BPFFS)
	 */
	if (strcmp(sb->s_type->name, "cgroup2") == 0) {
		/* 
		 * Nếu policy hỗ trợ capability cgroup_seclabel, sử dụng SECURITY_FS_USE_CGROUP2 
		 * Để gán nhãn linh hoạt cho từng cgroup node.
		 */
		if (security_policycap_supported(state, POLICYDB_CAPABILITY_CGROUP_SECLABEL))
			sbsec->behavior = SECURITY_FS_USE_CGROUP2;
		else
			sbsec->behavior = SECURITY_FS_USE_GENFS;
	} else if (strcmp(sb->s_type->name, "bpf") == 0) {
		/* BPFFS quy định gán nhãn thông qua quy tắc genfscon trong SELinux policy */
		sbsec->behavior = SECURITY_FS_USE_GENFS;
	}

	return rc;
}

/*
 * Khởi tạo thông tin an ninh (SID/Label) cho Inode mới tạo trong cgroup2 hoặc bpf
 */
static int selinux_inode_init_security(struct inode *inode, struct inode *dir,
				       const struct qstr *qstr,
				       const char **name, void **value,
				       size_t *len)
{
	struct superblock_security_struct *sbsec = inode->i_sb->s_security;
	struct inode_security_struct *isec = selinux_inode(inode);
	struct selinux_state *state = &selinux_state;
	u32 sid = SECINITSID_UNLABELED;
	int rc = 0;

	if (!sbsec)
		return -EOPNOTSUPP;

	/* 
	 * Xử lý gán nhãn cho Inode thuộc cgroup2 hoặc bpf theo behavior đã thiết lập 
	 */
	if (sbsec->behavior == SECURITY_FS_USE_GENFS || sbsec->behavior == SECURITY_FS_USE_CGROUP2) {
		/* Lấy SID dựa trên cấu hình genfs hoặc quy tắc transition */
		rc = security_genfs_sid(state, inode->i_sb->s_type->name,
					"/", inode->i_sb->s_magic, &sid);
		if (rc) {
			/* Fallback về SID mặc định của Superblock nếu không tìm thấy genfscon phù hợp */
			sid = sbsec->sid;
		}

		isec->sid = sid;
		isec->initialized = LABEL_INITIALIZED;
	}

	return 0;
}
