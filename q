---
 security/apparmor/.gitignore              |    1 +
 security/apparmor/Kconfig                 |   59 +-
 security/apparmor/Makefile                |   44 +-
 security/apparmor/af_unix.c               |  643 +++++++
 security/apparmor/apparmorfs.c            | 1200 ++++++++++--
 security/apparmor/audit.c                 |  120 +-
 security/apparmor/capability.c            |   56 +-
 security/apparmor/context.c               |  152 +-
 security/apparmor/crypto.c                |   37 +
 security/apparmor/domain.c                | 1416 +++++++++-----
 security/apparmor/file.c                  |  574 ++++--
 security/apparmor/include/af_unix.h       |  114 ++
 security/apparmor/include/apparmor.h      |   91 +-
 security/apparmor/include/apparmorfs.h    |   24 +-
 security/apparmor/include/audit.h         |  180 +-
 security/apparmor/include/capability.h    |    6 +-
 security/apparmor/include/context.h       |  216 ++-
 security/apparmor/include/crypto.h        |    5 +
 security/apparmor/include/domain.h        |    9 +-
 security/apparmor/include/file.h          |  120 +-
 security/apparmor/include/ipc.h           |   22 +-
 security/apparmor/include/label.h         |  502 +++++
 security/apparmor/include/lib.h           |  318 +++
 security/apparmor/include/match.h         |   20 +
 security/apparmor/include/mount.h         |   54 +
 security/apparmor/include/net.h           |  124 ++
 security/apparmor/include/path.h          |   63 +-
 security/apparmor/include/perms.h         |  173 ++
 security/apparmor/include/policy.h        |  291 +--
 security/apparmor/include/policy_ns.h     |  153 ++
 security/apparmor/include/policy_unpack.h |   28 +-
 security/apparmor/include/procattr.h      |    3 +-
 security/apparmor/include/resource.h      |    4 +-
 security/apparmor/include/sig_names.h     |   95 +
 security/apparmor/ipc.c                   |  234 ++-
 security/apparmor/label.c                 | 2142 +++++++++++++++++++++
 security/apparmor/lib.c                   |  473 ++++-
 security/apparmor/lsm.c                   | 1093 +++++++++--
 security/apparmor/match.c                 |   29 +-
 security/apparmor/mount.c                 |  705 +++++++
 security/apparmor/net.c                   |  357 ++++
 security/apparmor/nulldfa.in              |    1 +
 security/apparmor/path.c                  |  132 +-
 security/apparmor/policy.c                | 1000 ++++------
 security/apparmor/policy_ns.c             |  354 ++++
 security/apparmor/policy_unpack.c         |  323 +++-
 security/apparmor/procattr.c              |   94 +-
 security/apparmor/resource.c              |  114 +-
 48 files changed, 11377 insertions(+), 2591 deletions(-)
 create mode 100644 security/apparmor/af_unix.c
 create mode 100644 security/apparmor/include/af_unix.h
 create mode 100644 security/apparmor/include/label.h
 create mode 100644 security/apparmor/include/lib.h
 create mode 100644 security/apparmor/include/mount.h
 create mode 100644 security/apparmor/include/net.h
 create mode 100644 security/apparmor/include/perms.h
 create mode 100644 security/apparmor/include/policy_ns.h
 create mode 100644 security/apparmor/include/sig_names.h
 create mode 100644 security/apparmor/label.c
 create mode 100644 security/apparmor/mount.c
 create mode 100644 security/apparmor/net.c
 create mode 100644 security/apparmor/nulldfa.in
 create mode 100644 security/apparmor/policy_ns.c

diff --git a/security/apparmor/.gitignore b/security/apparmor/.gitignore
index 9cdec70d72b8..d5b291e94264 100644
--- a/security/apparmor/.gitignore
+++ b/security/apparmor/.gitignore
@@ -1,5 +1,6 @@
 #
 # Generated include files
 #
+net_names.h
 capability_names.h
 rlim_names.h
diff --git a/security/apparmor/Kconfig b/security/apparmor/Kconfig
index be5e9414a295..ae38e60a5ac7 100644
--- a/security/apparmor/Kconfig
+++ b/security/apparmor/Kconfig
@@ -30,6 +30,41 @@ config SECURITY_APPARMOR_BOOTPARAM_VALUE
 
 	  If you are unsure how to answer this question, answer 1.
 
+config SECURITY_APPARMOR_STATS
+	bool "enable debug statistics"
+	depends on SECURITY_APPARMOR
+	select APPARMOR_LABEL_STATS
+	default n
+	help
+	  This enables keeping statistics on various internal structures
+	  and functions in apparmor.
+
+	  If you are unsure how to answer this question, answer N.
+
+config SECURITY_APPARMOR_UNCONFINED_INIT
+	bool "Set init to unconfined on boot"
+	depends on SECURITY_APPARMOR
+	default y
+	help
+	  This option determines policy behavior during early boot by
+	  placing the init process in the unconfined state, or the
+	  'default' profile.
+
+	  This option determines policy behavior during early boot by
+	  placing the init process in the unconfined state, or the
+	  'default' profile.
+
+	  'Y' means init and its children are not confined, unless the
+	  init process is re-execed after a policy load; loaded policy
+	  will only apply to processes started after the load.
+
+	  'N' means init and its children are confined in a profile
+	  named 'default', which can be replaced later and thus
+	  provide for confinement for processes started early at boot,
+	  though not confined during early boot.
+
+	  If you are unsure how to answer this question, answer Y.
+
 config SECURITY_APPARMOR_HASH
 	bool "Enable introspection of sha1 hashes for loaded profiles"
 	depends on SECURITY_APPARMOR
@@ -42,15 +77,15 @@ config SECURITY_APPARMOR_HASH
 	  is available to userspace via the apparmor filesystem.
 
 config SECURITY_APPARMOR_HASH_DEFAULT
-       bool "Enable policy hash introspection by default"
-       depends on SECURITY_APPARMOR_HASH
-       default y
-
-       help
-         This option selects whether sha1 hashing of loaded policy
-	 is enabled by default. The generation of sha1 hashes for
-	 loaded policy provide system administrators a quick way
-	 to verify that policy in the kernel matches what is expected,
-	 however it can slow down policy load on some devices. In
-	 these cases policy hashing can be disabled by default and
-	 enabled only if needed.
+	bool "Enable policy hash introspection by default"
+	depends on SECURITY_APPARMOR_HASH
+	default y
+
+	help
+	  This option selects whether sha1 hashing of loaded policy
+	  is enabled by default. The generation of sha1 hashes for
+	  loaded policy provide system administrators a quick way
+	  to verify that policy in the kernel matches what is expected,
+	  however it can slow down policy load on some devices. In
+	  these cases policy hashing can be disabled by default and
+	  enabled only if needed.
diff --git a/security/apparmor/Makefile b/security/apparmor/Makefile
index d693df874818..3a2d39530137 100644
--- a/security/apparmor/Makefile
+++ b/security/apparmor/Makefile
@@ -4,11 +4,45 @@ obj-$(CONFIG_SECURITY_APPARMOR) += apparmor.o
 
 apparmor-y := apparmorfs.o audit.o capability.o context.o ipc.o lib.o match.o \
               path.o domain.o policy.o policy_unpack.o procattr.o lsm.o \
-              resource.o sid.o file.o
+              resource.o sid.o file.o label.o mount.o net.o af_unix.o \
+              policy_ns.o
 apparmor-$(CONFIG_SECURITY_APPARMOR_HASH) += crypto.o
 
-clean-files := capability_names.h rlim_names.h
+clean-files := capability_names.h rlim_names.h net_names.h
 
+# Build a lower case string table of address family names
+# Transform lines from
+#    define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
+#    #define AF_INET		2	/* Internet IP Protocol 	*/
+# to
+#    [1] = "local",
+#    [2] = "inet",
+#
+# and build the securityfs entries for the mapping.
+# Transforms lines from
+#    #define AF_INET		2	/* Internet IP Protocol 	*/
+# to
+#    #define AA_FS_AF_MASK "local inet"
+quiet_cmd_make-af = GEN     $@
+cmd_make-af = echo "static const char *address_family_names[] = {" > $@ ;\
+	sed $< >>$@ -r -n -e "/AF_MAX/d" -e "/AF_LOCAL/d" -e "/AF_ROUTE/d" -e \
+	 's/^\#define[ \t]+AF_([A-Z0-9_]+)[ \t]+([0-9]+)(.*)/[\2] = "\L\1",/p';\
+	echo "};" >> $@ ;\
+	echo -n '\#define AA_FS_AF_MASK "' >> $@ ;\
+	sed -r -n -e "/AF_MAX/d" -e "/AF_LOCAL/d" -e "/AF_ROUTE/d" -e \
+	 's/^\#define[ \t]+AF_([A-Z0-9_]+)[ \t]+([0-9]+)(.*)/\L\1/p'\
+	 $< | tr '\n' ' ' | sed -e 's/ $$/"\n/' >> $@
+
+# Build a lower case string table of sock type names
+# Transform lines from
+#    SOCK_STREAM	= 1,
+# to
+#    [1] = "stream",
+quiet_cmd_make-sock = GEN     $@
+cmd_make-sock = echo "static const char *sock_type_names[] = {" >> $@ ;\
+	sed $^ >>$@ -r -n \
+	-e 's/^\tSOCK_([A-Z0-9_]+)[\t]+=[ \t]+([0-9]+)(.*)/[\2] = "\L\1",/p';\
+	echo "};" >> $@
 
 # Build a lower case string table of capability names
 # Transforms lines from
@@ -61,6 +95,7 @@ cmd_make-rlim = echo "static const char *const rlim_names[RLIM_NLIMITS] = {" \
 	    tr '\n' ' ' | sed -e 's/ $$/"\n/' >> $@
 
 $(obj)/capability.o : $(obj)/capability_names.h
+$(obj)/net.o : $(obj)/net_names.h
 $(obj)/resource.o : $(obj)/rlim_names.h
 $(obj)/capability_names.h : $(srctree)/include/uapi/linux/capability.h \
 			    $(src)/Makefile
@@ -68,3 +103,8 @@ $(obj)/capability_names.h : $(srctree)/include/uapi/linux/capability.h \
 $(obj)/rlim_names.h : $(srctree)/include/uapi/asm-generic/resource.h \
 		      $(src)/Makefile
 	$(call cmd,make-rlim)
+$(obj)/net_names.h : $(srctree)/include/linux/socket.h \
+		     $(srctree)/include/linux/net.h \
+		     $(src)/Makefile
+	$(call cmd,make-af)
+	$(call cmd,make-sock)
diff --git a/security/apparmor/af_unix.c b/security/apparmor/af_unix.c
new file mode 100644
index 000000000000..757df1ade9a0
--- /dev/null
+++ b/security/apparmor/af_unix.c
@@ -0,0 +1,643 @@
+/*
+ * AppArmor security module
+ *
+ * This file contains AppArmor af_unix fine grained mediation
+ *
+ * Copyright 2014 Canonical Ltd.
+ *
+ * This program is free software; you can redistribute it and/or
+ * modify it under the terms of the GNU General Public License as
+ * published by the Free Software Foundation, version 2 of the
+ * License.
+ */
+
+#include <net/tcp_states.h>
+
+#include "include/af_unix.h"
+#include "include/apparmor.h"
+#include "include/context.h"
+#include "include/file.h"
+#include "include/label.h"
+#include "include/path.h"
+#include "include/policy.h"
+
+static inline struct sock *aa_sock(struct unix_sock *u)
+{
+	return &u->sk;
+}
+
+static inline int unix_fs_perm(const char *op, u32 mask, struct aa_label *label,
+			       struct unix_sock *u, int flags)
+{
+	AA_BUG(!label);
+	AA_BUG(!u);
+	AA_BUG(!UNIX_FS(aa_sock(u)));
+
+	if (unconfined(label) || !LABEL_MEDIATES(label, AA_CLASS_FILE))
+		return 0;
+
+	mask &= NET_FS_PERMS;
+	if (!u->path.dentry) {
+		struct path_cond cond = { };
+		struct aa_perms perms = { };
+		struct aa_profile *profile;
+
+		/* socket path has been cleared because it is being shutdown
+		 * can only fall back to original sun_path request
+		 */
+		struct aa_sk_ctx *ctx = SK_CTX(&u->sk);
+		if (ctx->path.dentry)
+			return aa_path_perm(op, label, &ctx->path, flags, mask,
+					    &cond);
+		return fn_for_each_confined(label, profile,
+			((flags | profile->path_flags) & PATH_MEDIATE_DELETED) ?
+				__aa_path_perm(op, profile,
+					       u->addr->name->sun_path, mask,
+					       &cond, flags, &perms) :
+				aa_audit_file(profile, &nullperms, op, mask,
+					      u->addr->name->sun_path, NULL,
+					      NULL, cond.uid,
+					      "Failed name lookup - "
+					      "deleted entry", -EACCES));
+	} else {
+		/* the sunpath may not be valid for this ns so use the path */
+		struct path_cond cond = { u->path.dentry->d_inode->i_uid,
+					  u->path.dentry->d_inode->i_mode
+		};
+
+		return aa_path_perm(op, label, &u->path, flags, mask, &cond);
+	}
+
+	return 0;
+}
+
+/* passing in state returned by PROFILE_MEDIATES_AF */
+static unsigned int match_to_prot(struct aa_profile *profile,
+				  unsigned int state, int type, int protocol,
+				  const char **info)
+{
+	u16 buffer[2];
+	buffer[0] = cpu_to_be16(type);
+	buffer[1] = cpu_to_be16(protocol);
+	state = aa_dfa_match_len(profile->policy.dfa, state, (char *) &buffer,
+				 4);
+	if (!state)
+		*info = "failed type and protocol match";
+	return state;
+}
+
+static unsigned int match_addr(struct aa_profile *profile, unsigned int state,
+			       struct sockaddr_un *addr, int addrlen)
+{
+	if (addr)
+		/* include leading \0 */
+		state = aa_dfa_match_len(profile->policy.dfa, state,
+					 addr->sun_path,
+					 unix_addr_len(addrlen));
+	else
+		/* anonymous end point */
+		state = aa_dfa_match_len(profile->policy.dfa, state, "\x01",
+					 1);
+	/* todo change to out of band */
+	state = aa_dfa_null_transition(profile->policy.dfa, state);
+	return state;
+}
+
+static unsigned int match_to_local(struct aa_profile *profile,
+				   unsigned int state, int type, int protocol,
+				   struct sockaddr_un *addr, int addrlen,
+				   const char **info)
+{
+	state = match_to_prot(profile, state, type, protocol, info);
+	if (state) {
+		state = match_addr(profile, state, addr, addrlen);
+		if (state) {
+			/* todo: local label matching */
+			state = aa_dfa_null_transition(profile->policy.dfa,
+						       state);
+			if (!state)
+				*info = "failed local label match";
+		} else
+			*info = "failed local address match";
+	}
+
+	return state;
+}
+
+static unsigned int match_to_sk(struct aa_profile *profile,
+				unsigned int state, struct unix_sock *u,
+				const char **info)
+{
+	struct sockaddr_un *addr = NULL;
+	int addrlen = 0;
+
+	if (u->addr) {
+		addr = u->addr->name;
+		addrlen = u->addr->len;
+	}
+
+	return match_to_local(profile, state, u->sk.sk_type, u->sk.sk_protocol,
+			      addr, addrlen, info);
+}
+
+#define CMD_ADDR	1
+#define CMD_LISTEN	2
+#define CMD_OPT		4
+
+static inline unsigned int match_to_cmd(struct aa_profile *profile,
+					unsigned int state, struct unix_sock *u,
+					char cmd, const char **info)
+{
+	state = match_to_sk(profile, state, u, info);
+	if (state) {
+		state = aa_dfa_match_len(profile->policy.dfa, state, &cmd, 1);
+		if (!state)
+			*info = "failed cmd selection match";
+	}
+
+	return state;
+}
+
+static inline unsigned int match_to_peer(struct aa_profile *profile,
+					 unsigned int state,
+					 struct unix_sock *u,
+					 struct sockaddr_un *peer_addr,
+					 int peer_addrlen,
+					 const char **info)
+{
+	state = match_to_cmd(profile, state, u, CMD_ADDR, info);
+	if (state) {
+		state = match_addr(profile, state, peer_addr, peer_addrlen);
+		if (!state)
+			*info = "failed peer address match";
+	}
+	return state;
+}
+
+static int do_perms(struct aa_profile *profile, unsigned int state, u32 request,
+		    struct common_audit_data *sa)
+{
+	struct aa_perms perms;
+
+	AA_BUG(!profile);
+
+	aa_compute_perms(profile->policy.dfa, state, &perms);
+	aa_apply_modes_to_perms(profile, &perms);
+	return aa_check_perms(profile, &perms, request, sa,
+			      audit_net_cb);
+}
+
+static int match_label(struct aa_profile *profile, struct aa_profile *peer,
+			      unsigned int state, u32 request,
+			      struct common_audit_data *sa)
+{
+	AA_BUG(!profile);
+	AA_BUG(!peer);
+
+	aad(sa)->peer = &peer->label;
+
+	if (state) {
+		state = aa_dfa_match(profile->policy.dfa, state, aa_peer_name(peer));
+		if (!state)
+			aad(sa)->info = "failed peer label match";
+	}
+	return do_perms(profile, state, request, sa);
+}
+
+
+/* unix sock creation comes before we know if the socket will be an fs
+ * socket
+ * v6 - semantics are handled by mapping in profile load
+ * v7 - semantics require sock create for tasks creating an fs socket.
+ */
+static int profile_create_perm(struct aa_profile *profile, int family,
+			       int type, int protocol)
+{
+	unsigned int state;
+	DEFINE_AUDIT_NET(sa, OP_CREATE, NULL, family, type, protocol);
+
+	AA_BUG(!profile);
+	AA_BUG(profile_unconfined(profile));
+
+	if ((state = PROFILE_MEDIATES_AF(profile, AF_UNIX))) {
+		state = match_to_prot(profile, state, type, protocol,
+				      &aad(&sa)->info);
+		return do_perms(profile, state, AA_MAY_CREATE, &sa);
+	}
+
+	return aa_profile_af_perm(profile, &sa, AA_MAY_CREATE, family, type);
+}
+
+int aa_unix_create_perm(struct aa_label *label, int family, int type,
+			int protocol)
+{
+	struct aa_profile *profile;
+
+	if (unconfined(label))
+		return 0;
+
+	return fn_for_each_confined(label, profile,
+			profile_create_perm(profile, family, type, protocol));
+}
+
+
+static inline int profile_sk_perm(struct aa_profile *profile, const char *op,
+				  u32 request, struct sock *sk)
+{
+	unsigned int state;
+	DEFINE_AUDIT_SK(sa, op, sk);
+
+	AA_BUG(!profile);
+	AA_BUG(!sk);
+	AA_BUG(UNIX_FS(sk));
+	AA_BUG(profile_unconfined(profile));
+
+	state = PROFILE_MEDIATES_AF(profile, AF_UNIX);
+	if (state) {
+		state = match_to_sk(profile, state, unix_sk(sk),
+				    &aad(&sa)->info);
+		return do_perms(profile, state, request, &sa);
+	}
+
+	return aa_profile_af_sk_perm(profile, &sa, request, sk);
+}
+
+int aa_unix_label_sk_perm(struct aa_label *label, const char *op, u32 request,
+			  struct sock *sk)
+{
+	struct aa_profile *profile;
+
+	return fn_for_each_confined(label, profile,
+			profile_sk_perm(profile, op, request, sk));
+}
+
+static int unix_label_sock_perm(struct aa_label *label, const char *op, u32 request,
+				struct socket *sock)
+{
+	if (unconfined(label))
+		return 0;
+	if (UNIX_FS(sock->sk))
+		return unix_fs_perm(op, request, label, unix_sk(sock->sk), 0);
+
+	return aa_unix_label_sk_perm(label, op, request, sock->sk);
+}
+
+/* revaliation, get/set attr */
+int aa_unix_sock_perm(const char *op, u32 request, struct socket *sock)
+{
+	struct aa_label *label = aa_begin_current_label(DO_UPDATE);
+	int error = unix_label_sock_perm(label, op, request, sock);
+	aa_end_current_label(label);
+
+	return error;
+}
+
+static int profile_bind_perm(struct aa_profile *profile, struct sock *sk,
+			     struct sockaddr *addr, int addrlen)
+{
+	unsigned int state;
+	DEFINE_AUDIT_SK(sa, OP_BIND, sk);
+
+	AA_BUG(!profile);
+	AA_BUG(!sk);
+	AA_BUG(addr->sa_family != AF_UNIX);
+	AA_BUG(profile_unconfined(profile));
+	AA_BUG(unix_addr_fs(addr, addrlen));
+
+	state = PROFILE_MEDIATES_AF(profile, AF_UNIX);
+	if (state) {
+		/* bind for abstract socket */
+		aad(&sa)->net.addr = unix_addr(addr);
+		aad(&sa)->net.addrlen = addrlen;
+
+		state = match_to_local(profile, state,
+				       sk->sk_type, sk->sk_protocol,
+				       unix_addr(addr), addrlen,
+				       &aad(&sa)->info);
+		return do_perms(profile, state, AA_MAY_BIND, &sa);
+	}
+
+	return aa_profile_af_sk_perm(profile, &sa, AA_MAY_BIND, sk);
+}
+
+int aa_unix_bind_perm(struct socket *sock, struct sockaddr *address,
+		      int addrlen)
+{
+	struct aa_profile *profile;
+	struct aa_label *label = aa_begin_current_label(DO_UPDATE);
+	int error = 0;
+
+	 /* fs bind is handled by mknod */
+	if (!(unconfined(label) || unix_addr_fs(address, addrlen)))
+		error = fn_for_each_confined(label, profile,
+				profile_bind_perm(profile, sock->sk, address,
+						  addrlen));
+	aa_end_current_label(label);
+
+	return error;
+}
+
+int aa_unix_connect_perm(struct socket *sock, struct sockaddr *address,
+			 int addrlen)
+{
+	/* unix connections are covered by the
+	 * - unix_stream_connect (stream) and unix_may_send hooks (dgram)
+	 * - fs connect is handled by open
+	 */
+	return 0;
+}
+
+static int profile_listen_perm(struct aa_profile *profile, struct sock *sk,
+			       int backlog)
+{
+	unsigned int state;
+	DEFINE_AUDIT_SK(sa, OP_LISTEN, sk);
+
+	AA_BUG(!profile);
+	AA_BUG(!sk);
+	AA_BUG(UNIX_FS(sk));
+	AA_BUG(profile_unconfined(profile));
+
+	state = PROFILE_MEDIATES_AF(profile, AF_UNIX);
+	if (state) {
+		u16 b = cpu_to_be16(backlog);
+
+		state = match_to_cmd(profile, state, unix_sk(sk), CMD_LISTEN,
+				     &aad(&sa)->info);
+		if (state) {
+			state = aa_dfa_match_len(profile->policy.dfa, state,
+						 (char *) &b, 2);
+			if (!state)
+				aad(&sa)->info = "failed listen backlog match";
+		}
+		return do_perms(profile, state, AA_MAY_LISTEN, &sa);
+	}
+
+	return aa_profile_af_sk_perm(profile, &sa, AA_MAY_LISTEN, sk);
+}
+
+int aa_unix_listen_perm(struct socket *sock, int backlog)
+{
+	struct aa_profile *profile;
+	struct aa_label *label = aa_begin_current_label(DO_UPDATE);
+	int error = 0;
+
+	if (!(unconfined(label) || UNIX_FS(sock->sk)))
+		error = fn_for_each_confined(label, profile,
+				profile_listen_perm(profile, sock->sk,
+						    backlog));
+	aa_end_current_label(label);
+
+	return error;
+}
+
+
+static inline int profile_accept_perm(struct aa_profile *profile,
+				      struct sock *sk,
+				      struct sock *newsk)
+{
+	unsigned int state;
+	DEFINE_AUDIT_SK(sa, OP_ACCEPT, sk);
+
+	AA_BUG(!profile);
+	AA_BUG(!sk);
+	AA_BUG(UNIX_FS(sk));
+	AA_BUG(profile_unconfined(profile));
+
+	state = PROFILE_MEDIATES_AF(profile, AF_UNIX);
+	if (state) {
+		state = match_to_sk(profile, state, unix_sk(sk),
+				    &aad(&sa)->info);
+		return do_perms(profile, state, AA_MAY_ACCEPT, &sa);
+	}
+
+	return aa_profile_af_sk_perm(profile, &sa, AA_MAY_ACCEPT, sk);
+}
+
+/* ability of sock to connect, not peer address binding */
+int aa_unix_accept_perm(struct socket *sock, struct socket *newsock)
+{
+	struct aa_profile *profile;
+	struct aa_label *label = aa_begin_current_label(DO_UPDATE);
+	int error = 0;
+
+	if (!(unconfined(label) || UNIX_FS(sock->sk)))
+		error = fn_for_each_confined(label, profile,
+				profile_accept_perm(profile, sock->sk,
+						    newsock->sk));
+	aa_end_current_label(label);
+
+	return error;
+}
+
+
+/* dgram handled by unix_may_sendmsg, right to send on stream done at connect
+ * could do per msg unix_stream here
+ */
+/* sendmsg, recvmsg */
+int aa_unix_msg_perm(const char *op, u32 request, struct socket *sock,
+		     struct msghdr *msg, int size)
+{
+	return 0;
+}
+
+
+static int profile_opt_perm(struct aa_profile *profile, const char *op, u32 request,
+			    struct sock *sk, int level, int optname)
+{
+	unsigned int state;
+	DEFINE_AUDIT_SK(sa, op, sk);
+
+	AA_BUG(!profile);
+	AA_BUG(!sk);
+	AA_BUG(UNIX_FS(sk));
+	AA_BUG(profile_unconfined(profile));
+
+	state = PROFILE_MEDIATES_AF(profile, AF_UNIX);
+	if (state) {
+		u16 b = cpu_to_be16(optname);
+
+		state = match_to_cmd(profile, state, unix_sk(sk), CMD_OPT,
+				     &aad(&sa)->info);
+		if (state) {
+			state = aa_dfa_match_len(profile->policy.dfa, state,
+						 (char *) &b, 2);
+			if (!state)
+				aad(&sa)->info = "failed sockopt match";
+		}
+		return do_perms(profile, state, request, &sa);
+	}
+
+	return aa_profile_af_sk_perm(profile, &sa, request, sk);
+}
+
+int aa_unix_opt_perm(const char *op, u32 request, struct socket *sock, int level,
+		     int optname)
+{
+	struct aa_profile *profile;
+	struct aa_label *label = aa_begin_current_label(DO_UPDATE);
+	int error = 0;
+
+	if (!(unconfined(label) || UNIX_FS(sock->sk)))
+		error = fn_for_each_confined(label, profile,
+				profile_opt_perm(profile, op, request,
+						 sock->sk, level, optname));
+	aa_end_current_label(label);
+
+	return error;
+}
+
+/* null peer_label is allowed, in which case the peer_sk label is used */
+static int profile_peer_perm(struct aa_profile *profile, const char *op, u32 request,
+			     struct sock *sk, struct sock *peer_sk,
+			     struct aa_label *peer_label,
+			     struct common_audit_data *sa)
+{
+	unsigned int state;
+
+	AA_BUG(!profile);
+	AA_BUG(profile_unconfined(profile));
+	AA_BUG(!sk);
+	AA_BUG(!peer_sk);
+	AA_BUG(UNIX_FS(peer_sk));
+
+	state = PROFILE_MEDIATES_AF(profile, AF_UNIX);
+	if (state) {
+		struct aa_sk_ctx *peer_ctx = SK_CTX(peer_sk);
+		struct aa_profile *peerp;
+		struct sockaddr_un *addr = NULL;
+		int len = 0;
+		if (unix_sk(peer_sk)->addr) {
+			addr = unix_sk(peer_sk)->addr->name;
+			len = unix_sk(peer_sk)->addr->len;
+		}
+		state = match_to_peer(profile, state, unix_sk(sk),
+				      addr, len, &aad(sa)->info);
+		if (!peer_label)
+			peer_label = peer_ctx->label;
+		return fn_for_each_in_ns(peer_label, peerp,
+				   match_label(profile, peerp, state, request,
+					       sa));
+	}
+
+	return aa_profile_af_sk_perm(profile, sa, request, sk);
+}
+
+/**
+ *
+ * Requires: lock held on both @sk and @peer_sk
+ */
+int aa_unix_peer_perm(struct aa_label *label, const char *op, u32 request,
+		      struct sock *sk, struct sock *peer_sk,
+		      struct aa_label *peer_label)
+{
+	struct unix_sock *peeru = unix_sk(peer_sk);
+	struct unix_sock *u = unix_sk(sk);
+
+	AA_BUG(!label);
+	AA_BUG(!sk);
+	AA_BUG(!peer_sk);
+
+	if (UNIX_FS(aa_sock(peeru)))
+		return unix_fs_perm(op, request, label, peeru, 0);
+	else if (UNIX_FS(aa_sock(u)))
+		return unix_fs_perm(op, request, label, u, 0);
+	else {
+		struct aa_profile *profile;
+		DEFINE_AUDIT_SK(sa, op, sk);
+		aad(&sa)->net.peer_sk = peer_sk;
+
+		/* TODO: ns!!! */
+		if (!net_eq(sock_net(sk), sock_net(peer_sk))) {
+			;
+		}
+
+		if (unconfined(label))
+			return 0;
+
+		return fn_for_each_confined(label, profile,
+				profile_peer_perm(profile, op, request, sk,
+						  peer_sk, peer_label, &sa));
+	}
+}
+
+
+/* from net/unix/af_unix.c */
+static void unix_state_double_lock(struct sock *sk1, struct sock *sk2)
+{
+	if (unlikely(sk1 == sk2) || !sk2) {
+		unix_state_lock(sk1);
+		return;
+	}
+	if (sk1 < sk2) {
+		unix_state_lock(sk1);
+		unix_state_lock_nested(sk2);
+	} else {
+		unix_state_lock(sk2);
+		unix_state_lock_nested(sk1);
+	}
+}
+
+static void unix_state_double_unlock(struct sock *sk1, struct sock *sk2)
+{
+	if (unlikely(sk1 == sk2) || !sk2) {
+		unix_state_unlock(sk1);
+		return;
+	}
+	unix_state_unlock(sk1);
+	unix_state_unlock(sk2);
+}
+
+int aa_unix_file_perm(struct aa_label *label, const char *op, u32 request,
+		      struct socket *sock)
+{
+	struct sock *peer_sk = NULL;
+	u32 sk_req = request & ~NET_PEER_MASK;
+	int error = 0;
+
+	AA_BUG(!label);
+	AA_BUG(!sock);
+	AA_BUG(!sock->sk);
+	AA_BUG(sock->sk->sk_family != AF_UNIX);
+
+	/* TODO: update sock label with new task label */
+	unix_state_lock(sock->sk);
+	peer_sk = unix_peer(sock->sk);
+	if (peer_sk)
+		sock_hold(peer_sk);
+	if (!unix_connected(sock) && sk_req) {
+		error = unix_label_sock_perm(label, op, sk_req, sock);
+		if (!error) {
+			// update label
+		}
+	}
+	unix_state_unlock(sock->sk);
+	if (!peer_sk)
+		return error;
+
+	unix_state_double_lock(sock->sk, peer_sk);
+	if (UNIX_FS(sock->sk)) {
+		error = unix_fs_perm(op, request, label, unix_sk(sock->sk),
+				     PATH_SOCK_COND);
+	} else if (UNIX_FS(peer_sk)) {
+		error = unix_fs_perm(op, request, label, unix_sk(peer_sk),
+				     PATH_SOCK_COND);
+	} else {
+		struct aa_sk_ctx *pctx = SK_CTX(peer_sk);
+		if (sk_req)
+			error = aa_unix_label_sk_perm(label, op, sk_req,
+						      sock->sk);
+		last_error(error,
+			xcheck(aa_unix_peer_perm(label, op,
+						 MAY_READ | MAY_WRITE,
+						 sock->sk, peer_sk, NULL),
+			       aa_unix_peer_perm(pctx->label, op,
+						 MAY_READ | MAY_WRITE,
+						 peer_sk, sock->sk, label)));
+	}
+
+	unix_state_double_unlock(sock->sk, peer_sk);
+	sock_put(peer_sk);
+
+	return error;
+}
diff --git a/security/apparmor/apparmorfs.c b/security/apparmor/apparmorfs.c
index 5923d5665209..5c07e57da706 100644
--- a/security/apparmor/apparmorfs.c
+++ b/security/apparmor/apparmorfs.c
@@ -18,17 +18,26 @@
 #include <linux/module.h>
 #include <linux/seq_file.h>
 #include <linux/uaccess.h>
+#include <linux/mount.h>
 #include <linux/namei.h>
 #include <linux/capability.h>
 #include <linux/rcupdate.h>
+#include <uapi/linux/major.h>
+#include <linux/fs.h>
 
 #include "include/apparmor.h"
 #include "include/apparmorfs.h"
 #include "include/audit.h"
 #include "include/context.h"
 #include "include/crypto.h"
+#include "include/ipc.h"
+#include "include/policy_ns.h"
+#include "include/label.h"
 #include "include/policy.h"
 #include "include/resource.h"
+#include "include/label.h"
+#include "include/lib.h"
+#include "include/policy_unpack.h"
 
 /**
  * aa_mangle_name - mangle a profile name to std profile layout form
@@ -37,7 +46,7 @@
  *
  * Returns: length of mangled name
  */
-static int mangle_name(char *name, char *target)
+static int mangle_name(const char *name, char *target)
 {
 	char *t = target;
 
@@ -71,7 +80,6 @@ static int mangle_name(char *name, char *target)
 
 /**
  * aa_simple_write_to_buffer - common routine for getting policy from user
- * @op: operation doing the user buffer copy
  * @userbuf: user buffer to copy data from  (NOT NULL)
  * @alloc_size: size of user buffer (REQUIRES: @alloc_size >= @copy_size)
  * @copy_size: size of data to copy from user buffer
@@ -80,11 +88,12 @@ static int mangle_name(char *name, char *target)
  * Returns: kernel buffer containing copy of user buffer data or an
  *          ERR_PTR on failure.
  */
-static char *aa_simple_write_to_buffer(int op, const char __user *userbuf,
-				       size_t alloc_size, size_t copy_size,
-				       loff_t *pos)
+static struct aa_loaddata *aa_simple_write_to_buffer(const char __user *userbuf,
+						     size_t alloc_size,
+						     size_t copy_size,
+						     loff_t *pos)
 {
-	char *data;
+	struct aa_loaddata *data;
 
 	BUG_ON(copy_size > alloc_size);
 
@@ -92,19 +101,16 @@ static char *aa_simple_write_to_buffer(int op, const char __user *userbuf,
 		/* only writes from pos 0, that is complete writes */
 		return ERR_PTR(-ESPIPE);
 
-	/*
-	 * Don't allow profile load/replace/remove from profiles that don't
-	 * have CAP_MAC_ADMIN
-	 */
-	if (!aa_may_manage_policy(op))
-		return ERR_PTR(-EACCES);
-
 	/* freed by caller to simple_write_to_buffer */
-	data = kvmalloc(alloc_size);
+	data = kvmalloc(sizeof(*data) + alloc_size);
 	if (data == NULL)
 		return ERR_PTR(-ENOMEM);
+	kref_init(&data->count);
+	data->size = copy_size;
+	data->hash = NULL;
+	data->abi = 0;
 
-	if (copy_from_user(data, userbuf, copy_size)) {
+	if (copy_from_user(data->data, userbuf, copy_size)) {
 		kvfree(data);
 		return ERR_PTR(-EFAULT);
 	}
@@ -112,21 +118,41 @@ static char *aa_simple_write_to_buffer(int op, const char __user *userbuf,
 	return data;
 }
 
-
-/* .load file hook fn to load policy */
-static ssize_t profile_load(struct file *f, const char __user *buf, size_t size,
-			    loff_t *pos)
+static ssize_t policy_update(u32 mask, const char __user *buf, size_t size,
+			     loff_t *pos, struct aa_ns *ns)
 {
-	char *data;
+	struct aa_label *label;
 	ssize_t error;
+	struct aa_loaddata *data;
 
-	data = aa_simple_write_to_buffer(OP_PROF_LOAD, buf, size, size, pos);
+	label = aa_begin_current_label(DO_UPDATE);
 
+	/* high level check about policy management - fine grained in
+	 * below after unpack
+	 */
+	error = aa_may_manage_policy(label, ns, mask);
+	if (error)
+		return error;
+
+	data = aa_simple_write_to_buffer(buf, size, size, pos);
 	error = PTR_ERR(data);
 	if (!IS_ERR(data)) {
-		error = aa_replace_profiles(data, size, PROF_ADD);
-		kvfree(data);
+		error = aa_replace_profiles(ns ? ns : labels_ns(label), label,
+					    mask, data);
+		aa_put_loaddata(data);
 	}
+	aa_end_current_label(label);
+
+	return error;
+}
+
+/* .load file hook fn to load policy */
+static ssize_t profile_load(struct file *f, const char __user *buf, size_t size,
+			    loff_t *pos)
+{
+	struct aa_ns *ns = aa_get_ns(f->f_inode->i_private);
+	int error = policy_update(AA_MAY_LOAD_POLICY, buf, size, pos, ns);
+	aa_put_ns(ns);
 
 	return error;
 }
@@ -140,15 +166,10 @@ static const struct file_operations aa_fs_profile_load = {
 static ssize_t profile_replace(struct file *f, const char __user *buf,
 			       size_t size, loff_t *pos)
 {
-	char *data;
-	ssize_t error;
-
-	data = aa_simple_write_to_buffer(OP_PROF_REPL, buf, size, size, pos);
-	error = PTR_ERR(data);
-	if (!IS_ERR(data)) {
-		error = aa_replace_profiles(data, size, PROF_REPLACE);
-		kvfree(data);
-	}
+	struct aa_ns *ns = aa_get_ns(f->f_inode->i_private);
+	int error = policy_update(AA_MAY_LOAD_POLICY | AA_MAY_REPLACE_POLICY,
+				  buf, size, pos, ns);
+	aa_put_ns(ns);
 
 	return error;
 }
@@ -162,22 +183,35 @@ static const struct file_operations aa_fs_profile_replace = {
 static ssize_t profile_remove(struct file *f, const char __user *buf,
 			      size_t size, loff_t *pos)
 {
-	char *data;
+	struct aa_loaddata *data;
+	struct aa_label *label;
 	ssize_t error;
+	struct aa_ns *ns = aa_get_ns(f->f_inode->i_private);
+
+	label = aa_begin_current_label(DO_UPDATE);
+	/* high level check about policy management - fine grained in
+	 * below after unpack
+	 */
+	error = aa_may_manage_policy(label, ns, AA_MAY_REMOVE_POLICY);
+	if (error)
+		goto out;
 
 	/*
 	 * aa_remove_profile needs a null terminated string so 1 extra
 	 * byte is allocated and the copied data is null terminated.
 	 */
-	data = aa_simple_write_to_buffer(OP_PROF_RM, buf, size + 1, size, pos);
+	data = aa_simple_write_to_buffer(buf, size + 1, size, pos);
 
 	error = PTR_ERR(data);
 	if (!IS_ERR(data)) {
-		data[size] = 0;
-		error = aa_remove_profiles(data, size);
-		kvfree(data);
+		data->data[size] = 0;
+		error = aa_remove_profiles(ns ? ns : labels_ns(label), label,
+					   data->data, size);
+		aa_put_loaddata(data);
 	}
-
+ out:
+	aa_end_current_label(label);
+	aa_put_ns(ns);
 	return error;
 }
 
@@ -186,6 +220,376 @@ static const struct file_operations aa_fs_profile_remove = {
 	.llseek = default_llseek,
 };
 
+struct aa_revision {
+	struct aa_ns *ns;
+	long last_read;
+};
+
+/* revision file hook fn for policy loads */
+static int ns_revision_release(struct inode *inode, struct file *file)
+{
+	struct aa_revision *rev = file->private_data;
+
+	if (rev) {
+		aa_put_ns(rev->ns);
+		kfree(rev);
+	}
+
+	return 0;
+}
+
+static ssize_t ns_revision_read(struct file *file, char __user *buf,
+				size_t size, loff_t *ppos)
+{
+	struct aa_revision *rev = file->private_data;
+	char buffer[32];
+	long last_read;
+	int avail;
+
+	mutex_lock(&rev->ns->lock);
+	last_read = rev->last_read;
+	if (last_read == rev->ns->revision) {
+		mutex_unlock(&rev->ns->lock);
+		if (file->f_flags & O_NONBLOCK)
+			return -EAGAIN;
+		if (wait_event_interruptible(rev->ns->wait,
+					     last_read !=
+					     READ_ONCE(rev->ns->revision)))
+			return -ERESTARTSYS;
+		mutex_lock(&rev->ns->lock);
+	}
+
+	avail = sprintf(buffer, "%ld\n", rev->ns->revision);
+	if (*ppos + size > avail) {
+		rev->last_read = rev->ns->revision;
+		*ppos = 0;
+	}
+	mutex_unlock(&rev->ns->lock);
+
+	return simple_read_from_buffer(buf, size, ppos, buffer, avail);
+}
+
+static int ns_revision_open(struct inode *inode, struct file *file)
+{
+	struct aa_revision *rev = kzalloc(sizeof(*rev), GFP_KERNEL);
+
+	if (!rev)
+		return -ENOMEM;
+
+	rev->ns = aa_get_ns(inode->i_private);
+	if (!rev->ns)
+		rev->ns = aa_get_current_ns();
+	file->private_data = rev;
+
+	return 0;
+}
+
+static unsigned int ns_revision_poll(struct file *file, poll_table *pt)
+{
+	struct aa_revision *rev = file->private_data;
+	unsigned int mask = 0;
+
+	if (rev) {
+		mutex_lock(&rev->ns->lock);
+		poll_wait(file, &rev->ns->wait, pt);
+		if (rev->last_read < rev->ns->revision)
+			mask |= POLLIN | POLLRDNORM;
+		mutex_unlock(&rev->ns->lock);
+	}
+
+	return mask;
+}
+
+void __aa_bump_ns_revision(struct aa_ns *ns)
+{
+	ns->revision++;
+	wake_up_interruptible(&ns->wait);
+}
+
+static const struct file_operations ns_revision_fops = {
+	.owner		= THIS_MODULE,
+	.open		= ns_revision_open,
+	.poll		= ns_revision_poll,
+	.read		= ns_revision_read,
+	.llseek		= generic_file_llseek,
+	.release	= ns_revision_release,
+};
+
+static void profile_query_cb(struct aa_profile *profile, struct aa_perms *perms,
+			     const char *match_str, size_t match_len)
+{
+	struct aa_perms tmp;
+	struct aa_dfa *dfa;
+	unsigned int state = 0;
+
+	if (profile_unconfined(profile))
+		return;
+	if (profile->file.dfa && *match_str == AA_CLASS_FILE) {
+		dfa = profile->file.dfa;
+		state = aa_dfa_match_len(dfa, profile->file.start,
+					 match_str + 1, match_len - 1);
+		tmp = nullperms;
+		if (state) {
+			struct path_cond cond = { };
+			tmp = aa_compute_fperms(dfa, state, &cond);
+		}
+	} else if (profile->policy.dfa) {
+		if (!PROFILE_MEDIATES_SAFE(profile, *match_str))
+			return;	/* no change to current perms */
+		dfa = profile->policy.dfa;
+		state = aa_dfa_match_len(dfa, profile->policy.start[0],
+					 match_str, match_len);
+		if (state)
+			aa_compute_perms(dfa, state, &tmp);
+		else
+			tmp = nullperms;
+	}
+	aa_apply_modes_to_perms(profile, &tmp);
+	aa_perms_accum_raw(perms, &tmp);
+}
+
+/**
+ * query_data - queries a policy and writes its data to buf
+ * @buf: the resulting data is stored here (NOT NULL)
+ * @buf_len: size of buf
+ * @query: query string used to retrieve data
+ * @query_len: size of query including second NUL byte
+ *
+ * The buffers pointed to by buf and query may overlap. The query buffer is
+ * parsed before buf is written to.
+ *
+ * The query should look like "<LABEL>\0<KEY>\0", where <LABEL> is the name of
+ * the security confinement context and <KEY> is the name of the data to
+ * retrieve. <LABEL> and <KEY> must not be NUL-terminated.
+ *
+ * Don't expect the contents of buf to be preserved on failure.
+ *
+ * Returns: number of characters written to buf or -errno on failure
+ */
+static ssize_t query_data(char *buf, size_t buf_len,
+			  char *query, size_t query_len)
+{
+	char *out;
+	const char *key;
+	struct label_it i;
+	struct aa_label *label, *curr;
+	struct aa_profile *profile;
+	struct aa_data *data;
+	u32 bytes;
+	u32 blocks;
+	u32 size;
+
+	if (!query_len)
+		return -EINVAL; /* need a query */
+
+	key = query + strnlen(query, query_len) + 1;
+	if (key + 1 >= query + query_len)
+		return -EINVAL; /* not enough space for a non-empty key */
+	if (key + strnlen(key, query + query_len - key) >= query + query_len)
+		return -EINVAL; /* must end with NUL */
+
+	if (buf_len < sizeof(bytes) + sizeof(blocks))
+		return -EINVAL; /* not enough space */
+
+	curr = aa_begin_current_label(DO_UPDATE);
+	label = aa_label_parse(curr, query, GFP_KERNEL, false, false);
+	aa_end_current_label(curr);
+	if (IS_ERR(label))
+		return PTR_ERR(label);
+
+	/* We are going to leave space for two numbers. The first is the total
+	 * number of bytes we are writing after the first number. This is so
+	 * users can read the full output without reallocation.
+	 *
+	 * The second number is the number of data blocks we're writing. An
+	 * application might be confined by multiple policies having data in
+	 * the same key.
+	 */
+	memset(buf, 0, sizeof(bytes) + sizeof(blocks));
+	out = buf + sizeof(bytes) + sizeof(blocks);
+
+	blocks = 0;
+	label_for_each_confined(i, label, profile) {
+		if (!profile->data)
+			continue;
+
+		data = rhashtable_lookup_fast(profile->data, &key,
+					      profile->data->p);
+
+		if (data) {
+			if (out + sizeof(size) + data->size > buf + buf_len) {
+				aa_put_label(label);
+				return -EINVAL; /* not enough space */
+			}
+			size = __cpu_to_le32(data->size);
+			memcpy(out, &size, sizeof(size));
+			out += sizeof(size);
+			memcpy(out, data->data, data->size);
+			out += data->size;
+			blocks++;
+		}
+	}
+	aa_put_label(label);
+
+	bytes = out - buf - sizeof(bytes);
+	bytes = __cpu_to_le32(bytes);
+	blocks = __cpu_to_le32(blocks);
+	memcpy(buf, &bytes, sizeof(bytes));
+	memcpy(buf + sizeof(bytes), &blocks, sizeof(blocks));
+
+	return out - buf;
+}
+
+/**
+ * query_label - queries a label and writes permissions to buf
+ * @buf: the resulting permissions string is stored here (NOT NULL)
+ * @buf_len: size of buf
+ * @query: binary query string to match against the dfa
+ * @query_len: size of query
+ *
+ * The buffers pointed to by buf and query may overlap. The query buffer is
+ * parsed before buf is written to.
+ *
+ * The query should look like "LABEL_NAME\0DFA_STRING" where LABEL_NAME is
+ * the name of the label, in the current namespace, that is to be queried and
+ * DFA_STRING is a binary string to match against the label(s)'s DFA.
+ *
+ * LABEL_NAME must be NUL terminated. DFA_STRING may contain NUL characters
+ * but must *not* be NUL terminated.
+ *
+ * Returns: number of characters written to buf or -errno on failure
+ */
+static ssize_t query_label(char *buf, size_t buf_len,
+			   char *query, size_t query_len, bool ns_only)
+{
+	struct aa_profile *profile;
+	struct aa_label *label, *curr;
+	char *label_name, *match_str;
+	size_t label_name_len, match_len;
+	struct aa_perms perms;
+	struct label_it i;
+
+	if (!query_len)
+		return -EINVAL;
+
+	label_name = query;
+	label_name_len = strnlen(query, query_len);
+	if (!label_name_len || label_name_len == query_len)
+		return -EINVAL;
+
+	/**
+	 * The extra byte is to account for the null byte between the
+	 * profile name and dfa string. profile_name_len is greater
+	 * than zero and less than query_len, so a byte can be safely
+	 * added or subtracted.
+	 */
+	match_str = label_name + label_name_len + 1;
+	match_len = query_len - label_name_len - 1;
+
+	curr = aa_begin_current_label(DO_UPDATE);
+	label = aa_label_parse(curr, label_name, GFP_KERNEL, false, false);
+	aa_end_current_label(curr);
+	if (IS_ERR(label))
+		return PTR_ERR(label);
+
+	perms = allperms;
+	if (ns_only) {
+		label_for_each_in_ns(i, labels_ns(label), label, profile) {
+			profile_query_cb(profile, &perms, match_str, match_len);
+		}
+	} else {
+		label_for_each(i, label, profile) {
+			profile_query_cb(profile, &perms, match_str, match_len);
+		}
+	}
+	aa_put_label(label);
+
+	return scnprintf(buf, buf_len,
+		      "allow 0x%08x\ndeny 0x%08x\naudit 0x%08x\nquiet 0x%08x\n",
+		      perms.allow, perms.deny, perms.audit, perms.quiet);
+}
+
+#define QUERY_CMD_LABEL		"label\0"
+#define QUERY_CMD_LABEL_LEN	6
+#define QUERY_CMD_PROFILE	"profile\0"
+#define QUERY_CMD_PROFILE_LEN	8
+#define QUERY_CMD_LABELALL	"labelall\0"
+#define QUERY_CMD_LABELALL_LEN	9
+#define QUERY_CMD_DATA		"data\0"
+#define QUERY_CMD_DATA_LEN	5
+
+/**
+ * aa_write_access - generic permissions and data query
+ * @file: pointer to open apparmorfs/access file
+ * @ubuf: user buffer containing the complete query string (NOT NULL)
+ * @count: size of ubuf
+ * @ppos: position in the file (MUST BE ZERO)
+ *
+ * Allows for one permissions or data query per open(), write(), and read()
+ * sequence. The only queries currently supported are label-based queries for
+ * permissions or data.
+ *
+ * For permissions queries, ubuf must begin with "label\0", followed by the
+ * profile query specific format described in the query_label() function
+ * documentation.
+ *
+ * For data queries, ubuf must have the form "data\0<LABEL>\0<KEY>\0", where
+ * <LABEL> is the name of the security confinement context and <KEY> is the
+ * name of the data to retrieve.
+ *
+ * Returns: number of bytes written or -errno on failure
+ */
+static ssize_t aa_write_access(struct file *file, const char __user *ubuf,
+			       size_t count, loff_t *ppos)
+{
+	char *buf;
+	ssize_t len;
+
+	if (*ppos)
+		return -ESPIPE;
+
+	buf = simple_transaction_get(file, ubuf, count);
+	if (IS_ERR(buf))
+		return PTR_ERR(buf);
+
+	if (count > QUERY_CMD_PROFILE_LEN &&
+	    !memcmp(buf, QUERY_CMD_PROFILE, QUERY_CMD_PROFILE_LEN)) {
+		len = query_label(buf, SIMPLE_TRANSACTION_LIMIT,
+				  buf + QUERY_CMD_PROFILE_LEN,
+				  count - QUERY_CMD_PROFILE_LEN, true);
+	} else if (count > QUERY_CMD_LABEL_LEN &&
+		   !memcmp(buf, QUERY_CMD_LABEL, QUERY_CMD_LABEL_LEN)) {
+		len = query_label(buf, SIMPLE_TRANSACTION_LIMIT,
+				  buf + QUERY_CMD_LABEL_LEN,
+				  count - QUERY_CMD_LABEL_LEN, true);
+	} else if (count > QUERY_CMD_LABELALL_LEN &&
+		   !memcmp(buf, QUERY_CMD_LABELALL, QUERY_CMD_LABELALL_LEN)) {
+		len = query_label(buf, SIMPLE_TRANSACTION_LIMIT,
+				  buf + QUERY_CMD_LABELALL_LEN,
+				  count - QUERY_CMD_LABELALL_LEN, false);
+	} else if (count > QUERY_CMD_DATA_LEN &&
+		   !memcmp(buf, QUERY_CMD_DATA, QUERY_CMD_DATA_LEN)) {
+		len = query_data(buf, SIMPLE_TRANSACTION_LIMIT,
+				 buf + QUERY_CMD_DATA_LEN,
+				 count - QUERY_CMD_DATA_LEN);
+	} else
+		len = -EINVAL;
+
+	if (len < 0)
+		return len;
+
+	simple_transaction_set(file, len);
+
+	return count;
+}
+
+static const struct file_operations aa_fs_access = {
+	.write		= aa_write_access,
+	.read		= simple_transaction_read,
+	.release	= simple_transaction_release,
+	.llseek		= generic_file_llseek,
+};
+
 static int aa_fs_seq_show(struct seq_file *seq, void *v)
 {
 	struct aa_fs_entry *fs_file = seq->private;
@@ -227,12 +631,12 @@ const struct file_operations aa_fs_seq_file_ops = {
 static int aa_fs_seq_profile_open(struct inode *inode, struct file *file,
 				  int (*show)(struct seq_file *, void *))
 {
-	struct aa_replacedby *r = aa_get_replacedby(inode->i_private);
-	int error = single_open(file, show, r);
+	struct aa_proxy *proxy = aa_get_proxy(inode->i_private);
+	int error = single_open(file, show, proxy);
 
 	if (error) {
 		file->private_data = NULL;
-		aa_put_replacedby(r);
+		aa_put_proxy(proxy);
 	}
 
 	return error;
@@ -242,16 +646,17 @@ static int aa_fs_seq_profile_release(struct inode *inode, struct file *file)
 {
 	struct seq_file *seq = (struct seq_file *) file->private_data;
 	if (seq)
-		aa_put_replacedby(seq->private);
+		aa_put_proxy(seq->private);
 	return single_release(inode, file);
 }
 
 static int aa_fs_seq_profname_show(struct seq_file *seq, void *v)
 {
-	struct aa_replacedby *r = seq->private;
-	struct aa_profile *profile = aa_get_profile_rcu(&r->profile);
+	struct aa_proxy *proxy = seq->private;
+	struct aa_label *label = aa_get_label_rcu(&proxy->label);
+	struct aa_profile *profile = labels_profile(label);
 	seq_printf(seq, "%s\n", profile->base.name);
-	aa_put_profile(profile);
+	aa_put_label(label);
 
 	return 0;
 }
@@ -271,10 +676,11 @@ static const struct file_operations aa_fs_profname_fops = {
 
 static int aa_fs_seq_profmode_show(struct seq_file *seq, void *v)
 {
-	struct aa_replacedby *r = seq->private;
-	struct aa_profile *profile = aa_get_profile_rcu(&r->profile);
+	struct aa_proxy *proxy = seq->private;
+	struct aa_label *label = aa_get_label_rcu(&proxy->label);
+	struct aa_profile *profile = labels_profile(label);
 	seq_printf(seq, "%s\n", aa_profile_mode_names[profile->mode]);
-	aa_put_profile(profile);
+	aa_put_label(label);
 
 	return 0;
 }
@@ -294,15 +700,16 @@ static const struct file_operations aa_fs_profmode_fops = {
 
 static int aa_fs_seq_profattach_show(struct seq_file *seq, void *v)
 {
-	struct aa_replacedby *r = seq->private;
-	struct aa_profile *profile = aa_get_profile_rcu(&r->profile);
+	struct aa_proxy *proxy = seq->private;
+	struct aa_label *label = aa_get_label_rcu(&proxy->label);
+	struct aa_profile *profile = labels_profile(label);
 	if (profile->attach)
 		seq_printf(seq, "%s\n", profile->attach);
 	else if (profile->xmatch)
 		seq_puts(seq, "<unknown>\n");
 	else
 		seq_printf(seq, "%s\n", profile->base.name);
-	aa_put_profile(profile);
+	aa_put_label(label);
 
 	return 0;
 }
@@ -322,8 +729,9 @@ static const struct file_operations aa_fs_profattach_fops = {
 
 static int aa_fs_seq_hash_show(struct seq_file *seq, void *v)
 {
-	struct aa_replacedby *r = seq->private;
-	struct aa_profile *profile = aa_get_profile_rcu(&r->profile);
+	struct aa_proxy *proxy = seq->private;
+	struct aa_label *label = aa_get_label_rcu(&proxy->label);
+	struct aa_profile *profile = labels_profile(label);
 	unsigned int i, size = aa_hash_size();
 
 	if (profile->hash) {
@@ -331,7 +739,7 @@ static int aa_fs_seq_hash_show(struct seq_file *seq, void *v)
 			seq_printf(seq, "%.2x", profile->hash[i]);
 		seq_puts(seq, "\n");
 	}
-	aa_put_profile(profile);
+	aa_put_label(label);
 
 	return 0;
 }
@@ -349,7 +757,210 @@ static const struct file_operations aa_fs_seq_hash_fops = {
 	.release	= single_release,
 };
 
+static int aa_fs_seq_show_stacked(struct seq_file *seq, void *v)
+{
+	struct aa_label *label = aa_begin_current_label(DO_UPDATE);
+	seq_printf(seq, "%s\n", label->size > 1 ? "yes" : "no");
+	aa_end_current_label(label);
+
+	return 0;
+}
+
+static int aa_fs_seq_open_stacked(struct inode *inode, struct file *file)
+{
+	return single_open(file, aa_fs_seq_show_stacked, inode->i_private);
+}
+
+static const struct file_operations aa_fs_stacked = {
+	.owner		= THIS_MODULE,
+	.open		= aa_fs_seq_open_stacked,
+	.read		= seq_read,
+	.llseek		= seq_lseek,
+	.release	= single_release,
+};
+
+static int aa_fs_seq_show_ns_stacked(struct seq_file *seq, void *v)
+{
+	struct aa_label *label = aa_begin_current_label(DO_UPDATE);
+	struct aa_profile *profile;
+	struct label_it it;
+	int count = 1;
+
+	if (label->size > 1) {
+		label_for_each(it, label, profile)
+			if (profile->ns != labels_ns(label)) {
+				count++;
+				break;
+			}
+	}
+
+	seq_printf(seq, "%s\n", count > 1 ? "yes" : "no");
+	aa_end_current_label(label);
+
+	return 0;
+}
+
+static int aa_fs_seq_open_ns_stacked(struct inode *inode, struct file *file)
+{
+	return single_open(file, aa_fs_seq_show_ns_stacked, inode->i_private);
+}
+
+static const struct file_operations aa_fs_ns_stacked = {
+	.owner		= THIS_MODULE,
+	.open		= aa_fs_seq_open_ns_stacked,
+	.read		= seq_read,
+	.llseek		= seq_lseek,
+	.release	= single_release,
+};
+
+static int aa_fs_seq_show_ns_level(struct seq_file *seq, void *v)
+{
+	struct aa_label *label = aa_begin_current_label(DO_UPDATE);
+	seq_printf(seq, "%d\n", labels_ns(label)->level);
+	aa_end_current_label(label);
+
+	return 0;
+}
+
+static int aa_fs_seq_open_ns_level(struct inode *inode, struct file *file)
+{
+	return single_open(file, aa_fs_seq_show_ns_level, inode->i_private);
+}
+
+static const struct file_operations aa_fs_ns_level = {
+	.owner		= THIS_MODULE,
+	.open		= aa_fs_seq_open_ns_level,
+	.read		= seq_read,
+	.llseek		= seq_lseek,
+	.release	= single_release,
+};
+
+static int aa_fs_seq_show_ns_name(struct seq_file *seq, void *v)
+{
+	struct aa_label *label = aa_begin_current_label(DO_UPDATE);
+	seq_printf(seq, "%s\n", labels_ns(label)->base.name);
+	aa_end_current_label(label);
+
+	return 0;
+}
+
+static int aa_fs_seq_open_ns_name(struct inode *inode, struct file *file)
+{
+	return single_open(file, aa_fs_seq_show_ns_name, inode->i_private);
+}
+
+static const struct file_operations aa_fs_ns_name = {
+	.owner		= THIS_MODULE,
+	.open		= aa_fs_seq_open_ns_name,
+	.read		= seq_read,
+	.llseek		= seq_lseek,
+	.release	= single_release,
+};
+
+static int rawdata_release(struct inode *inode, struct file *file)
+{
+	/* TODO: switch to loaddata when profile switched to symlink */
+	aa_put_loaddata(file->private_data);
+
+	return 0;
+}
+
+static int aa_fs_seq_raw_abi_show(struct seq_file *seq, void *v)
+{
+	struct aa_proxy *proxy = seq->private;
+	struct aa_label *label = aa_get_label_rcu(&proxy->label);
+	struct aa_profile *profile = labels_profile(label);
+
+	if (profile->rawdata->abi) {
+		seq_printf(seq, "v%d", profile->rawdata->abi);
+		seq_puts(seq, "\n");
+	}
+	aa_put_label(label);
+
+	return 0;
+}
+
+static int aa_fs_seq_raw_abi_open(struct inode *inode, struct file *file)
+{
+	return aa_fs_seq_profile_open(inode, file, aa_fs_seq_raw_abi_show);
+}
+
+static const struct file_operations aa_fs_seq_raw_abi_fops = {
+	.owner		= THIS_MODULE,
+	.open		= aa_fs_seq_raw_abi_open,
+	.read		= seq_read,
+	.llseek		= seq_lseek,
+	.release	= aa_fs_seq_profile_release,
+};
+
+static int aa_fs_seq_raw_hash_show(struct seq_file *seq, void *v)
+{
+	struct aa_proxy *proxy = seq->private;
+	struct aa_label *label = aa_get_label_rcu(&proxy->label);
+	struct aa_profile *profile = labels_profile(label);
+	unsigned int i, size = aa_hash_size();
+
+	if (profile->rawdata->hash) {
+		for (i = 0; i < size; i++)
+			seq_printf(seq, "%.2x", profile->rawdata->hash[i]);
+		seq_puts(seq, "\n");
+	}
+	aa_put_label(label);
+
+	return 0;
+}
+
+static int aa_fs_seq_raw_hash_open(struct inode *inode, struct file *file)
+{
+	return aa_fs_seq_profile_open(inode, file, aa_fs_seq_raw_hash_show);
+}
+
+static const struct file_operations aa_fs_seq_raw_hash_fops = {
+	.owner		= THIS_MODULE,
+	.open		= aa_fs_seq_raw_hash_open,
+	.read		= seq_read,
+	.llseek		= seq_lseek,
+	.release	= aa_fs_seq_profile_release,
+};
+
+static ssize_t rawdata_read(struct file *file, char __user *buf, size_t size,
+			    loff_t *ppos)
+{
+	struct aa_loaddata *rawdata = file->private_data;
+
+	return simple_read_from_buffer(buf, size, ppos, rawdata->data,
+				       rawdata->size);
+}
+
+static int rawdata_open(struct inode *inode, struct file *file)
+{
+	struct aa_proxy *proxy = inode->i_private;
+	struct aa_label *label;
+	struct aa_profile *profile;
+
+	if (!policy_view_capable(NULL))
+		return -EACCES;
+	label = aa_get_label_rcu(&proxy->label);
+	profile = labels_profile(label);
+	file->private_data = aa_get_loaddata(profile->rawdata);
+	aa_put_label(label);
+
+	return 0;
+}
+
+static const struct file_operations aa_fs_rawdata_fops = {
+	.open = rawdata_open,
+	.read = rawdata_read,
+	.llseek = generic_file_llseek,
+	.release = rawdata_release,
+};
+
 /** fns to setup dynamic per profile/namespace files **/
+
+/**
+ *
+ * Requires: @profile->ns->lock held
+ */
 void __aa_fs_profile_rmdir(struct aa_profile *profile)
 {
 	struct aa_profile *child;
@@ -357,27 +968,36 @@ void __aa_fs_profile_rmdir(struct aa_profile *profile)
 
 	if (!profile)
 		return;
+	AA_BUG(!mutex_is_locked(&profiles_ns(profile)->lock));
 
 	list_for_each_entry(child, &profile->base.profiles, base.list)
 		__aa_fs_profile_rmdir(child);
 
 	for (i = AAFS_PROF_SIZEOF - 1; i >= 0; --i) {
-		struct aa_replacedby *r;
+		struct aa_proxy *proxy;
 		if (!profile->dents[i])
 			continue;
 
-		r = d_inode(profile->dents[i])->i_private;
+		proxy = d_inode(profile->dents[i])->i_private;
 		securityfs_remove(profile->dents[i]);
-		aa_put_replacedby(r);
+		aa_put_proxy(proxy);
 		profile->dents[i] = NULL;
 	}
 }
 
+/**
+ *
+ * Requires: @old->ns->lock held
+ */
 void __aa_fs_profile_migrate_dents(struct aa_profile *old,
 				   struct aa_profile *new)
 {
 	int i;
 
+	AA_BUG(!old);
+	AA_BUG(!new);
+	AA_BUG(!mutex_is_locked(&profiles_ns(old)->lock));
+
 	for (i = 0; i < AAFS_PROF_SIZEOF; i++) {
 		new->dents[i] = old->dents[i];
 		if (new->dents[i])
@@ -390,23 +1010,29 @@ static struct dentry *create_profile_file(struct dentry *dir, const char *name,
 					  struct aa_profile *profile,
 					  const struct file_operations *fops)
 {
-	struct aa_replacedby *r = aa_get_replacedby(profile->replacedby);
+	struct aa_proxy *proxy = aa_get_proxy(profile->label.proxy);
 	struct dentry *dent;
 
-	dent = securityfs_create_file(name, S_IFREG | 0444, dir, r, fops);
+	dent = securityfs_create_file(name, S_IFREG | 0444, dir, proxy, fops);
 	if (IS_ERR(dent))
-		aa_put_replacedby(r);
+		aa_put_proxy(proxy);
 
 	return dent;
 }
 
-/* requires lock be held */
+/**
+ *
+ * Requires: @profile->ns->lock held
+ */
 int __aa_fs_profile_mkdir(struct aa_profile *profile, struct dentry *parent)
 {
 	struct aa_profile *child;
 	struct dentry *dent = NULL, *dir;
 	int error;
 
+	AA_BUG(!profile);
+	AA_BUG(!mutex_is_locked(&profiles_ns(profile)->lock));
+
 	if (!parent) {
 		struct aa_profile *p;
 		p = aa_deref_parent(profile);
@@ -460,6 +1086,29 @@ int __aa_fs_profile_mkdir(struct aa_profile *profile, struct dentry *parent)
 		profile->dents[AAFS_PROF_HASH] = dent;
 	}
 
+	if (profile->rawdata) {
+		dent = create_profile_file(dir, "raw_hash", profile,
+					   &aa_fs_seq_raw_hash_fops);
+		if (IS_ERR(dent))
+			goto fail;
+		profile->dents[AAFS_PROF_RAW_HASH] = dent;
+
+		dent = create_profile_file(dir, "raw_abi", profile,
+					   &aa_fs_seq_raw_abi_fops);
+		if (IS_ERR(dent))
+			goto fail;
+		profile->dents[AAFS_PROF_RAW_ABI] = dent;
+
+		dent = securityfs_create_file("raw_data", S_IFREG | 0444, dir,
+					      profile->label.proxy,
+					      &aa_fs_rawdata_fops);
+		if (IS_ERR(dent))
+			goto fail;
+		profile->dents[AAFS_PROF_RAW_DATA] = dent;
+		d_inode(dent)->i_size = profile->rawdata->size;
+		aa_get_proxy(profile->label.proxy);
+	}
+
 	list_for_each_entry(child, &profile->base.profiles, base.list) {
 		error = __aa_fs_profile_mkdir(child, prof_child_dir(profile));
 		if (error)
@@ -477,65 +1126,238 @@ int __aa_fs_profile_mkdir(struct aa_profile *profile, struct dentry *parent)
 	return error;
 }
 
-void __aa_fs_namespace_rmdir(struct aa_namespace *ns)
+static int ns_mkdir_op(struct inode *dir, struct dentry *dentry, umode_t mode)
+{
+	struct aa_ns *ns, *parent;
+	/* TODO: improve permission check */
+	struct aa_label *label = aa_begin_current_label(DO_UPDATE);
+	int error = aa_may_manage_policy(label, NULL, AA_MAY_LOAD_POLICY);
+	aa_end_current_label(label);
+	if (error)
+		return error;
+
+	parent = aa_get_ns(dir->i_private);
+	AA_BUG(d_inode(ns_subns_dir(parent)) != dir);
+
+	/* we have to unlock and then relock to get locking order right
+	 * for pin_fs
+	 */
+	inode_unlock(dir);
+	securityfs_pin_fs();
+	inode_lock_nested(dir, I_MUTEX_PARENT);
+
+	error = __securityfs_setup_d_inode(dir, dentry, mode | S_IFDIR,  NULL,
+					   NULL, NULL);
+	if (error)
+		return error;
+
+	ns = aa_create_ns(parent, ACCESS_ONCE(dentry->d_name.name), dentry);
+	if (IS_ERR(ns)) {
+		error = PTR_ERR(ns);
+		ns = NULL;
+	}
+
+	aa_put_ns(ns);		/* list ref remains */
+	aa_put_ns(parent);
+
+	return error;
+}
+
+static int ns_rmdir_op(struct inode *dir, struct dentry *dentry)
+{
+	struct aa_ns *ns, *parent;
+	/* TODO: improve permission check */
+	struct aa_label *label = aa_begin_current_label(DO_UPDATE);
+	int error = aa_may_manage_policy(label, NULL, AA_MAY_LOAD_POLICY);
+	aa_end_current_label(label);
+	if (error)
+		return error;
+
+	 parent = aa_get_ns(dir->i_private);
+	/* rmdir calls the generic securityfs functions to remove files
+	 * from the apparmor dir. It is up to the apparmor ns locking
+	 * to avoid races.
+	 */
+	inode_unlock(dir);
+	inode_unlock(dentry->d_inode);
+
+	mutex_lock(&parent->lock);
+	ns = aa_get_ns(__aa_findn_ns(&parent->sub_ns, dentry->d_name.name,
+				     dentry->d_name.len));
+	if (!ns) {
+		error = -ENOENT;
+		goto out;
+	}
+	AA_BUG(ns_dir(ns) != dentry);
+
+	__aa_remove_ns(ns);
+	aa_put_ns(ns);
+
+out:
+	mutex_unlock(&parent->lock);
+	inode_lock_nested(dir, I_MUTEX_PARENT);
+	inode_lock(dentry->d_inode);
+	aa_put_ns(parent);
+
+	return error;
+}
+
+static const struct inode_operations ns_dir_inode_operations = {
+	.lookup		= simple_lookup,
+	.mkdir		= ns_mkdir_op,
+	.rmdir		= ns_rmdir_op,
+};
+
+/**
+ *
+ * Requires: @ns->lock held
+ */
+void __aa_fs_ns_rmdir(struct aa_ns *ns)
 {
-	struct aa_namespace *sub;
+	struct aa_ns *sub;
 	struct aa_profile *child;
 	int i;
 
 	if (!ns)
 		return;
+	AA_BUG(!mutex_is_locked(&ns->lock));
 
 	list_for_each_entry(child, &ns->base.profiles, base.list)
 		__aa_fs_profile_rmdir(child);
 
 	list_for_each_entry(sub, &ns->sub_ns, base.list) {
 		mutex_lock(&sub->lock);
-		__aa_fs_namespace_rmdir(sub);
+		__aa_fs_ns_rmdir(sub);
 		mutex_unlock(&sub->lock);
 	}
 
+	if (ns_subns_dir(ns)) {
+		sub = d_inode(ns_subns_dir(ns))->i_private;
+		aa_put_ns(sub);
+	}
+	if (ns_subload(ns)) {
+		sub = d_inode(ns_subload(ns))->i_private;
+		aa_put_ns(sub);
+	}
+	if (ns_subreplace(ns)) {
+		sub = d_inode(ns_subreplace(ns))->i_private;
+		aa_put_ns(sub);
+	}
+	if (ns_subremove(ns)) {
+		sub = d_inode(ns_subremove(ns))->i_private;
+		aa_put_ns(sub);
+	}
+	if (ns_subrevision(ns)) {
+		sub = d_inode(ns_subrevision(ns))->i_private;
+		aa_put_ns(sub);
+	}
+
 	for (i = AAFS_NS_SIZEOF - 1; i >= 0; --i) {
 		securityfs_remove(ns->dents[i]);
 		ns->dents[i] = NULL;
 	}
 }
 
-int __aa_fs_namespace_mkdir(struct aa_namespace *ns, struct dentry *parent,
-			    const char *name)
+/* assumes cleanup in caller */
+static int __aa_fs_ns_mkdir_entries(struct aa_ns *ns, struct dentry *dir)
 {
-	struct aa_namespace *sub;
-	struct aa_profile *child;
-	struct dentry *dent, *dir;
-	int error;
-
-	if (!name)
-		name = ns->base.name;
+	struct dentry *dent;
 
-	dent = securityfs_create_dir(name, parent);
-	if (IS_ERR(dent))
-		goto fail;
-	ns_dir(ns) = dir = dent;
+	AA_BUG(!ns);
+	AA_BUG(!dir);
 
 	dent = securityfs_create_dir("profiles", dir);
 	if (IS_ERR(dent))
-		goto fail;
+		return PTR_ERR(dent);
 	ns_subprofs_dir(ns) = dent;
 
-	dent = securityfs_create_dir("namespaces", dir);
+	dent = securityfs_create_dir("raw_data", dir);
 	if (IS_ERR(dent))
-		goto fail;
+		return PTR_ERR(dent);
+	ns_subdata_dir(ns) = dent;
+
+	dent = securityfs_create_file("revision", 0444, dir, ns,
+				      &ns_revision_fops);
+	if (IS_ERR(dent))
+		return PTR_ERR(dent);
+	ns_subrevision(ns) = dent;
+
+	dent = securityfs_create_file(".load", 0666, dir, ns,
+				      &aa_fs_profile_load);
+	if (IS_ERR(dent))
+		return PTR_ERR(dent);
+	aa_get_ns(ns);
+	ns_subload(ns) = dent;
+
+	dent = securityfs_create_file(".replace", 0666, dir, ns,
+				      &aa_fs_profile_replace);
+	if (IS_ERR(dent))
+		return PTR_ERR(dent);
+	aa_get_ns(ns);
+	ns_subreplace(ns) = dent;
+
+	dent = securityfs_create_file(".remove", 0666, dir, ns,
+				      &aa_fs_profile_remove);
+	if (IS_ERR(dent))
+		return PTR_ERR(dent);
+	aa_get_ns(ns);
+	ns_subremove(ns) = dent;
+
+	  /* use create_dentry so we can supply private data */
+	dent = securityfs_create_dentry("namespaces",
+					S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO,
+					dir, ns, NULL,
+					&ns_dir_inode_operations);
+	if (IS_ERR(dent))
+		return PTR_ERR(dent);
+	aa_get_ns(ns);
 	ns_subns_dir(ns) = dent;
 
+	return 0;
+}
+
+/**
+ *
+ * Requires: @ns->lock held
+ */
+int __aa_fs_ns_mkdir(struct aa_ns *ns, struct dentry *parent, const char *name,
+		     struct dentry *dent)
+{
+	struct aa_ns *sub;
+	struct aa_profile *child;
+	struct dentry *dir;
+	int error;
+
+	AA_BUG(!ns);
+	AA_BUG(!parent);
+	AA_BUG(!mutex_is_locked(&ns->lock));
+
+	if (!name)
+		name = ns->base.name;
+
+	if (!dent) {
+		/* create ns dir if it doesn't already exist */
+		dent = securityfs_create_dir(name, parent);
+		if (IS_ERR(dent))
+			goto fail;
+	} else
+		dget(dent);
+	ns_dir(ns) = dir = dent;
+	error = __aa_fs_ns_mkdir_entries(ns, dir);
+	if (error)
+		goto fail2;
+
+	/* profiles */
 	list_for_each_entry(child, &ns->base.profiles, base.list) {
 		error = __aa_fs_profile_mkdir(child, ns_subprofs_dir(ns));
 		if (error)
 			goto fail2;
 	}
 
+	/* subnamespaces */
 	list_for_each_entry(sub, &ns->sub_ns, base.list) {
 		mutex_lock(&sub->lock);
-		error = __aa_fs_namespace_mkdir(sub, ns_subns_dir(ns), NULL);
+		error = __aa_fs_ns_mkdir(sub, ns_subns_dir(ns), NULL, NULL);
 		mutex_unlock(&sub->lock);
 		if (error)
 			goto fail2;
@@ -547,7 +1369,7 @@ int __aa_fs_namespace_mkdir(struct aa_namespace *ns, struct dentry *parent,
 	error = PTR_ERR(dent);
 
 fail2:
-	__aa_fs_namespace_rmdir(ns);
+	__aa_fs_ns_rmdir(ns);
 
 	return error;
 }
@@ -556,7 +1378,7 @@ int __aa_fs_namespace_mkdir(struct aa_namespace *ns, struct dentry *parent,
 #define list_entry_is_head(pos, head, member) (&pos->member == (head))
 
 /**
- * __next_namespace - find the next namespace to list
+ * __next_ns - find the next namespace to list
  * @root: root namespace to stop search at (NOT NULL)
  * @ns: current ns position (NOT NULL)
  *
@@ -567,10 +1389,13 @@ int __aa_fs_namespace_mkdir(struct aa_namespace *ns, struct dentry *parent,
  * Requires: ns->parent->lock to be held
  * NOTE: will not unlock root->lock
  */
-static struct aa_namespace *__next_namespace(struct aa_namespace *root,
-					     struct aa_namespace *ns)
+static struct aa_ns *__next_ns(struct aa_ns *root, struct aa_ns *ns)
 {
-	struct aa_namespace *parent, *next;
+	struct aa_ns *parent, *next;
+
+	AA_BUG(!root);
+	AA_BUG(!ns);
+	AA_BUG(ns != root && !mutex_is_locked(&ns->parent->lock));
 
 	/* is next namespace a child */
 	if (!list_empty(&ns->sub_ns)) {
@@ -598,15 +1423,17 @@ static struct aa_namespace *__next_namespace(struct aa_namespace *root,
 /**
  * __first_profile - find the first profile in a namespace
  * @root: namespace that is root of profiles being displayed (NOT NULL)
- * @ns: namespace to start in   (NOT NULL)
+ * @ns: namespace to start in   (MAY BE NULL)
  *
  * Returns: unrefcounted profile or NULL if no profile
- * Requires: profile->ns.lock to be held
+ * Requires: ns.lock to be held
  */
-static struct aa_profile *__first_profile(struct aa_namespace *root,
-					  struct aa_namespace *ns)
+static struct aa_profile *__first_profile(struct aa_ns *root, struct aa_ns *ns)
 {
-	for (; ns; ns = __next_namespace(root, ns)) {
+	AA_BUG(!root);
+	AA_BUG(ns && !mutex_is_locked(&ns->lock));
+
+	for (; ns; ns = __next_ns(root, ns)) {
 		if (!list_empty(&ns->base.profiles))
 			return list_first_entry(&ns->base.profiles,
 						struct aa_profile, base.list);
@@ -626,7 +1453,9 @@ static struct aa_profile *__first_profile(struct aa_namespace *root,
 static struct aa_profile *__next_profile(struct aa_profile *p)
 {
 	struct aa_profile *parent;
-	struct aa_namespace *ns = p->ns;
+	struct aa_ns *ns = p->ns;
+
+	AA_BUG(!mutex_is_locked(&profiles_ns(p)->lock));
 
 	/* is next profile a child */
 	if (!list_empty(&p->base.profiles))
@@ -660,7 +1489,7 @@ static struct aa_profile *__next_profile(struct aa_profile *p)
  *
  * Returns: next profile or NULL if there isn't one
  */
-static struct aa_profile *next_profile(struct aa_namespace *root,
+static struct aa_profile *next_profile(struct aa_ns *root,
 				       struct aa_profile *profile)
 {
 	struct aa_profile *next = __next_profile(profile);
@@ -668,7 +1497,7 @@ static struct aa_profile *next_profile(struct aa_namespace *root,
 		return next;
 
 	/* finished all profiles in namespace move to next namespace */
-	return __first_profile(root, __next_namespace(root, profile->ns));
+	return __first_profile(root, __next_ns(root, profile->ns));
 }
 
 /**
@@ -683,10 +1512,9 @@ static struct aa_profile *next_profile(struct aa_namespace *root,
 static void *p_start(struct seq_file *f, loff_t *pos)
 {
 	struct aa_profile *profile = NULL;
-	struct aa_namespace *root = aa_current_profile()->ns;
+	struct aa_ns *root = aa_get_current_ns();
 	loff_t l = *pos;
-	f->private = aa_get_namespace(root);
-
+	f->private = root;
 
 	/* find the first profile */
 	mutex_lock(&root->lock);
@@ -712,7 +1540,7 @@ static void *p_start(struct seq_file *f, loff_t *pos)
 static void *p_next(struct seq_file *f, void *p, loff_t *pos)
 {
 	struct aa_profile *profile = p;
-	struct aa_namespace *ns = f->private;
+	struct aa_ns *ns = f->private;
 	(*pos)++;
 
 	return next_profile(ns, profile);
@@ -728,14 +1556,14 @@ static void *p_next(struct seq_file *f, void *p, loff_t *pos)
 static void p_stop(struct seq_file *f, void *p)
 {
 	struct aa_profile *profile = p;
-	struct aa_namespace *root = f->private, *ns;
+	struct aa_ns *root = f->private, *ns;
 
 	if (profile) {
 		for (ns = profile->ns; ns && ns != root; ns = ns->parent)
 			mutex_unlock(&ns->lock);
 	}
 	mutex_unlock(&root->lock);
-	aa_put_namespace(root);
+	aa_put_ns(root);
 }
 
 /**
@@ -748,12 +1576,11 @@ static void p_stop(struct seq_file *f, void *p)
 static int seq_show_profile(struct seq_file *f, void *p)
 {
 	struct aa_profile *profile = (struct aa_profile *)p;
-	struct aa_namespace *root = f->private;
+	struct aa_ns *root = f->private;
 
-	if (profile->ns != root)
-		seq_printf(f, ":%s://", aa_ns_name(root, profile->ns));
-	seq_printf(f, "%s (%s)\n", profile->base.hname,
-		   aa_profile_mode_names[profile->mode]);
+	aa_label_seq_xprint(f, root, &profile->label,
+			    FLAG_SHOW_MODE | FLAG_VIEW_SUBNS, GFP_KERNEL);
+	seq_printf(f, "\n");
 
 	return 0;
 }
@@ -767,6 +1594,9 @@ static const struct seq_operations aa_fs_profiles_op = {
 
 static int profiles_open(struct inode *inode, struct file *file)
 {
+	if (!policy_view_capable(NULL))
+		return -EACCES;
+
 	return seq_open(file, &aa_fs_profiles_op);
 }
 
@@ -790,34 +1620,90 @@ static struct aa_fs_entry aa_fs_entry_file[] = {
 	{ }
 };
 
+static struct aa_fs_entry aa_fs_entry_ptrace[] = {
+	AA_FS_FILE_STRING("mask", "read trace"),
+	{ }
+};
+
+static struct aa_fs_entry aa_fs_entry_signal[] = {
+	AA_FS_FILE_STRING("mask", AA_FS_SIG_MASK),
+	{ }
+};
+
 static struct aa_fs_entry aa_fs_entry_domain[] = {
 	AA_FS_FILE_BOOLEAN("change_hat",	1),
 	AA_FS_FILE_BOOLEAN("change_hatv",	1),
 	AA_FS_FILE_BOOLEAN("change_onexec",	1),
 	AA_FS_FILE_BOOLEAN("change_profile",	1),
+	AA_FS_FILE_BOOLEAN("stack",		1),
+	AA_FS_FILE_BOOLEAN("fix_binfmt_elf_mmap",	1),
+	AA_FS_FILE_STRING("version", "1.2"),
+	{ }
+};
+
+static struct aa_fs_entry aa_fs_entry_versions[] = {
+	AA_FS_FILE_BOOLEAN("v5",	1),
+	AA_FS_FILE_BOOLEAN("v6",	1),
+	AA_FS_FILE_BOOLEAN("v7",	1),
 	{ }
 };
 
 static struct aa_fs_entry aa_fs_entry_policy[] = {
-	AA_FS_FILE_BOOLEAN("set_load",          1),
-	{}
+	AA_FS_DIR("versions",                   aa_fs_entry_versions),
+	AA_FS_FILE_BOOLEAN("set_load",		1),
+	{ }
+};
+
+static struct aa_fs_entry aa_fs_entry_mount[] = {
+	AA_FS_FILE_STRING("mask", "mount umount"),
+	{ }
+};
+
+static struct aa_fs_entry aa_fs_entry_ns[] = {
+	AA_FS_FILE_BOOLEAN("profile",		1),
+	AA_FS_FILE_BOOLEAN("pivot_root",	1),
+	{ }
+};
+
+static struct aa_fs_entry aa_fs_entry_dbus[] = {
+	AA_FS_FILE_STRING("mask", "acquire send receive"),
+	{ }
+};
+
+static struct aa_fs_entry aa_fs_entry_query_label[] = {
+	AA_FS_FILE_STRING("perms", "allow deny audit quiet"),
+	AA_FS_FILE_BOOLEAN("data",		1),
+	{ }
 };
 
+static struct aa_fs_entry aa_fs_entry_query[] = {
+	AA_FS_DIR("label",			aa_fs_entry_query_label),
+	{ }
+};
 static struct aa_fs_entry aa_fs_entry_features[] = {
 	AA_FS_DIR("policy",			aa_fs_entry_policy),
 	AA_FS_DIR("domain",			aa_fs_entry_domain),
 	AA_FS_DIR("file",			aa_fs_entry_file),
+	AA_FS_DIR("network",			aa_fs_entry_network),
+	AA_FS_DIR("mount",			aa_fs_entry_mount),
+	AA_FS_DIR("namespaces",			aa_fs_entry_ns),
 	AA_FS_FILE_U64("capability",		VFS_CAP_FLAGS_MASK),
 	AA_FS_DIR("rlimit",			aa_fs_entry_rlimit),
 	AA_FS_DIR("caps",			aa_fs_entry_caps),
+	AA_FS_DIR("ptrace",			aa_fs_entry_ptrace),
+	AA_FS_DIR("signal",			aa_fs_entry_signal),
+	AA_FS_DIR("dbus",			aa_fs_entry_dbus),
+	AA_FS_DIR("query",			aa_fs_entry_query),
 	{ }
 };
 
 static struct aa_fs_entry aa_fs_entry_apparmor[] = {
-	AA_FS_FILE_FOPS(".load", 0640, &aa_fs_profile_load),
-	AA_FS_FILE_FOPS(".replace", 0640, &aa_fs_profile_replace),
-	AA_FS_FILE_FOPS(".remove", 0640, &aa_fs_profile_remove),
-	AA_FS_FILE_FOPS("profiles", 0640, &aa_fs_profiles_fops),
+	AA_FS_FILE_FOPS(".access", 0666, &aa_fs_access),
+	AA_FS_FILE_FOPS(".stacked", 0666, &aa_fs_stacked),
+	AA_FS_FILE_FOPS(".ns_stacked", 0666, &aa_fs_ns_stacked),
+	AA_FS_FILE_FOPS(".ns_level", 0666, &aa_fs_ns_level),
+	AA_FS_FILE_FOPS(".ns_name", 0666, &aa_fs_ns_name),
+	AA_FS_FILE_FOPS("profiles", 0444, &aa_fs_profiles_fops),
 	AA_FS_DIR("features", aa_fs_entry_features),
 	{ }
 };
@@ -926,6 +1812,51 @@ void __init aa_destroy_aafs(void)
 	aafs_remove_dir(&aa_fs_entry);
 }
 
+
+#define NULL_FILE_NAME ".null"
+struct path aa_null;
+
+static int aa_mk_null_file(struct dentry *parent)
+{
+	struct vfsmount *mount = NULL;
+	struct dentry *dentry;
+	struct inode *inode;
+	int count = 0;
+	int error = simple_pin_fs(parent->d_sb->s_type, &mount, &count);
+	if (error)
+		return error;
+
+	inode_lock(d_inode(parent));
+	dentry = lookup_one_len(NULL_FILE_NAME, parent, strlen(NULL_FILE_NAME));
+	if (IS_ERR(dentry)) {
+		error = PTR_ERR(dentry);
+		goto out;
+	}
+	inode = new_inode(parent->d_inode->i_sb);
+	if (!inode) {
+		error = -ENOMEM;
+		goto out1;
+	}
+
+	inode->i_ino = get_next_ino();
+	inode->i_mode = S_IFCHR | S_IRUGO | S_IWUGO;
+	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
+	init_special_inode(inode, S_IFCHR | S_IRUGO | S_IWUGO,
+			   MKDEV(MEM_MAJOR, 3));
+	d_instantiate(dentry, inode);
+	aa_null.dentry = dget(dentry);
+	aa_null.mnt = mntget(mount);
+
+	error = 0;
+
+out1:
+	dput(dentry);
+out:
+	inode_unlock(d_inode(parent));
+	simple_release_fs(&mount, &count);
+	return error;
+}
+
 /**
  * aa_create_aafs - create the apparmor security filesystem
  *
@@ -935,6 +1866,7 @@ void __init aa_destroy_aafs(void)
  */
 static int __init aa_create_aafs(void)
 {
+	struct dentry *dent;
 	int error;
 
 	if (!apparmor_initialized)
@@ -950,12 +1882,52 @@ static int __init aa_create_aafs(void)
 	if (error)
 		goto error;
 
-	error = __aa_fs_namespace_mkdir(root_ns, aa_fs_entry.dentry,
-					"policy");
+	dent = securityfs_create_file(".load", 0666, aa_fs_entry.dentry,
+				      NULL, &aa_fs_profile_load);
+	if (IS_ERR(dent)) {
+		error = PTR_ERR(dent);
+		goto error;
+	}
+	ns_subload(root_ns) = dent;
+
+	dent = securityfs_create_file(".replace", 0666, aa_fs_entry.dentry,
+				      NULL, &aa_fs_profile_replace);
+	if (IS_ERR(dent)) {
+		error = PTR_ERR(dent);
+		goto error;
+	}
+	ns_subreplace(root_ns) = dent;
+
+	dent = securityfs_create_file(".remove", 0666, aa_fs_entry.dentry,
+				      NULL, &aa_fs_profile_remove);
+	if (IS_ERR(dent)) {
+		error = PTR_ERR(dent);
+		goto error;
+	}
+	ns_subremove(root_ns) = dent;
+
+	dent = securityfs_create_file("revision", 0444, aa_fs_entry.dentry,
+				      NULL, &ns_revision_fops);
+	if (IS_ERR(dent)) {
+		error = PTR_ERR(dent);
+		goto error;
+	}
+	ns_subrevision(root_ns) = dent;
+
+	mutex_lock(&root_ns->lock);
+	error = __aa_fs_ns_mkdir(root_ns, aa_fs_entry.dentry, "policy", NULL);
+	mutex_unlock(&root_ns->lock);
+
+	if (error)
+		goto error;
+
+	error = aa_mk_null_file(aa_fs_entry.dentry);
 	if (error)
 		goto error;
 
-	/* TODO: add support for apparmorfs_null and apparmorfs_mnt */
+	if (!aa_g_unconfined_init) {
+		/* TODO: add default profile to apparmorfs */
+	}
 
 	/* Report that AppArmor fs is enabled */
 	aa_info_message("AppArmor Filesystem Enabled");
diff --git a/security/apparmor/audit.c b/security/apparmor/audit.c
index 3a7f1da1425e..ec2daa2c3425 100644
--- a/security/apparmor/audit.c
+++ b/security/apparmor/audit.c
@@ -18,60 +18,8 @@
 #include "include/apparmor.h"
 #include "include/audit.h"
 #include "include/policy.h"
+#include "include/policy_ns.h"
 
-const char *const op_table[] = {
-	"null",
-
-	"sysctl",
-	"capable",
-
-	"unlink",
-	"mkdir",
-	"rmdir",
-	"mknod",
-	"truncate",
-	"link",
-	"symlink",
-	"rename_src",
-	"rename_dest",
-	"chmod",
-	"chown",
-	"getattr",
-	"open",
-
-	"file_perm",
-	"file_lock",
-	"file_mmap",
-	"file_mprotect",
-
-	"create",
-	"post_create",
-	"bind",
-	"connect",
-	"listen",
-	"accept",
-	"s