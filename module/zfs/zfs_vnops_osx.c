/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2013 Will Andrews <will@firepipe.net>
 * Copyright (c) 2013, 2016 Jorgen Lundman <lundman@lundman.net>
 * Copyright (c) 2017 Sean Doran <smd@use.net>.  All rights reserved.
 */

/*
 * OS X ZFS vnode operation wrappers.
 *
 * The argument structure layouts were obtained from:
 * http://www.opensource.apple.com/source/xnu/xnu-792.13.8/bsd/vfs/vfs_support.c
 * http://code.ohloh.net/project?pid=Ybsxw4FOQb8
 *
 * This file should contain primarily interface points; if an interface
 * definition is more than 100 lines long, parts of it should be refactored
 * into zfs_vnops_osx_lib.c.
 */

/*
 * XXX GENERAL COMPATIBILITY ISSUES
 *
 * 'name' is a common argument, but in OS X (and FreeBSD), we need to pass
 * the componentname pointer, so other things can use them.  We should
 * change the 'name' argument to be an opaque name pointer, and define
 * OS-dependent macros that yield the desired results when needed.
 *
 * On OS X, VFS performs access checks before calling anything, so
 * zfs_zaccess_* calls are not used.  Not true on FreeBSD, though.  Perhaps
 * those calls should be conditionally #if 0'd?
 *
 * On OS X, VFS & I/O objects are often opaque, e.g. uio_t and struct vnode
 * require using functions to access elements of an object.  Should convert
 * the Solaris code to use macros on other platforms.
 *
 * OS X and FreeBSD appear to use similar zfs-vfs interfaces; see Apple's
 * comment in zfs_remove() about the fact that VFS holds the last ref while
 * in Solaris it's the ZFS code that does.  On FreeBSD, the code Apple
 * refers to here results in a panic if the branch is actually taken.
 *
 * OS X uses vnode_put() in place of VN_RELE - needs a #define?
 * (Already is, see vnode.h)
 */

#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_ioctl.h>
#include <sys/fs/zfs.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/spa.h>
#include <sys/txg.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/sa.h>
#include <sys/zfs_vnops.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_rlock.h>
#include <sys/zfs_ctldir.h>

#include <sys/xattr.h>
#include <sys/utfconv.h>
#include <sys/ubc.h>
#include <sys/callb.h>
#include <sys/unistd.h>

#include <miscfs/fifofs/fifo.h>
#include <miscfs/specfs/specdev.h>
#include <vfs/vfs_support.h>
#include <sys/ioccom.h>

#include <sys/znode_z_map_lock.h>

extern const size_t MAX_UPL_SIZE_BYTES;

typedef struct vnops_osx_stats {
	kstat_named_t mmap_calls;
	kstat_named_t mmap_file_first_mmapped;
	kstat_named_t mnomap_calls;
	kstat_named_t reclaim_mapped;
	kstat_named_t bluster_pageout_calls;
	kstat_named_t bluster_pageout_dmu_bytes;
	kstat_named_t bluster_pageout_pages;
	kstat_named_t pageoutv2_calls;
	kstat_named_t pageoutv2_msync;
	kstat_named_t pageoutv2_pageout;
	kstat_named_t pageoutv2_want_lock;
	kstat_named_t pageoutv2_upl_iosync;
	kstat_named_t pageoutv2_no_pages_valid;
	kstat_named_t pageoutv2_invalid_tail_pages;
	kstat_named_t pageoutv2_present_pages_aborted;
	kstat_named_t pageoutv2_precious_pages_cleaned;
	kstat_named_t pageoutv2_dirty_pages_blustered;
	kstat_named_t pageoutv2_error;
	kstat_named_t pageoutv1_pages;
	kstat_named_t pageoutv1_want_lock;
	kstat_named_t pagein_calls;
	kstat_named_t pagein_pages;
	kstat_named_t pagein_want_lock;
} vnops_osx_stats_t;

static vnops_osx_stats_t vnops_osx_stats = {
	/* */
	{ "mmap_calls",                        KSTAT_DATA_UINT64 },
	{ "mmap_file_first_mmapped",           KSTAT_DATA_UINT64 },
	{ "mnomap_calls",                      KSTAT_DATA_UINT64 },
	{ "reclaim_mapped",                    KSTAT_DATA_UINT64 },
	{ "bluster_pageout_calls",             KSTAT_DATA_UINT64 },
	{ "bluster_pageout_dmu_bytes",         KSTAT_DATA_UINT64 },
	{ "bluster_pageout_pages",             KSTAT_DATA_UINT64 },
	{ "pageoutv2_calls",                   KSTAT_DATA_UINT64 },
	{ "pageoutv2_msync",                   KSTAT_DATA_UINT64 },
	{ "pageoutv2_pageout",                 KSTAT_DATA_UINT64 },
	{ "pageoutv2_want_lock",               KSTAT_DATA_UINT64 },
	{ "pageoutv2_upl_iosync",              KSTAT_DATA_UINT64 },
	{ "pageoutv2_no_pages_valid",          KSTAT_DATA_UINT64 },
	{ "pageoutv2_invalid_tail_pages",      KSTAT_DATA_UINT64 },
	{ "pageoutv2_present_pages_aborted",   KSTAT_DATA_UINT64 },
	{ "pageoutv2_precious_pages_cleaned",  KSTAT_DATA_UINT64 },
	{ "pageoutv2_dirty_pages_blustered",   KSTAT_DATA_UINT64 },
	{ "pageoutv2_error",                   KSTAT_DATA_UINT64 },
	{ "pageoutv1_pages",                   KSTAT_DATA_UINT64 },
	{ "pageoutv1_want_lock",               KSTAT_DATA_UINT64 },
	{ "pagein_calls",                      KSTAT_DATA_UINT64 },
	{ "pagein_pages",                      KSTAT_DATA_UINT64 },
	{ "pagein_want_lock",                  KSTAT_DATA_UINT64 },
};

#define VNOPS_OSX_STAT(statname)           (vnops_osx_stats.statname.value.ui64)
#define VNOPS_OSX_STAT_INCR(statname, val) \
	atomic_add_64(&vnops_osx_stats.statname.value.ui64, (val))
#define VNOPS_OSX_STAT_BUMP(stat)      VNOPS_OSX_STAT_INCR(stat, 1)
#define VNOPS_OSX_STAT_BUMPDOWN(stat)  VNOPS_OSX_STAT_INCR(stat, -1)

static kstat_t *vnops_osx_ksp;

void
vnops_osx_stat_init(void)
{
	vnops_osx_ksp = kstat_create("zfs", 0, "vnops_osx", "misc", KSTAT_TYPE_NAMED,
	    sizeof (vnops_osx_stats) / sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);
	if (vnops_osx_ksp != NULL) {
		vnops_osx_ksp->ks_data = &vnops_osx_stats;
		kstat_install(vnops_osx_ksp);
	}
}

void
vnops_osx_stat_fini(void)
{
	if (vnops_osx_ksp != NULL) {
		kstat_delete(vnops_osx_ksp);
		vnops_osx_ksp = NULL;
	}
}

#ifdef _KERNEL
#include <sys/sysctl.h>
#include <sys/hfs_internal.h>

unsigned int debug_vnop_osx_printf = 0;
unsigned int zfs_vnop_ignore_negatives = 0;
unsigned int zfs_vnop_ignore_positives = 0;
unsigned int zfs_vnop_create_negatives = 1;
#endif

#define	DECLARE_CRED(ap) \
	cred_t *cr = (cred_t *)vfs_context_ucred((ap)->a_context)
#define	DECLARE_CONTEXT(ap) \
	caller_context_t *ct = (caller_context_t *)(ap)->a_context
#define	DECLARE_CRED_AND_CONTEXT(ap)	\
	DECLARE_CRED(ap);		\
	DECLARE_CONTEXT(ap)

#undef dprintf
#define	dprintf if (debug_vnop_osx_printf) printf
//#define	dprintf if (debug_vnop_osx_printf) kprintf
//#define dprintf kprintf

//#define	dprintf(...) if (debug_vnop_osx_printf) {printf(__VA_ARGS__);delay(hz>>2);}

/*
 * zfs vfs operations.
 */
static struct vfsops zfs_vfsops_template = {
	zfs_vfs_mount,
	zfs_vfs_start,
	zfs_vfs_unmount,
	zfs_vfs_root,
	zfs_vfs_quotactl,
	zfs_vfs_getattr,
	zfs_vfs_sync,
	zfs_vfs_vget,
	zfs_vfs_fhtovp,
	zfs_vfs_vptofh,
	zfs_vfs_init,
	zfs_vfs_sysctl,
	zfs_vfs_setattr,
#if defined (MAC_OS_X_VERSION_10_12) &&							\
	(MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12)
	NULL, /* vfs_ioctl */
	NULL, /* vfs_vget_snapdir */
	NULL
#else
	{NULL}
#endif
};
extern struct vnodeopv_desc zfs_dvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_fvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_symvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_xdvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_evnodeop_opv_desc;
extern struct vnodeopv_desc zfs_fifonodeop_opv_desc;

extern struct vnodeopv_desc zfsctl_ops_root;
extern struct vnodeopv_desc zfsctl_ops_snapdir;
extern struct vnodeopv_desc zfsctl_ops_snapshot;

#define	ZFS_VNOP_TBL_CNT	8


static struct vnodeopv_desc *zfs_vnodeop_opv_desc_list[ZFS_VNOP_TBL_CNT] =
{
	&zfs_dvnodeop_opv_desc,
	&zfs_fvnodeop_opv_desc,
	&zfs_symvnodeop_opv_desc,
	&zfs_xdvnodeop_opv_desc,
	//&zfs_evnodeop_opv_desc,
	&zfs_fifonodeop_opv_desc,
	&zfsctl_ops_root,
	&zfsctl_ops_snapdir,
	&zfsctl_ops_snapshot,
};

static vfstable_t zfs_vfsconf;

int
zfs_vfs_init(__unused struct vfsconf *vfsp)
{
	return (0);
}

int
zfs_vfs_start(__unused struct mount *mp, __unused int flags,
    __unused vfs_context_t context)
{
	return (0);
}

int
zfs_vfs_quotactl(__unused struct mount *mp, __unused int cmds,
    __unused uid_t uid, __unused caddr_t datap, __unused vfs_context_t context)
{
dprintf("%s ENOTSUP\n", __func__);
	return (ENOTSUP);
}

static kmutex_t		zfs_findernotify_lock;
static kcondvar_t	zfs_findernotify_thread_cv;
static boolean_t	zfs_findernotify_thread_exit;

#define VNODE_EVENT_ATTRIB              0x00000008

static int
zfs_findernotify_callback(mount_t mp, __unused void *arg)
{
	/* Do some quick checks to see if it is ZFS */
	struct vfsstatfs *vsf = vfs_statfs(mp);

	// Filesystem ZFS?
	if (vsf->f_fssubtype == MNTTYPE_ZFS_SUBTYPE) {
		vfs_context_t kernelctx = spl_vfs_context_kernel();
		struct vnode *rootvp, *vp;

		/* Since potentially other filesystems could be using "our"
		 * fssubtype, and we don't always announce as "zfs" due to
		 * hfs-mimic requirements, we have to make extra care here to
		 * make sure this "mp" really is ZFS.
		 */
		zfsvfs_t *zfsvfs;

		zfsvfs = vfs_fsprivate(mp);

		/* The first entry in struct zfsvfs is the vfs ptr, so they
		 * should be equal if it is ZFS
		 */
		if (!zfsvfs ||
			(mp != zfsvfs->z_vfs))
			return (VFS_RETURNED);

		/* Guard against unmount */
		ZFS_ENTER_NOERROR(zfsvfs);
		if (zfsvfs->z_unmounted) goto out;

		/* Check if space usage has changed sufficiently to bother updating */
		uint64_t refdbytes, availbytes, usedobjs, availobjs;
		uint64_t delta;
		dmu_objset_space(zfsvfs->z_os,
						 &refdbytes, &availbytes, &usedobjs, &availobjs);
		if (availbytes >= zfsvfs->z_findernotify_space) {
			delta = availbytes - zfsvfs->z_findernotify_space;
		} else {
			delta = zfsvfs->z_findernotify_space - availbytes;
		}

#define ZFS_FINDERNOTIFY_THRESHOLD (1ULL<<20)

		/* Under the limit ? */
		if (delta <= ZFS_FINDERNOTIFY_THRESHOLD) goto out;

		/* Over threadhold, so we will notify finder, remember the value */
		zfsvfs->z_findernotify_space = availbytes;

		/* If old value is zero (first run), don't bother sending events */
		if (availbytes == delta)
			goto out;

		dprintf("ZFS: findernotify %p space delta %llu\n", mp, delta);

		// Grab the root zp
		if (!VFS_ROOT(mp, 0, &rootvp)) {

			struct componentname cn;
			char *tmpname = ".fseventsd";

			bzero(&cn, sizeof(cn));
			cn.cn_nameiop = LOOKUP;
			cn.cn_flags = ISLASTCN;
			//cn.cn_context = kernelctx;
			cn.cn_pnbuf = tmpname;
			cn.cn_pnlen = sizeof(tmpname);
			cn.cn_nameptr = cn.cn_pnbuf;
			cn.cn_namelen = strlen(tmpname);

			// Attempt to lookup .Trashes
			if (!VOP_LOOKUP(rootvp, &vp, &cn, kernelctx)) {

				// Send the event to wake up Finder
				struct vnode_attr vattr;
				// Also calls VATTR_INIT
				spl_vfs_get_notify_attributes(&vattr);
				// Fill in vap
				vnode_getattr(vp, &vattr, kernelctx);
				// Send event
				spl_vnode_notify(vp, VNODE_EVENT_ATTRIB, &vattr);

				// Cleanup vp
				vnode_put(vp);

			} // VNOP_LOOKUP

			// Cleanup rootvp
			vnode_put(rootvp);

		} // VFS_ROOT

	  out:
		ZFS_EXIT(zfsvfs);

	} // SUBTYPE_ZFS

	return (VFS_RETURNED);
}


static void
zfs_findernotify_thread(void *notused)
{
	callb_cpr_t		cpr;

	dprintf("ZFS: findernotify thread start\n");
	CALLB_CPR_INIT(&cpr, &zfs_findernotify_lock, callb_generic_cpr, FTAG);

	mutex_enter(&zfs_findernotify_lock);
	while (!zfs_findernotify_thread_exit) {

		/* Sleep 32 seconds */
		CALLB_CPR_SAFE_BEGIN(&cpr);
		(void) cv_timedwait(&zfs_findernotify_thread_cv,
							&zfs_findernotify_lock, ddi_get_lbolt() + (hz<<5));
		CALLB_CPR_SAFE_END(&cpr, &zfs_findernotify_lock);

		if (!zfs_findernotify_thread_exit)
			vfs_iterate(LK_NOWAIT, zfs_findernotify_callback, NULL);

	}

	zfs_findernotify_thread_exit = FALSE;
	cv_broadcast(&zfs_findernotify_thread_cv);
	CALLB_CPR_EXIT(&cpr);		/* drops arc_reclaim_lock */
	dprintf("ZFS: findernotify thread exit\n");
	thread_exit();
}

void zfs_start_notify_thread(void)
{
	mutex_init(&zfs_findernotify_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&zfs_findernotify_thread_cv, NULL, CV_DEFAULT, NULL);
	zfs_findernotify_thread_exit = FALSE;
	(void) thread_create(NULL, 0, zfs_findernotify_thread, NULL, 0, &p0,
	    TS_RUN, minclsyspri);
}


void zfs_stop_notify_thread(void)
{
	mutex_enter(&zfs_findernotify_lock);
	zfs_findernotify_thread_exit = TRUE;
	/*
	 * The reclaim thread will set arc_reclaim_thread_exit back to
	 * FALSE when it is finished exiting; we're waiting for that.
	 */
	while (zfs_findernotify_thread_exit) {
		cv_signal(&zfs_findernotify_thread_cv);
		cv_wait(&zfs_findernotify_thread_cv, &zfs_findernotify_lock);
	}
	mutex_exit(&zfs_findernotify_lock);
	mutex_destroy(&zfs_findernotify_lock);
	cv_destroy(&zfs_findernotify_thread_cv);
}



/*
 * All these functions could be declared as 'static' but to assist with
 * dtrace debugging, we do not.
 */

int
zfs_vnop_open(struct vnop_open_args *ap)
#if 0
	struct vnop_open_args {
		struct vnode	*a_vp;
		int		a_mode;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int err = 0;

	err = zfs_open(&ap->a_vp, ap->a_mode, cr, ct);

	if (err) dprintf("zfs_open() failed %d\n", err);
	return (err);
}

int
zfs_vnop_close(struct vnop_close_args *ap)
#if 0
	struct vnop_close_args {
		struct vnode	*a_vp;
		int		a_fflag;
		vfs_context_t	a_context;
	};
#endif
{
	int count = 1;
	int offset = 0;
	DECLARE_CRED_AND_CONTEXT(ap);

	return (zfs_close(ap->a_vp, ap->a_fflag, count, offset, cr, ct));
}

int
zfs_vnop_ioctl(struct vnop_ioctl_args *ap)
#if 0
	struct vnop_ioctl_args {
		struct vnode	*a_vp;
		u_long		a_command;
		caddr_t		a_data;
		int		a_fflag;
		kauth_cred_t	a_cred;
		struct proc	*a_p;
	};
#endif
{
	/* OS X has no use for zfs_ioctl(). */
	znode_t *zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error = 0;
	DECLARE_CRED_AND_CONTEXT(ap);

	dprintf("vnop_ioctl %08lx: VTYPE %d\n", ap->a_command,
			vnode_vtype(ZTOV(zp)));

	ZFS_ENTER(zfsvfs);
	if (IFTOVT((mode_t)zp->z_mode) == VFIFO) {
		dprintf("ZFS: FIFO ioctl  %02lx ('%lu' + %lu)\n",
			   ap->a_command, (ap->a_command&0xff00)>>8,
			   ap->a_command&0xff);
		error = fifo_ioctl(ap);
		error = 0;
		ZFS_EXIT(zfsvfs);
		goto out;
	}

	if ((IFTOVT((mode_t)zp->z_mode) == VBLK) ||
		(IFTOVT((mode_t)zp->z_mode) == VCHR)) {
		dprintf("ZFS: spec ioctl  %02lx ('%lu' + %lu)\n",
			   ap->a_command, (ap->a_command&0xff00)>>8,
			   ap->a_command&0xff);
		error = spec_ioctl(ap);
		ZFS_EXIT(zfsvfs);
		goto out;
	}
	ZFS_EXIT(zfsvfs);

	switch (ap->a_command) {

		/* ioctl supported by ZFS and POSIX */

		case F_FULLFSYNC:
			dprintf("%s F_FULLFSYNC\n", __func__);
#ifdef F_BARRIERFSYNC
		case F_BARRIERFSYNC:
			dprintf("%s F_BARRIERFSYNC\n", __func__);
#endif
			error = zfs_fsync(ap->a_vp, /* flag */0, cr, ct);
		case F_CHKCLEAN:
			dprintf("%s F_CHKCLEAN\n", __func__);
			/* normally calls http://fxr.watson.org/fxr/source/bsd/vfs/vfs_cluster.c?v=xnu-2050.18.24#L5839 */
			/* XXX Why don't we? */
off_t fsize = zp->z_size;
			error = is_file_clean(ap->a_vp, fsize);
			//error = is_file_clean(ap->a_vp, zp->z_size);

/* XXX be loud */
printf("F_CHKCLEAN size %llu ret %d\n", fsize, error);
			if (error) dprintf("F_CHKCLEAN ret %d\n", error);
			break;

		case F_RDADVISE:
			dprintf("%s F_RDADVISE\n", __func__);
			uint64_t file_size;
			struct radvisory *ra;
			int len;

			ra = (struct radvisory *)(ap->a_data);

			file_size = zp->z_size;
			len = ra->ra_count;

			/* XXX Check request size */
			if (ra->ra_offset > file_size) {
				dprintf("invalid request offset\n");
				error = EFBIG;
				break;
			}

			if ((ra->ra_offset + len) > file_size) {
				len = file_size - ra->ra_offset;
				dprintf("%s truncating F_RDADVISE from"
				    " %08x -> %08x\n", __func__,
				    ra->ra_count, len);
			}

			/*
			 * Rather than advisory_read (which calls
			 * cluster_io->VNOP_BLOCKMAP), prefetch
			 * the level 0 metadata and level 1 data
			 * at the requested offset + length.
			 */
			//error = advisory_read(ap->a_vp, file_size,
			//    ra->ra_offset, len);
			dmu_prefetch(zfsvfs->z_os, zp->z_id,
			    0, 0, 0, ZIO_PRIORITY_ASYNC_READ);
			dmu_prefetch(zfsvfs->z_os, zp->z_id,
			    1, ra->ra_offset, len,
			    ZIO_PRIORITY_ASYNC_READ);

			/* follow some of the logic from advisory_read_ext */



#if 0
	{
		const char *name = vnode_getname(ap->a_vp);
		printf("%s F_RDADVISE: prefetch issued for "
		    "[%s](0x%016llx) (0x%016llx 0x%08x)\n", __func__,
		    (name ? name : ""), zp->z_id,
		    ra->ra_offset, len);
		if (name) vnode_putname(name);
	}
#endif

			break;

		case SPOTLIGHT_GET_MOUNT_TIME:
			dprintf("%s SPOTLIGHT_GET_MOUNT_TIME\n", __func__);
			*(uint32_t *)ap->a_data = zfsvfs->z_mount_time;
			break;
		case SPOTLIGHT_FSCTL_GET_MOUNT_TIME:
			dprintf("%s SPOTLIGHT_FSCTL_GET_MOUNT_TIME\n", __func__);
			*(uint32_t *)ap->a_data = zfsvfs->z_mount_time;
			break;

		case SPOTLIGHT_GET_UNMOUNT_TIME:
			dprintf("%s SPOTLIGHT_GET_UNMOUNT_TIME\n", __func__);
			*(uint32_t *)ap->a_data = zfsvfs->z_last_unmount_time;
			break;
		case SPOTLIGHT_FSCTL_GET_LAST_MTIME:
			dprintf("%s SPOTLIGHT_FSCTL_GET_LAST_MTIME\n", __func__);
			*(uint32_t *)ap->a_data = zfsvfs->z_last_unmount_time;
			break;

		case HFS_SET_ALWAYS_ZEROFILL:
			dprintf("%s HFS_SET_ALWAYS_ZEROFILL\n", __func__);
			/* Required by Spotlight search */
			break;
		case HFS_EXT_BULKACCESS_FSCTL:
			dprintf("%s HFS_EXT_BULKACCESS_FSCTL\n", __func__);
			/* Required by Spotlight search */
			break;

		/* ioctl required to simulate HFS mimic behavior */
		case 0x80005802:
			dprintf("%s 0x80005802 unknown\n", __func__);
			/* unknown as to what this is - is from subsystem read, 'X', 2 */
			break;

		case HFS_GETPATH:
			dprintf("%s HFS_GETPATH\n", __func__);
  		    {
				struct vfsstatfs *vfsp;
				struct vnode *file_vp;
				ino64_t cnid;
				int  outlen;
				char *bufptr;
				int flags = 0;

				/* Caller must be owner of file system. */
				vfsp = vfs_statfs(zfsvfs->z_vfs);
				/*if (suser((kauth_cred_t)cr, NULL) &&  APPLE denied suser */
				if (proc_suser(current_proc()) &&
					kauth_cred_getuid((kauth_cred_t)cr) != vfsp->f_owner) {
					error = EACCES;
					goto out;
				}
				/* Target vnode must be file system's root. */
				if (!vnode_isvroot(ap->a_vp)) {
					error = EINVAL;
					goto out;
				}

				/* We are passed a string containing a inode number */
				bufptr = (char *)ap->a_data;
                cnid = strtoul(bufptr, NULL, 10);
                if (ap->a_fflag & HFS_GETPATH_VOLUME_RELATIVE) {
					flags |= BUILDPATH_VOLUME_RELATIVE;
                }

				if ((error = zfs_vfs_vget(zfsvfs->z_vfs, cnid, &file_vp,
										  (vfs_context_t)ct))) {
					goto out;
                }
                error = build_path(file_vp, bufptr, MAXPATHLEN,
								   &outlen, flags, (vfs_context_t)ct);
                vnode_put(file_vp);

				dprintf("ZFS: HFS_GETPATH done %d : '%s'\n", error,
					   error ? "" : bufptr);
			}
			break;

		case HFS_TRANSFER_DOCUMENT_ID:
			dprintf("%s HFS_TRANSFER_DOCUMENT_ID\n", __func__);
		    {
				u_int32_t to_fd = *(u_int32_t *)ap->a_data;
				file_t *to_fp;
				struct vnode *to_vp;
				znode_t *to_zp;

				to_fp = getf(to_fd);
				if (to_fp == NULL) {
					error = EBADF;
					goto out;
				}

				to_vp = getf_vnode(to_fp);

				if ( (error = vnode_getwithref(to_vp)) ) {
					releasef(to_fd);
					goto out;
				}

				/* Confirm it is inside our mount */
				if (((zfsvfs_t *)vfs_fsprivate(vnode_mount((to_vp)))) != zfsvfs) {
					error = EXDEV;
					goto transfer_out;
				}

				to_zp = VTOZ(to_vp);

				/* Source should have UF_TRACKED */
				if (!(zp->z_pflags & ZFS_TRACKED)) {
					dprintf("ZFS: source is not TRACKED\n");
					error = EINVAL;
					/* destination should NOT have UF_TRACKED */
				} else if (to_zp->z_pflags & ZFS_TRACKED) {
					dprintf("ZFS: destination is already TRACKED\n");
					error = EEXIST;
					/* should be valid types */
				} else if ((IFTOVT((mode_t)zp->z_mode) == VDIR) ||
						   (IFTOVT((mode_t)zp->z_mode) == VREG) ||
						   (IFTOVT((mode_t)zp->z_mode) == VLNK)) {
					/* Make sure source has a document id  - although it can't*/
					if (!zp->z_document_id)
						zfs_setattr_generate_id(zp, 0, NULL);

					/* transfer over */
					to_zp->z_document_id = zp->z_document_id;
					zp->z_document_id = 0;
					to_zp->z_pflags |= ZFS_TRACKED;
					zp->z_pflags &= ~ZFS_TRACKED;

					/* Commit to disk */
					zfs_setattr_set_documentid(to_zp, B_TRUE);
					zfs_setattr_set_documentid(zp, B_TRUE); /* also update flags */
					dprintf("ZFS: Moved docid %u from id %llu to id %llu\n",
						   to_zp->z_document_id, zp->z_id, to_zp->z_id);
				}
			  transfer_out:
				vnode_put(to_vp);
				releasef(to_fd);
			}
			break;


		case F_MAKECOMPRESSED:
			dprintf("%s F_MAKECOMPRESSED\n", __func__);
			/*
			 * Not entirely sure what this does, but HFS comments include:
			 * "Make the file compressed; truncate & toggle BSD bits"
			 * makes compressed copy of allocated blocks
			 * shortens file to new length
			 * sets BSD bits to indicate per-file compression
			 *
			 * On HFS, locks cnode and compresses its data. ZFS inband
			 * compression makes this obsolete.
			 */
			if (vfs_isrdonly(zfsvfs->z_vfs) ||
			    vfs_flags(zfsvfs->z_vfs) & MNT_RDONLY ||
			    !spa_writeable(dmu_objset_spa(zfsvfs->z_os))) {
				error = EROFS;
				goto out;
			}

			/* Are there any other usecounts/FDs? */
			if (vnode_isinuse(ap->a_vp, 1)) {
				error = EBUSY;
				goto out;
			}

			if (zp->z_pflags & ZFS_IMMUTABLE) {
				error = EINVAL;
				goto out;
			}

			/* Return success */
			error = 0;
			break;

		case HFS_PREV_LINK:
		case HFS_NEXT_LINK:
			dprintf("%s HFS_PREV/NEXT_LINK\n", __func__);
		{
			/*
			 * Find sibling linkids with hardlinks. a_data points to the
			 * "current" linkid, and look up either prev or next (a_command)
			 * linkid. Return in a_data.
			 */
			uint32_t linkfileid;
			struct vfsstatfs *vfsp;
			/* Caller must be owner of file system. */
			vfsp = vfs_statfs(zfsvfs->z_vfs);
			if ((kauth_cred_getuid(cr) == 0) &&
				kauth_cred_getuid(cr) != vfsp->f_owner) {
				error = EACCES;
				goto out;
			}
			/* Target vnode must be file system's root. */
			if (!vnode_isvroot(ap->a_vp)) {
				error = EINVAL;
				goto out;
			}
			linkfileid = *(uint32_t *)ap->a_data;
			if (linkfileid < 16 ) { /* kHFSFirstUserCatalogNodeID */
				error = EINVAL;
				goto out;
			}

			/* Attempt to find the linkid in the hardlink_link AVL tree
			 * If found, call to get prev or next.
			 */
			hardlinks_t *searchnode, *findnode, *sibling;
			avl_index_t loc;

			searchnode = kmem_alloc(sizeof(hardlinks_t), KM_SLEEP);
			searchnode->hl_linkid = linkfileid;

			rw_enter(&zfsvfs->z_hardlinks_lock, RW_READER);
			findnode = avl_find(&zfsvfs->z_hardlinks_linkid, searchnode, &loc);
			kmem_free(searchnode, sizeof(hardlinks_t));

			if (!findnode) {
				rw_exit(&zfsvfs->z_hardlinks_lock);
				*(uint32_t *)ap->a_data = 0;
				dprintf("ZFS: HFS_NEXT_LINK/HFS_PREV_LINK %u not found\n",
					linkfileid);
				goto out;
			}

			if (ap->a_command != HFS_NEXT_LINK) {

				// Walk the next nodes, looking for fileid to match
				while ((sibling = AVL_NEXT(&zfsvfs->z_hardlinks_linkid,
										   findnode)) != NULL) {
					if (findnode->hl_fileid == sibling->hl_fileid)
						break;
				}

			} else {

				// Walk the prev nodes, looking for fileid to match
				while ((sibling = AVL_PREV(&zfsvfs->z_hardlinks_linkid,
										   findnode)) != NULL) {
					if (findnode->hl_fileid == sibling->hl_fileid)
						break;
				}

			}
			rw_exit(&zfsvfs->z_hardlinks_lock);

			dprintf("ZFS: HFS_%s_LINK %u sibling %u\n",
					(ap->a_command != HFS_NEXT_LINK) ? "NEXT" : "PREV",
					linkfileid,
					sibling ? sibling->hl_linkid : 0);

			// Did we get a new node?
			if (sibling == NULL) {
				*(uint32_t *)ap->a_data = 0;
				goto out;
			}

			*(uint32_t *)ap->a_data = sibling->hl_linkid;
			error = 0;
		}
			break;

		case HFS_RESIZE_PROGRESS:
			dprintf("%s HFS_RESIZE_PROGRESS\n", __func__);
			/* fail as if requested of non-root fs */
			error = EINVAL;
			break;

		case HFS_RESIZE_VOLUME:
			dprintf("%s HFS_RESIZE_VOLUME\n", __func__);
			/* fail as if requested of non-root fs */
			error = EINVAL;
			break;

		case HFS_CHANGE_NEXT_ALLOCATION:
			dprintf("%s HFS_CHANGE_NEXT_ALLOCATION\n", __func__);
			/* fail as if requested of non-root fs */
			error = EINVAL;
			break;

		case HFS_CHANGE_NEXTCNID:
			dprintf("%s HFS_CHANGE_NEXTCNID\n", __func__);
			/* FIXME : fail as though read only */
			error = EROFS;
			break;

		case F_FREEZE_FS:
			dprintf("%s F_FREEZE_FS\n", __func__);
			/* Dont support freeze */
			error = ENOTSUP;
			break;

		case F_THAW_FS:
			dprintf("%s F_THAW_FS\n", __func__);
			/* dont support fail as though insufficient privilege */
			error = EACCES;
			break;

		case HFS_BULKACCESS_FSCTL:
			dprintf("%s HFS_BULKACCESS_FSCTL\n", __func__);
			/* Respond as if HFS_STANDARD flag is set */
			error = EINVAL;
			break;

		case HFS_FSCTL_GET_VERY_LOW_DISK:
			dprintf("%s HFS_FSCTL_GET_VERY_LOW_DISK\n", __func__);
			*(uint32_t*)ap->a_data = zfsvfs->z_freespace_notify_dangerlimit;
			break;

		case HFS_FSCTL_SET_VERY_LOW_DISK:
			dprintf("%s HFS_FSCTL_SET_VERY_LOW_DISK\n", __func__);
			if (*(uint32_t *)ap->a_data >= zfsvfs->z_freespace_notify_warninglimit) {
				error = EINVAL;
			} else {
				zfsvfs->z_freespace_notify_dangerlimit = *(uint32_t *)ap->a_data;
            }
			break;

		case HFS_FSCTL_GET_LOW_DISK:
			dprintf("%s HFS_FSCTL_GET_LOW_DISK\n", __func__);
			*(uint32_t*)ap->a_data = zfsvfs->z_freespace_notify_warninglimit;
			break;

		case HFS_FSCTL_SET_LOW_DISK:
			dprintf("%s HFS_FSCTL_SET_LOW_DISK\n", __func__);
			if (   *(uint32_t *)ap->a_data >= zfsvfs->z_freespace_notify_desiredlevel
				   || *(uint32_t *)ap->a_data <= zfsvfs->z_freespace_notify_dangerlimit) {
				error = EINVAL;
			} else {
				zfsvfs->z_freespace_notify_warninglimit = *(uint32_t *)ap->a_data;
			}
			break;

		case HFS_FSCTL_GET_DESIRED_DISK:
			dprintf("%s HFS_FSCTL_GET_DESIRED_DISK\n", __func__);
			*(uint32_t*)ap->a_data = zfsvfs->z_freespace_notify_desiredlevel;
			break;

		case HFS_FSCTL_SET_DESIRED_DISK:
			dprintf("%s HFS_FSCTL_SET_DESIRED_DISK\n", __func__);
			if (*(uint32_t *)ap->a_data <= zfsvfs->z_freespace_notify_warninglimit) {
				error = EINVAL;
			} else {
				zfsvfs->z_freespace_notify_desiredlevel = *(uint32_t *)ap->a_data;
			}
			break;

		case HFS_VOLUME_STATUS:
			dprintf("%s HFS_VOLUME_STATUS\n", __func__);
			/* For now we always reply "all ok" */
			*(uint32_t *)ap->a_data = zfsvfs->z_notification_conditions;
			break;

		case HFS_SET_BOOT_INFO:
			dprintf("%s HFS_SET_BOOT_INFO\n", __func__);
			/* ZFS booting is not supported, mimic selection of a non-root HFS volume */
			*(uint32_t *)ap->a_data = 0;
			error = EINVAL;
			break;
		case HFS_GET_BOOT_INFO:
			{
				u_int32_t       vcbFndrInfo[8];
				printf("%s HFS_GET_BOOT_INFO\n", __func__);
				/* ZFS booting is not supported, mimic selection of a non-root HFS volume */
				memset(vcbFndrInfo, 0, sizeof(vcbFndrInfo));
				struct vfsstatfs *vfsstatfs;
				vfsstatfs = vfs_statfs(zfsvfs->z_vfs);
				vcbFndrInfo[6] = vfsstatfs->f_fsid.val[0];
				vcbFndrInfo[7] = vfsstatfs->f_fsid.val[1];
				bcopy(vcbFndrInfo, ap->a_data, sizeof(vcbFndrInfo));
			}
			break;
		case HFS_MARK_BOOT_CORRUPT:
			dprintf("%s HFS_MARK_BOOT_CORRUPT\n", __func__);
			/* ZFS booting is not supported, mimic selection of a non-root HFS volume */
			*(uint32_t *)ap->a_data = 0;
			error = EINVAL;
			break;

		case HFS_FSCTL_GET_JOURNAL_INFO:
dprintf("%s HFS_FSCTL_GET_JOURNAL_INFO\n", __func__);
/* XXX We're setting the mount as 'Journaled' so this might conflict */
			/* Respond as though journal is empty/disabled */
		{
		    struct hfs_journal_info *jip;
		    jip = (struct hfs_journal_info*)ap->a_data;
		    jip->jstart = 0;
		    jip->jsize = 0;
		}
		break;

		case HFS_DISABLE_METAZONE:
			dprintf("%s HFS_DISABLE_METAZONE\n", __func__);
			/* fail as though insufficient privs */
			error = EACCES;
			break;

#ifdef HFS_GET_FSINFO
		case HFS_GET_FSINFO:
			dprintf("%s HFS_GET_FSINFO\n", __func__);
			break;
#endif

#ifdef HFS_REPIN_HOTFILE_STATE
		case HFS_REPIN_HOTFILE_STATE:
			dprintf("%s HFS_REPIN_HOTFILE_STATE\n", __func__);
			break;
#endif

#ifdef HFS_SET_HOTFILE_STATE
		case HFS_SET_HOTFILE_STATE:
			dprintf("%s HFS_SET_HOTFILE_STATE\n", __func__);
			break;
#endif

			/* End HFS mimic ioctl */


		default:
			dprintf("%s: Unknown ioctl %02lx ('%lu' + %lu)\n",
			    __func__, ap->a_command, (ap->a_command&0xff00)>>8,
			    ap->a_command&0xff);
			error = ENOTTY;
	}

  out:
	if (error) {
		dprintf("%s: failing ioctl: %02lx ('%lu' + %lu) returned %d\n",
		    __func__, ap->a_command, (ap->a_command&0xff00)>>8,
		    ap->a_command&0xff, error);
	}

	return (error);
}


int
zfs_vnop_read(struct vnop_read_args *ap)
#if 0
	struct vnop_read_args {
		struct vnode	*a_vp;
		struct uio	*a_uio;
		int		a_ioflag;
		vfs_context_t	a_context;
	};
#endif
{
	int ioflag = zfs_ioflags(ap->a_ioflag);
	int error;
	/* uint64_t resid; */
	DECLARE_CRED_AND_CONTEXT(ap);

	/* resid = uio_resid(ap->a_uio); */
	error = zfs_read(ap->a_vp, ap->a_uio, ioflag, cr, ct);

	if (error) dprintf("vnop_read %d\n", error);
	return (error);
}

int
zfs_vnop_write(struct vnop_write_args *ap)
#if 0
	struct vnop_write_args {
		struct vnode	*a_vp;
		struct uio	*a_uio;
		int		a_ioflag;
		vfs_context_t	a_context;
	};
#endif
{
	int ioflag = zfs_ioflags(ap->a_ioflag);
	int error = 0;

	DECLARE_CRED_AND_CONTEXT(ap);

	dprintf("zfs_vnop_write(vp %p, offset 0x%llx size 0x%llx\n",
	    ap->a_vp, uio_offset(ap->a_uio), uio_resid(ap->a_uio));

	/*
	 * Loop down to zfs_write which will make progress on the uio;
	 * we only return to the writer when we get either error != 0 OR
	 * uio_resid == 0.
	 */

	uio_t *uio = ap->a_uio;
	const off_t start_resid = uio_resid(uio);
	const off_t start_eof = ubc_getsize(ap->a_vp);
	int64_t cur_resid = start_resid;

	if (start_resid == 0) {
		/* zero length write */
		return (0);
	}

	ASSERT3S(cur_resid, >, 0);
	off_t cum_bytes = 0;
	char *file_name = NULL;

	const hrtime_t start_time = gethrtime();
	off_t last_resid = uio_resid(uio);
	boolean_t old_style = B_FALSE;

	for (int i = 0; cur_resid > 0; cur_resid = uio_resid(uio)) {
		i++;
		if (i > 1) {
			uint64_t elapsed_msec = NSEC2MSEC(gethrtime() - start_time);
			printf("ZFS: %s:%d (retry %d, msec %lld) continuing to progress uio"
			    " (resid = %lld) for file %s (cum_bytes %lld, old_style %d)\n",
			    __func__, __LINE__,
			    i, elapsed_msec, cur_resid,
			    (file_name != NULL) ? file_name : "(NULL)", cum_bytes, old_style);
			extern void IOSleep(unsigned milliseconds);
			IOSleep(i);
		}

		error = zfs_write(ap->a_vp, ap->a_uio, ioflag, cr, ct, &file_name, old_style);

		if (error) {
			uint64_t elapsed_msec = NSEC2MSEC(gethrtime() - start_time);
			printf("ZFS: %s:%d error %d pass %d msec %lld from zfs_write for file"
			    " %s (cum_bytes %lld)\n",
			    __func__, __LINE__, error, i, elapsed_msec,
			    (file_name != NULL) ? file_name : "(NULL)", cum_bytes);
			break;
		}

		/* finished everything OK */
		if (uio_resid(uio) == 0)
			return (0);

		if (error == -ERANGE) {
			printf("ZFS: %s:%d: error == -ERANGE (%d), returning uio_resid %lld\n",
			    __func__, __LINE__, error, uio_resid(uio));
			return (0);
		}


		const int64_t returned_uioresid = uio_resid(uio);
		ASSERT3S(returned_uioresid, >, 0);
		cum_bytes += cur_resid - returned_uioresid;

		/* adjust flag if needed */
		if (returned_uioresid < last_resid) {
			/* we made progress */
			last_resid = returned_uioresid;
			i = 0;
			/*
			 * strip out FAPPEND, as we would have mutated the uio_offset in the
			 * previous pass
			 */
			IMPLY(ioflag & FAPPEND, uio_offset(uio) == start_eof + cum_bytes);
			ioflag &= ~(FAPPEND);
			continue;
		}

		/* try to salvage */
		if (i > 5 && cum_bytes == 0) {
			printf("ZFS: %s:%d: salvage (%d), trying old_style zfs_write for file %s\n",
			    __func__, __LINE__, i, (file_name != NULL) ? file_name : "(NULL)");
			old_style = B_TRUE;
		}

		/* give up */
		if (i > 6) {
			printf("ZFS: %s:%d aborting, out of retries for file %s"
			    " (resid = %lld cum_bytes = %lld)\n",
			    __func__, __LINE__, (file_name != NULL) ? file_name : "(NULL)",
			    returned_uioresid, cum_bytes);
			if (cum_bytes < 1)
				error = EIO;
			break;
		}

	}

	return (error);
}

int
zfs_vnop_access(struct vnop_access_args *ap)
#if 0
	struct vnop_access_args {
		struct vnodeop_desc *a_desc;
		struct vnode	a_vp;
		int		a_action;
		vfs_context_t	a_context;
	};
#endif
{
	int error = ENOTSUP;
	int action = ap->a_action;
	int mode = 0;
	DECLARE_CRED_AND_CONTEXT(ap);

	/*
	 * KAUTH_VNODE_READ_EXTATTRIBUTES, as well?
	 * KAUTH_VNODE_WRITE_EXTATTRIBUTES
	 */
	if (action & KAUTH_VNODE_READ_DATA)
		mode |= VREAD;
	if (action & KAUTH_VNODE_WRITE_DATA)
		mode |= VWRITE;
	if (action & KAUTH_VNODE_EXECUTE)
		mode |= VEXEC;

	dprintf("vnop_access: action %04x -> mode %04x\n", action, mode);
	error = zfs_access(ap->a_vp, mode, 0, cr, ct);

	if (error) dprintf("%s: error %d\n", __func__, error);
	return (error);
}


/*
 * hard link references?
 * Read the comment in zfs_getattr_znode_unlocked for the reason
 * for this hackery. Since getattr(VA_NAME) is extremely common
 * call in OSX, we opt to always save the name. We need to be careful
 * as zfs_dirlook can return ctldir node as well (".zfs").
 * Hardlinks also need to be able to return the correct parentid.
 */
static void zfs_cache_name(struct vnode *vp, struct vnode *dvp, char *filename)
{
	znode_t *zp;
	if (!vp ||
		!filename ||
		!filename[0] ||
		zfsctl_is_node(vp) ||
		!VTOZ(vp))
		return;

	// Only cache files, or we might end up caching "."
	if (!vnode_isreg(vp)) return;

	zp = VTOZ(vp);

	mutex_enter(&zp->z_lock);

	strlcpy(zp->z_name_cache,
			filename,
			MAXPATHLEN);

	// If hardlink, remember the parentid.
	if ((zp->z_links > 1) &&
		(IFTOVT((mode_t)zp->z_mode) == VREG) &&
		dvp) {
		zp->z_finder_parentid = VTOZ(dvp)->z_id;
	}

	mutex_exit(&zp->z_lock);
}


int
zfs_vnop_lookup(struct vnop_lookup_args *ap)
#if 0
	struct vnop_lookup_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		vfs_context_t	a_context;
	};
#endif
{
	struct componentname *cnp = ap->a_cnp;
	DECLARE_CRED(ap);
	int error;
	char *filename = NULL;
	int negative_cache = 0;
	int filename_num_bytes = 0;

	*ap->a_vpp = NULL;	/* In case we return an error */

	/*
	 * Darwin uses namelen as an optimisation, for example it can be
	 * set to 5 for the string "alpha/beta" to look up "alpha". In this
	 * case we need to copy it out to null-terminate.
	 */
	if (cnp->cn_nameptr[cnp->cn_namelen] != 0) {
		filename_num_bytes = cnp->cn_namelen + 1;
		filename = (char*)kmem_alloc(filename_num_bytes, KM_SLEEP);
		if (filename == NULL)
			return (ENOMEM);
		bcopy(cnp->cn_nameptr, filename, cnp->cn_namelen);
		filename[cnp->cn_namelen] = '\0';
	}

#if 1
	/*
	 * cache_lookup() returns 0 for no-entry
	 * -1 for cache found (a_vpp set)
	 * ENOENT for negative cache
	 */
	error = cache_lookup(ap->a_dvp, ap->a_vpp, cnp);
	if (error) {
		/* We found a cache entry, positive or negative. */
		if (error == -1) {	/* Positive entry? */
			if (!zfs_vnop_ignore_positives) {
				error = 0;
				goto exit;	/* Positive cache, return it */
			}
			/* Release iocount held by cache_lookup */
			vnode_put(*ap->a_vpp);
		}
		/* Negatives are only followed if not CREATE, from HFS+. */
		if (cnp->cn_nameiop != CREATE) {
			if (!zfs_vnop_ignore_negatives) {
				goto exit; /* Negative cache hit */
			}
			negative_cache = 1;
		}
	}
#endif

	dprintf("+vnop_lookup '%s' %s\n", filename ? filename : cnp->cn_nameptr,
			negative_cache ? "negative_cache":"");

	error = zfs_lookup(ap->a_dvp, filename ? filename : cnp->cn_nameptr,
	    ap->a_vpp, cnp, cnp->cn_nameiop, cr, /* flags */ 0);
	/* flags can be LOOKUP_XATTR | FIGNORECASE */

#if 1
	/*
	 * It appears that VFS layer adds negative cache entries for us, so
	 * we do not need to add them here, or they are duplicated.
	 */
	if ((error == ENOENT) && zfs_vnop_create_negatives) {
		if ((ap->a_cnp->cn_nameiop == CREATE ||
		    ap->a_cnp->cn_nameiop == RENAME) &&
		    (cnp->cn_flags & ISLASTCN)) {
			error = EJUSTRETURN;
			goto exit;
		}
		/* Insert name into cache (as non-existent) if appropriate. */
		if ((cnp->cn_flags & MAKEENTRY) &&
		    ap->a_cnp->cn_nameiop != CREATE) {
			cache_enter(ap->a_dvp, NULL, ap->a_cnp);
			dprintf("Negative-cache made for '%s'\n",
			    filename ? filename : cnp->cn_nameptr);
		}
	} /* ENOENT */
#endif

#if 0
	if (!error && negative_cache) {
		printf("[ZFS] Incorrect negative_cache entry for '%s'\n",
		    filename ? filename : cnp->cn_nameptr);
		cache_purge_negatives(ap->a_dvp);
	}
#endif


exit:

#ifdef __APPLE__
	if (!error)
		zfs_cache_name(*ap->a_vpp, ap->a_dvp,
					   filename ? filename : cnp->cn_nameptr);
#endif

	dprintf("-vnop_lookup %d : dvp %llu '%s'\n", error, VTOZ(ap->a_dvp)->z_id,
			filename ? filename : cnp->cn_nameptr);

	if (filename)
		kmem_free(filename, filename_num_bytes);

	return (error);
}

int
zfs_vnop_create(struct vnop_create_args *ap)
#if 0
	struct vnop_create_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		vfs_context_t	a_context;
	};
#endif
{
	struct componentname *cnp = ap->a_cnp;
	vattr_t *vap = ap->a_vap;
	DECLARE_CRED(ap);
	vcexcl_t excl;
	int mode = 0;	/* FIXME */
	int error;

	dprintf("vnop_create: '%s'\n", cnp->cn_nameptr);

	/*
	 * extern int zfs_create(struct vnode *dvp, char *name, vattr_t *vap,
	 *     int excl, int mode, struct vnode **vpp, cred_t *cr);
	 */
	excl = (vap->va_vaflags & VA_EXCLUSIVE) ? EXCL : NONEXCL;

	error = zfs_create(ap->a_dvp, cnp->cn_nameptr, vap, excl, mode,
	    ap->a_vpp, cr);
	if (!error) {
		cache_purge_negatives(ap->a_dvp);
	} else {
		dprintf("%s error %d\n", __func__, error);
	}

	return (error);
}


static int zfs_remove_hardlink(struct vnode *vp, struct vnode *dvp, char *name)
{
	/*
	 * Because we store hash of hardlinks in an AVLtree, we need to remove
	 * any entries in it upon deletion. Since it is complicated to know
	 * if an entry was a hardlink, we simply check if the avltree has the
	 * name.
	 */
	hardlinks_t *searchnode, *findnode;
	avl_index_t loc;

	if (!vp || !VTOZ(vp)) return 1;
	if (!dvp || !VTOZ(dvp)) return 1;
	znode_t *zp = VTOZ(vp);
	znode_t *dzp = VTOZ(dvp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int ishardlink = 0;

	ishardlink = ((zp->z_links > 1) && (IFTOVT((mode_t)zp->z_mode) == VREG)) ?
		1 : 0;
	if (zp->z_finder_hardlink)
		ishardlink = 1;

	if (!ishardlink) return 0;

	dprintf("ZFS: removing hash (%llu,%llu,'%s')\n",
		   dzp->z_id, zp->z_id, name);

	// Attempt to remove from hardlink avl, if its there
	searchnode = kmem_alloc(sizeof(hardlinks_t), KM_SLEEP);
	searchnode->hl_parent = dzp->z_id == zfsvfs->z_root ? 2 : dzp->z_id;
	searchnode->hl_fileid = zp->z_id;
	strlcpy(searchnode->hl_name, name, PATH_MAX);

	rw_enter(&zfsvfs->z_hardlinks_lock, RW_READER);
	findnode = avl_find(&zfsvfs->z_hardlinks, searchnode, &loc);
	rw_exit(&zfsvfs->z_hardlinks_lock);
	kmem_free(searchnode, sizeof(hardlinks_t));

	// Found it? remove it
	if (findnode) {
		rw_enter(&zfsvfs->z_hardlinks_lock, RW_WRITER);
		avl_remove(&zfsvfs->z_hardlinks, findnode);
		avl_remove(&zfsvfs->z_hardlinks_linkid, findnode);
		rw_exit(&zfsvfs->z_hardlinks_lock);
		kmem_free(findnode, sizeof(*findnode));
		dprintf("ZFS: removed hash '%s'\n", name);
		mutex_enter(&zp->z_lock);
		zp->z_name_cache[0] = 0;
		zp->z_finder_parentid = 0;
		mutex_exit(&zp->z_lock);
		return 1;
	}
	return 0;
}


static int zfs_rename_hardlink(struct vnode *vp, struct vnode *tvp,
							   struct vnode *fdvp, struct vnode *tdvp,
							   char *from, char *to)
{
	/*
	 * Because we store hash of hardlinks in an AVLtree, we need to update
	 * any entries in it upon rename. Since it is complicated to know
	 * if an entry was a hardlink, we simply check if the avltree has the
	 * name.
	 */
	hardlinks_t *searchnode, *findnode, *delnode;
	avl_index_t loc;
	uint64_t parent_fid, parent_tid;
	int ishardlink = 0;

	if (!vp || !VTOZ(vp)) return 0;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	ishardlink = ((zp->z_links > 1) && (IFTOVT((mode_t)zp->z_mode) == VREG)) ?
		1 : 0;
	if (zp->z_finder_hardlink)
		ishardlink = 1;

	if (!ishardlink) return 0;

	if (!fdvp || !VTOZ(fdvp)) return 0;
	parent_fid = VTOZ(fdvp)->z_id;
	parent_fid = parent_fid == zfsvfs->z_root ? 2 : parent_fid;

	if (!tdvp || !VTOZ(tdvp)) {
		parent_tid = parent_fid;
	} else {
		parent_tid = VTOZ(tdvp)->z_id;
		parent_tid = parent_tid == zfsvfs->z_root ? 2 : parent_tid;
	}

	dprintf("ZFS: looking to rename hardlinks (%llu,%llu,%s)\n",
		   parent_fid, zp->z_id, from);


	// Attempt to remove from hardlink avl, if its there
	searchnode = kmem_alloc(sizeof(hardlinks_t), KM_SLEEP);
	searchnode->hl_parent = parent_fid;
	searchnode->hl_fileid = zp->z_id;
	strlcpy(searchnode->hl_name, from, PATH_MAX);

	rw_enter(&zfsvfs->z_hardlinks_lock, RW_READER);
	findnode = avl_find(&zfsvfs->z_hardlinks, searchnode, &loc);
	rw_exit(&zfsvfs->z_hardlinks_lock);

	// Found it? update it
	if (findnode) {

		rw_enter(&zfsvfs->z_hardlinks_lock, RW_WRITER);

		// Technically, we do not need to re-do the _linkid AVL here.
		avl_remove(&zfsvfs->z_hardlinks, findnode);
		avl_remove(&zfsvfs->z_hardlinks_linkid, findnode);

		// If we already have a hashid for "to" and the rename presumably
		// unlinked it, we need to remove it first.
		searchnode->hl_parent = parent_tid;
		strlcpy(searchnode->hl_name, to, PATH_MAX);
		delnode = avl_find(&zfsvfs->z_hardlinks, searchnode, &loc);
		if (delnode) {
			dprintf("ZFS: apparently %llu:'%s' exists, deleting\n",
				   parent_tid, to);
			avl_remove(&zfsvfs->z_hardlinks, delnode);
			avl_remove(&zfsvfs->z_hardlinks_linkid, delnode);
			kmem_free(delnode, sizeof(*delnode));
		}

		dprintf("ZFS: renamed hash %llu (%llu:'%s' to %llu:'%s'): %s\n",
			   zp->z_id,
			   parent_fid, from,
			   parent_tid, to,
			   delnode ? "deleted":"");

		// Update source node to new hash, and name.
		findnode->hl_parent = parent_tid;
		strlcpy(findnode->hl_name, to, PATH_MAX);
		//zp->z_finder_parentid = parent_tid;

		avl_add(&zfsvfs->z_hardlinks, findnode);
		avl_add(&zfsvfs->z_hardlinks_linkid, findnode);

		rw_exit(&zfsvfs->z_hardlinks_lock);
		kmem_free(searchnode, sizeof(hardlinks_t));

		return 1;
	}

	kmem_free(searchnode, sizeof(hardlinks_t));
	return 0;
}


int
zfs_vnop_remove(struct vnop_remove_args *ap)
#if 0
	struct vnop_remove_args {
		struct vnode	*a_dvp;
		struct vnode	*a_vp;
		struct componentname *a_cnp;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error;

	dprintf("vnop_remove: %p (%s)\n", ap->a_vp, ap->a_cnp->cn_nameptr);

	/*
	 * extern int zfs_remove ( struct vnode *dvp, char *name, cred_t *cr,
	 *     caller_context_t *ct, int flags);
	 */
	error = zfs_remove(ap->a_dvp, ap->a_cnp->cn_nameptr, cr, ct,
	    /* flags */0);
	if (!error) {
		cache_purge(ap->a_vp);

		zfs_remove_hardlink(ap->a_vp,
							ap->a_dvp,
							ap->a_cnp->cn_nameptr);
	} else {
		dprintf("%s error %d\n", __func__, error);
	}

	return (error);
}

int
zfs_vnop_mkdir(struct vnop_mkdir_args *ap)
#if 0
	struct vnop_mkdir_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error;

	dprintf("vnop_mkdir '%s'\n", ap->a_cnp->cn_nameptr);

#if 0
	/* Let's deny OS X fseventd for now */
	if (ap->a_cnp->cn_nameptr &&
	    strcmp(ap->a_cnp->cn_nameptr, ".fseventsd") == 0)
		return (EINVAL);
#endif

#if 0
	/* spotlight for now */
	if (ap->a_cnp->cn_nameptr &&
	    strcmp(ap->a_cnp->cn_nameptr, ".Spotlight-V100") == 0)
		return (EINVAL);
#endif
	/*
	 * extern int zfs_mkdir(struct vnode *dvp, char *dirname, vattr_t *vap,
	 *     struct vnode **vpp, cred_t *cr, caller_context_t *ct, int flags,
	 *     vsecattr_t *vsecp);
	 */
	error = zfs_mkdir(ap->a_dvp, ap->a_cnp->cn_nameptr, ap->a_vap,
	    ap->a_vpp, cr, ct, /* flags */0, /* vsecp */NULL);
	if (!error) {
		cache_purge_negatives(ap->a_dvp);
	} else {
		dprintf("%s error %d\n", __func__, error);
	}

	return (error);
}

int
zfs_vnop_rmdir(struct vnop_rmdir_args *ap)
#if 0
	struct vnop_rmdir_args {
		struct vnode	*a_dvp;
		struct vnode	*a_vp;
		struct componentname *a_cnp;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error;

	dprintf("vnop_rmdir\n");

	/*
	 * extern int zfs_rmdir(struct vnode *dvp, char *name,
	 *     struct vnode *cwd, cred_t *cr, caller_context_t *ct, int flags);
	 */
	error = zfs_rmdir(ap->a_dvp, ap->a_cnp->cn_nameptr, /* cwd */NULL, cr,
	    ct, /* flags */0);
	if (!error) {
		cache_purge(ap->a_vp);
	} else {
		dprintf("%s error %d\n", __func__, error);
	}

	return (error);
}

int
zfs_vnop_readdir(struct vnop_readdir_args *ap)
#if 0
	struct vnop_readdir_args {
		struct vnode	a_vp;
		struct uio	*a_uio;
		int		a_flags;
		int		*a_eofflag;
		int		*a_numdirent;
		vfs_context_t	a_context;
	};
#endif
{
	int error;
	DECLARE_CRED(ap);

	dprintf("+readdir: %p\n", ap->a_vp);

	/*
	 * XXX This interface needs vfs_has_feature.
	 * XXX zfs_readdir() also needs to grow support for passing back the
	 * number of entries (OS X/FreeBSD) and cookies (FreeBSD). However,
	 * it should be the responsibility of the OS caller to malloc/free
	 * space for that.
	 */

	/*
	 * extern int zfs_readdir(struct vnode *vp, uio_t *uio, cred_t *cr,
	 *     int *eofp, int flags, int *a_numdirent);
	 */
	*ap->a_numdirent = 0;

	error = zfs_readdir(ap->a_vp, ap->a_uio, cr, ap->a_eofflag, ap->a_flags,
	    ap->a_numdirent);

	/* .zfs dirs can be completely empty */
	if (*ap->a_numdirent == 0)
		*ap->a_numdirent = 2; /* . and .. */

	if (error) {
		dprintf("-readdir %d (nument %d)\n", error, *ap->a_numdirent);
	}
	return (error);
}

int
zfs_vnop_fsync(struct vnop_fsync_args *ap)
#if 0
	struct vnop_fsync_args {
		struct vnode	*a_vp;
		int		a_waitfor;
		vfs_context_t	a_context;
	};
#endif
{
	znode_t *zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs;
	DECLARE_CRED_AND_CONTEXT(ap);
	int err;

	/*
	 * Check if this znode has already been synced, freed, and recycled
	 * by znode_pageout_func.
	 *
	 * XXX What is this? Substitute for Illumos vn_has_cached_data()?
	 */
	if (zp == NULL)
		return (0);

	zfsvfs = zp->z_zfsvfs;

	if (!zfsvfs)
		return (0);

	err = zfs_fsync(ap->a_vp, /* flag */0, cr, ct);

	if (err) dprintf("%s err %d\n", __func__, err);

	return (err);
}

int
zfs_vnop_getattr(struct vnop_getattr_args *ap)
#if 0
	struct vnop_getattr_args {
		struct vnode	*a_vp;
		struct vnode_vattr *a_vap;
		vfs_context_t	a_context;
	};
#endif
{
	int error;
	DECLARE_CRED_AND_CONTEXT(ap);

	/* dprintf("+vnop_getattr zp %p vp %p\n", VTOZ(ap->a_vp), ap->a_vp); */

	error = zfs_getattr(ap->a_vp, ap->a_vap, /* flags */0, cr, ct);

	if (!error)
		error = zfs_getattr_znode_unlocked(ap->a_vp, ap->a_vap);

	if (error)
		dprintf("-vnop_getattr '%p' %d\n", (ap->a_vp), error);

	return (error);
}

int
zfs_vnop_setattr(struct vnop_setattr_args *ap)
#if 0
	struct vnop_setattr_args {
		struct vnode	*a_vp;
		struct vnode_vattr *a_vap;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	vattr_t *vap = ap->a_vap;
	uint_t mask = vap->va_mask;
	int error = 0;


	int ignore_ownership = (((unsigned int)vfs_flags(vnode_mount(ap->a_vp)))
							& MNT_IGNORE_OWNERSHIP);

	/* Translate OS X requested mask to ZFS */
	if (VATTR_IS_ACTIVE(vap, va_data_size))
		mask |= AT_SIZE;
	if (VATTR_IS_ACTIVE(vap, va_mode))
		mask |= AT_MODE;
	if (VATTR_IS_ACTIVE(vap, va_uid) && !ignore_ownership)
		mask |= AT_UID;
	if (VATTR_IS_ACTIVE(vap, va_gid) && !ignore_ownership)
		mask |= AT_GID;
	if (VATTR_IS_ACTIVE(vap, va_access_time))
		mask |= AT_ATIME;
	if (VATTR_IS_ACTIVE(vap, va_modify_time))
		mask |= AT_MTIME;
	/*
	 * We abuse AT_CTIME here, to function as a place holder for "creation
	 * time," since you are not allowed to change "change time" in POSIX,
	 * and we don't have an AT_CRTIME.
	 */
	if (VATTR_IS_ACTIVE(vap, va_create_time))
		mask |= AT_CTIME;
	/*
	 * if (VATTR_IS_ACTIVE(vap, va_backup_time))
	 *     mask |= AT_BTIME; // really?
	 */
	/*
	 * Both 'flags' and 'acl' can come to setattr, but without 'mode' set.
	 * However, ZFS assumes 'mode' is also set. We need to look up 'mode' in
	 * this case.
	 */
	if ((VATTR_IS_ACTIVE(vap, va_flags) || VATTR_IS_ACTIVE(vap, va_acl)) &&
	    !VATTR_IS_ACTIVE(vap, va_mode)) {
		znode_t *zp = VTOZ(ap->a_vp);
		uint64_t mode;

		mask |= AT_MODE;

		dprintf("fetching MODE for FLAGS or ACL\n");
		ZFS_ENTER(zp->z_zfsvfs);
		ZFS_VERIFY_ZP(zp);
		(void) sa_lookup(zp->z_sa_hdl, SA_ZPL_MODE(zp->z_zfsvfs), &mode,
		    sizeof (mode));
		vap->va_mode = mode;
		ZFS_EXIT(zp->z_zfsvfs);
	}
	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		znode_t *zp = VTOZ(ap->a_vp);

		/* If TRACKED is wanted, and not previously set, go set DocumentID */
		if ((vap->va_flags & UF_TRACKED) && !(zp->z_pflags & ZFS_TRACKED)) {
			zfs_setattr_generate_id(zp, 0, NULL);
			zfs_setattr_set_documentid(zp, B_FALSE); /* flags updated in vnops */
		}

		/* Map OS X file flags to zfs file flags */
		zfs_setbsdflags(zp, vap->va_flags);
		dprintf("OS X flags %08x changed to ZFS %04llx\n",
		    vap->va_flags, zp->z_pflags);
		vap->va_flags = zp->z_pflags;

	}
	if (VATTR_IS_ACTIVE(vap, va_acl)) {
		mask |= AT_ACL;
	}

	vap->va_mask = mask;
	error = zfs_setattr(ap->a_vp, ap->a_vap, /* flag */0, cr, ct);

	dprintf("vnop_setattr: called on vp %p with mask %04x, err=%d\n",
	    ap->a_vp, mask, error);

	if (!error) {
		/* If successful, tell OS X which fields ZFS set. */
		if (VATTR_IS_ACTIVE(vap, va_data_size)) {
			dprintf("ZFS: setattr new size %llx %llx\n", vap->va_size,
					ubc_getsize(ap->a_vp));
			/* take a lock when calling ubc_setsize, to avoid
			 * interfering with an in-progress update_pages,
			 * mappedread, pagein, pageoutv2, or other caller
			 * of ubc_setsize/vnode_pager_setsize
			 */

			znode_t *zp = VTOZ(ap->a_vp);
			rl_t *rl;
			int i = 0;
			const hrtime_t start_time = gethrtime();
			boolean_t need_release = B_FALSE, need_upgrade = B_FALSE;

			for (i = 0; i < INT32_MAX; i++) {
				rl = zfs_range_lock(zp, 0, UINT64_MAX, RL_WRITER);
				if (i > 10000) {
					printf("ZFS: %s:%d: DEADLOCK AVOIDANCE i=%d\n",
					    __func__, __LINE__, i);
				}
				if (!rw_tryenter(&zp->z_map_lock, RW_WRITER)) {
					zfs_range_unlock(rl);
					extern void IOSleep(unsigned milliseconds);
					IOSleep(1);
				} else {
					need_release = B_TRUE;
					zp->z_map_lock_holder = zp->z_name_cache;
					break;
				}
			}
			const hrtime_t end_time = gethrtime();
			if (NSEC2MSEC(end_time - start_time) > 10) {
				printf("ZFS: %s:%d: number of milliseconds looking for a lock %lld,"
				    " iters %d\n", __func__, __LINE__,
				    NSEC2MSEC(end_time - start_time), i);
			}
			if (spl_ubc_is_mapped(ZTOV(zp), NULL)) {
				ASSERT3S(vap->va_size, >=, ubc_getsize(ZTOV(zp)));
			}
			int setsize_retval = ubc_setsize(ap->a_vp, vap->va_size);
			z_map_drop_lock(zp, &need_release, &need_upgrade);
			VATTR_SET_SUPPORTED(vap, va_data_size);
			zfs_range_unlock(rl);
			ASSERT3S(setsize_retval, !=, 0); // ubc_setsize returns true on success
		}
		if (VATTR_IS_ACTIVE(vap, va_mode))
			VATTR_SET_SUPPORTED(vap, va_mode);
		if (VATTR_IS_ACTIVE(vap, va_acl))
			VATTR_SET_SUPPORTED(vap, va_acl);
		if (VATTR_IS_ACTIVE(vap, va_uid))
			VATTR_SET_SUPPORTED(vap, va_uid);
		if (VATTR_IS_ACTIVE(vap, va_gid))
			VATTR_SET_SUPPORTED(vap, va_gid);
		if (VATTR_IS_ACTIVE(vap, va_access_time))
			VATTR_SET_SUPPORTED(vap, va_access_time);
		if (VATTR_IS_ACTIVE(vap, va_modify_time))
			VATTR_SET_SUPPORTED(vap, va_modify_time);
		if (VATTR_IS_ACTIVE(vap, va_change_time))
			VATTR_SET_SUPPORTED(vap, va_change_time);
		if (VATTR_IS_ACTIVE(vap, va_create_time))
			VATTR_SET_SUPPORTED(vap, va_create_time);
		if (VATTR_IS_ACTIVE(vap, va_backup_time))
			VATTR_SET_SUPPORTED(vap, va_backup_time);
		if (VATTR_IS_ACTIVE(vap, va_flags)) {
			VATTR_SET_SUPPORTED(vap, va_flags);
		}
	}

#if 0
	uint64_t missing = 0;
	missing = (vap->va_active ^ (vap->va_active & vap->va_supported));
	if ( missing != 0) {
		printf("vnop_setattr:: asked %08llx replied %08llx       missing %08llx\n",
			   vap->va_active, vap->va_supported,
			   missing);
	}
#endif

	if (error)
		dprintf("ZFS: vnop_setattr return failure %d\n", error);
	return (error);
}

int
zfs_vnop_rename(struct vnop_rename_args *ap)
#if 0
	struct vnop_rename_args {
		struct vnode	*a_fdvp;
		struct vnode	*a_fvp;
		struct componentname *a_fcnp;
		struct vnode	*a_tdvp;
		struct vnode	*a_tvp;
		struct componentname *a_tcnp;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error;

	dprintf("vnop_rename\n");

	/*
	 * extern int zfs_rename(struct vnode *sdvp, char *snm,
	 *     struct vnode *tdvp, char *tnm, cred_t *cr, caller_context_t *ct,
	 *     int flags);
	 */
	error = zfs_rename(ap->a_fdvp, ap->a_fcnp->cn_nameptr, ap->a_tdvp,
	    ap->a_tcnp->cn_nameptr, cr, ct, /* flags */0);

	if (!error) {
		cache_purge_negatives(ap->a_fdvp);
		cache_purge_negatives(ap->a_tdvp);
		cache_purge(ap->a_fvp);

		zfs_rename_hardlink(ap->a_fvp, ap->a_tvp,
							ap->a_fdvp, ap->a_tdvp,
							ap->a_fcnp->cn_nameptr,
							ap->a_tcnp->cn_nameptr);
		if (ap->a_tvp) {
			cache_purge(ap->a_tvp);
		}

#ifdef __APPLE__
		/*
		 * After a rename, the VGET path /.vol/$fsid/$ino fails for a short
		 * period on hardlinks (until someone calls lookup).
		 * So until we can figure out exactly why this is, we drive a lookup
		 * here to ensure that vget will work (Finder/Spotlight).
		 */
		if (ap->a_fvp && VTOZ(ap->a_fvp) &&
			VTOZ(ap->a_fvp)->z_finder_hardlink) {
			struct vnode *vp;
			if (VOP_LOOKUP(ap->a_tdvp, &vp, ap->a_tcnp, spl_vfs_context_kernel())
				== 0) vnode_put(vp);
		}
#endif

	}

	if (error) dprintf("%s: error %d\n", __func__, error);
	return (error);
}
int
zfs_vnop_symlink(struct vnop_symlink_args *ap)
#if 0
	struct vnop_symlink_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		char		*a_target;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED(ap);
	int error;

	dprintf("vnop_symlink\n");

	/*
	 * extern int zfs_symlink(struct vnode *dvp, struct vnode **vpp,
	 *     char *name, vattr_t *vap, char *link, cred_t *cr);
	 */

	/* OS X doesn't need to set vap->va_mode? */
	error = zfs_symlink(ap->a_dvp, ap->a_vpp, ap->a_cnp->cn_nameptr,
	    ap->a_vap, ap->a_target, cr);
	if (!error) {
		cache_purge_negatives(ap->a_dvp);
	} else {
		dprintf("%s: error %d\n", __func__, error);
	}
	/* XXX zfs_attach_vnode()? */
	return (error);
}


int
zfs_vnop_readlink(struct vnop_readlink_args *ap)
#if 0
	struct vnop_readlink_args {
		struct vnode	*vp;
		struct uio	*uio;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);

	dprintf("vnop_readlink\n");

	/*
	 * extern int zfs_readlink(struct vnode *vp, uio_t *uio, cred_t *cr,
	 *     caller_context_t *ct);
	 */
	return (zfs_readlink(ap->a_vp, ap->a_uio, cr, ct));
}

int
zfs_vnop_link(struct vnop_link_args *ap)
#if 0
	struct vnop_link_args {
		struct vnode	*a_vp;
		struct vnode	*a_tdvp;
		struct componentname *a_cnp;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error;

	dprintf("vnop_link\n");

	/* XXX Translate this inside zfs_link() instead. */
	if (vnode_mount(ap->a_vp) != vnode_mount(ap->a_tdvp)) {
		dprintf("%s: vp and tdvp on different mounts\n", __func__);
		return (EXDEV);
	}

	/*
	 * XXX Understand why Apple made this comparison in so many places where
	 * others do not.
	 */
	if (ap->a_cnp->cn_namelen >= ZAP_MAXNAMELEN) {
		dprintf("%s: name too long %d\n", __func__,
		    ap->a_cnp->cn_namelen);
		return (ENAMETOOLONG);
	}

	/*
	 * extern int zfs_link(struct vnode *tdvp, struct vnode *svp,
	 *     char *name, cred_t *cr, caller_context_t *ct, int flags);
	 */

	error = zfs_link(ap->a_tdvp, ap->a_vp, ap->a_cnp->cn_nameptr, cr, ct,
	    /* flags */0);
	if (!error) {
		// Set source vnode to multipath too, zfs_get_vnode() handles the target
		vnode_setmultipath(ap->a_vp);
		cache_purge(ap->a_vp);
		cache_purge_negatives(ap->a_tdvp);
	} else {
		dprintf("%s error %d\n", __func__, error);
	}

	return (error);
}

int
zfs_vnop_pagein(struct vnop_pagein_args *ap)
#if 0
	struct vnop_pagein_args {
		struct vnode	*a_vp;
		upl_t		a_pl;
		upl_offset_t	a_pl_offset;
		off_t		a_foffset;
		size_t		a_size;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	/* XXX Crib this from the Apple zfs_vnops.c. */
	struct vnode *vp = ap->a_vp;
	offset_t off = ap->a_f_offset;
	size_t len = ap->a_size;
	upl_t upl = ap->a_pl;
	upl_offset_t upl_offset = ap->a_pl_offset;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	caddr_t vaddr = NULL;
	/* vm_offset_t vaddr = NULL; */
	int flags = ap->a_flags;
	int error = 0;
	uint64_t file_sz;

	dprintf("+vnop_pagein: %p/%p off 0x%llx size 0x%lx filesz 0x%llx\n",
			zp, vp, off, len, zp->z_size);

	VNOPS_OSX_STAT_BUMP(pagein_calls);

	if (upl == (upl_t)NULL)
		panic("zfs_vnop_pagein: no upl!");

	if (len <= 0) {
		printf("ZFS: %s:%d: invalid size %ld upl_off %d\n", __func__, __LINE__, len, upl_offset);
		if (!(flags & UPL_NOCOMMIT)) {
			int abort_unknown_ret = ubc_upl_abort_range(upl, upl_offset, ap->a_size,
				UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR);
			ASSERT3S(abort_unknown_ret, ==, KERN_SUCCESS);
		}
		return (EINVAL);
	}

	ZFS_ENTER(zfsvfs);

	file_sz = zp->z_size;
	ASSERT3S(file_sz, ==, ubc_getsize(vp));
	const off_t ubcsize_at_entry = ubc_getsize(vp);
	const char *fname = zp->z_name_cache;
	const char *fsname = vfs_statfs(zfsvfs->z_vfs)->f_mntfromname;

	ASSERT(vn_has_cached_data(vp));
	if (!vn_has_cached_data(vp)) {
		printf("ZFS: %s:%d: file without vn_has_cached_data(vp) (file_sz %lld): %s\n",
		    __func__, __LINE__, file_sz, zp->z_name_cache);

	}
	/* ASSERT(zp->z_dbuf_held && zp->z_phys); */
	/* can't fault passed EOF */
	if ((off < 0) || (off >= file_sz) ||
		(len & PAGE_MASK) || (upl_offset & PAGE_MASK)) {
		dprintf("passed EOF or size error\n");
		ZFS_EXIT(zfsvfs);
		if (!(flags & UPL_NOCOMMIT)) {
			printf("ZFS: %s:%d: aborting out-of-range UPL (off %lld file_sz %lld)"
			    " fs %s file %s\n",
			    __func__, __LINE__, off, file_sz, fsname, fname);
			int aret = ubc_upl_abort_range(upl, upl_offset, len,
			    (UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY));
			ASSERT3S(aret, ==, KERN_SUCCESS);
		}
		return (EFAULT);
	}

	/*
	 * If we already own z_map_lock, then we must be page faulting in the
	 * middle of a write to this file (i.e., we are writing to this file
	 * using data from a mapped region of the file).
	 *
	 * An example stack is zfs_vnop_write->fill_holes_in_range->ubc_create_upl->
	 * vm_fault_page->vnode_pager_data_request->zfs_vnop_pagein (that's us).
	 *
	 * For this file, we lock against update_pages() which is called
	 * from zfs_write() to update the UBC.  If we have contention,
	 * then we serialize the whole contending operations.
	 *
	 * We also lock against zfs_vnop_pageoutv2 and zfs_vnop_pageout,
	 * and ourselves (if in other threads), since any of these may
	 * modify the UBC with respect to this file.
	 *
	 * Finally we also lock against new callers of zfs_vnop_mmap() and
	 * zfs_vnop_mnomap(), since those may update the file as well.
	 */

	boolean_t need_rl_unlock;
	boolean_t need_z_lock;
	rl_t *rl;

	if (rw_write_held(&zp->z_map_lock)) {
		need_rl_unlock = B_FALSE;
		need_z_lock = B_FALSE;
		printf("ZFS: %s:%d: lock held on entry for [%lld..%lld] (size %ld uploff %u) fs %s file %s,"
		    " avoiding rangelocking\n",
		    __func__, __LINE__, ap->a_f_offset, ap->a_f_offset + ap->a_size,
		    ap->a_size, ap->a_pl_offset,
		    vfs_statfs(zfsvfs->z_vfs)->f_mntfromname, zp->z_name_cache);
	} else {
		need_rl_unlock = B_TRUE;
		need_z_lock = B_TRUE;
		rl = zfs_range_lock(zp, off, len, RL_READER);
	}

	boolean_t need_release = B_FALSE;
	boolean_t need_upgrade = B_FALSE;
	if (need_z_lock) {
		hrtime_t print_time = gethrtime() + SEC2NSEC(1);
		int secs = 0;
		extern void IOSleep(unsigned milliseconds); // yields thread
		extern void IODelay(unsigned microseconds); // x86_64 rep nop
		ASSERT3S(need_rl_unlock, ==, B_TRUE);
		uint64_t tries = 0;
		while(!rw_write_held(&zp->z_map_lock)){
			tries++;
			if (secs == 0)
				secs = 1;
			if (rw_tryenter(&zp->z_map_lock, RW_WRITER))
				break;
			// couldn't get it, maybe drop the range lock
			if (rl->r_write_wanted || rl->r_read_wanted) {
				printf("ZFS: %s:%d range lock contended, dropping it for [%lld, %ld] for file %s\n",
				    __func__, __LINE__, ap->a_f_offset, ap->a_size, zp->z_name_cache);
				zfs_range_unlock(rl);
				IOSleep(1); // we hold no locks, so let work be done
				rl = zfs_range_lock(zp, off, len, RL_WRITER);
			}
			hrtime_t cur_time = gethrtime();
			if (cur_time > print_time) {
				secs++;
				printf("ZFS: %s:%d: looping for z_map_lock for %d sec"
				    " (held by %s) file %s\n", __func__, __LINE__, secs,
				    (zp->z_map_lock_holder != NULL)
				    ? zp->z_map_lock_holder
				    : "(NULL)",
				    zp->z_name_cache);
				print_time = cur_time + SEC2NSEC(1);
			}
			IODelay(1);
		}
		ASSERT(rw_write_held(&zp->z_map_lock));
		need_release = B_TRUE;
		zp->z_map_lock_holder = __func__;
		VNOPS_OSX_STAT_INCR(pagein_want_lock, tries);
	}

	int ubc_map_retval = 0;
	if ((ubc_map_retval = ubc_upl_map(upl, (vm_offset_t *)&vaddr)) != KERN_SUCCESS) {
		ASSERT3S(ubc_map_retval, ==, KERN_SUCCESS);
		printf("%s:%d error %d failed to ubc_upl_map for file %s\n", __func__, __LINE__,
		    ubc_map_retval, zp->z_name_cache);
		if (!(flags & UPL_NOCOMMIT)) {
			int aret = ubc_upl_abort_range(upl, upl_offset, ap->a_size,
				UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR);
			ASSERT3S(aret, ==, KERN_SUCCESS);
		}
		if (need_z_lock) { z_map_drop_lock(zp, &need_release, &need_upgrade); }
		if (need_rl_unlock) { zfs_range_unlock(rl); }
		ZFS_EXIT(zfsvfs);
		return (ENOMEM);
	}

	dprintf("vaddr %p with upl_off 0x%x\n", vaddr, upl_offset);
	vaddr += upl_offset;

	/* Can't read beyond EOF - but we need to zero those extra bytes. */
	if (off + len > file_sz) {
		uint64_t newend = file_sz - off;

		dprintf("ZFS: pagein zeroing offset 0x%llx for 0x%llx bytes.\n",
				newend, len - newend);
		memset(&vaddr[newend], 0, len - newend);
		len = newend;
	}
	/*
	 * Fill pages with data from the file.
	 */
	uint64_t bytes_read = 0;

	while (len > 0) {
		uint64_t readlen;

		readlen = MIN(PAGESIZE, len);

		dprintf("pagein from off 0x%llx len 0x%llx into address %p (len 0x%lx)\n",
				off, readlen, vaddr, len);

		error = dmu_read(zp->z_zfsvfs->z_os, zp->z_id, off, readlen,
		    (void *)vaddr, DMU_READ_PREFETCH);
		if (error) {
			printf("ZFS: %s:%d: zfs_vnop_pagein: dmu_read err %d file %s\n",
			    __func__, __LINE__, error, zp->z_name_cache);
			break;
		} else {
			bytes_read += readlen;
		}
		off += readlen;
		vaddr += readlen;
		len -= readlen;
	}

	(void) ubc_upl_unmap(upl); // return results aren't interesting

	if (bytes_read > 0) {
		uint64_t pgs = 1ULL + atop_64(bytes_read);
		VNOPS_OSX_STAT_INCR(pagein_pages, pgs);
	}

	if (!(flags & UPL_NOCOMMIT)) {
		if (error) {
			printf("ZFS: %s:%d: error %d, aborting UPL (uploffsets) [%u..%lu]"
			    " foff %lld fs %s fn %s\n", __func__, __LINE__, error,
			    upl_offset, ap->a_size, ap->a_f_offset, fsname, fname);
			kern_return_t abortret = ubc_upl_abort_range(upl, upl_offset, ap->a_size,
			    (UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY));
			if (abortret != KERN_SUCCESS) {
				printf("ZFS: %s:%d: ubc_upl_abort_range returned %d"
				    " (uoff %d sz %ld) at off %lld file %s error was already %d\n",
				    __func__, __LINE__, abortret, upl_offset, ap->a_size, off,
				    zp->z_name_cache, error);
			}
		} else {
			kern_return_t commitret = ubc_upl_commit_range(upl, upl_offset,
			    ap->a_size, UPL_COMMIT_FREE_ON_EMPTY);
			if (commitret != KERN_SUCCESS) {
				printf("ZFS: %s:%d: ubc_upl_commit_range returned %d"
				    " (uoff %d sz %ld) at off %lld file %s error was already %d\n",
				    __func__, __LINE__, commitret, upl_offset, ap->a_size, off,
				    zp->z_name_cache, error);
			}
		}
	}
	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	/*
	 * We can't grab the range lock for the page as reader which would stop
	 * truncation as this leads to deadlock. So we need to recheck the file
	 * size.
	 */
	    ASSERT3S(file_sz, ==, zp->z_size);
	    ASSERT3S(ap->a_f_offset, <, file_sz);
	    ASSERT3S(ap->a_f_offset, <, zp->z_size);
	    ASSERT3S(zp->z_size, ==, ubc_getsize(vp));

	if (ap->a_f_offset >= file_sz || ap->a_f_offset >= zp->z_size)
		error = EFAULT;

	if (need_z_lock) { z_map_drop_lock(zp, &need_release, &need_upgrade); }
	if (need_rl_unlock) { zfs_range_unlock(rl); }
	ASSERT3S(ubc_getsize(vp), >=, ubcsize_at_entry);
	ZFS_EXIT(zfsvfs);
	if (error) {
		printf("ZFS: %s:%d returning error %d for (%lld, %ld) in file %s\n", __func__, __LINE__,
		    error, ap->a_f_offset, ap->a_size, zp->z_name_cache);
	}
	if (error == EAGAIN || error == EPERM) {
		printf("ZFS: %s:%d: changing error %d to EIO becaus eof special handling in our caller\n",
		    __func__, __LINE__, error);
		error = EIO;
	}
	return (error);
}

int
zfs_pageout(zfsvfs_t *zfsvfs, znode_t *zp, upl_t upl, const vm_offset_t upl_offset,
    offset_t off, const size_t size, const int flags, const boolean_t take_rlock,
    const boolean_t inactivate, const boolean_t clear_flags)
{
	dmu_tx_t *tx;
	rl_t *rl;
	uint64_t filesz;
	int err = 0;
	size_t len = size;

	printf("+vnop_pageout: %p/%p off 0x%llx len 0x%lx upl_off 0x%lx: "
			"blksz 0x%x, z_size 0x%llx upl %p flags 0x%x\n", zp, ZTOV(zp),
			off, len, upl_offset, zp->z_blksz,
			zp->z_size, upl, flags);

	ASSERT3P(upl, !=, NULL);
	if (upl == (upl_t)NULL) {
		printf("ZFS: %s:%d: failed on NULL upl, f_off %lld, size %ld, file %s\n",
		    __func__, __LINE__, off, size, zp->z_name_cache);
		return (EINVAL);
	}
	/*
	 * We can't leave this function without either calling upl_commit or
	 * upl_abort. So use the non-error version.
	 */
	ZFS_ENTER_NOERROR(zfsvfs);
	if (zfsvfs->z_unmounted) {
		printf("ZFS: %s:%d: dumping pages on z_unmounted, uploff %ld foff %lld sz %ld file %s\n",
		    __func__, __LINE__, upl_offset, off, size, zp->z_name_cache);
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort_range(upl, upl_offset, size,
			    UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY);
		ZFS_EXIT(zfsvfs);
		return (EIO);
	}
	if (zp->z_sa_hdl == NULL) {
		printf("ZFS: %s:%d: abort on no z_sa_hdl, uploff %ld foff %lld sz %ld file %s\n",
		    __func__, __LINE__, upl_offset, off, size, zp->z_name_cache);
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort_range(upl, upl_offset, size,
			    UPL_ABORT_FREE_ON_EMPTY);
		ZFS_EXIT(zfsvfs);
		return (EIO);
	}

	ASSERT(vn_has_cached_data(ZTOV(zp)));
	ASSERT(ubc_pages_resident(ZTOV(zp)));
	/* ASSERT(zp->z_dbuf_held); */ /* field no longer present in znode. */

	if (len <= 0) {
		ASSERT3S(len, <=, 0);
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY);
		err = EINVAL;
		goto exit;
	}
	if (vnode_vfsisrdonly(ZTOV(zp)) ||
	    vfs_flags(zfsvfs->z_vfs) & MNT_RDONLY ||
	    !spa_writeable(dmu_objset_spa(zfsvfs->z_os))) {
		printf("ZFS: %s:%d: read-only filesystem for file %s\n",
		    __func__, __LINE__, zp->z_name_cache);
		if (!(flags & UPL_NOCOMMIT)) {
			ASSERT3S(len, ==, size);
			printf("ZFS: %s:%d: aborting UPL range [%lu..%ld] for read-only"
			    " object file %s\n",
			    __func__, __LINE__, upl_offset, len, zp->z_name_cache);
			int aret = ubc_upl_abort_range(upl, upl_offset, len,
			    UPL_ABORT_DUMP_PAGES| UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
			ASSERT3S(aret, ==, KERN_SUCCESS);
		}
		err = EROFS;
		goto exit;
	}

	filesz = zp->z_size; /* get consistent copy of zp_size */

	ASSERT3S(off, >=, 0);
	ASSERT3S(off, <, filesz);
	ASSERT0(off & PAGE_MASK_64);
	ASSERT0(len & PAGE_MASK);
	if (off < 0 || off >= filesz || (off & PAGE_MASK_64) ||
	    (len & PAGE_MASK)) {
		if (!(flags & UPL_NOCOMMIT)) {
			ASSERT3S(len, ==, size);
			printf("ZFS: %s:%d: aborting UPL [%lu..%ld] out of range or unaligned"
			    " off %lld fsz %lld off&PAGE_MASK_64 %lld len&PAGE_MASK %ld fn %s\n",
			    __func__, __LINE__, upl_offset, len, off, filesz,
			    off & PAGE_MASK_64, len & PAGE_MASK, zp->z_name_cache);
			ubc_upl_abort_range(upl, upl_offset, len,
			    UPL_ABORT_ERROR |
			    UPL_ABORT_DUMP_PAGES |
			    UPL_ABORT_FREE_ON_EMPTY);
		}
		err = EINVAL;
		goto exit;
	}

	dprintf("ZFS: starting with size %lx\n", len);

top:
	if (take_rlock)
		rl = zfs_range_lock(zp, off, len, RL_WRITER);
	/*
	 * can't push pages past end-of-file
	 */
	filesz = zp->z_size;
	if (off >= filesz) {
		/* ignore all pages */
		err = 0;
		goto out;
	} else if (off + len > filesz) {

		len = filesz - off;
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	if (!tx) {
		printf("ZFS: %s:%d: zfs_vnops_osx: NULL TX encountered!\n", __func__, __LINE__);
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort(upl, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
		err = EINVAL;
		goto exit;
	}
	dmu_tx_hold_write(tx, zp->z_id, off, len);

	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	zfs_sa_upgrade_txholds(tx, zp);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err != 0) {
		if (err == ERESTART) {
			if (take_rlock)
				zfs_range_unlock(rl);
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		printf("ZFS: %s:%d, dmu_tx_assign failed, file %s\n",
		    __func__, __LINE__, zp->z_name_cache);
		goto out;
	}

	caddr_t va;

	if (ubc_upl_map(upl, (vm_offset_t *)&va) != KERN_SUCCESS) {
		printf("ZFS: %s:%d: ubc_upl_map failed, file %s\n",
		    __func__, __LINE__, zp->z_name_cache);
		err = EINVAL;
		goto out;
	}

	va += upl_offset;
	uint64_t pages_written = 0;
	while (len >= PAGESIZE) {
		ssize_t sz = PAGESIZE;

		printf("ZFS: %s:%d: pageout: dmu_write off 0x%llx size 0x%lx\n",
		    __func__, __LINE__, off, sz);

		dmu_write(zfsvfs->z_os, zp->z_id, off, sz, va, tx);
		va += sz;
		off += sz;
		len -= sz;
		pages_written++;
	}

	/*
	 * The last, possibly partial block needs slightly special handling.
	 */
	if (len > 0) {
		ssize_t sz = len;

		printf("ZFS: %s:%d (last block) pageout: dmu_writeX off 0x%llx size 0x%lx file size 0x%llx\n",
		    __func__, __LINE__, off, sz, zp->z_size);
		const off_t pre_size = zp->z_size;
		vnode_t *vp = ZTOV(zp);
		dmu_write(zfsvfs->z_os, zp->z_id, off, sz, va, tx);
		ASSERT3S(pre_size, ==, zp->z_size);
		if (vnode_isreg(vp) && ubc_getsize(vp) < zp->z_size) {
			ASSERT3S(zp->z_size, ==, pre_size);
			off_t ubcsize = ubc_getsize(vp);
			int setsize_retval = ubc_setsize(vp, zp->z_size);
			printf("ZFS: %s:%d: (error if nonzero) %d when increasing ubc size"
			    " from %lld to z_size %lld fs %s file %s\n",
			    __func__, __LINE__, setsize_retval, ubcsize, zp->z_size,
			    vfs_statfs(zfsvfs->z_vfs)->f_mntfromname, zp->z_name_cache);
		}

		va += sz;
		off += sz;
		len -= sz;

		pages_written++;
	}

	ubc_upl_unmap(upl);

	VNOPS_OSX_STAT_INCR(pageoutv1_pages, pages_written);

	if (err == 0 && !zfsvfs->z_unmounted && zp->z_sa_hdl) {
		uint64_t mtime[2], ctime[2];
		sa_bulk_attr_t bulk[4];
		int count = 0;

		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL,
		    &mtime, 16);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL,
		    &ctime, 16);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
		    &zp->z_pflags, 8);
		zfs_tstamp_update_setup(zp, CONTENT_MODIFIED, mtime, ctime,
		    B_TRUE);
		ASSERT3S(ubc_getsize(ZTOV(zp)), ==, zp->z_size);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_SIZE(zfsvfs), NULL,
		    &zp->z_size, 8);
		err = sa_bulk_update(zp->z_sa_hdl, bulk, count, tx);
		ASSERT0(err);
		zfs_log_write(zfsvfs->z_log, tx, TX_WRITE, zp, off, size, 0,
		    NULL, NULL);
	} else {
		ASSERT0(zfsvfs->z_unmounted);
		ASSERT3P(zp->z_sa_hdl, !=, NULL);
		ASSERT0(err);
	}
	dmu_tx_commit(tx);

out:
	if (take_rlock)
		zfs_range_unlock(rl);
	if (flags & UPL_IOSYNC)
		zil_commit(zfsvfs->z_log, zp->z_id);

	if (!(flags & UPL_NOCOMMIT)) {
		if (err) {
			printf("ZFS: %s:%d: aborting UPL range [%lu..%ld] file %s\n",
			    __func__, __LINE__, upl_offset, size, zp->z_name_cache);
			ubc_upl_abort_range(upl, upl_offset, size,
			    (UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY));
		} else {
			int cflags = UPL_COMMIT_FREE_ON_EMPTY;
			if (clear_flags) {
				cflags |= UPL_COMMIT_CLEAR_DIRTY;
				cflags |= UPL_COMMIT_CLEAR_PRECIOUS;
			}
			if (inactivate)
				cflags |= UPL_COMMIT_INACTIVATE;

			ubc_upl_commit_range(upl, upl_offset, size, cflags);
		}
	}
exit:
	if (err) printf("ZFS: %s:%d err %d\n", __func__, __LINE__, err);
	ZFS_EXIT(zfsvfs);
	return (err);
}

int
zfs_vnop_pageout(struct vnop_pageout_args *ap)
#if 0
	struct vnop_pageout_args {
		struct vnode	*a_vp;
		upl_t		a_pl;
		vm_offset_t	a_pl_offset;
		off_t		a_foffset;
		size_t		a_size;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	struct vnode *vp = ap->a_vp;
	int flags = ap->a_flags;
	upl_t upl = ap->a_pl;
	vm_offset_t upl_offset = ap->a_pl_offset;
	size_t len = ap->a_size;
	offset_t off = ap->a_f_offset;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = NULL;

	if (!zp || !zp->z_zfsvfs) {
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort(upl,
			    (UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY));
		printf("ZFS: vnop_pageout: null zp or zfsvfs\n");
		return (ENXIO);
	}

	zfsvfs = zp->z_zfsvfs;

	dprintf("+vnop_pageout: off 0x%llx len 0x%lx upl_off 0x%lx: "
	    "blksz 0x%x, z_size 0x%llx\n", off, len, upl_offset, zp->z_blksz,
	    zp->z_size);

	/*
	 * We lock against update_pages() [part of zfs_write()] and
	 * zfs_vnop_pagein(), and zfs_vnop_pageoutv2(), and ourselves
	 * (if in other threads), since any of these may dirty the UBC
	 * for this file.
	 */

	boolean_t need_release = B_FALSE;
	boolean_t need_upgrade = B_FALSE;

	if (!rw_write_held(&zp->z_map_lock)) {
		ASSERT(spl_ubc_is_mapped(vp, NULL));
		uint64_t tries = z_map_rw_lock(zp, &need_release, &need_upgrade, __func__);
		VNOPS_OSX_STAT_INCR(pageoutv1_want_lock, tries);
	} else {
		printf("ZFS: %s: z_map_lock already held\n", __func__);
	}

	/*
	 * XXX Crib this too, although Apple uses parts of zfs_putapage().
	 * Break up that function into smaller bits so it can be reused.
	 */

	int retval =  zfs_pageout(zfsvfs, zp, upl, upl_offset, ap->a_f_offset,
	    len, flags, B_TRUE, B_FALSE, B_TRUE);

	z_map_drop_lock(zp, &need_release, &need_upgrade);

	return (retval);
}

#if 0
static int
copy_upl_to_mem(upl_t upl, upl_page_info_t *pl,
    int upl_offset, int bytes_to_copy, void *mem)
{

	int error;
	uio_t uio;

	ASSERT3S(upl_offset, >, 0);
	ASSERT3S(upl_offset, <=, MAX_UPL_SIZE_BYTES - round_page(bytes_to_copy));

	int page_index_start, page_index_end, it;
	page_index_start = upl_offset / PAGE_SIZE;
	page_index_end = howmany(upl_offset + bytes_to_copy, PAGE_SIZE);
	for (i = page_index_start; i < page_index_end; i++) {
		ASSERT(upl_valid_page(pl, i));
	}

	uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
	uio_addiov(uio, CAST_USER_ADDR_T(mem), bytes_to_copy);
	error = cluster_copy_upl_data(uio, upl, upl_offset, &bytes_to_copy);
	ASSERT3S(error, ==, 0);
	ASSERT3S(bytes_to_copy, ==, 0);
	uio_free(uio);
	return (error);
}

static int
copy_avoiding_ubc_upl_map(upl_t upl, upl_page_info_t *upl,
    int upl_offset, int bytes_to_copy)
{
	/* where do we get the memory from?  abd? */
}
#endif

static int
bluster_pageout(zfsvfs_t *zfsvfs, znode_t *zp, upl_t upl,
    const upl_offset_t upl_offset, const off_t f_offset, const int size,
    const uint64_t filesize, const int flags,
    struct vnop_pageout_args *ap,
    caddr_t *pvaddr, int pages_remaining, boolean_t *caller_unmapped)
{
	int           is_clcommit = 0;
	dmu_tx_t *tx;
	int       error = 0;

	VNOPS_OSX_STAT_BUMP(bluster_pageout_calls);

	ASSERT3P(caller_unmapped, !=, NULL);

	ASSERT0(upl_offset & PAGE_MASK_64);
	ASSERT0(size & PAGE_MASK_64);
	ASSERT3S(size, >=, PAGE_SIZE_64);

	ASSERT3S(ubc_getsize(ZTOV(zp)), ==, filesize);

	/* we had better not be calling this with UPL_NOCOMMIT set */
	ASSERT3S(flags & UPL_NOCOMMIT, ==, 0);
	is_clcommit = 1;

	boolean_t unmap = B_FALSE;
	if (pages_remaining == 1 || pages_remaining == howmany(size, PAGE_SIZE)) {
		if (is_clcommit)
			unmap = B_TRUE;
	} else {
		ASSERT3S(pages_remaining, >, 1);
		ASSERT3S(pages_remaining, >, howmany(size, PAGE_SIZE));
	}

	/*
	 * if is_clcommit (expected to be true) then we MUST commit or
	 * abort all the pages from upl_offset to upl_offset + size
	 * before returning
	 */

	/*
	 * If they didn't specify any I/O, then we are done...
	 * we can't issue an abort because we don't know how
	 * big the upl really is : our caller should VERIFY that
	 * it is not giving us a zero-length size.
	 */
	if (size <= 0) {
		panic("ZFS: %s:%d invalid size %d file %s\n", __func__, __LINE__,
		    size, zp->z_name_cache);
	}

	if (vnode_vfsisrdonly(ZTOV(zp)) ||
	    vfs_flags(zfsvfs->z_vfs) & MNT_RDONLY ||
            !spa_writeable(dmu_objset_spa(zfsvfs->z_os))) {
		printf("ZFS: %s:%d readonly fs %s for [%lld..%lld] file %s\n", __func__,
		    __LINE__, vfs_statfs(zfsvfs->z_vfs)->f_mntfromname,
		    f_offset, f_offset + size, zp->z_name_cache);
		if (unmap) {
			ubc_upl_unmap(upl);
			*caller_unmapped = B_TRUE;
		}
		if (is_clcommit) {
			ubc_upl_abort_range(upl, upl_offset, size,
			    UPL_ABORT_ERROR
			    | UPL_ABORT_FREE_ON_EMPTY
			    | UPL_ABORT_DUMP_PAGES);
		}
		return (EROFS);
	}

	/*
	 * can't page-in from a negative offset
	 * or if we're starting beyond the EOF
	 * or if the file offset isn't page aligned
	 * or the size requested isn't a multiple of PAGE_SIZE
	 */
	if (f_offset < 0 ||
		(f_offset & PAGE_MASK_64) || (size & PAGE_MASK)) {
		printf("ZFS: %s:%d invalid offset or size (off %lld, size %d, filesize %lld)"
		    " file %s\n" , __func__, __LINE__, f_offset, size, filesize, zp->z_name_cache);
		if (unmap) {
			ubc_upl_unmap(upl);
			*caller_unmapped = B_TRUE;
		}
		if (is_clcommit)
			ubc_upl_abort_range(upl, upl_offset, size,
			    UPL_ABORT_ERROR
			    | UPL_ABORT_FREE_ON_EMPTY
			    | UPL_ABORT_DUMP_PAGES);
		return (EINVAL);
	}

	if (f_offset > filesize) {
		printf("ZFS: %s:%d: trying to write starting past filesize %lld : off %lld, size %u,"
		    " filename %s\n",
		    __func__, __LINE__, filesize, f_offset, size, zp->z_name_cache);
		if (unmap) {
			ubc_upl_unmap(upl);
			*caller_unmapped = B_TRUE;
		}
		if (is_clcommit) {
			int abortret = ubc_upl_abort_range(upl, upl_offset, size,
			    UPL_ABORT_ERROR
			    | UPL_ABORT_FREE_ON_EMPTY
			    | UPL_ABORT_DUMP_PAGES);
			ASSERT3S(abortret, ==, KERN_SUCCESS);
		}
		return (SET_ERROR(EINVAL));
	}

	off_t write_size = size;
	if (f_offset + size > filesize) {
		ASSERT3S(filesize - f_offset, <, INT_MAX);
		ASSERT3S(filesize - f_offset, >, 0);
		off_t write_space = filesize - f_offset;
		if (write_space <= 0)  {
			printf("ZFS: %s:%d: write_space %lld, filesize (%lld) - foffset (%lld) < 1 (%lld)"
			    " ! for upl_offset %u a_f_off %lld a_size %ld @ file %s\n",
			    __func__, __LINE__, write_space, filesize, f_offset, write_space,
			    upl_offset, ap->a_f_offset, ap->a_size, zp->z_name_cache);
			if (unmap) {
				ubc_upl_unmap(upl);
				*caller_unmapped = B_TRUE;
			}
			if (is_clcommit) {
				int abortret = ubc_upl_abort_range(upl, upl_offset, size,
				    UPL_ABORT_FREE_ON_EMPTY
				    | UPL_ABORT_ERROR);
				ASSERT3S(abortret, ==, KERN_SUCCESS);
			}
			return (SET_ERROR(EINVAL));
		}
		write_size = MIN((off_t)size, write_space);
		if (write_size < (off_t)size) {
			dprintf("ZFS: %s:%d reducing write_size from size %u to %lld,"
			    " off %lld filesize %lld file %s\n",
			    __func__, __LINE__,
			    size, write_size,
			    f_offset, filesize, zp->z_name_cache);
		}
	}

	if (!dmu_write_is_safe(zp, f_offset, f_offset + write_size)) {
		printf("ZFS: %s:%d: cannot safely write [%lld, %lld] z_blksz %d file %s\n",
		    __func__, __LINE__, f_offset, f_offset + write_size,
		    zp->z_blksz, zp->z_name_cache);
		if (unmap) {
			ubc_upl_unmap(upl);
			*caller_unmapped = B_TRUE;
		}
		if (is_clcommit) {
			int abortret = ubc_upl_abort_range(upl, upl_offset, size,
			    UPL_ABORT_FREE_ON_EMPTY
			    | UPL_ABORT_ERROR);
			ASSERT3S(abortret, ==, KERN_SUCCESS);
		}
		return(EAGAIN);
	}

	dprintf("ZFS: %s:%d: beginning DMU transaction on %s\n", __func__, __LINE__,
	    zp->z_name_cache);

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	zfs_sa_upgrade_txholds(tx, zp);
	dmu_tx_hold_write(tx, zp->z_id, f_offset, write_size);
	error = dmu_tx_assign(tx, TXG_WAIT);
	ASSERT3S(error, ==, 0);
	if (error != 0) {
		dmu_tx_abort(tx);
		printf("ZFS: %s:%d: dmu_tx_assign error %d, aborting range [%u..%d] file %s fs %s\n",
		    __func__, __LINE__, error, upl_offset, size, zp->z_name_cache,
		    vfs_statfs(zfsvfs->z_vfs)->f_mntfromname);
		if (unmap) {
			ubc_upl_unmap(upl);
			*caller_unmapped = B_TRUE;
		}
		if (is_clcommit) {
			kern_return_t abort_ret = ubc_upl_abort_range(upl,
			    upl_offset, size,
			    UPL_ABORT_FREE_ON_EMPTY
			    | UPL_ABORT_ERROR);
			ASSERT3S(abort_ret, ==, KERN_SUCCESS);
		}
		return (error);
	}

	upl_page_info_t *pl = ubc_upl_pageinfo(upl);
	const int64_t stpage = (int64_t)upl_offset / PAGE_SIZE_64;
	const int64_t endpage = ((int64_t)(upl_offset + size) / PAGE_SIZE_64) - 1LL;
	ASSERT3S(endpage - stpage, >=, 0);
	ASSERT3S((endpage - stpage) + 1LL, <=, pages_remaining);
	for (int64_t i = endpage; i >= stpage; i--) {
		if (upl_valid_page(pl, i) ||
		    upl_dirty_page(pl, i)) {
			ASSERT(upl_page_present(pl, i));
		} else {
			printf("ZFS: %s:%d: bad page %lld (pgs %lld-%lld)"
			    " [file bytes to write %lld-%lld] (size %lld)"
			    " fs %s file %s (mapped %d) (caller_unmapped %d)"
			    " val %d pres %d dirt %d size %d f_offset+size %lld"
			    " pages remaining %d upl_offset %d\n",
			    __func__, __LINE__, i, stpage, endpage,
			    f_offset, f_offset + write_size, write_size,
			    vfs_statfs(zfsvfs->z_vfs)->f_mntfromname,
			    zp->z_name_cache, unmap, *caller_unmapped,
			    upl_valid_page(pl, i), upl_page_present(pl, i),
			    upl_dirty_page(pl, i), size, f_offset + size,
			    pages_remaining, upl_offset);
			extern void IOSleep(unsigned milliseconds);
			IOSleep(10);
			if (unmap) {
				ubc_upl_unmap(upl);
				*caller_unmapped = B_TRUE;
			}
			if (is_clcommit) {
				kern_return_t abort_ret = ubc_upl_abort_range(upl,
				    upl_offset, size,
				    UPL_ABORT_FREE_ON_EMPTY
				    | UPL_ABORT_ERROR);
				ASSERT3S(abort_ret, ==, KERN_SUCCESS);
			}
			dmu_tx_commit(tx);
			error = EFAULT;
			return (error);
		}
	}
	ASSERT3S(round_page_64(upl_offset + write_size), <=, upl_offset + size);

	for (int i = endpage; i >= stpage; i--) {
		dprintf("ZFS: %s:%d: page %d : '0x%x'\n", __func__, __LINE__, i,
		    *pvaddr[i*PAGE_SIZE]);
	}

	dprintf("ZFS: %s:%d: dmu_write %lld bytes (of %d) from pvaddr[%u] to offset %lld in file %s\n",
	    __func__, __LINE__, write_size, size, upl_offset, f_offset, zp->z_name_cache);

	dmu_write(zfsvfs->z_os, zp->z_id, f_offset, write_size, pvaddr[upl_offset], tx);

	/* update SA and finish off transaction */
        if (error == 0) {
                uint64_t mtime[2], ctime[2];
                sa_bulk_attr_t bulk[4];
                int count = 0;

                SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL,
                    &mtime, 16);
                SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL,
                    &ctime, 16);
                SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
                    &zp->z_pflags, 8);
                zfs_tstamp_update_setup(zp, CONTENT_MODIFIED, mtime, ctime,
                    B_TRUE);
		ASSERT3S(ubc_getsize(ZTOV(zp)), ==, zp->z_size);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_SIZE(zfsvfs), NULL, &zp->z_size, 8);
		error = sa_bulk_update(zp->z_sa_hdl, bulk, count, tx);
		ASSERT0(error);
                zfs_log_write(zfsvfs->z_log, tx, TX_WRITE, zp, f_offset, write_size, 0,
                    NULL, NULL);
        } else {
		printf("ZFS: %s:%d: because of earlier error %d, did not SA update %s\n",
		    __func__, __LINE__, error, zp->z_name_cache);
	}

	dprintf("ZFS: %s:%d: DMU committing tx for [%lld..%lld] in file %s\n",
	    __func__, __LINE__, f_offset, f_offset + write_size, zp->z_name_cache);

	dmu_tx_commit(tx);

	ASSERT3S(ubc_getsize(ZTOV(zp)), ==, zp->z_size);
	ASSERT3S(ubc_getsize(ZTOV(zp)), >=, f_offset + write_size);
	VNOPS_OSX_STAT_INCR(bluster_pageout_dmu_bytes, write_size);

	dprintf("ZFS: %s:%d: successfully committed tx for [%lld..%lld] in file %s\n",
	    __func__, __LINE__, f_offset, f_offset+size, zp->z_name_cache);

	if (unmap) {
		ASSERT3S(*caller_unmapped, ==, B_FALSE);
		int unmapret = ubc_upl_unmap(upl);
		if (unmapret != KERN_SUCCESS)
			printf("ZFS: %s:%d: error unmapping UPL for [%lld..%lld] file %s\n",
			    __func__, __LINE__, f_offset, f_offset + size, zp->z_name_cache);
		*caller_unmapped = B_TRUE;
	}

	if (is_clcommit) {
		if (error != 0) {
			printf("ZFS: %s:%d: error %d so aborting uploff %u abortlen %d uplfoff %lld"
			    " fs %s file %s\n", __func__, __LINE__, error, upl_offset,
			    size, f_offset, vfs_statfs(zfsvfs->z_vfs)->f_mntfromname, zp->z_name_cache);
			int abortflags = UPL_ABORT_FREE_ON_EMPTY;
			if (error == 35)
				abortflags |= UPL_ABORT_RESTART;
			else
				abortflags |= UPL_ABORT_ERROR;
			kern_return_t abortret = ubc_upl_abort_range(upl,
			    upl_offset, size, abortflags);
			if (abortret != KERN_SUCCESS) {
				printf("ZFS: %s:%d error %d aborting after error %d"
				    " uploff %u abortlen %d uplfoff %lld file %s\n",
				    __func__, __LINE__, abortret, error,
				    upl_offset, size, f_offset, zp->z_name_cache);
			} else {
				printf("ZFS: %s:%d successful abort after error %d"
				    " uploff %u abortlen %d uplfoff %lld file %s\n",
				    __func__, __LINE__, error,
				    upl_offset, size, f_offset, zp->z_name_cache);
			}
		} else {
			int commitflags = UPL_COMMIT_FREE_ON_EMPTY
			    | UPL_COMMIT_CLEAR_DIRTY
			    | UPL_COMMIT_CLEAR_PRECIOUS;
			kern_return_t commitret = ubc_upl_commit_range(upl, upl_offset, size, commitflags);
			if (commitret != KERN_SUCCESS) {
				printf("ZFS: %s:%d: error %d"
				    " from ubc_upl_commit_range %u - %d f_off %lld .. %lld file %s fs %s\n",
				    __func__, __LINE__, commitret,
				    upl_offset, size, f_offset, f_offset + size,
				    zp->z_name_cache, vfs_statfs(zfsvfs->z_vfs)->f_mntfromname);
				error = commitret;
			} else {
				dprintf("ZFS: %s:%d: successfully committed range %u - %d"
				    " f_off %lld file %s\n", __func__, __LINE__,
				    upl_offset, size, f_offset, zp->z_name_cache);
			}
		}
	}

	if (error == 0 && size > 0) {
		uint64_t pgs = atop_64(size) + 1ULL;
		VNOPS_OSX_STAT_INCR(bluster_pageout_pages, pgs);
	}

	ASSERT3S(ubc_getsize(ZTOV(zp)), ==, zp->z_size);
	ASSERT3S(ubc_getsize(ZTOV(zp)), >=, f_offset + write_size);

	return (error);
}

/*
 * serialize calls to ubc_msync for a given znode
 * (ultimate goal: total FIFO
 */

int
zfs_ubc_msync(vnode_t *vp, off_t start, off_t end, off_t *resid, int flags)
{

	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	boolean_t do_zil_commit = B_FALSE;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	const hrtime_t entry_time = gethrtime();

	/*
	 * watch out for reentrancy!
	 */

	if (flags & ZFS_UBC_FORCE_MSYNC)
		flags &= ~(ZFS_UBC_FORCE_MSYNC);

	/*
	 * If the file's clean, ubc_msync might not descend into pageoutv2,
	 * so we should do a zil_commit
	 */

	if (ubc_getsize(vp) == 0 && zp->z_size != 0) {
		printf("ZFS: %s:%d: called with zero ubcsize; z_size %lld, start %lld, end %lld,"
		    "flags %d, file %s\n",
		    __func__, __LINE__, zp->z_size, start, end, flags, zp->z_name_cache);
	}

	if (flags & UBC_SYNC &&
	    is_file_clean(vp, end) == 0)
		do_zil_commit = B_TRUE;

	ASSERT3P(zp->z_syncer_active, !=, curthread);

	mutex_enter(&zp->z_ubc_msync_lock);

	while (zp->z_syncer_active != NULL && zp->z_syncer_active != curthread) {
		ASSERT3P(zp->z_syncer_active, !=, curthread);
		cv_wait(&zp->z_ubc_msync_cv, &zp->z_ubc_msync_lock);
	}

	ASSERT3P(zp->z_syncer_active, ==, NULL);
	zp->z_syncer_active = curthread;

	mutex_exit(&zp->z_ubc_msync_lock);

	int retval = ubc_msync(vp, start, end, resid, flags);

	mutex_enter(&zp->z_ubc_msync_lock);

	ASSERT3S(zp->z_syncer_active, ==, curthread);
	zp->z_syncer_active = NULL;

	cv_signal(&zp->z_ubc_msync_cv);

	mutex_exit(&zp->z_ubc_msync_lock);

	const hrtime_t exit_time = gethrtime();
	const hrtime_t elapsed_time = exit_time - entry_time;
	const int elapsed_seconds = NSEC2SEC(elapsed_time);
	if (elapsed_seconds > 1) {
		printf("ZFS: %s:%d: long ubc_msync, %d seconds, file %s\n",
		    __func__, __LINE__, elapsed_seconds, zp->z_name_cache);
	}

	if (do_zil_commit && zfsvfs->z_log)
		zil_commit(zfsvfs->z_log, zp->z_id);

	if (retval == 0)
		zp->z_mr_sync = exit_time;

	ZFS_EXIT(zfsvfs);

	return (retval);
}


/*
 * In V2 of vnop_pageout, we are given a NULL upl, so that we can
 * grab the file locks first, then request the upl to lock down pages.
 */

static int
pageoutv2_helper(struct vnop_pageout_args *ap)
#if 0
	struct vnop_pageout_args {
		struct vnode	*a_vp;
		upl_t		a_pl;
		vm_offset_t	a_pl_offset;
		off_t		a_foffset;
		size_t		a_size;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	struct vnode *vp = ap->a_vp;
	int a_flags = ap->a_flags;
	vm_offset_t	a_pl_offset = ap->a_pl_offset;
	size_t a_size = ap->a_size;
	upl_t upl = ap->a_pl;
	upl_page_info_t* pl;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = NULL;
	int error = 0;
	uint64_t filesize;
	rl_t *rl;
	boolean_t mapped = B_FALSE;

	VNOPS_OSX_STAT_BUMP(pageoutv2_calls);

	/* We can still get into this function as non-v2 style, by the default
	 * pager (ie, swap - when we eventually support it)
	 */
	if (upl) {
		printf("ZFS: Relaying vnop_pageoutv2 to vnop_pageout\n");
		return zfs_vnop_pageout(ap);
	}

	if (!zp || !zp->z_zfsvfs || !zp->z_sa_hdl) {
		printf("ZFS: vnop_pageout: null zp or zfsvfs\n");
		return (ENXIO);
	}

	zfsvfs = zp->z_zfsvfs;

	dprintf("+vnop_pageout2: off 0x%llx len 0x%lx upl_off 0x%lx: "
		   "blksz 0x%x, z_size 0x%llx\n", ap->a_f_offset, a_size,
			a_pl_offset, zp->z_blksz,
			zp->z_size);


	/* Start the pageout request */
	/*
	 * We can't leave this function without either calling upl_commit or
	 * upl_abort. So use the non-error version.
	 */
	ZFS_ENTER_NOERROR(zfsvfs);
	const off_t ubcsize_at_entry = ubc_getsize(vp);
	if (zfsvfs->z_unmounted) {
		printf("ZFS: vnop_pageoutv2: abort on z_unmounted\n");
		error = EIO;
		goto exit_abort;

	}

	ASSERT3P(zp->z_sa_hdl, !=, NULL);
	ASSERT(ubc_pages_resident(vp));

	if (ap->a_size <= 0) {
		printf("ZFS: %s:%d: invalid ap->a_size %ld, ap->a_f_offset %lld, file %s\n",
		    __func__, __LINE__, ap->a_size, ap->a_f_offset, zp->z_name_cache);
		error = EINVAL;
		goto exit_abort;
	}

	if (ap->a_f_offset < 0 || ap->a_f_offset >= zp->z_size) {
		printf("ZFS: %s:%d: invalid offset %lld vs filesize %lld\n",
		    __func__, __LINE__, ap->a_f_offset, zp->z_size);
		error = EINVAL;
		goto exit_abort;
	}

	/*
	 * To avoid deadlocking, we must take the range lock, then
	 * acquire the z_map_lock lock.  If we enter with the
	 * z_map_enter lock held, drop it.  Then go through the process
	 * of (a) acquire range lock (b) try to acquire z_map_lock.  If
	 * we can't acquire z_map_lock, then if there are other waiters
	 * for this range lock, we drop the range lock, then reacquire
	 * it, and continue with (b).
	 *
	 * Eventually we have ordered: [1] rl [2] z_map_lock.
	 */
	boolean_t had_map_lock_at_entry = B_FALSE;
	if (rw_write_held(&zp->z_map_lock)) {
		dprintf("ZFS: %s:%d: dropping held-on-entry z_map_lock for file %s\n",
		    __func__, __LINE__, zp->z_name_cache);
		rw_exit(&zp->z_map_lock);
		had_map_lock_at_entry = B_TRUE;
	}

	/*
	 * We need to lock whole pages, because we have to lock
	 * whole pages for the UPL.  We *must* prevent this thread
	 * from trying to build a UPL that contains a page that's
	 * held by another threaad.
	 */

	const off_t rloff = trunc_page_64(ap->a_f_offset);
	const off_t rllen = round_page_64(a_size);

	rl = zfs_range_lock(zp, rloff, rllen, RL_WRITER);

	hrtime_t print_time = gethrtime() + SEC2NSEC(1);
	int secs = 0;

	extern void IOSleep(unsigned milliseconds); // yields thread
	extern void IODelay(unsigned microseconds); // x86_64 rep nop


	boolean_t need_release = B_FALSE;
	boolean_t need_upgrade = B_FALSE;

	while(!rw_write_held(&zp->z_map_lock)){
		if (secs == 0)
			secs = 1;
		if (rw_tryenter(&zp->z_map_lock, RW_WRITER))
			break;
		hrtime_t cur_time = gethrtime();
		if (cur_time > print_time) {
			secs++;
			printf("ZFS: %s:%d: looping for z_map_lock for %d sec"
			    " (held by %s) file %s\n", __func__, __LINE__, secs,
                            (zp->z_map_lock_holder != NULL)
                            ? zp->z_map_lock_holder
                            : "(NULL)",
			    zp->z_name_cache);
			print_time = cur_time + SEC2NSEC(1);
			zfs_range_unlock(rl);
			printf("ZFS: %s:%d range lock dropedit for [%lld, %ld] for file %s\n",
			    __func__, __LINE__, ap->a_f_offset, a_size, zp->z_name_cache);
			IOSleep(1); // we hold no locks, so let work be done
			rl = zfs_range_lock(zp, rloff, rllen, RL_WRITER);
		}
		IODelay(1);
	}

	ASSERT(rw_write_held(&zp->z_map_lock));
	need_release = B_TRUE;
	zp->z_map_lock_holder = __func__;

	if (secs == 0) {
		printf("ZFS: %s:%d: lock was already held for %s\n",
		    __func__, __LINE__, zp->z_name_cache);
	} else {
		VNOPS_OSX_STAT_INCR(pageoutv2_want_lock, secs);
	}

	/* extend file if necessary */
	extern int zfs_write_maybe_extend_file(znode_t *zp, off_t woff, off_t start_resid, rl_t *rl);
	error = zfs_write_maybe_extend_file(zp, ap->a_f_offset, ap->a_size, rl);

	if (error) {
		ZFS_EXIT(zfsvfs);
                printf("ZFS: %s:%d: (extend fail) returning error %d\n", __func__, __LINE__, error);
		goto pageout_done;
	}

	/*
	 * If zfs_range_lock() over-locked we grow the blocksize
	 * and then reduce the lock range.  This will only happen
	 * on the first iteration since zfs_range_reduce() will
	 * shrink down r_len to the appropriate size.
	 */
	off_t woff = ap->a_f_offset;
	off_t end_size = MAX(zp->z_size, woff + a_size);

	if (rl->r_len == UINT64_MAX ||
	    (end_size > zp->z_blksz &&
		((!ISP2(zp->z_blksz || zp->z_blksz < zfsvfs->z_max_blksz)) ||
		    !dmu_write_is_safe(zp, woff, end_size)))) {

		uint64_t new_blksz = 0;
		const int max_blksz = zfsvfs->z_max_blksz;
		if (zp->z_blksz < max_blksz) {
			ASSERT(!ISP2(zp->z_blksz));
			new_blksz = MIN(end_size,
			    1 << highbit64(zp->z_blksz));
			if (new_blksz == end_size) {
				ASSERT(!ISP2(end_size));
			}
		} else {
			new_blksz = MIN(end_size, max_blksz);
		}
		if (ISP2(new_blksz) && new_blksz < max_blksz) {
			uint64_t new_new_blksz = new_blksz + 1;
			dprintf("ZFS: %s:%d: bumping new_blksz from %lld to %lld\n",
			    __func__, __LINE__, new_blksz, new_new_blksz);
			ASSERT(!ISP2(new_new_blksz));
			new_blksz = new_new_blksz;
		}
		if (new_blksz > zp->z_blksz) {
			printf("ZFS: %s:%d growing buffer to %llu (from %d) file %s\n",
			    __func__, __LINE__, new_blksz, zp->z_blksz, zp->z_name_cache);
			dmu_tx_t *tx = dmu_tx_create(zfsvfs->z_os);
			dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
			zfs_sa_upgrade_txholds(tx, zp);
			dmu_tx_hold_write(tx, zp->z_id, ap->a_f_offset, ap->a_size);
			error = dmu_tx_assign(tx, TXG_WAIT);
			ASSERT3S(error, ==, 0);
			if (error != 0) {
				dmu_tx_abort(tx);
				goto pageout_done;
			}
			zfs_grow_blocksize(zp, new_blksz, tx);
			dmu_tx_commit(tx);
		}
		zfs_range_reduce(rl, rloff, rllen);
	}

	const char *fname = zp->z_name_cache;
	const char *fsname = vfs_statfs(zfsvfs->z_vfs)->f_mntfromname;

	if (ubc_getsize(vp) < zp->z_size) {
		printf("ZFS: %s:%d: increasing ubc size from %lld to z_size %lld for"
		    " fs %s file %s\n", __func__, __LINE__,
		    ubc_getsize(vp), zp->z_size, fsname, fname);
		int setsize_retval = ubc_setsize(vp, zp->z_size);
		ASSERT3S(setsize_retval, !=, 0); // ubc_setsize returns true on success
	}

	/* Grab UPL now */
	int request_flags;

	/*
	 * we're in control of any UPL we commit
	 * make sure someone hasn't accidentally passed in UPL_NOCOMMIT
	 */
	a_flags &= ~UPL_NOCOMMIT;
	a_pl_offset = 0;

	if (a_flags & UPL_MSYNC) {
		request_flags = UPL_UBC_MSYNC | UPL_RET_ONLY_DIRTY;
		VNOPS_OSX_STAT_BUMP(pageoutv2_msync);
	}
	else {
		request_flags = UPL_UBC_PAGEOUT | UPL_RET_ONLY_DIRTY;
		VNOPS_OSX_STAT_BUMP(pageoutv2_pageout);
	}

	ASSERT3S(ap->a_size, <=, MAX_UPL_SIZE_BYTES);

	error = ubc_create_upl(vp, ap->a_f_offset, ap->a_size, &upl, &pl,
						   request_flags );
	if (error || (upl == NULL)) {
		printf("ZFS: %s: Failed to create UPL! %d\n", __func__, error);
		goto pageout_done;
	}

	const off_t f_start_of_upl = ap->a_f_offset;
	const off_t f_end_of_upl = f_start_of_upl + ap->a_size;

	/*
	 * The caller may hand us a memory range that results in a run
	 * of pages at the end of the UPL that aren't present now.
	 * Under memory pressure, the kernel may reclaim the whole UPL
	 * from the moment we use a FREE_ON_EMPTY, if the UPL is
	 * entirely non-present pages.  If this happens while we hold a
	 * ubc_upl_map, then we have one of two problems: [a] if we call
	 * ubc_upl_unmap, we will panic because the UPL is now empty or
	 * [b] we cannot call ubc_upl_unmap, but the mapping is not
	 * automatically reclaimed by the kernel, so an ioreference
	 * remains on the backing file.
	 *
	 * So here we scan from the back of the UPL looking for the first
	 * valid (== present and not marked absent) page; we will treat
	 * that as the practical end of the UPL.
	 */

	int upl_pages_dismissed = 0;
	const int pages_in_upl = howmany(ap->a_size, PAGE_SIZE_64);
	for (int page_index = pages_in_upl; page_index > 0; ) {
		if (upl_valid_page(pl, --page_index)) {
			ASSERT(upl_page_present(pl, page_index));
			break;
		} else {
			ASSERT0(upl_dirty_page(pl, page_index));
			if (upl_page_present(pl, page_index)) {
				printf("ZFS: %s:%d: page index %d (of %d) not valid but"
				    " present, dismissing anyway XXX, [%lld..%lld] in"
				    " filesize %lld fs %s file %s\n",
				    __func__, __LINE__, page_index, pages_in_upl - 1,
				    f_start_of_upl, f_end_of_upl, zp->z_size,
				    fsname, fname);
			}
			upl_pages_dismissed++;
		}
	}

	if (upl_pages_dismissed == pages_in_upl) {
		printf("ZFS: %s:%d: entire UPL absent (%d pages)"
		    " [%lld..%lld] filesize %lld fs %s file %s\n",
		    __func__, __LINE__, upl_pages_dismissed,
		    f_start_of_upl, f_end_of_upl, zp->z_size,
		    fsname, fname);
		int abortall = ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
		ASSERT3S(abortall, ==, KERN_SUCCESS);
		error = abortall;
		VNOPS_OSX_STAT_BUMP(pageoutv2_no_pages_valid);
		VNOPS_OSX_STAT_INCR(pageoutv2_invalid_tail_pages, upl_pages_dismissed);
		goto pageout_done;
	} else if (upl_pages_dismissed > 0) {
		ASSERT3S(pages_in_upl, >, 1);
		const int lowest_page_dismissed = pages_in_upl - upl_pages_dismissed;
		const int start_of_tail = lowest_page_dismissed * PAGE_SIZE;
		const int end_of_tail = ap->a_size;
		/*
		 * The abort can return 5 (KERN_FAILURE) without
		 * apparent problem We are not outright obliged to abort
		 * empty pages, and they are "donated" to the vm map, which
		 * disposes of them at unmap time.
		 */
		int abort_tail = ubc_upl_abort_range(upl, start_of_tail, end_of_tail,
		    UPL_ABORT_FREE_ON_EMPTY);
		printf("ZFS: %s:%d: %d pages [%d..%d] trimmed from tail of %d page UPL"
		    " [%lld..%lld] fs %s file %s (abort_tail err %d)\n",
		    __func__, __LINE__, upl_pages_dismissed,
		    start_of_tail, end_of_tail, pages_in_upl,
		    f_start_of_upl, f_end_of_upl, fsname, fname, abort_tail);
		if (abort_tail == KERN_SUCCESS) {
			VNOPS_OSX_STAT_INCR(pageoutv2_invalid_tail_pages, upl_pages_dismissed);
		} else {
			int abortall_after_tail_fail = ubc_upl_abort(upl,
			    UPL_ABORT_FREE_ON_EMPTY);
			ASSERT3S(abortall_after_tail_fail, ==, KERN_SUCCESS);
			error = abort_tail;
			goto pageout_done;
		}
	}

	const off_t trimmed_upl_size = (off_t)ap->a_size - ((off_t)upl_pages_dismissed * PAGE_SIZE_64);
	ASSERT3S(trimmed_upl_size, >=, PAGE_SIZE_64);

	if (vnode_vfsisrdonly(ZTOV(zp)) ||
	    !spa_writeable(dmu_objset_spa(zfsvfs->z_os))) {
		printf("ZFS: %s:%d: WARNING: readonly filesystem %s for [%lld...%lld] file %s\n",
		    __func__, __LINE__,
		    vfs_statfs(zfsvfs->z_vfs)->f_mntfromname,
		    ap->a_f_offset,
		    ap->a_f_offset + ap->a_size, zp->z_name_cache);
		int erofs_abortret = ubc_upl_abort(upl, UPL_ABORT_ERROR
		    | UPL_ABORT_DUMP_PAGES
		    | UPL_ABORT_FREE_ON_EMPTY);
		ASSERT3S(erofs_abortret, ==, KERN_SUCCESS);
		error = EROFS;
		goto pageout_done;
	}

	if (zp->z_pflags & ZFS_IMMUTABLE) {
		printf("ZFS: %s:%d: immutable flags set for file %s\n",
		    __func__, __LINE__, zp->z_name_cache);
		int immutable_abort_ret = ubc_upl_abort(upl, UPL_ABORT_ERROR
		    | UPL_ABORT_DUMP_PAGES
		    | UPL_ABORT_FREE_ON_EMPTY);
		ASSERT3S(immutable_abort_ret, ==, KERN_SUCCESS);
		error = EPERM;
		goto pageout_done;
	}

	/* map in UPL address space */

	dprintf("ZFS: %s:%d: mapping upl [%lld...%lld] @ file %s\n",
	    __func__, __LINE__, ap->a_f_offset, ap->a_f_offset + ap->a_size,
	    zp->z_name_cache);

	caddr_t v_addr;
	int mapret = 0;
	if ((mapret = ubc_upl_map(upl, (vm_offset_t *)&v_addr)) != KERN_SUCCESS) {
		error = EINVAL;
		printf("ZFS: %s:%d unable to map, error %d\n", __func__, __LINE__, mapret);
		int abortret = ubc_upl_abort(upl, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
		ASSERT3S(abortret, ==, KERN_SUCCESS);
		goto pageout_done;
	}
	mapped = B_TRUE;

	int64_t pg_index;

	filesize = zp->z_size; /* get consistent copy of zp_size */

	/*
	 * Scan from the start of the UPL to the last valid page in the UPL.
	 *
	 * If we have an absent page, keep gathering subsequnt absent pages,
	 * then abort them as a range.
	 *
	 * If we have a present-but-not-dirty page, keep gathering subsequent
	 * present-but-not-dirty pages, then abort them as a range.
	 *
	 * If in either of the above cases we will deal with the last page in the UPL,
	 * then unmap before the {commit,abort}_range call.
	 *
	 * If we have a dirty page, keep gathering dirty pages and then bluster them all.
	 *
	 * If we have run out of pages, we are done.
	 */
	const off_t just_past_last_valid_pg = howmany(trimmed_upl_size, PAGE_SIZE_64);
	const off_t upl_end_pg = just_past_last_valid_pg - 1;
	ASSERT3S(upl_end_pg, >=, 0);

	for (pg_index = 0; pg_index < just_past_last_valid_pg; ) {
		VERIFY3S(mapped, ==, B_TRUE);
		/* we found an absent page */
		if (!upl_valid_page(pl, pg_index)) {
			ASSERT0(upl_dirty_page(pl, pg_index));
			int64_t page_past_end_of_range = pg_index + 1;
			/* gather up a range of absent pages */
			for ( ; page_past_end_of_range < just_past_last_valid_pg;
			      page_past_end_of_range++) {
				if (upl_page_present(pl, page_past_end_of_range))
					break;
			}
			ASSERT3S(page_past_end_of_range, <=, just_past_last_valid_pg);
			const off_t start_of_range = pg_index * PAGE_SIZE_64;
			const off_t end_of_range = page_past_end_of_range * PAGE_SIZE_64;
			const off_t pages_in_range = page_past_end_of_range - pg_index;
			const off_t last_page_in_range = pg_index + pages_in_range - 1;
			ASSERT3S(pages_in_range, ==, howmany(end_of_range - start_of_range, PAGE_SIZE_64));
			ASSERT3S(end_of_range, <=, ap->a_size);
			dprintf("ZFS: %s:%d: aborting absent upl bytes [%lld..%lld] (%lld pages)"
			    " of file bytes [%lld..%lld] (%d pages)"
			    " fs %s file %s\n", __func__, __LINE__,
			    start_of_range, end_of_range, pages_in_range,
			    f_start_of_upl, f_end_of_upl, pages_in_upl, fsname, fname);
			if (last_page_in_range == upl_end_pg) {
				dprintf("ZFS: %s:%d: as aborting last UPL page, unmapping fs %s file %s\n",
				    __func__, __LINE__, fsname, fname);
				const int unmapret = ubc_upl_unmap(upl);
				if (unmapret != KERN_SUCCESS) {
					printf("ZFS: %s:%d: error %d unmapping UPL [%lld..%lld]"
					    " fs %s file %s\n", __func__, __LINE__, unmapret,
					    f_start_of_upl, f_end_of_upl, fsname, fname);
				}
				error = unmapret;
				mapped = B_FALSE;
			}
			const int abortret = ubc_upl_abort_range(upl, start_of_range, end_of_range,
			    UPL_ABORT_FREE_ON_EMPTY);
			if (abortret != KERN_SUCCESS) {
				printf("ZFS: %s:%d: error %d aborting UPL range [%lld, %lld] of UPL"
				    " [%lld..%lld] fs %s file %s (mapped %d)"
				    " z_size %lld ubcsize %lld a_size %ld\n", __func__, __LINE__,
				    abortret,
				    start_of_range, end_of_range,
				    f_start_of_upl, f_end_of_upl,
				    fsname, fname, mapped,
				    zp->z_size, ubc_getsize(vp), ap->a_size);
				error = abortret;
				if (mapped) {
					mapped = B_FALSE;
					int umapret_err = ubc_upl_unmap(upl);
					ASSERT3S(umapret_err, ==, KERN_SUCCESS);
				}
				ubc_upl_abort(upl, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
				goto pageout_done;
			}
			VNOPS_OSX_STAT_INCR(pageoutv2_present_pages_aborted, pages_in_range);
			pg_index = page_past_end_of_range;
			continue;
		}
		/* we found a present but not dirty page */
		else if (upl_valid_page(pl, pg_index) && !upl_dirty_page(pl, pg_index)) {
			ASSERT(upl_page_present(pl, pg_index));
			int64_t page_past_end_of_range = pg_index + 1;
			/* gather up a range of present-but-not-dirty pages */
			for ( ; page_past_end_of_range < just_past_last_valid_pg;
			      page_past_end_of_range++) {
				if (!upl_page_present(pl, page_past_end_of_range) ||
				    !upl_valid_page(pl, page_past_end_of_range) ||
				    upl_dirty_page(pl, page_past_end_of_range)) {
					break;
				}
				ASSERT0(upl_dirty_page(pl, page_past_end_of_range));
				ASSERT(upl_page_present(pl, page_past_end_of_range));
				ASSERT(upl_valid_page(pl, page_past_end_of_range));
			}
                        ASSERT3S(page_past_end_of_range, <=, just_past_last_valid_pg);
                        const off_t start_of_range = pg_index * PAGE_SIZE_64;
                        const off_t end_of_range = page_past_end_of_range * PAGE_SIZE_64;
                        const off_t pages_in_range = page_past_end_of_range - pg_index;
			const off_t last_page_in_range = pg_index + pages_in_range - 1;
                        ASSERT3S(pages_in_range, ==, howmany(end_of_range - start_of_range, PAGE_SIZE_64));
			ASSERT3S(end_of_range, <=, ap->a_size);
			dprintf("ZFS: %s:%d committing precious (present-but-not-dirty) upl bytes"
			    " [%lld..%lld] (%lld pages) of file bytes [%lld..%lld] (%d pages)"
			    " fs %s file %s\n", __func__, __LINE__,
			    start_of_range, end_of_range, pages_in_range,
			    f_start_of_upl, f_end_of_upl, pages_in_upl, fsname, fname);
			if (last_page_in_range == upl_end_pg) {
                                dprintf("ZFS: %s:%d: as committing last UPL page, unmapping fs %s file %s\n",
                                    __func__, __LINE__, fsname, fname);
                                const int unmapret = ubc_upl_unmap(upl);
                                if (unmapret != KERN_SUCCESS) {
                                        printf("ZFS: %s:%d: error %d unmapping UPL [%lld..%lld]"
                                            " fs %s file %s\n", __func__, __LINE__, unmapret,
                                            f_start_of_upl, f_end_of_upl, fsname, fname);
                                }
                                error = unmapret;
				mapped = B_FALSE;
                        }
			const int commit_precious_flags = UPL_COMMIT_FREE_ON_EMPTY
			    | UPL_COMMIT_CLEAR_PRECIOUS;
			const int commit_precious_ret = ubc_upl_commit_range(upl, start_of_range,
			    end_of_range, commit_precious_flags);
			if (commit_precious_ret != KERN_SUCCESS) {
				printf("ZFS: %s:%d: ERROR %d committing UPL range [%lld, %lld] of UPL"
                                    " [%lld..%lld] fs %s file %s (mapped %d)\n", __func__, __LINE__,
				    commit_precious_ret,
                                    start_of_range, end_of_range,
				    f_start_of_upl, f_end_of_upl,
				    fsname, fname, mapped);
				error = commit_precious_ret;
				if (mapped) {
					mapped = B_FALSE;
					int umapret_err = ubc_upl_unmap(upl);
					ASSERT3S(umapret_err, ==, KERN_SUCCESS);
				}
				ubc_upl_abort(upl, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
				goto pageout_done;
			} else {
				printf("ZFS: %s:%d: successfully committed precious (unmap %d)"
				    " UPL range [%lld..%lld] of file range [%lld..%lld] fs %s file %s"
				    " pg_index %lld page_past_end_of_range %lld\n",
				    __func__, __LINE__, mapped,
				    start_of_range, end_of_range,
				    f_start_of_upl, f_end_of_upl,
				    fsname, fname, pg_index, page_past_end_of_range);
			}
			VNOPS_OSX_STAT_INCR(pageoutv2_precious_pages_cleaned, pages_in_range);
			pg_index = page_past_end_of_range;
			continue;
		}
		/* we have found a dirty page */
		else if (upl_dirty_page(pl, pg_index)) {
			ASSERT(upl_page_present(pl, pg_index));
			ASSERT(upl_valid_page(pl, pg_index));
			int page_past_end_of_range = pg_index + 1;
			for ( ; page_past_end_of_range < just_past_last_valid_pg;
			      page_past_end_of_range++) {
				if (!upl_dirty_page(pl, page_past_end_of_range) ||
				    !upl_valid_page(pl, page_past_end_of_range) ||
				    !upl_page_present(pl, page_past_end_of_range))
					break;
				ASSERT(upl_page_present(pl, page_past_end_of_range));
				ASSERT(upl_valid_page(pl, page_past_end_of_range));
				ASSERT(upl_dirty_page(pl, page_past_end_of_range));
			}
			ASSERT3S(page_past_end_of_range, <=, just_past_last_valid_pg);
			const off_t start_of_range = pg_index * PAGE_SIZE_64;
                        const off_t end_of_range = page_past_end_of_range * PAGE_SIZE_64;
                        const off_t pages_in_range = page_past_end_of_range - pg_index;
			const off_t last_page_in_range = pg_index + pages_in_range - 1;
                        ASSERT3S(pages_in_range, ==, howmany(end_of_range - start_of_range, PAGE_SIZE_64));
			ASSERT3S(end_of_range, <=, ap->a_size);
			dprintf("ZFS: %s:%d bluster_pageout dirty upl bytes"
			    " [%lld..%lld] (%lld pages) of file bytes [%lld..%lld] (%lld pages)"
			    " fs %s file %s\n", __func__, __LINE__,
			    start_of_range, end_of_range, pages_in_range,
			    f_start_of_upl, f_end_of_upl, just_past_last_valid_pg, fsname, fname);
			/*
			 * bluster_pageout MUST commit or abort all the UPL pages
			 * between start_of_range and end_of_range, and must also
			 * unmap the upl if necessary.   We cannot give bluster_pageout
			 * a zero-length write, it would not know what to do and would
			 * panic in response.
			 */
			VERIFY3S(end_of_range - start_of_range, >=, PAGE_SIZE_64);
			const off_t pages_remaining = just_past_last_valid_pg - pg_index;
			ASSERT3S(pages_remaining, >, 0);
			ASSERT3S(pages_remaining, <=, just_past_last_valid_pg);
			ASSERT3S(pages_remaining, >=, howmany(end_of_range - start_of_range, PAGE_SIZE_64));
			ASSERT3S(mapped, ==, B_TRUE);
			ASSERT3S(end_of_range, <=, trimmed_upl_size);

			boolean_t bl_unmapped = B_FALSE;
			error = bluster_pageout(zfsvfs, zp, upl, start_of_range,
			    f_start_of_upl,
			    (end_of_range - start_of_range), filesize, a_flags, ap,
			    &v_addr, pages_remaining, &bl_unmapped);

			EQUIV(last_page_in_range == upl_end_pg, bl_unmapped == B_TRUE);
			/* post-bluster test if we should set mapped flag false */
			if (last_page_in_range == upl_end_pg) {
				ASSERT3S(bl_unmapped, ==, B_TRUE);
                                dprintf("ZFS: %s:%d: as bluster_pageout handed last UPL page,"
				    " it must have unmapped fs %s file %s\n",
                                    __func__, __LINE__, fsname, fname);
				mapped = B_FALSE;
			}
			ASSERT3S(mapped, ==, !bl_unmapped);

			if (error != 0) {
				printf("ZFS: %s:%d: bluster_pageout error %d for"
				    " UPL range [%lld..%lld], for file range [%lld..%lld], "
				    " pages_remaining %lld, fsz %lld, fs %s file %s (mapped %d)"
				    " last_page_in_range %lld upl_end_pg %lld\n",
				    __func__, __LINE__, error,
				    start_of_range, end_of_range,
				    f_start_of_upl, f_end_of_upl, pages_remaining,
				    filesize, fsname, fname, mapped,
				    last_page_in_range, upl_end_pg);
				/* bluster may not have unmapped */
				if (mapped) {
					mapped = B_FALSE;
					int umapret_err = ubc_upl_unmap(upl);
					ASSERT3S(umapret_err, ==, KERN_SUCCESS);
				}
				if (last_page_in_range < upl_end_pg) {
					if (bl_unmapped == B_FALSE) {
						ubc_upl_abort(upl,
						    UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
					} else {
						printf("ZFS: %s:%d: WOAH, bl_unmapped true but"
						    " %lld < %lld fs %s file %s\n", __func__, __LINE__,
						    last_page_in_range, upl_end_pg,
						    fsname, fname);
					}
				}
				goto pageout_done;
			}

			VNOPS_OSX_STAT_INCR(pageoutv2_dirty_pages_blustered, pages_in_range);
			pg_index = page_past_end_of_range;
			continue;
		} else {
			ASSERT0(upl_page_present(pl, pg_index));
			ASSERT0(upl_dirty_page(pl, pg_index));
			ASSERT0(upl_valid_page(pl, pg_index));
			panic("unknown page type, pg_index %lld of file range [%lld..%lld] fs %s file %s",
			    pg_index, f_start_of_upl, f_end_of_upl, fsname, fname);
		}
	} // for

	ASSERT3S(pg_index, ==, just_past_last_valid_pg);
	ASSERT3S(mapped, ==, B_FALSE);

	ASSERT3S(ubc_getsize(vp), >=, ubcsize_at_entry);

	if (had_map_lock_at_entry == B_FALSE) {
		z_map_drop_lock(zp, &need_release, &need_upgrade);
		ASSERT(!rw_write_held(&zp->z_map_lock));
	}

	zfs_range_unlock(rl);

	if (a_flags & UPL_IOSYNC) {
		dprintf("ZFS: %s:%d zil_commit file %s\n", __func__, __LINE__, zp->z_name_cache);
		zil_commit(zfsvfs->z_log, zp->z_id);
		VNOPS_OSX_STAT_BUMP(pageoutv2_upl_iosync);
	}

	if (error != 0) {
		printf("ZFS: %s:%d: pageoutv2 ERROR %d [%lld..%lld] file %s filesystem %s\n",
		    __func__, __LINE__, error, ap->a_f_offset, ap->a_f_offset + ap->a_size,
		    zp->z_name_cache, vfs_statfs(zfsvfs->z_vfs)->f_mntfromname);
	}

	ZFS_EXIT(zfsvfs);
	if (error != 0)
		VNOPS_OSX_STAT_BUMP(pageoutv2_error);
	return (error);

pageout_done:

	ASSERT3S(mapped, ==, B_FALSE);
	if (had_map_lock_at_entry == B_FALSE) {
		z_map_drop_lock(zp, &need_release, &need_upgrade);
		ASSERT(!rw_write_held(&zp->z_map_lock));
	}

	zfs_range_unlock(rl);

exit_abort:

	if (error) {
		printf("ZFS: %s:%d pageoutv2 returning ERROR %d, [%lld..%lld] file %s filesystem %s\n",
		    __func__, __LINE__, error, ap->a_f_offset, ap->a_f_offset + ap->a_size,
		    zp->z_name_cache, vfs_statfs(zfsvfs->z_vfs)->f_mntfromname);
		VNOPS_OSX_STAT_BUMP(pageoutv2_error);
	}
	//VERIFY(ubc_create_upl(vp, off, len, &upl, &pl, flags) == 0);
	//ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);

	ASSERT3S(ubc_getsize(vp), >=, ubcsize_at_entry);

	if (zfsvfs)
		ZFS_EXIT(zfsvfs);
	return (error);
}

int
zfs_vnop_pageoutv2(struct vnop_pageout_args *ap)
#if 0
	struct vnop_pageout_args {
		struct vnode	*a_vp;
		upl_t		a_pl;
		vm_offset_t	a_pl_offset;
		off_t		a_f_offset;
		size_t		a_size;
		int		a_flags;
		vfs_context_t	a_context;
#endif
{
	if (ap->a_size <= MAX_UPL_SIZE_BYTES || ap->a_pl != NULL)
		return(pageoutv2_helper(ap));

	/*
	 * break the work into UPL-fitting pieces
	 */

	printf("ZFS: %s:%d breaking up %ld bytes of work\n",
	    __func__, __LINE__, ap->a_size);

	struct vnop_pageout_args *cur_ap = kmem_zalloc(sizeof(struct vnop_pageout_args), KM_SLEEP);
	VERIFY3P(cur_ap, !=, NULL);

	cur_ap->a_vp = ap->a_vp;
	cur_ap->a_pl = ap->a_pl;
	cur_ap->a_pl_offset = ap->a_pl_offset;
	cur_ap->a_f_offset = ap->a_f_offset;
	cur_ap->a_size = ap->a_size;
	cur_ap->a_flags = ap->a_flags;
	cur_ap->a_context = ap->a_context;

	ASSERT3P(cur_ap->a_pl, ==, NULL);

	size_t cur_size = cur_ap->a_size;
	const int proj_calls = howmany(cur_size, MAX_UPL_SIZE_BYTES);
	int error = 0;

	for (int c = proj_calls; cur_size > 0; c--) {
		ASSERT3S(c, >=, 0);
		const off_t  call_offset = cur_ap->a_f_offset;
		const size_t call_size = MIN(cur_size,
		    MAX_UPL_SIZE_BYTES - P2PHASE(call_offset, MAX_UPL_SIZE_BYTES));
		ASSERT3S(call_size, <=, MAX_UPL_SIZE_BYTES);
		ASSERT3S(call_size, >, 0);
		cur_ap->a_size = call_size;
		int cur_error = pageoutv2_helper(cur_ap);
		if (cur_error != 0) {
			printf("ZFS: %s:%d: (passes togo: %d) pageoutv2 error %d : %ld@%lld\n",
			    __func__, __LINE__, c, cur_error, call_size, call_offset);
			if (error == 0) {
				error = cur_error;
			} else if (error != cur_error) {
				printf("ZFS: %s:%d already had an error %d so not setting to %d\n",
				    __func__, __LINE__, error, cur_error);
			}
		}
		ASSERT3S(cur_ap->a_size, ==, call_size);
		ASSERT3S(cur_ap->a_f_offset, ==, call_offset);
		ASSERT3P(cur_ap->a_context, ==, ap->a_context);
		ASSERT3S(cur_ap->a_flags, ==, ap->a_flags);
		ASSERT3P(cur_ap->a_pl, ==, NULL);

		cur_size -= call_size;
		cur_ap->a_f_offset = call_offset + call_size;
	}
	return (error);
}


int
zfs_vnop_mmap(struct vnop_mmap_args *ap)
#if 0
	struct vnop_mmap_args {
		struct vnode	*a_vp;
		int		a_fflags;
		kauth_cred_t	a_cred;
		struct proc	*a_p;
	};
#endif
{
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs;

	//DECLARE_CRED_AND_CONTEXT(ap);

	if (!zp) return ENODEV;

	zfsvfs = zp->z_zfsvfs;

	dprintf("+vnop_mmap: %p\n", ap->a_vp);

	ZFS_ENTER(zfsvfs);

	ASSERT(vnode_isreg(vp));

	if (!vnode_isreg(vp)) {
		ZFS_EXIT(zfsvfs);
		return (ENODEV);
	}

	/* EPERM to write mmaps if we are r/o */
	if (ISSET(ap->a_fflags, VM_PROT_WRITE)) {
		ASSERT0(zp->z_pflags & ZFS_IMMUTABLE);
		ASSERT0(vfs_flags(zfsvfs->z_vfs) & MNT_RDONLY);
		ASSERT0(vfs_isrdonly(zfsvfs->z_vfs));
		if ((zp->z_pflags & ZFS_IMMUTABLE) ||
		    (vfs_flags(zfsvfs->z_vfs) & MNT_RDONLY) ||
		    vfs_isrdonly(zfsvfs->z_vfs)) {
			printf("ZFS: %s:%d: EPERM to PROT_WRITE for file %s fs %s\n",
			    __func__, __LINE__, zp->z_name_cache,
			    vfs_statfs(zfsvfs->z_vfs)->f_mntfromname);
			ZFS_EXIT(zfsvfs);
			return (EPERM);
		}
	}

	if (!spl_ubc_is_mapped(vp, NULL))
		VNOPS_OSX_STAT_BUMP(mmap_file_first_mmapped);

	VNOPS_OSX_STAT_BUMP(mmap_calls);
	ASSERT3S(ubc_getsize(vp), ==, zp->z_size);
	ZFS_EXIT(zfsvfs);
	dprintf("-vnop_mmap\n");
	return (0);
}

int
zfs_vnop_mnomap(struct vnop_mnomap_args *ap)
#if 0
	10.11:
	struct vnop_mnomap_args {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		vfs_context_t a_context;
	};

        ???
	struct vnop_mnomap_args {
		struct vnode	*a_vp;
		int		a_fflags;
		kauth_cred_t	a_cred;
		struct proc	*a_p;
	};
#endif
{
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	//DECLARE_CRED_AND_CONTEXT(ap);

	dprintf("+vnop_mnomap: %p\n", ap->a_vp);

	ZFS_ENTER(zfsvfs);

	ASSERT(vnode_isreg(vp));

	if (!vnode_isreg(vp)) {
		ZFS_EXIT(zfsvfs);
		return (ENODEV);
	}

	ASSERT(spl_ubc_is_mapped(vp, NULL));

	VNOPS_OSX_STAT_BUMP(mnomap_calls);

	ZFS_EXIT(zfsvfs);
	if (zp->z_mod_while_mapped != 0) {
		printf("ZFS: %s:%d: mnomap: z_mod_while_mapped set file %s\n",
		    __func__, __LINE__, zp->z_name_cache);
	}

	ASSERT3S(ubc_getsize(vp), ==, zp->z_size);
	dprintf("-vnop_mnomap\n");
	return (0);
}

int
zfs_vnop_inactive(struct vnop_inactive_args *ap)
#if 0
	struct vnop_inactive_args {
		struct vnode	*a_vp;
		vfs_context_t	a_context;
	};
#endif
{
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = NULL;
	DECLARE_CRED(ap);

	dprintf("vnop_inactive: zp %p vp %p type %u\n", zp, vp, vnode_vtype(vp));

	if (!zp) return 0; /* zfs_remove will clear it in fastpath */

	zfsvfs = zp->z_zfsvfs;

	if (vnode_isrecycled(ap->a_vp)) {
		/*
		 * We can not call inactive at this time, as we are inside
		 * vnode_create()->vclean() path. But since we are only here to
		 * sync out atime, and we know vnop_reclaim will called next.
		 *
		 * However, we can cheat a little, by looking inside zfs_inactive
		 * we can take the fast exits here as well, and only keep
		 * node around for the syncing case
		 */
		rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);
		if (zp->z_sa_hdl == NULL) {
			/*
			 * The fs has been unmounted, or we did a
			 * suspend/resume and this file no longer exists.
			 */
			rw_exit(&zfsvfs->z_teardown_inactive_lock);
			return 0;
		}

		mutex_enter(&zp->z_lock);
		if (zp->z_unlinked) {
			/*
			 * Fast path to recycle a vnode of a removed file.
			 */
			mutex_exit(&zp->z_lock);
			rw_exit(&zfsvfs->z_teardown_inactive_lock);
			return 0;
		}
		mutex_exit(&zp->z_lock);
		rw_exit(&zfsvfs->z_teardown_inactive_lock);

		return (0);
	}


	/* We can call it directly, huzzah! */
	zfs_inactive(vp, cr, NULL);

	/* dprintf("-vnop_inactive\n"); */
	return (0);
}



#ifdef _KERNEL
uint64_t vnop_num_reclaims = 0;
uint64_t vnop_num_vnodes = 0;
#endif


int
zfs_vnop_reclaim(struct vnop_reclaim_args *ap)
#if 0
	struct vnop_reclaim_args {
		struct vnode	*a_vp;
		vfs_context_t	a_context;
	};
#endif
{
	/*
	 * Care needs to be taken here, we may already have called reclaim
	 * from vnop_inactive, if so, very little needs to be done.
	 */

	struct vnode	*vp = ap->a_vp;
	znode_t	*zp = NULL;
	zfsvfs_t *zfsvfs = NULL;
	boolean_t fastpath;


	/* Destroy the vm object and flush associated pages. */
#ifndef __APPLE__
	vnode_destroy_vobject(vp);
#endif

	/* Already been released? */
	zp = VTOZ(vp);
	ASSERT3P(zp, !=, NULL);
	ASSERT3P(zp->z_sa_hdl, !=, NULL);
	dprintf("+vnop_reclaim zp %p/%p type %d\n", zp, vp, vnode_vtype(vp));
	if (!zp) goto out;

	off_t ubcsize = ubc_getsize(vp);
	ASSERT3S(ubcsize, >=, 0);
	if (zp->z_mod_while_mapped != 0) {
		printf("ZFS: %s:%d: z_mod_while_mapped set, ubc size %lld, file %s\n",
		    __func__, __LINE__, ubcsize, zp->z_name_cache);
	}
	VNOPS_OSX_STAT_BUMP(reclaim_mapped);
	if (ubcsize == 0)
		ASSERT0(ubc_pages_resident(vp));
	if (ubcsize > 0) {
		ASSERT(ubc_pages_resident(vp));
		ASSERT0(spl_ubc_is_mapped_writable(vp));
		ASSERT0(spl_ubc_is_mapped(vp, NULL));
		ASSERT3S(zp->z_size, ==, ubcsize);
		if (is_file_clean(vp, ubcsize)) {
			    // nonzero is unclean
			printf("ZFS: %s:%d: (syncing out) unclean file %s size %lld\n",
			    __func__, __LINE__, zp->z_name_cache, ubcsize);
		}
		off_t resid_off = 0;
		int retval = 0;
		boolean_t need_release = B_FALSE, need_upgrade = B_FALSE;
		uint64_t tries = z_map_rw_lock(zp, &need_release, &need_upgrade, __func__);
		int msync_flags = UBC_PUSHDIRTY | UBC_SYNC | ZFS_UBC_FORCE_MSYNC;
		retval = zfs_ubc_msync(vp, (off_t)0, ubcsize, &resid_off, msync_flags);
		z_map_drop_lock(zp, &need_release, &need_upgrade);
		ASSERT3S(tries, <=, 2);
		ASSERT3S(retval, ==, 0);
		if (retval != 0)
			ASSERT3S(resid_off, ==, ubcsize);
		ASSERT0(ubc_pages_resident(vp));
	}
	ASSERT3P(zp->z_sa_hdl, !=, NULL);
	ASSERT0(vnode_isinuse(vp, 0));

	zfsvfs = zp->z_zfsvfs;

	if (!zfsvfs) {
		printf("ZFS: vnop_reclaim with zfsvfs == NULL - tell lundman\n");
		return 0;
	}

	if (zfsctl_is_node(vp)) {
		printf("ZFS: vnop_reclaim with ctldir node - tell lundman\n");
		return 0;
	}

	ZTOV(zp) = NULL;

	/*
	 * Purge old data structures associated with the denode.
	 */
	vnode_clearfsnode(vp); /* vp->v_data = NULL */
	vnode_removefsref(vp); /* ADDREF from vnode_create */
	atomic_dec_64(&vnop_num_vnodes);

	fastpath = zp->z_fastpath;

	dprintf("+vnop_reclaim zp %p/%p fast %d unlinked %d unmount %d sa_hdl %p\n",
		   zp, vp, zp->z_fastpath, zp->z_unlinked,
			zfsvfs->z_unmounted, zp->z_sa_hdl);
	/*
	 * This will release as much as it can, based on reclaim_reentry,
	 * if we are from fastpath, we do not call free here, as zfs_remove
	 * calls zfs_znode_delete() directly.
	 * zfs_zinactive() will leave earlier if z_reclaim_reentry is true.
	 */
	if (fastpath == B_FALSE) {
		rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);
		if (zp->z_sa_hdl == NULL)
			zfs_znode_free(zp);
		else
			zfs_zinactive(zp);
		rw_exit(&zfsvfs->z_teardown_inactive_lock);
	}

	/* Direct zfs_remove? We are done */
	if (fastpath == B_TRUE) goto out;


#ifdef _KERNEL
	atomic_inc_64(&vnop_num_reclaims);
#endif

  out:
	return (0);
}

int
zfs_vnop_mknod(struct vnop_mknod_args *ap)
#if 0
	struct vnop_mknod_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *vap;
		vfs_context_t	a_context;
	};
#endif
{
	struct vnop_create_args create_ap;
	int error;

	dprintf("%s\n", __func__);

	bzero(&create_ap, sizeof(struct vnop_create_args));

	create_ap.a_dvp = ap->a_dvp;
	create_ap.a_vpp = ap->a_vpp;
	create_ap.a_cnp = ap->a_cnp;
	create_ap.a_vap = ap->a_vap;
	create_ap.a_context = ap->a_context;

	error = zfs_vnop_create(&create_ap);
	if (error) dprintf("%s error %d\n", __func__, error);
	return error;
}

int
zfs_vnop_allocate(struct vnop_allocate_args *ap)
#if 0
	struct vnop_allocate_args {
		struct vnode	*a_vp;
		off_t		a_length;
		u_int32_t	a_flags;
		off_t		*a_bytesallocated;
		off_t		a_offset;
		vfs_context_t	a_context;
	};
#endif
{
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs;
	int err = 0;

	ASSERT3P(zp, !=, NULL);
	if (!zp) return ENODEV;

	zfsvfs = zp->z_zfsvfs;

	ZFS_ENTER(zfsvfs);

	ASSERT(vnode_isreg(vp));
	if (!vnode_isreg(vp)) {
		ZFS_EXIT(zfsvfs);
		return (ENODEV);
	}

	const off_t filesize = zp->z_size;
	off_t wantedsize = ap->a_length;

	if (ap->a_flags & ALLOCATEFROMPEOF)
		wantedsize += filesize;
	if (ap->a_flags & ALLOCATEFROMVOL)
		/* blockhint = ap->a_offset / blocksize */  // yeah, no idea
		printf("ZFS: %s:%d help, allocatefromvolume set? flags 0x%x file %s\n", __func__, __LINE__,
		    ap->a_flags, zp->z_name_cache);
	if (ap->a_flags & ~(ALLOCATEFROMVOL | ALLOCATEFROMPEOF | PREALLOCATE))
		printf("ZFS: %s:%d: help, flags are 0x%x (masked 0x%x) file %s\n", __func__, __LINE__,
		    ap->a_flags, (ap->a_flags & ~(ALLOCATEFROMVOL | ALLOCATEFROMPEOF | PREALLOCATE)),
		    zp->z_name_cache);

	printf("ZFS: %s:%d: a_length %llu flags 0x%x a_bytesallocated (null? %d) %lld a_offset %lld"
	    " filesize %lld wantedsize %lld file %s\n", __func__, __LINE__,
	    ap->a_length, ap->a_flags, (ap->a_bytesallocated ? 0 : 1),
	    (ap->a_bytesallocated ? *ap->a_bytesallocated : 0), ap->a_offset,
	    filesize, wantedsize, zp->z_name_cache);

	// If we are extending
	if (wantedsize > filesize) {
		err = zfs_freesp(zp, wantedsize, 0, FWRITE, B_TRUE);
		// If we are truncating, Apple claims this code is never called.
	} else if (wantedsize < filesize) {
		printf("ZFS: %s:%d file shrinking branch taken? (wanted %lld z_size %lld) file %s\n",
		    __func__, __LINE__, wantedsize, filesize, zp->z_name_cache);
	} else {
		ASSERT3S(wantedsize, ==, filesize);
		printf("ZFS: %s:%d: wantedsize == filesize (%lld) for file %s\n", __func__, __LINE__,
		    wantedsize, zp->z_name_cache);
	}

	if (!err) {
		*(ap->a_bytesallocated) = wantedsize - filesize;
	}

	ZFS_EXIT(zfsvfs);
	if (err != 0)
		printf("ZFS: -%s:%d err %d\n", __func__, __LINE__, err);
	return (err);
}

int
zfs_vnop_whiteout(struct vnop_whiteout_args *ap)
#if 0
	struct vnop_whiteout_args {
		struct vnode	*a_dvp;
		struct componentname *a_cnp;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	dprintf("vnop_whiteout: ENOTSUP\n");

	return (ENOTSUP);
}

int
zfs_vnop_pathconf(struct vnop_pathconf_args *ap)
#if 0
	struct vnop_pathconf_args {
		struct vnode	*a_vp;
		int		a_name;
		register_t	*a_retval;
		vfs_context_t	a_context;
	};
#endif
{
	int32_t  *valp = ap->a_retval;
	int error = 0;

	dprintf("+vnop_pathconf a_name %d\n", ap->a_name);

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*valp = INT_MAX;
		break;
	case _PC_PIPE_BUF:
		*valp = PIPE_BUF;
		break;
	case _PC_CHOWN_RESTRICTED:
		*valp = 200112;  /* POSIX */
		break;
	case _PC_NO_TRUNC:
		*valp = 200112;  /* POSIX */
		break;
	case _PC_NAME_MAX:
	case _PC_NAME_CHARS_MAX:
		*valp = ZAP_MAXNAMELEN - 1;  /* 255 */
		break;
	case _PC_PATH_MAX:
	case _PC_SYMLINK_MAX:
		*valp = PATH_MAX;  /* 1024 */
		break;
	case _PC_CASE_SENSITIVE:
	{
		znode_t *zp = VTOZ(ap->a_vp);
		*valp = 1;
		if (zp && zp->z_zfsvfs) {
			zfsvfs_t *zfsvfs = zp->z_zfsvfs;
			*valp = (zfsvfs->z_case == ZFS_CASE_SENSITIVE) ? 1 : 0;
		}
	}
		break;
	case _PC_CASE_PRESERVING:
		*valp = 1;
		break;
/*
 * OS X 10.6 does not define this.
 */
#ifndef	_PC_XATTR_SIZE_BITS
#define	_PC_XATTR_SIZE_BITS   26
#endif
/*
 * Even though ZFS has 64 bit limit on XATTR size, there would appear to be a
 * limit in SMB2 that the bit size returned has to be 18, or we will get an
 * error from most XATTR calls (STATUS_ALLOTTED_SPACE_EXCEEDED).
 */
#ifndef	AD_XATTR_SIZE_BITS
#define	AD_XATTR_SIZE_BITS 18
#endif
	case _PC_XATTR_SIZE_BITS:
		*valp = AD_XATTR_SIZE_BITS;
		break;
	case _PC_FILESIZEBITS:
		*valp = 64;
		break;
	default:
		printf("ZFS: unknown pathconf %d called.\n", ap->a_name);
		error = EINVAL;
	}

	if (error) dprintf("%s vp %p : %d\n", __func__, ap->a_vp, error);
	return (error);
}

int
zfs_vnop_getxattr(struct vnop_getxattr_args *ap)
#if 0
	struct vnop_getxattr_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		char		*a_name;
		struct uio	*a_uio;
		size_t		*a_size;
		int		a_options;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	struct vnode *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct uio *uio = ap->a_uio;
	pathname_t cn = { 0 };
	int  error = 0;
	struct uio *finderinfo_uio = NULL;

	/* dprintf("+getxattr vp %p\n", ap->a_vp); */

	/* xattrs disabled? */
	if (zfsvfs->z_xattr == B_FALSE) {
		return ENOTSUP;
	}

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

#if 0
	if (zp->z_xattr == 0) {
		error = ENOATTR;
		goto out;
	}
#endif


	if (zfsvfs->z_use_sa && zp->z_is_sa) {
		uint64_t size = uio_resid(uio);
		char *value;

		rw_enter(&zp->z_xattr_lock, RW_READER);
		if (zp->z_xattr_cached == NULL)
			error = -zfs_sa_get_xattr(zp);
		rw_exit(&zp->z_xattr_lock);

		if (!size) { /* Lookup size */

			rw_enter(&zp->z_xattr_lock, RW_READER);
			error = zpl_xattr_get_sa(vp, ap->a_name, NULL, 0);
			rw_exit(&zp->z_xattr_lock);
			if (error > 0) {
				dprintf("ZFS: returning XATTR size %d\n", error);
				*ap->a_size = error;
				error = 0;
				goto out;
			}
		}

		value = kmem_alloc(size, KM_SLEEP);
		if (value) {
			rw_enter(&zp->z_xattr_lock, RW_READER);
			error = zpl_xattr_get_sa(vp, ap->a_name, value, size);
			rw_exit(&zp->z_xattr_lock);

			//dprintf("ZFS: SA XATTR said %d\n", error);

			if (error > 0) {
				uiomove((const char*)value, error, 0, uio);
				error = 0;
			}
			kmem_free(value, size);

			if (error != -ENOENT)
				goto out;
		}
	}


	/* Grab the hidden attribute directory vnode. */
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, 0))) {
		goto out;
	}

	cn.pn_bufsize = strlen(ap->a_name) + 1;
	cn.pn_buf = (char*)kmem_zalloc(cn.pn_bufsize, KM_SLEEP);

	/* Lookup the attribute name. */
	if ((error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, &xvp, 0, NULL,
	    &cn))) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	/*
	 * If we are dealing with FinderInfo, we duplicate the UIO first
	 * so that we can uiomove to/from it to modify contents.
	 */
	if (!error && uio &&
		bcmp(ap->a_name, XATTR_FINDERINFO_NAME, sizeof(XATTR_FINDERINFO_NAME)) == 0) {
		if ((user_size_t)uio_resid(uio) < 32) {/* FinderInfo is 32 bytes */
			error = ERANGE;
			goto out;
		}

		finderinfo_uio = uio_duplicate(uio);
	}


	/* Read the attribute data. */
	if (uio == NULL) {
		znode_t  *xzp = VTOZ(xvp);

		mutex_enter(&xzp->z_lock);
		*ap->a_size = (size_t)xzp->z_size;
		mutex_exit(&xzp->z_lock);
	} else {
		error = VNOP_READ(xvp, uio, 0, ap->a_context);
	}


	/*
	 * Handle FinderInfo
	 */
	if ((error == 0) && (finderinfo_uio != NULL)) {
		u_int8_t finderinfo[32];
		size_t bytes;

		/* Copy in the data we just read */
		uiocopy((const char *)&finderinfo, 32, UIO_WRITE,
				finderinfo_uio, &bytes);
		if (bytes != 32) {
			error = ERANGE;
			goto out;
		}

		finderinfo_update((uint8_t *)&finderinfo, zp);

		/* Copy out the data we just modified */
		uiomove((const char*)&finderinfo, 32, 0, finderinfo_uio);

	}



out:
	if (finderinfo_uio) uio_free(finderinfo_uio);

	if (cn.pn_buf)
		kmem_free(cn.pn_buf, cn.pn_bufsize);
	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}

	ZFS_EXIT(zfsvfs);
	/* dprintf("-getxattr vp %p : %d\n", ap->a_vp, error); */
	return (error);
}

int
zfs_vnop_setxattr(struct vnop_setxattr_args *ap)
#if 0
	struct vnop_setxattr_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		char		*a_name;
		struct uio	*a_uio;
		int		a_options;
		vfs_context_t	a_context;
	};
#endif
{
//dprintf("%s\n", __func__);
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	struct vnode *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct uio *uio = ap->a_uio;
	int  flag;
	int  error = 0;

	dprintf("+setxattr vp %p '%s' enabled? %d\n", ap->a_vp,
		   ap->a_name, zfsvfs->z_xattr);

	/* xattrs disabled? */
	if (zfsvfs->z_xattr == B_FALSE) {
		return ENOTSUP;
	}

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	if (strlen(ap->a_name) >= ZAP_MAXNAMELEN) {
		error = ENAMETOOLONG;
		goto out;
	}

	if (ap->a_options & XATTR_CREATE)
		flag = ZNEW;	 /* expect no pre-existing entry */
	else if (ap->a_options & XATTR_REPLACE)
		flag = ZEXISTS;  /* expect an existing entry */
	else
		flag = 0;


	/* Preferentially store the xattr as a SA for better performance */
	if (zfsvfs->z_use_sa && zfsvfs->z_xattr_sa && zp->z_is_sa) {
		char *value;
		uint64_t size;

		rw_enter(&zp->z_xattr_lock, RW_READER);
		if (zp->z_xattr_cached == NULL)
			error = -zfs_sa_get_xattr(zp);
		rw_exit(&zp->z_xattr_lock);

		rw_enter(&zp->z_xattr_lock, RW_WRITER);

		/* New, expect it to not exist .. */
		if ((flag & ZNEW) &&
			(zpl_xattr_get_sa(vp, ap->a_name, NULL, 0) > 0)) {
			error = EEXIST;
			rw_exit(&zp->z_xattr_lock);
			goto out;
		}

		/* Replace, XATTR must exist .. */
		if ((flag & ZEXISTS) &&
			((error = zpl_xattr_get_sa(vp, ap->a_name, NULL, 0)) <= 0) &&
			error == -ENOENT) {
			error = ENOATTR;
			rw_exit(&zp->z_xattr_lock);
			goto out;
		}

		size = uio_resid(uio);
		value = kmem_alloc(size, KM_SLEEP);
		if (value) {
			size_t bytes;

			/* Copy in the xattr value */
			uiocopy((const char *)value, size, UIO_WRITE,
					uio, &bytes);

			error = zpl_xattr_set_sa(vp, ap->a_name,
									 value, bytes,
									 flag, cr);
			kmem_free(value, size);

			if (error == 0) {
				rw_exit(&zp->z_xattr_lock);
				goto out;
			}
		}
		dprintf("ZFS: zpl_xattr_set_sa failed %d\n", error);

		rw_exit(&zp->z_xattr_lock);
	}

	/* Grab the hidden attribute directory vnode. */
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR))) {
		goto out;
	}

	/* Lookup or create the named attribute. */
	error = zfs_obtain_xattr(VTOZ(xdvp), ap->a_name, VTOZ(vp)->z_mode, cr,
	    &xvp, flag);
	if (error)
		goto out;

	/* Write the attribute data. */
	ASSERT(uio != NULL);
	error = zfs_freesp(VTOZ(xvp), 0, 0, VTOZ(vp)->z_mode, TRUE);

    /*
	 * TODO:
	 * When writing FINDERINFO, we need to replace the ADDEDTIME date
	 * with actual crtime and not let userland overwrite it.
	 */

	error = VNOP_WRITE(xvp, uio, 0, ap->a_context);

out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	if (xvp) {
		vnode_put(xvp);
	}

	ZFS_EXIT(zfsvfs);
	if (error) dprintf("-setxattr vp %p: err %d\n", ap->a_vp, error);
	return (error);
}

int
zfs_vnop_removexattr(struct vnop_removexattr_args *ap)
#if 0
	struct vnop_removexattr_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		char		*a_name;
		int		a_options;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	struct vnode *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	pathname_t cn = { 0 };
	int  error;
	uint64_t xattr;

	dprintf("+removexattr vp %p '%s'\n", ap->a_vp, ap->a_name);

	/* xattrs disabled? */
	if (zfsvfs->z_xattr == B_FALSE) {
		return ENOTSUP;
	}

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	if (zfsvfs->z_use_sa && zfsvfs->z_xattr_sa && zp->z_is_sa) {
        nvlist_t *nvl;

		rw_enter(&zp->z_xattr_lock, RW_READER);
		if (zp->z_xattr_cached == NULL)
			error = -zfs_sa_get_xattr(zp);
		rw_exit(&zp->z_xattr_lock);

		nvl = zp->z_xattr_cached;

		rw_enter(&zp->z_xattr_lock, RW_WRITER);
		error = -nvlist_remove(nvl, ap->a_name, DATA_TYPE_BYTE_ARRAY);

		dprintf("ZFS: removexattr nvlist_remove said %d\n", error);
		if (!error) {
			/* Update the SA for additions, modifications, and removals. */
			error = -zfs_sa_set_xattr(zp);
			rw_exit(&zp->z_xattr_lock);
			goto out;
		}
		rw_exit(&zp->z_xattr_lock);
	}

	sa_lookup(zp->z_sa_hdl, SA_ZPL_XATTR(zfsvfs), &xattr, sizeof (xattr));
	if (xattr == 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, 0))) {
		goto out;
	}

	cn.pn_bufsize = strlen(ap->a_name)+1;
	cn.pn_buf = (char *)kmem_zalloc(cn.pn_bufsize, KM_SLEEP);

	/* Lookup the attribute name. */
	if ((error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, &xvp, 0, NULL,
	    &cn))) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	error = zfs_remove(xdvp, (char *)ap->a_name, cr, ct, /* flags */0);

out:
	if (cn.pn_buf)
		kmem_free(cn.pn_buf, cn.pn_bufsize);

	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}

	ZFS_EXIT(zfsvfs);
	if (error) dprintf("%s vp %p: error %d\n", __func__, ap->a_vp, error);
	return (error);
}

int
zfs_vnop_listxattr(struct vnop_listxattr_args *ap)
#if 0
	struct vnop_listxattr_args {
		struct vnodeop_desc *a_desc;
        vnode_t a_vp;
        uio_t a_uio;
        size_t *a_size;
        int a_options;
        vfs_context_t a_context;
	};
#endif
{
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct uio *uio = ap->a_uio;
	zap_cursor_t  zc;
	zap_attribute_t  za;
	objset_t  *os;
	size_t size = 0;
	char  *nameptr;
	char  nfd_name[ZAP_MAXNAMELEN];
	size_t  namelen;
	int  error = 0;
	uint64_t xattr;
	int force_formd_normalized_output;

	dprintf("+listxattr vp %p: \n", ap->a_vp);

	/* xattrs disabled? */
	if (zfsvfs->z_xattr == B_FALSE) {
		return EINVAL;
	}

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	if (zfsvfs->z_use_sa && zp->z_is_sa && zp->z_xattr_cached) {
        nvpair_t *nvp = NULL;

		rw_enter(&zp->z_xattr_lock, RW_READER);
		if (zp->z_xattr_cached == NULL)
			error = -zfs_sa_get_xattr(zp);
		rw_exit(&zp->z_xattr_lock);

		while ((nvp = nvlist_next_nvpair(zp->z_xattr_cached, nvp)) != NULL) {
			ASSERT3U(nvpair_type(nvp), ==, DATA_TYPE_BYTE_ARRAY);

			namelen = strlen(nvpair_name(nvp)) + 1; /* Null byte */

			/* Just checking for space requirements? */
			if (uio == NULL) {
				size += namelen;
			} else {
				if (namelen > uio_resid(uio)) {
					error = ERANGE;
					break;
				}
				dprintf("ZFS: listxattr '%s'\n", nvpair_name(nvp));
				error = uiomove((caddr_t)nvpair_name(nvp), namelen,
								UIO_READ, uio);
				if (error)
					break;
			}
		} /* while nvlist */
	} /* SA xattr */
	if (error) goto out;

	/* Do we even have any attributes? */
	if (sa_lookup(zp->z_sa_hdl, SA_ZPL_XATTR(zfsvfs), &xattr,
	    sizeof (xattr)) || (xattr == 0)) {
		goto out;  /* all done */
	}

	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0) {
		goto out;
	}
	os = zfsvfs->z_os;

	for (zap_cursor_init(&zc, os, VTOZ(xdvp)->z_id);
	    zap_cursor_retrieve(&zc, &za) == 0; zap_cursor_advance(&zc)) {
		if (xattr_protected(za.za_name))
			continue;	 /* skip */
		/*
		 * Mac OS X: non-ascii names are UTF-8 NFC on disk
		 * so convert to NFD before exporting them.
		 */
		namelen = strlen(za.za_name);

		if (zfs_vnop_force_formd_normalized_output &&
		    !is_ascii_str(za.za_name))
			force_formd_normalized_output = 1;
		else
			force_formd_normalized_output = 0;

		if (force_formd_normalized_output &&
		    utf8_normalizestr((const u_int8_t *)za.za_name, namelen,
		    (u_int8_t *)nfd_name, &namelen, sizeof (nfd_name),
		    UTF_DECOMPOSED) == 0) {
			nameptr = nfd_name;
		} else {
			nameptr = &za.za_name[0];
		}
		++namelen;  /* account for NULL termination byte */
		if (uio == NULL) {
			size += namelen;
		} else {
			if (namelen > uio_resid(uio)) {
				error = ERANGE;
				break;
			}
			error = uiomove((caddr_t)nameptr, namelen, UIO_READ,
			    uio);
			if (error)
				break;
		}
	}
	zap_cursor_fini(&zc);
out:
	if (uio == NULL) {
		*ap->a_size = size;
	}
	if (xdvp) {
		vnode_put(xdvp);
	}

	ZFS_EXIT(zfsvfs);
	if (error) {
		dprintf("%s vp %p: error %d size %ld\n", __func__,
		    ap->a_vp, error, size);
	}
	return (error);
}

#ifdef HAVE_NAMED_STREAMS
int
zfs_vnop_getnamedstream(struct vnop_getnamedstream_args *ap)
#if 0
	struct vnop_getnamedstream_args {
		struct vnode	*a_vp;
		struct vnode	**a_svpp;
		char		*a_name;
	};
#endif
{
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode **svpp = ap->a_svpp;
	struct vnode *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	pathname_t cn = { 0 };
	int  error = ENOATTR;

	dprintf("+getnamedstream vp %p\n", ap->a_vp);

	*svpp = NULLVP;

	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME,
	    sizeof (XATTR_RESOURCEFORK_NAME)) != 0)
		goto out;

	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0)
		goto out;

	cn.pn_bufsize = strlen(ap->a_name) + 1;
	cn.pn_buf = (char *)kmem_zalloc(cn.pn_bufsize, KM_SLEEP);

	/* Lookup the attribute name. */
	if ((error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, svpp, 0, NULL,
	    &cn))) {
		if (error == ENOENT)
			error = ENOATTR;
	}

	kmem_free(cn.pn_buf, cn.pn_bufsize);

out:
	if (xdvp)
		vnode_put(xdvp);

	/*
	 * If the lookup is NS_OPEN, they are accessing "..namedfork/rsrc"
	 * to which we should return 0 with empty vp to empty file.
	 * See hfs_vnop_getnamedstream()
	 */
	if ((error == ENOATTR) &&
		ap->a_operation == NS_OPEN) {

		if ((error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)) == 0) {
			/* Lookup or create the named attribute. */
			error = zfs_obtain_xattr(VTOZ(xdvp), ap->a_name,
									 VTOZ(vp)->z_mode, cr, ap->a_svpp,
									 ZNEW);
			vnode_put(xdvp);
		}
	}

	ZFS_EXIT(zfsvfs);
	if (error) dprintf("%s vp %p: error %d\n", __func__, ap->a_vp, error);
	return (error);
}

int
zfs_vnop_makenamedstream(struct vnop_makenamedstream_args *ap)
#if 0
	struct vnop_makenamedstream_args {
		struct vnode	*a_vp;
		struct vnode	**a_svpp;
		char		*a_name;
	};
#endif
{
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct componentname  cn;
	struct vnode_attr  vattr;
	int  error = 0;

	dprintf("+makenamedstream vp %p\n", ap->a_vp);

	*ap->a_svpp = NULLVP;

	ZFS_ENTER(zfsvfs);

	/* Only regular files can have a resource fork stream. */
	if (!vnode_isreg(vp)) {
		error = EPERM;
		goto out;
	}

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME,
	    sizeof (XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)))
		goto out;

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = CREATE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	VATTR_INIT(&vattr);
	VATTR_SET(&vattr, va_type, VREG);
	VATTR_SET(&vattr, va_mode, VTOZ(vp)->z_mode & ~S_IFMT);

	error = zfs_create(xdvp, (char *)ap->a_name, &vattr, NONEXCL,
	    VTOZ(vp)->z_mode, ap->a_svpp, cr);

out:
	if (xdvp)
		vnode_put(xdvp);

	ZFS_EXIT(zfsvfs);
	if (error) dprintf("%s vp %p: error %d\n", __func__, ap->a_vp, error);
	return (error);
}

int
zfs_vnop_removenamedstream(struct vnop_removenamedstream_args *ap)
#if 0
	struct vnop_removenamedstream_args {
		struct vnode	*a_vp;
		struct vnode	**a_svpp;
		char		*a_name;
	};
#endif
{
	struct vnode *svp = ap->a_svp;
	znode_t *zp = VTOZ(svp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error = 0;

	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME,
	    sizeof (XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* ### MISING CODE ### */
	printf("zfs_vnop_removenamedstream\n");
	error = EPERM;
out:
	ZFS_EXIT(zfsvfs);
	return (ENOTSUP);
}
#endif /* HAVE_NAMED_STREAMS */

/*
 * The Darwin kernel's HFS+ appears to implement this by two methods,
 *
 * if (ap->a_options & FSOPT_EXCHANGE_DATA_ONLY) is set
 *	** Copy the data of the files over (including rsrc)
 *
 * if not set
 *	** exchange FileID between the two nodes, copy over vnode information
 *	   like that of *time records, uid/gid, flags, mode, linkcount,
 *	   finderinfo, c_desc, c_attr, c_flag, and cache_purge().
 *
 * This call is deprecated in 10.8
 */
int
zfs_vnop_exchange(struct vnop_exchange_args *ap)
#if 0
	struct vnop_exchange_args {
		struct vnode	*a_fvp;
		struct vnode	*a_tvp;
		int		a_options;
		vfs_context_t	a_context;
	};
#endif
{
	vnode_t *fvp = ap->a_fvp;
	vnode_t *tvp = ap->a_tvp;
	znode_t  *fzp;
	zfsvfs_t  *zfsvfs;

	/* The files must be on the same volume. */
	if (vnode_mount(fvp) != vnode_mount(tvp)) {
		dprintf("%s fvp and tvp not in same mountpoint\n",
		    __func__);
		return (EXDEV);
	}

	if (fvp == tvp) {
		dprintf("%s fvp == tvp\n", __func__);
		return (EINVAL);
	}

	/* Only normal files can be exchanged. */
	if (!vnode_isreg(fvp) || !vnode_isreg(tvp)) {
		dprintf("%s fvp or tvp is not a regular file\n",
		    __func__);
		return (EINVAL);
	}

	fzp = VTOZ(fvp);
	zfsvfs = fzp->z_zfsvfs;

	ZFS_ENTER(zfsvfs);

	/* ADD MISSING CODE HERE */

	ZFS_EXIT(zfsvfs);
	printf("vnop_exchange: ENOTSUP\n");
	return (ENOTSUP);
}

int
zfs_vnop_revoke(struct vnop_revoke_args *ap)
#if 0
	struct vnop_revoke_args {
		struct vnode	*a_vp;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	return (vn_revoke(ap->a_vp, ap->a_flags, ap->a_context));
}

int
zfs_vnop_blktooff(struct vnop_blktooff_args *ap)
#if 0
	struct vnop_blktooff_args {
		struct vnode	*a_vp;
		daddr64_t	a_lblkno;
		off_t		*a_offset;
	};
#endif
{
#if 1
	dprintf("vnop_blktooff: 0\n");
	return (ENOTSUP);
#else
	ASSERT3P(ap, !=, NULL);
	ASSERT3P(ap->a_vp, !=, NULL);

	vnode_t *vp = ap->a_vp;

	// must be a regular file
	boolean_t isreg = vnode_isreg(vp);
	ASSERT3S(isreg, !=, B_FALSE);
	if (isreg == B_FALSE)
		return (ENOTSUP);

	znode_t *zp = VTOZ(ap->a_vp);
	ASSERT3P(zp, !=, NULL);
	if (zp == NULL)
		return (ENODEV);

	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	ASSERT3P(zfsvfs, !=, NULL);
	if (zfsvfs == NULL)
		return (ENODEV);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	ASSERT3U(zp->z_blksz, >=, SPA_MINBLOCKSIZE);
	ASSERT3U(zp->z_blksz, <=, SPA_MAXBLOCKSIZE);

	uint32_t blocksize = MIN(zp->z_blksz, SPA_MINBLOCKSIZE);

	if (blocksize < SPA_MINBLOCKSIZE || zp->z_blksz > SPA_MAXBLOCKSIZE) {
		const uint64_t fs_max_blksize = zfsvfs->z_max_blksz;
		ASSERT3U(fs_max_blksize, >=, SPA_MINBLOCKSIZE);
		ASSERT3U(fs_max_blksize, <=, SPA_MAXBLOCKSIZE);
		blocksize = fs_max_blksize;
	}
	VERIFY3U(blocksize, >, 0);

	*ap->a_offset = (off_t)(ap->a_lblkno * blocksize);

	ZFS_EXIT(zfsvfs);

	return (0);
#endif
}

int
zfs_vnop_offtoblk(struct vnop_offtoblk_args *ap)
#if 0
	struct vnop_offtoblk_args {
		struct vnode	*a_vp;
		off_t		a_offset;
		daddr64_t	*a_lblkno;
	};
#endif
{
#if 1
	dprintf("+vnop_offtoblk\n");
	return (ENOTSUP);
#else
	ASSERT3P(ap, !=, NULL);
	ASSERT3P(ap->a_vp, !=, NULL);

	vnode_t *vp = ap->a_vp;

	// must be a regular file
	boolean_t isreg = vnode_isreg(vp);
	ASSERT3S(isreg, !=, B_FALSE);
	if (isreg == B_FALSE)
		return (ENOTSUP);

	znode_t *zp = VTOZ(ap->a_vp);
	ASSERT3P(zp, !=, NULL);
	if (zp == NULL)
		return (ENODEV);

	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	ASSERT3P(zfsvfs, !=, NULL);
	if (zfsvfs == NULL)
		return (ENODEV);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	ASSERT3U(zp->z_blksz, >=, SPA_MINBLOCKSIZE);
	ASSERT3U(zp->z_blksz, <=, SPA_MAXBLOCKSIZE);

	uint32_t blocksize = MIN(zp->z_blksz, SPA_MINBLOCKSIZE);
	if (blocksize > SPA_MAXBLOCKSIZE)
		blocksize = SPA_MAXBLOCKSIZE;

	if (blocksize < SPA_MINBLOCKSIZE || zp->z_blksz > SPA_MAXBLOCKSIZE) {
		const uint64_t fs_max_blksize = zfsvfs->z_max_blksz;
		ASSERT3U(fs_max_blksize, >=, SPA_MINBLOCKSIZE);
		ASSERT3U(fs_max_blksize, <=, SPA_MAXBLOCKSIZE);
		blocksize = fs_max_blksize;
	}
	VERIFY3U(blocksize, >, 0);

	*ap->a_lblkno = (daddr64_t)(ap->a_offset / blocksize);

	ZFS_EXIT(zfsvfs);

	return (0);
#endif
}

int
zfs_vnop_blockmap(struct vnop_blockmap_args *ap)
#if 0
	struct vnop_blockmap_args {
		struct vnode	*a_vp;
		off_t		a_foffset;
		size_t		a_size; // io_size
		daddr64_t	*a_bpn; // &blkno
		size_t		*a_run; // &io_size_tmp, run
		void		*a_poff;// generally NULL
		int		a_flags;// bmap_flags (e.g. VNODE_READ)
};
#endif
{
	dprintf("+vnop_blockmap\n");
#if 1
	return (ENOTSUP);
#else
	/* partially from mockfs_blockmap() in bsd/mockfs/mockfs_vnops.c,
	 * partially from #if 0 below */

	ASSERT3P(ap, !=, NULL);
	ASSERT3P(ap->a_vp, !=, NULL);
	ASSERT3S(ap->a_size, !=, 0);

	vnode_t *vp = ap->a_vp;
	daddr64_t *blkno = ap->a_bpn;

	ASSERT3P(blkno, !=, NULL);
	if (blkno == NULL)
		return (ENOTSUP);

	// must be a regular file
	boolean_t isreg = vnode_isreg(vp);
	ASSERT3S(isreg, !=, B_FALSE);
	if (isreg == B_FALSE)
		return (ENOTSUP);

	znode_t *zp = VTOZ(ap->a_vp);
	ASSERT3P(zp, !=, NULL);
	if (zp == NULL)
		return (ENODEV);

	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	ASSERT3P(zfsvfs, !=, NULL);
	if (zfsvfs == NULL)
		return (ENODEV);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	off_t foffset = ap->a_foffset;
	size_t *run = ap->a_run;

	ASSERT3U(zp->z_blksz, >=, SPA_MINBLOCKSIZE);
	ASSERT3U(zp->z_blksz, <=, SPA_MAXBLOCKSIZE);

	uint32_t blocksize = MIN(zp->z_blksz, SPA_MINBLOCKSIZE);
	if (blocksize > SPA_MAXBLOCKSIZE)
		blocksize = SPA_MAXBLOCKSIZE;

	if (blocksize < SPA_MINBLOCKSIZE || zp->z_blksz > SPA_MAXBLOCKSIZE) {
		const uint64_t fs_max_blksize = zfsvfs->z_max_blksz;
		ASSERT3U(fs_max_blksize, >=, SPA_MINBLOCKSIZE);
		ASSERT3U(fs_max_blksize, <=, SPA_MAXBLOCKSIZE);
		blocksize = fs_max_blksize;
	}
	VERIFY3U(blocksize, >, 0);

	/* xnu says: "... the vnode must be VREG (init), and the mapping will be 1 to 1.
	 * This also means that [the] request should always be contiguous, so the run
	 * calculation is easy!"
	 */

	*blkno = foffset / blocksize; // block number within the file
	ASSERT3S(*blkno, >=, 0);

	size_t io_size = ap->a_size;
	size_t filesize = zp->z_size;

	ASSERT3S(filesize, >, foffset);
	int64_t run_target = MAX(filesize - foffset, SPA_MAXBLOCKSIZE);
	ASSERT3S(run_target, >, 0);
	if (run_target < 0) {
		// prevent underflow of &io_size_tmp
		// NB: if cluster_io sees 0 in io_size_tmp,
		//     it will be as if we returned EINVAL
		run_target = 0;
	}

	*run = (size_t)run_target; // run is io_size_tmp in caller

	int retval = 0;

	ASSERT3S(io_size, <=, *run);
	if (io_size > *run)
		retval = ENOTSUP;

	ZFS_EXIT(zfsvfs);

	return (retval);

#endif

#if 0
	znode_t *zp;
	zfsvfs_t *zfsvfs;

	ASSERT(ap);
	ASSERT(ap->a_vp);
	ASSERT(ap->a_size);

	if (!ap->a_bpn) {
		return (0);
	}

	if (vnode_isdir(ap->a_vp)) {
		return (ENOTSUP);
	}

	zp = VTOZ(ap->a_vp);
	if (!zp) return (ENODEV);

	zfsvfs = zp->z_zfsvfs;
	if (!zfsvfs) return (ENODEV);

	/* Return full request size as contiguous */
	if (ap->a_run) {
		//*ap->a_run = ap->a_size;
		*ap->a_run = 0;
	}
	if (ap->a_poff) {
		*((int *)(ap->a_poff)) = 0;
		/*
		 * returning offset of -1 asks the
		 * caller to zero the ranges
		 */
		//*((int *)(ap->a_poff)) = -1;
	}
	*ap->a_bpn = 0;
//	*ap->a_bpn = (daddr64_t)(ap->a_foffset / zfsvfs->z_max_blksz);

	dprintf("%s ret %lu %d %llu\n", __func__,
	    ap->a_size, *((int*)(ap->a_poff)), *((uint64_t *)(ap->a_bpn)));

	return (0);
#endif
}

int
zfs_vnop_bwrite(struct vnop_bwrite_args *ap)
{
	int retval = 0;

	retval = vn_bwrite (ap);

	ASSERT3S(retval, !=, 0);

	return (retval);
}

int
zfs_vnop_strategy(struct vnop_strategy_args *ap)
#if 0
	struct vnop_strategy_args {
		struct buf	*a_bp;
	};
#endif
{
#if 1
	dprintf("vnop_strategy: 0\n");
	return (ENOTSUP);
#else
	//wip
	/* buf_bwrite(): after data in buffer has been modified, buf_bwrite()
	 * calls VNOP_STRATEGY to send it to disk.   Unless B_ASYNC
	 * is set on the buffer, data will be written to disk by
	 * the time buf_bwrite returns.
	 *
	 * buf_bread(): read a single logical block of a file through
	 * the buffer cache.  tries to find buffer memory in core,
	 * and calls VNOP_STRATEGY if necessary to bring the data
	 * into memory.   it will not be used for more than PAGESIZE I/O.
	 *
	 * retval seems to be ignored mainly, but not entirely
	 *
	 * spec_strategy() is interesting and lengthy
	 * ultimately it calls the device strategy routine
	 *
	 * vn_strategy calls down to file_io() which ultimately
	 * calls VNOP_READ or VNOP_WRITE after making an auio, this
	 * is a decent model
	 *
	 * hfs_vnop_strategy() just calls buf_strategy on the device, so
	 * is not a useful model.
	 */

	int error = 0;
	buf_t bp = ap->a_bp;
	VERIFY3P(bp, !=, NULL);

	// get vp from buf and znode from vp

	// check alignment; do transfers have to be a particular size?

	// check bounds; read or write less if crossing EOF from below,
	// but error if above EOF

done:
	if (error) {
		buf_seterror(bp, error);
	}
	buf_biodone(bp);
	return (error);

#endif
}

int
zfs_vnop_select(struct vnop_select_args *ap)
#if 0
	struct vnop_select_args {
		struct vnode	*a_vp;
		int		a_which;
		int		a_fflags;
		kauth_cred_t	a_cred;
		void		*a_wql;
		struct proc	*a_p;
	};
#endif
{
	dprintf("vnop_select: 1\n");
	return (1);
}

#ifdef WITH_READDIRATTR
int
zfs_vnop_readdirattr(struct vnop_readdirattr_args *ap)
#if 0
	struct vnop_readdirattr_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		struct attrlist	*a_alist;
		struct uio	*a_uio;
		u_long		a_maxcount;
		u_long		a_options;
		u_long		*a_newstate;
		int		*a_eofflag;
		u_long		*a_actualcount;
		vfs_context_t	a_context;
	};
#endif
{
	struct vnode *vp = ap->a_vp;
	struct attrlist *alp = ap->a_alist;
	struct uio *uio = ap->a_uio;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	zap_cursor_t zc;
	zap_attribute_t zap;
	attrinfo_t attrinfo;
	int maxcount = ap->a_maxcount;
	uint64_t offset = (uint64_t)uio_offset(uio);
	u_int32_t fixedsize;
	u_int32_t maxsize;
	u_int32_t attrbufsize;
	void *attrbufptr = NULL;
	void *attrptr;
	void *varptr;  /* variable-length storage area */
	boolean_t user64 = vfs_context_is64bit(ap->a_context);
	int prefetch = 0;
	int error = 0;

#if 0
	dprintf("+vnop_readdirattr\n");
#endif

	*(ap->a_actualcount) = 0;
	*(ap->a_eofflag) = 0;

	/*
	 * Check for invalid options or invalid uio.
	 */
	if (((ap->a_options & ~(FSOPT_NOINMEMUPDATE | FSOPT_NOFOLLOW)) != 0) ||
		(uio_resid(uio) <= 0) || (maxcount <= 0)) {
		dprintf("%s invalid argument\n");
		return (EINVAL);
	}
	/*
	 * Reject requests for unsupported attributes.
	 */
	if ((alp->bitmapcount != ZFS_ATTR_BIT_MAP_COUNT) ||
	    (alp->commonattr & ~ZFS_ATTR_CMN_VALID) ||
	    (alp->dirattr & ~ZFS_ATTR_DIR_VALID) ||
	    (alp->fileattr & ~ZFS_ATTR_FILE_VALID) ||
	    (alp->volattr != 0 || alp->forkattr != 0)) {
		dprintf("%s unsupported attr\n");
		return (EINVAL);
	}
	/*
	 * Check if we should prefetch znodes
	 */
	if ((alp->commonattr & ~ZFS_DIR_ENT_ATTRS) ||
		(alp->dirattr != 0) || (alp->fileattr != 0)) {
		prefetch = TRUE;
	}

	/*
	 * Setup a buffer to hold the packed attributes.
	 */
	fixedsize = sizeof (u_int32_t) + getpackedsize(alp, user64);
	maxsize = fixedsize;
	if (alp->commonattr & ATTR_CMN_NAME)
		maxsize += ZAP_MAXNAMELEN + 1;
	attrbufptr = (void*)kmem_alloc(maxsize, KM_SLEEP);
	if (attrbufptr == NULL) {
		dprintf("%s kmem_alloc failed\n");
		return (ENOMEM);
	}
	attrptr = attrbufptr;
	varptr = (char *)attrbufptr + fixedsize;

	attrinfo.ai_attrlist = alp;
	attrinfo.ai_varbufend = (char *)attrbufptr + maxsize;
	attrinfo.ai_context = ap->a_context;

	ZFS_ENTER(zfsvfs);

	/*
	 * Initialize the zap iterator cursor.
	 */

	if (offset <= 3) {
		/*
		 * Start iteration from the beginning of the directory.
		 */
		zap_cursor_init(&zc, zfsvfs->z_os, zp->z_id);
	} else {
		/*
		 * The offset is a serialized cursor.
		 */
		zap_cursor_init_serialized(&zc, zfsvfs->z_os, zp->z_id, offset);
	}

	while (1) {
		ino64_t objnum;
		enum vtype vtype = VNON;
		znode_t *tmp_zp = NULL;

		/*
		 * Note that the low 4 bits of the cookie returned by zap is
		 * always zero. This allows us to use the low nibble for
		 * "special" entries:
		 * We use 0 for '.', and 1 for '..' (ignored here).
		 * If this is the root of the filesystem, we use the offset 2
		 * for the *'.zfs' directory.
		 */
		if (offset <= 1) {
			offset = 2;
			continue;
		} else if (offset == 2 && zfs_show_ctldir(zp)) {
			(void) strlcpy(zap.za_name, ZFS_CTLDIR_NAME,
			    MAXNAMELEN);
			objnum = ZFSCTL_INO_ROOT;
			vtype = VDIR;
		} else {
			/*
			 * Grab next entry.
			 */
			if ((error = zap_cursor_retrieve(&zc, &zap))) {
				*(ap->a_eofflag) = (error == ENOENT);
				goto update;
			}

			if (zap.za_integer_length != 8 ||
				zap.za_num_integers != 1) {
				error = ENXIO;
				goto update;
			}

			objnum = ZFS_DIRENT_OBJ(zap.za_first_integer);
			vtype = DTTOVT(ZFS_DIRENT_TYPE(zap.za_first_integer));
			/* Check if vtype is MIA */
			if ((vtype == 0) && !prefetch && (alp->dirattr ||
			    alp->fileattr ||
			    (alp->commonattr & ATTR_CMN_OBJTYPE))) {
				prefetch = 1;
			}
		}

		/* Grab znode if required */
		if (prefetch) {
			dmu_prefetch(zfsvfs->z_os, objnum, 0, 0);
			if ((error = zfs_zget(zfsvfs, objnum, &tmp_zp)) == 0) {
				if (vtype == VNON) {
					/* SA_LOOKUP? */
					vtype = IFTOVT(tmp_zp->z_mode);
				}
			} else {
				tmp_zp = NULL;
				error = ENXIO;
				goto skip_entry;
				/*
				 * Currently ".zfs" entry is skipped, as we have
				 * no methods to pack that into the attrs (all
				 * helper functions take znode_t *, and .zfs is
				 * not a znode_t *). Add dummy .zfs code here if
				 * it is desirable to show .zfs in Finder.
				 */
			}
		}

		/*
		 * Setup for the next item's attribute list
		 */
		*((u_int32_t *)attrptr) = 0; /* byte count slot */
		attrptr = ((u_int32_t *)attrptr) + 1; /* fixed attr start */
		attrinfo.ai_attrbufpp = &attrptr;
		attrinfo.ai_varbufpp = &varptr;

		/*
		 * Pack entries into attribute buffer.
		 */
		if (alp->commonattr) {
			commonattrpack(&attrinfo, zfsvfs, tmp_zp, zap.za_name,
			    objnum, vtype, user64);
		}
		if (alp->dirattr && vtype == VDIR) {
			dirattrpack(&attrinfo, tmp_zp);
		}
		if (alp->fileattr && vtype != VDIR) {
			fileattrpack(&attrinfo, zfsvfs, tmp_zp);
		}
		/* All done with tmp znode. */
		if (prefetch && tmp_zp) {
			vnode_put(ZTOV(tmp_zp));
			tmp_zp = NULL;
		}
		attrbufsize = ((char *)varptr - (char *)attrbufptr);

		/*
		 * Make sure there's enough buffer space remaining.
		 */
		if (uio_resid(uio) < 0 ||
			attrbufsize > (u_int32_t)uio_resid(uio)) {
			break;
		} else {
			*((u_int32_t *)attrbufptr) = attrbufsize;
			error = uiomove((caddr_t)attrbufptr, attrbufsize,
			    UIO_READ, uio);
			if (error != 0)
				break;
			attrptr = attrbufptr;
			/* Point to variable-length storage */
			varptr = (char *)attrbufptr + fixedsize;
			*(ap->a_actualcount) += 1;

			/*
			 * Move to the next entry, fill in the previous offset.
			 */
		skip_entry:
			if ((offset > 2) || ((offset == 2) &&
			    !zfs_show_ctldir(zp))) {
				zap_cursor_advance(&zc);
				offset = zap_cursor_serialize(&zc);
			} else {
				offset += 1;
			}

			/* Termination checks */
			if (--maxcount <= 0 || uio_resid(uio) < 0 ||
			    (u_int32_t)uio_resid(uio) < (fixedsize +
			    ZAP_AVENAMELEN)) {
				break;
			}
		}
	}
update:
	zap_cursor_fini(&zc);

	if (attrbufptr) {
		kmem_free(attrbufptr, maxsize);
	}
	if (error == ENOENT) {
		error = 0;
	}
	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	/* XXX newstate TBD */
	*ap->a_newstate = zp->z_atime[0] + zp->z_atime[1];
	uio_setoffset(uio, offset);

	ZFS_EXIT(zfsvfs);
	dprintf("-readdirattr: error %d\n", error);
	return (error);
}
#endif


#ifdef WITH_SEARCHFS
int
zfs_vnop_searchfs(struct vnop_searchfs_args *ap)
#if 0
	struct vnop_searchfs_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		void		*a_searchparams1;
		void		*a_searchparams2;
		struct attrlist	*a_searchattrs;
		u_long		a_maxmatches;
		struct timeval	*a_timelimit;
		struct attrlist	*a_returnattrs;
		u_long		*a_nummatches;
		u_long		a_scriptcode;
		u_long		a_options;
		struct uio	*a_uio;
		struct searchstate *a_searchstate;
		vfs_context_t	a_context;
	};
#endif
{
	printf("vnop_searchfs called, type %d\n", vnode_vtype(ap->a_vp));

	*(ap->a_nummatches) = 0;

	return (ENOTSUP);
}
#endif



/*
 * Predeclare these here so that the compiler assumes that this is an "old
 * style" function declaration that does not include arguments so that we won't
 * get type mismatch errors in the initializations that follow.
 */
int zfs_vnop_inval(void);
static int zfs_isdir(void);

int
zfs_vnop_inval()
{
	dprintf("ZFS: Bad vnop: returning EINVAL\n");
	return (EINVAL);
}

static int
zfs_isdir()
{
	dprintf("ZFS: Bad vnop: returning EISDIR\n");
	return (EISDIR);
}


/*
 * Advisory locking shim: hand most of the work back to (spl_)lf_advlock()
 */

int
zfs_vnop_advlock(struct vnop_advlock_args *ap)
{
#if 0
	struct vnop_advlock_args {
                struct vnodeop_desc *a_desc;
                vnode_t a_vp;
                caddr_t a_id;
                int a_op;
                struct flock *a_fl;
                int a_flags;
                vfs_context_t a_context;
	}
#endif

#if 0
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	if (ap->a_op == F_SETLK ||  ap->a_op == F_SETLKW) {
		if (spl_ubc_is_mapped(vp, NULL)) {
			printf("ZFS: %s:%d: F_SETLK rejected for mapped file %s\n",
			    __func__, __LINE__, zp->z_name_cache);
			ZFS_EXIT(zfsvfs);
			return (EAGAIN);
		}
	}

	ZFS_EXIT(zfsvfs);
#endif

	return(spl_lf_advlock(ap));
}

#define	VOPFUNC int (*)(void *)

/* Directory vnode operations template */
int (**zfs_dvnodeops) (void *);
struct vnodeopv_entry_desc zfs_dvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_lookup_desc,	(VOPFUNC)zfs_vnop_lookup},
	{&vnop_create_desc,	(VOPFUNC)zfs_vnop_create},
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_mknod_desc,	(VOPFUNC)zfs_vnop_mknod},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_write_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_bwrite_desc, (VOPFUNC)zfs_isdir},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_remove_desc,	(VOPFUNC)zfs_vnop_remove},
	{&vnop_link_desc,	(VOPFUNC)zfs_vnop_link},
	{&vnop_rename_desc,	(VOPFUNC)zfs_vnop_rename},
	{&vnop_mkdir_desc,	(VOPFUNC)zfs_vnop_mkdir},
	{&vnop_rmdir_desc,	(VOPFUNC)zfs_vnop_rmdir},
	{&vnop_symlink_desc,	(VOPFUNC)zfs_vnop_symlink},
	{&vnop_readdir_desc,	(VOPFUNC)zfs_vnop_readdir},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc, (VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
#ifdef WITH_READDIRATTR
	{&vnop_readdirattr_desc, (VOPFUNC)zfs_vnop_readdirattr},
#endif
#ifdef WITH_SEARCHFS
	{&vnop_searchfs_desc,	(VOPFUNC)zfs_vnop_searchfs},
#endif
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_dvnodeop_opv_desc =
{ &zfs_dvnodeops, zfs_dvnodeops_template };

/* Regular file vnode operations template */
int (**zfs_fvnodeops) (void *);
struct vnodeopv_entry_desc zfs_fvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_vnop_read},
	{&vnop_write_desc,	(VOPFUNC)zfs_vnop_write},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_vnop_select},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_bwrite_desc, (VOPFUNC)zfs_vnop_inval},
	{&vnop_pagein_desc,	(VOPFUNC)zfs_vnop_pagein},
#if	HAVE_PAGEOUT_V2
	{&vnop_pageout_desc,	(VOPFUNC)zfs_vnop_pageoutv2},
#else
	{&vnop_pageout_desc,	(VOPFUNC)zfs_vnop_pageout},
#endif
	{&vnop_mmap_desc,	(VOPFUNC)zfs_vnop_mmap},
	{&vnop_mnomap_desc,	(VOPFUNC)zfs_vnop_mnomap},
	{&vnop_blktooff_desc,	(VOPFUNC)zfs_vnop_blktooff},
	{&vnop_offtoblk_desc,	(VOPFUNC)zfs_vnop_offtoblk},
	{&vnop_blockmap_desc,	(VOPFUNC)zfs_vnop_blockmap},
	{&vnop_strategy_desc,	(VOPFUNC)zfs_vnop_strategy},
	{&vnop_allocate_desc,   (VOPFUNC)zfs_vnop_allocate},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_exchange_desc,	(VOPFUNC)zfs_vnop_exchange},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc, (VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
#ifdef HAVE_NAMED_STREAMS
	{&vnop_getnamedstream_desc,	(VOPFUNC)zfs_vnop_getnamedstream},
	{&vnop_makenamedstream_desc,	(VOPFUNC)zfs_vnop_makenamedstream},
	{&vnop_removenamedstream_desc,	(VOPFUNC)zfs_vnop_removenamedstream},
#endif
#ifdef WITH_SEARCHFS
	{&vnop_searchfs_desc,	(VOPFUNC)zfs_vnop_searchfs},
#endif
	{ &vnop_advlock_desc, (VOPFUNC)zfs_vnop_advlock },           /* advlock */
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_fvnodeop_opv_desc =
{ &zfs_fvnodeops, zfs_fvnodeops_template };

/* Symbolic link vnode operations template */
int (**zfs_symvnodeops) (void *);
struct vnodeopv_entry_desc zfs_symvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_readlink_desc,	(VOPFUNC)zfs_vnop_readlink},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc, (VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_symvnodeop_opv_desc =
{ &zfs_symvnodeops, zfs_symvnodeops_template };

/* Extended attribtue directory vnode operations template */
int (**zfs_xdvnodeops) (void *);
struct vnodeopv_entry_desc zfs_xdvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_lookup_desc,	(VOPFUNC)zfs_vnop_lookup},
	{&vnop_create_desc,	(VOPFUNC)zfs_vnop_create},
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_mknod_desc,	(VOPFUNC)zfs_vnop_inval},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_vnop_read},
	{&vnop_write_desc,	(VOPFUNC)zfs_vnop_write},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_vnop_select},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_remove_desc,	(VOPFUNC)zfs_vnop_remove},
	{&vnop_link_desc,	(VOPFUNC)zfs_vnop_link},
	{&vnop_rename_desc,	(VOPFUNC)zfs_vnop_rename},
	{&vnop_mkdir_desc,	(VOPFUNC)zfs_vnop_inval},
	{&vnop_rmdir_desc,	(VOPFUNC)zfs_vnop_rmdir},
	{&vnop_symlink_desc,	(VOPFUNC)zfs_vnop_inval},
	{&vnop_readdir_desc,	(VOPFUNC)zfs_vnop_readdir},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_xdvnodeop_opv_desc =
{ &zfs_xdvnodeops, zfs_xdvnodeops_template };

/* Error vnode operations template */
int (**zfs_evnodeops) (void *);
struct vnodeopv_entry_desc zfs_evnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_evnodeop_opv_desc =
{ &zfs_evnodeops, zfs_evnodeops_template };

int (**zfs_fifonodeops)(void *);
struct vnodeopv_entry_desc zfs_fifonodeops_template[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)fifo_lookup },            /* lookup */
	{ &vnop_create_desc, (VOPFUNC)fifo_create },            /* create */
	{ &vnop_mknod_desc, (VOPFUNC)fifo_mknod },              /* mknod */
	{ &vnop_open_desc, (VOPFUNC)fifo_open },                        /* open
																	 */
	{ &vnop_close_desc, (VOPFUNC)fifo_close },           /* close */
	{ &vnop_getattr_desc, (VOPFUNC)zfs_vnop_getattr },      /* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)zfs_vnop_setattr },      /* setattr */
	{ &vnop_read_desc, (VOPFUNC)fifo_read },             /* read */
	{ &vnop_write_desc, (VOPFUNC)fifo_write },           /* write */
	{ &vnop_ioctl_desc, (VOPFUNC)fifo_ioctl },              /* ioctl */
	{ &vnop_select_desc, (VOPFUNC)fifo_select },            /* select */
	{ &vnop_revoke_desc, (VOPFUNC)fifo_revoke },            /* revoke */
	{ &vnop_mmap_desc, (VOPFUNC)fifo_mmap },                        /* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)zfs_vnop_fsync },          /* fsync */
	{ &vnop_remove_desc, (VOPFUNC)fifo_remove },            /* remove */
	{ &vnop_link_desc, (VOPFUNC)fifo_link },                        /* link */
	{ &vnop_rename_desc, (VOPFUNC)fifo_rename },            /* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)fifo_mkdir },              /* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)fifo_rmdir },              /* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)fifo_symlink },          /* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)fifo_readdir },          /* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)fifo_readlink },                /* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)zfs_vnop_inactive },    /* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)zfs_vnop_reclaim },      /* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)fifo_strategy },                /* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)fifo_pathconf },                /* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)zfs_vnop_advlock },           /* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)zfs_vnop_bwrite },
	{ &vnop_pagein_desc, (VOPFUNC)zfs_vnop_pagein },                /* Pagein */
#if	HAVE_PAGEOUT_V2
	{ &vnop_pageout_desc, (VOPFUNC)zfs_vnop_pageoutv2 },      /* Pageout */
#else
	{ &vnop_pageout_desc, (VOPFUNC)zfs_vnop_pageout },      /* Pageout */
#endif
	{ &vnop_copyfile_desc, (VOPFUNC)err_copyfile },                 /* copyfile */
	{ &vnop_blktooff_desc, (VOPFUNC)zfs_vnop_blktooff },    /* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)zfs_vnop_offtoblk },    /* offtoblk */
	{ &vnop_blockmap_desc, (VOPFUNC)zfs_vnop_blockmap },            /* blockmap */
	{ &vnop_getxattr_desc, (VOPFUNC)zfs_vnop_getxattr},
	{ &vnop_setxattr_desc, (VOPFUNC)zfs_vnop_setxattr},
	{ &vnop_removexattr_desc, (VOPFUNC)zfs_vnop_removexattr},
	{ &vnop_listxattr_desc, (VOPFUNC)zfs_vnop_listxattr},
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_fifonodeop_opv_desc =
	{ &zfs_fifonodeops, zfs_fifonodeops_template };






/*
 * Alas, OS X does not let us create a vnode, and assign the vtype later and we
 * do not know what type we want here. Is there a way around this? We could
 * allocate any old vnode, then recycle it to ensure a vnode is spare?
 */
void
getnewvnode_reserve(int num)
{
}

void
getnewvnode_drop_reserve()
{
}

/*
 * Get new vnode for znode.
 *
 * This function uses zp->z_zfsvfs, zp->z_mode, zp->z_flags, zp->z_id and sets
 * zp->z_vnode and zp->z_vid.
 */
int
zfs_znode_getvnode(znode_t *zp, zfsvfs_t *zfsvfs)
{
	struct vnode_fsparam vfsp;
	struct vnode *vp = NULL;

	dprintf("getvnode zp %p with vp %p zfsvfs %p vfs %p\n", zp, vp,
	    zfsvfs, zfsvfs->z_vfs);

	if (zp->z_vnode)
		panic("zp %p vnode already set\n", zp->z_vnode);

	bzero(&vfsp, sizeof (vfsp));
	vfsp.vnfs_str = "zfs";
	vfsp.vnfs_mp = zfsvfs->z_vfs;
	vfsp.vnfs_vtype = IFTOVT((mode_t)zp->z_mode);
	vfsp.vnfs_fsnode = zp;
	vfsp.vnfs_flags = VNFS_ADDFSREF;

	/*
	 * XXX HACK - workaround missing vnode_setnoflush() KPI...
	 */
	/* Tag system files */
#if 0
	if ((zp->z_flags & ZFS_XATTR) &&
	    (zfsvfs->z_last_unmount_time == 0xBADC0DE) &&
	    (zfsvfs->z_last_mtime_synced == zp->z_parent)) {
		vfsp.vnfs_marksystem = 1;
	}
#endif

	/* Tag root directory */
	if (zp->z_id == zfsvfs->z_root) {
		vfsp.vnfs_markroot = 1;
	}

	switch (vfsp.vnfs_vtype) {
	case VDIR:
		if (zp->z_pflags & ZFS_XATTR) {
			vfsp.vnfs_vops = zfs_xdvnodeops;
		} else {
			vfsp.vnfs_vops = zfs_dvnodeops;
		}
		zp->z_zn_prefetch = B_TRUE; /* z_prefetch default is enabled */
		break;
	case VBLK:
	case VCHR:
		{
			uint64_t rdev;
			VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_RDEV(zfsvfs),
			    &rdev, sizeof (rdev)) == 0);

			vfsp.vnfs_rdev = zfs_cmpldev(rdev);
		}
		/* FALLTHROUGH */
	case VSOCK:
		vfsp.vnfs_vops = zfs_fvnodeops;
		break;
	case VFIFO:
		vfsp.vnfs_vops = zfs_fifonodeops;
		break;
	case VREG:
		vfsp.vnfs_vops = zfs_fvnodeops;
		vfsp.vnfs_filesize = zp->z_size;
		break;
	case VLNK:
		vfsp.vnfs_vops = zfs_symvnodeops;
#if 0
		vfsp.vnfs_filesize = ???;
#endif
		break;
	default:
		vfsp.vnfs_vops = zfs_fvnodeops;
		printf("ZFS: Warning, error-vnops selected: vtype %d\n",vfsp.vnfs_vtype);
		break;
	}

	/*
	 * vnode_create() has a habit of calling both vnop_reclaim() and
	 * vnop_fsync(), which can create havok as we are already holding locks.
	 */

	/* So pageout can know if it is called recursively, add this thread to list*/
	while (vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, &vp) != 0) {
		kpreempt(KPREEMPT_SYNC);
	}
	atomic_inc_64(&vnop_num_vnodes);

	dprintf("Assigned zp %p with vp %p\n", zp, vp);

	/*
	 * Unfortunately, when it comes to IOCTL_GET_BOOT_INFO and getting
	 * the volume finderinfo, XNU checks the tags, and only acts on
	 * HFS. So we have to set it to HFS on the root. It is pretty gross
	 * but until XNU adds supporting code..
	 * The only place we use tags in ZFS is ctldir checking for VT_OTHER
	 */
	if (zp->z_id == zfsvfs->z_root)
		vnode_settag(vp, VT_HFS);
	else
		vnode_settag(vp, VT_ZFS);

	zp->z_vid = vnode_vid(vp);
	zp->z_vnode = vp;

	/*
	 * OS X Finder is hardlink agnostic, so we need to mark vp's that
	 * are hardlinks, so that it forces a lookup each time, ignoring
	 * the name cache.
	 */
	if ((zp->z_links > 1) && (IFTOVT((mode_t)zp->z_mode) == VREG))
		vnode_setmultipath(vp);

	return (0);
}

/*
 * Maybe these should live in vfsops
 */
int
zfs_vfsops_init(void)
{
	struct vfs_fsentry vfe;

	zfs_init();

	/* Start thread to notify Finder of changes */
	zfs_start_notify_thread();

	vfe.vfe_vfsops = &zfs_vfsops_template;
	vfe.vfe_vopcnt = ZFS_VNOP_TBL_CNT;
	vfe.vfe_opvdescs = zfs_vnodeop_opv_desc_list;

	strlcpy(vfe.vfe_fsname, "zfs", MFSNAMELEN);

	/*
	 * Note: must set VFS_TBLGENERICMNTARGS with VFS_TBLLOCALVOL
	 * to suppress local mount argument handling.
	 */
	vfe.vfe_flags = VFS_TBLTHREADSAFE | VFS_TBLNOTYPENUM | VFS_TBLLOCALVOL |
	    VFS_TBL64BITREADY | VFS_TBLNATIVEXATTR | VFS_TBLGENERICMNTARGS |
	    VFS_TBLREADDIR_EXTENDED;

#if	HAVE_PAGEOUT_V2
	vfe.vfe_flags |= VFS_TBLVNOP_PAGEOUTV2;
#endif

#ifdef VFS_TBLCANMOUNTROOT  // From 10.12
	vfe.vfe_flags |= VFS_TBLCANMOUNTROOT;
#endif

	vfe.vfe_reserv[0] = 0;
	vfe.vfe_reserv[1] = 0;

	if (vfs_fsadd(&vfe, &zfs_vfsconf) != 0)
		return (KERN_FAILURE);
	else
		return (KERN_SUCCESS);
}

int
zfs_vfsops_fini(void)
{

	zfs_stop_notify_thread();

	zfs_fini();

	return (vfs_fsremove(zfs_vfsconf));
}

/*
 * implement an advisory_read() for zfs
 */

int
zfs_advisory_read_ext(vnode_t *vp, off_t filesize, off_t f_offset, int resid, int (*callback)(buf_t, void *), void
*callback_arg, int bflag)
{
        upl_page_info_t *pl;
        upl_t            upl;
        vm_offset_t      upl_offset;
        int              upl_size;
        off_t            upl_f_offset;
        int              start_offset;
        int              start_pg;
        int              last_pg;
        int              pages_in_upl;
        off_t            max_size;
        int              io_size;
        kern_return_t    kret;
        int              retval = 0;
        int              issued_io;
        int              skip_range;
        uint32_t         max_io_size;


	/* should really be a bit like mappedread */
	/* or use cluster_copy_upl_data or cluster_copy_ubc_data */

	if (ubc_getsize(vp) == 0)
		return(EINVAL);

        if (resid < 0)
                return(EINVAL);

	max_io_size = (512 * 1024); // from speculative_prefetch_max_iosize

        while (resid && f_offset < filesize && retval == 0) {
                /*
                 * compute the size of the upl needed to encompass
                 * the requested read... limit each call to cluster_io
                 * to the maximum UPL size... cluster_io will clip if
                 * this exceeds the maximum io_size for the device,
                 * make sure to account for
                 * a starting offset that's not page aligned
                 */
                start_offset = (int)(f_offset & PAGE_MASK_64);
                upl_f_offset = f_offset - (off_t)start_offset;
                max_size     = filesize - f_offset;

                if (resid < max_size)
                        io_size = resid;
                else
                        io_size = max_size;

                upl_size = (start_offset + io_size + (PAGE_SIZE - 1)) & ~PAGE_MASK;
                if ((uint32_t)upl_size > max_io_size)
                        upl_size = max_io_size;

                skip_range = 0;
                /*
                 * return the number of contiguously present pages in the cache
                 * starting at upl_f_offset within the file
                 */
                ubc_range_op(vp, upl_f_offset, upl_f_offset + upl_size, UPL_ROP_PRESENT, &skip_range);

                if (skip_range) {
                        /*
                         * skip over pages already present in the cache
                         */
                        io_size = skip_range - start_offset;

                        f_offset += io_size;
                        resid    -= io_size;

                        if (skip_range == upl_size)
                                continue;
                        /*
                         * have to issue some real I/O
                         * at this point, we know it's starting on a page boundary
                         * because we've skipped over at least the first page in the request
                         */
                        start_offset = 0;
                        upl_f_offset += skip_range;
			                }
                pages_in_upl = upl_size / PAGE_SIZE;

                kret = ubc_create_upl(vp,
                                      upl_f_offset,
                                      upl_size,
                                      &upl,
                                      &pl,
                                      UPL_RET_ONLY_ABSENT | UPL_SET_LITE);
                if (kret != KERN_SUCCESS)
                        return(retval);
                issued_io = 0;

                /*
                 * before we start marching forward, we must make sure we end on
                 * a present page, otherwise we will be working with a freed
                 * upl
                 */
                for (last_pg = pages_in_upl - 1; last_pg >= 0; last_pg--) {
                        if (upl_page_present(pl, last_pg))
                                break;
                }
                pages_in_upl = last_pg + 1;

                for (last_pg = 0; last_pg < pages_in_upl; ) {
                        /*
                         * scan from the beginning of the upl looking for the first
                         * page that is present.... this will become the first page in
                         * the request we're going to make to 'cluster_io'... if all
                         * of the pages are absent, we won't call through to 'cluster_io'
                         */
                        for (start_pg = last_pg; start_pg < pages_in_upl; start_pg++) {
                                if (upl_page_present(pl, start_pg))
                                        break;
                        }

                        /*
                         * scan from the starting present page looking for an absent
                         * page before the end of the upl is reached, if we
                         * find one, then it will terminate the range of pages being
                         * presented to 'cluster_io'
                         */
                        for (last_pg = start_pg; last_pg < pages_in_upl; last_pg++) {
                                if (!upl_page_present(pl, last_pg))
                                        break;
                        }

                        if (last_pg > start_pg) {
                                /*
                                 * we found a range of pages that must be filled
                                 * if the last page in this range is the last page of the file
                                 * we may have to clip the size of it to keep from reading past
                                 * the end of the last physical block associated with the file
                                 */
                                upl_offset = start_pg * PAGE_SIZE;
                                io_size    = (last_pg - start_pg) * PAGE_SIZE;

                                if ((off_t)(upl_f_offset + upl_offset + io_size) > filesize)
                                        io_size = filesize - (upl_f_offset + upl_offset);

                                /*
                                 * issue an asynchronous read to cluster_io
                                 */
//                                retval = cluster_io(vp, upl, upl_offset, upl_f_offset + upl_offset, io_size,
//                                                    CL_ASYNC | CL_READ | CL_COMMIT | CL_AGE | bflag, (buf_t)NULL, (struct clios *)NULL, callback, callback_arg);

                                issued_io = 1;
                        }
                }
                if (issued_io == 0)
                        ubc_upl_abort(upl, 0);

                io_size = upl_size - start_offset;

                if (io_size > resid)
                        io_size = resid;
                f_offset += io_size;
                resid    -= io_size;
		        }

        return(retval);
}

int
zfs_advisory_read(vnode_t *vp, off_t filesize, off_t f_offset, int resid)
{
        return zfs_advisory_read_ext(vp, filesize, f_offset, resid, NULL, NULL, 0);
}
