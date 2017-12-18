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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2015 by Delphix. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2015 by Chunwei Chen. All rights reserved.
 * Copyright 2017, Sean Doran <smd@use.net>.  All rights reserved.
 */

/* Portions Copyright 2007 Jeremy Teo */
/* Portions Copyright 2010 Robert Milkowski */
/* Portions Copyright 2013 Jorgen Lundman */
/* Portions Copyright 2017 Sean Doran */

#ifdef __APPLE__
/*
 * cluster_copy_ubc_data takes XNU's uio_t which is (struct uio *)
 * whereas ZFS's uio_t is (struct uio)
 */
#define cluster_copy_ubc_data kern_cluster_copy_ubc_data
#define cluster_copy_upl_data kern_cluster_copy_upl_data
#define round_page_64(x) (((uint64_t)(x) + PAGE_MASK_64) & ~((uint64_t)PAGE_MASK_64))
#define trunc_page_64(x) ((uint64_t)(x) & ~((uint64_t)PAGE_MASK_64))
const int MAX_UPL_SIZE_BYTES = 16*1024*1024;

#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <sys/vm.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/taskq.h>
#include <sys/uio.h>
#include <sys/atomic.h>
#include <sys/namei.h>
#include <sys/mman.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/unistd.h>
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
#include <sys/dirent.h>
#include <sys/policy.h>
#include <sys/sunddi.h>
#include <sys/filio.h>
#include <sys/sid.h>
#include <sys/zfs_ctldir.h>
#include <sys/zfs_fuid.h>
#include <sys/zfs_sa.h>
#include <sys/dnlc.h>
#include <sys/zfs_rlock.h>
#include <sys/extdirent.h>
#include <sys/kidmap.h>
//#include <sys/bio.h>
#include <sys/buf.h>
//#include <sys/sf_buf.h>
//#include <sys/sched.h>
#include <sys/acl.h>
//#include <vm/vm_param.h>
#include <vm/vm_pageout.h>
#include <sys/utfconv.h>
#include <sys/ubc.h>
#include <sys/zfs_vnops.h>
#include <sys/zfs_vfsops.h>
#include <sys/vnode.h>
#include <sys/vdev.h>
#include <sys/znode_z_map_lock.h>
#include <sys/dnode.h>

#ifdef __APPLE__
/*
 * cluster_copy_ubc_data takes XNU's uio_t which is (struct uio *)
 * whereas ZFS's uio_t is (struct uio)
 */
#undef cluster_copy_ubc_data
#undef cluster_copy_upl_data
extern int cluster_copy_ubc_data(vnode_t *, uio_t *, int *, int);
extern int cluster_copy_upl_data(uio_t *, upl_t, int, int *);
#endif

//#define dprintf printf

int zfs_vnop_force_formd_normalized_output = 0; /* disabled by default */

typedef struct vnops_stats {
	kstat_named_t fill_holes_ubc_satisfied_all;
	kstat_named_t fill_holes_rop_present_total_skip;
	kstat_named_t fill_holes_rop_present_bytes_skipped;
	kstat_named_t fill_holes_upl_present_pages_skipped;
	kstat_named_t fill_holes_upl_absent_pages_filled;
	kstat_named_t zfs_write_calls;
	kstat_named_t zfs_write_clean_on_write;
	kstat_named_t zfs_write_clean_on_write_sync;
	kstat_named_t zfs_write_cluster_copy_ok;
	kstat_named_t zfs_write_cluster_copy_complete;
	kstat_named_t zfs_write_cluster_copy_bytes;
	kstat_named_t zfs_write_cluster_copy_error;
	kstat_named_t zfs_write_cluster_copy_short_write;
	kstat_named_t zfs_write_helper_iters;
	kstat_named_t zfs_write_msync;
	kstat_named_t zfs_write_arcbuf_assign;
	kstat_named_t zfs_write_arcbuf_assign_bytes;
	kstat_named_t zfs_write_uio_dbufs;
	kstat_named_t zfs_write_uio_dbuf_bytes;
	kstat_named_t zfs_zero_length_write;
	kstat_named_t update_pages;
	kstat_named_t update_pages_want_lock;
	kstat_named_t update_pages_lock_timeout;
	kstat_named_t zfs_read_calls;
	kstat_named_t zfs_read_clean_on_read;
	kstat_named_t mappedread_lock_tries;
	kstat_named_t zfs_read_mappedread_mapped_file_bytes;
	kstat_named_t zfs_read_mappedread_unmapped_file_bytes;
	kstat_named_t zfs_fsync_zil_commit_reg_vn;
	kstat_named_t zfs_fsync_ubc_msync;
	kstat_named_t zfs_fsync_non_isreg;
	kstat_named_t zfs_fsync_want_lock;
	kstat_named_t zfs_ubc_msync_error;
	kstat_named_t zfs_fsync_disabled;
} vnops_stats_t;

static vnops_stats_t vnops_stats = {
	{ "fill_holes_ubc_satisfied_all",                KSTAT_DATA_UINT64 },
	{ "fill_holes_rop_present_total_skip",           KSTAT_DATA_UINT64 },
	{ "fill_holes_rop_present_bytes_skipped",        KSTAT_DATA_UINT64 },
	{ "fill_holes_upl_present_pages_skipped",        KSTAT_DATA_UINT64 },
	{ "fill_holes_upl_absent_pages_filled",          KSTAT_DATA_UINT64 },
	{ "zfs_write_calls",                             KSTAT_DATA_UINT64 },
	{ "zfs_write_clean_on_write",                    KSTAT_DATA_UINT64 },
	{ "zfs_write_clean_on_write_sync",               KSTAT_DATA_UINT64 },
	{ "zfs_write_sync_cluster_copy_ok",              KSTAT_DATA_UINT64 },
	{ "zfs_write_sync_cluster_copy_complete",        KSTAT_DATA_UINT64 },
	{ "zfs_write_sync_cluster_copy_bytes",           KSTAT_DATA_UINT64 },
	{ "zfs_write_sync_cluster_copy_error",           KSTAT_DATA_UINT64 },
	{ "zfs_write_sync_cluster_short_write",          KSTAT_DATA_UINT64 },
	{ "zfs_write_helper_iters",                      KSTAT_DATA_UINT64 },
	{ "zfs_write_msync",                             KSTAT_DATA_UINT64 },
	{ "zfs_write_arcbuf_assign",                     KSTAT_DATA_UINT64 },
	{ "zfs_write_arcbuf_assign_bytes",               KSTAT_DATA_UINT64 },
	{ "zfs_write_uio_dbufs",                         KSTAT_DATA_UINT64 },
	{ "zfs_write_uio_dbuf_bytes",                    KSTAT_DATA_UINT64 },
	{ "zfs_zero_length_write",                       KSTAT_DATA_UINT64 },
	{ "update_pages",                                KSTAT_DATA_UINT64 },
	{ "update_pages_want_lock",                      KSTAT_DATA_UINT64 },
	{ "update_pages_lock_timeout",                   KSTAT_DATA_UINT64 },
	{ "zfs_read_calls",                              KSTAT_DATA_UINT64 },
	{ "zfs_read_clean_on_read",                      KSTAT_DATA_UINT64 },
	{ "mappedread_lock_tries",                       KSTAT_DATA_UINT64 },
	{ "zfs_read_mappedread_mapped_file_bytes",       KSTAT_DATA_UINT64 },
	{ "zfs_read_mappedread_unmapped_file_bytes",     KSTAT_DATA_UINT64 },
	{ "zfs_fsync_zil_commit_reg_vn",                 KSTAT_DATA_UINT64 },
	{ "zfs_fsync_ubc_msync",                         KSTAT_DATA_UINT64 },
	{ "zfs_fsync_non_isreg",                         KSTAT_DATA_UINT64 },
	{ "zfs_fsync_want_lock",                         KSTAT_DATA_UINT64 },
	{ "zfs_ubc_msync_error",                         KSTAT_DATA_UINT64 },
	{ "zfs_fsync_disabled",                          KSTAT_DATA_UINT64 },
};

#define VNOPS_STAT(statname)           (vnops_stats.statname.value.ui64)
#define VNOPS_STAT_INCR(statname, val) \
        atomic_add_64(&vnops_stats.statname.value.ui64, (val))
#define VNOPS_STAT_BUMP(stat)      VNOPS_STAT_INCR(stat, 1)
#define VNOPS_STAT_BUMPDOWN(stat)  VNOPS_STAT_INCR(stat, -1)

static kstat_t *vnops_ksp;

void
vnops_stat_init(void)
{
	vnops_ksp = kstat_create("zfs", 0, "vnops", "misc", KSTAT_TYPE_NAMED,
            sizeof (vnops_stats) / sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);
        if (vnops_ksp != NULL) {
                vnops_ksp->ks_data = &vnops_stats;
                kstat_install(vnops_ksp);
	}
}

void
vnops_stat_fini(void)
{
        if (vnops_ksp != NULL) {
                kstat_delete(vnops_ksp);
                vnops_ksp = NULL;
        }
}

/*
 * Programming rules.
 *
 * Each vnode op performs some logical unit of work.  To do this, the ZPL must
 * properly lock its in-core state, create a DMU transaction, do the work,
 * record this work in the intent log (ZIL), commit the DMU transaction,
 * and wait for the intent log to commit if it is a synchronous operation.
 * Moreover, the vnode ops must work in both normal and log replay context.
 * The ordering of events is important to avoid deadlocks and references
 * to freed memory.  The example below illustrates the following Big Rules:
 *
 *  (1) A check must be made in each zfs thread for a mounted file system.
 *	This is done avoiding races using ZFS_ENTER(zfsvfs).
 *      A ZFS_EXIT(zfsvfs) is needed before all returns.  Any znodes
 *      must be checked with ZFS_VERIFY_ZP(zp).  Both of these macros
 *      can return EIO from the calling function.
 *
 *  (2)	VN_RELE() should always be the last thing except for zil_commit()
 *	(if necessary) and ZFS_EXIT(). This is for 3 reasons:
 *	First, if it's the last reference, the vnode/znode
 *	can be freed, so the zp may point to freed memory.  Second, the last
 *	reference will call zfs_zinactive(), which may induce a lot of work --
 *	pushing cached pages (which acquires range locks) and syncing out
 *	cached atime changes.  Third, zfs_zinactive() may require a new tx,
 *	which could deadlock the system if you were already holding one.
 *	If you must call VN_RELE() within a tx then use VN_RELE_ASYNC().
 *
 *  (3)	All range locks must be grabbed before calling dmu_tx_assign(),
 *	as they can span dmu_tx_assign() calls.
 *
 *  (4) If ZPL locks are held, pass TXG_NOWAIT as the second argument to
 *      dmu_tx_assign().  This is critical because we don't want to block
 *      while holding locks.
 *
 *	If no ZPL locks are held (aside from ZFS_ENTER()), use TXG_WAIT.  This
 *	reduces lock contention and CPU usage when we must wait (note that if
 *	throughput is constrained by the storage, nearly every transaction
 *	must wait).
 *
 *      Note, in particular, that if a lock is sometimes acquired before
 *      the tx assigns, and sometimes after (e.g. z_lock), then failing
 *      to use a non-blocking assign can deadlock the system.  The scenario:
 *
 *	Thread A has grabbed a lock before calling dmu_tx_assign().
 *	Thread B is in an already-assigned tx, and blocks for this lock.
 *	Thread A calls dmu_tx_assign(TXG_WAIT) and blocks in txg_wait_open()
 *	forever, because the previous txg can't quiesce until B's tx commits.
 *
 *	If dmu_tx_assign() returns ERESTART and zsb->z_assign is TXG_NOWAIT,
 *	then drop all locks, call dmu_tx_wait(), and try again.  On subsequent
 *	calls to dmu_tx_assign(), pass TXG_WAITED rather than TXG_NOWAIT,
 *	to indicate that this operation has already called dmu_tx_wait().
 *	This will ensure that we don't retry forever, waiting a short bit
 *	each time.
 *
 *  (5)	If the operation succeeded, generate the intent log entry for it
 *	before dropping locks.  This ensures that the ordering of events
 *	in the intent log matches the order in which they actually occurred.
 *	During ZIL replay the zfs_log_* functions will update the sequence
 *	number to indicate the zil transaction has replayed.
 *
 *  (6)	At the end of each vnode op, the DMU tx must always commit,
 *	regardless of whether there were any errors.
 *
 *  (7)	After dropping all locks, invoke zil_commit(zilog, foid)
 *	to ensure that synchronous semantics are provided when necessary.
 *
 * In general, this is how things should be ordered in each vnode op:
 *
 *	ZFS_ENTER(zfsvfs);		// exit if unmounted
 * top:
 *	zfs_dirent_lock(&dl, ...)	// lock directory entry (may VN_HOLD())
 *	rw_enter(...);			// grab any other locks you need
 *	tx = dmu_tx_create(...);	// get DMU tx
 *	dmu_tx_hold_*();		// hold each object you might modify
 *	error = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
 *	if (error) {
 *		rw_exit(...);		// drop locks
 *		zfs_dirent_unlock(dl);	// unlock directory entry
 *		VN_RELE(...);		// release held vnodes
 *		if (error == ERESTART) {
 *			waited = B_TRUE;
 *			dmu_tx_wait(tx);
 *			dmu_tx_abort(tx);
 *			goto top;
 *		}
 *		dmu_tx_abort(tx);	// abort DMU tx
 *		ZFS_EXIT(zfsvfs);	// finished in zfs
 *		return (error);		// really out of space
 *	}
 *	error = do_real_work();		// do whatever this VOP does
 *	if (error == 0)
 *		zfs_log_*(...);		// on success, make ZIL entry
 *	dmu_tx_commit(tx);		// commit DMU tx -- error or not
 *	rw_exit(...);			// drop locks
 *	zfs_dirent_unlock(dl);		// unlock directory entry
 *	VN_RELE(...);			// release held vnodes
 *	zil_commit(zilog, foid);	// synchronous when necessary
 *	ZFS_EXIT(zfsvfs);		// finished in zfs
 *	return (error);			// done, report error
 */

/* ARGSUSED */
int
zfs_open(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	znode_t	*zp = VTOZ(*vpp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	/* Honor ZFS_APPENDONLY file attribute */
	if ((flag & FWRITE) && (zp->z_pflags & ZFS_APPENDONLY) &&
	    ((flag & FAPPEND) == 0)) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EPERM));
	}

#if 0
	if (!zfs_has_ctldir(zp) && zp->z_zfsvfs->z_vscan &&
	    ZTOV(zp)->v_type == VREG &&
	    !(zp->z_pflags & ZFS_AV_QUARANTINED) && zp->z_size > 0) {
		if (fs_vscan(*vpp, cr, 0) != 0) {
			ZFS_EXIT(zfsvfs);
			return ((EACCES));
		}
	}
#endif

	/* Keep a count of the synchronous opens in the znode */
	if (flag & (FSYNC | FDSYNC)) {
		ASSERT3S(zp->z_sync_cnt, <, UINT32_MAX);
		ASSERT3S(zp->z_sync_cnt, <, 1024);  // XXX: ARBITRARY
		atomic_inc_32(&zp->z_sync_cnt);
	}

	ZFS_EXIT(zfsvfs);
	return (0);
}

/* ARGSUSED */
int
zfs_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
    caller_context_t *ct)
{
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	/*
	 * Clean up any locks held by this process on the vp.
	 */
#ifndef __APPLE__
	cleanlocks(vp, ddi_get_pid(), 0);
	cleanshares(vp, ddi_get_pid());
#endif

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	/* Decrement the synchronous opens in the znode */
	if ((flag & (FSYNC | FDSYNC)) && (count == 1)) {
		ASSERT3S(zp->z_sync_cnt, >, 0);
		atomic_dec_32(&zp->z_sync_cnt);
	}

#if 0
	if (!zfs_has_ctldir(zp) && zp->z_zfsvfs->z_vscan &&
	    ZTOV(zp)->v_type == VREG &&
	    !(zp->z_pflags & ZFS_AV_QUARANTINED) && zp->z_size > 0)
		VERIFY(fs_vscan(vp, cr, 1) == 0);
#endif

	ZFS_EXIT(zfsvfs);
	return (0);
}

#if defined(SEEK_HOLE) && defined(SEEK_DATA)
/*
 * Lseek support for finding holes (cmd == SEEK_HOLE) and
 * data (cmd == SEEK_DATA). "off" is an in/out parameter.
 */
static int
zfs_holey_common(struct vnode *vp, int cmd, loff_t *off)
{
	znode_t	*zp = VTOZ(vp);
	uint64_t noff = (uint64_t)*off; /* new offset */
	uint64_t file_sz;
	int error;
	boolean_t hole;

	file_sz = zp->z_size;
	if (noff >= file_sz)  {
		return (SET_ERROR(ENXIO));
	}

	if (cmd == SEEK_HOLE)
		hole = B_TRUE;
	else
		hole = B_FALSE;

	error = dmu_offset_next(zp->z_zfsvfs->z_os, zp->z_id, hole, &noff);

	if (error == ESRCH)
		return (SET_ERROR(ENXIO));

	/*
	 * We could find a hole that begins after the logical end-of-file,
	 * because dmu_offset_next() only works on whole blocks.  If the
	 * EOF falls mid-block, then indicate that the "virtual hole"
	 * at the end of the file begins at the logical EOF, rather than
	 * at the end of the last block.
	 */
	if (noff > file_sz) {
		ASSERT(hole);
		noff = file_sz;
	}

	if (noff < *off)
		return (error);
	*off = noff;
	return (error);
}

int
zfs_holey(struct vnode *vp, int cmd, loff_t *off)
{
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	error = zfs_holey_common(vp, cmd, off);

	ZFS_EXIT(zfsvfs);
	return (error);
}

#endif /* SEEK_HOLE && SEEK_DATA */

static
int ubc_invalidate_range_impl(vnode_t *vp, off_t start, off_t end)
{
	znode_t *zp = VTOZ(vp);

	off_t size = end - start;
	int retval_msync = 0;

	off_t resid_msync_off = end;

	boolean_t need_release = B_FALSE, need_upgrade = B_FALSE;
	uint64_t tries = z_map_rw_lock(zp, &need_release, &need_upgrade, __func__);
	retval_msync = zfs_ubc_msync(vp, start, end, &resid_msync_off, UBC_PUSHALL | UBC_SYNC);
	z_map_drop_lock(zp, &need_release, &need_upgrade);
	ASSERT3S(tries, <=, 2);

	if (retval_msync != 0) {
		if (resid_msync_off != end)
			printf("ZFS: %s:%d: msync error %d invalidating %lld - %lld (%lld bytes),"
			    " resid_off = %lld, file %s\n",
			    __func__, __LINE__, retval_msync, start, end, size,
			    resid_msync_off, zp->z_name_cache);
		else
			ASSERT3U(resid_msync_off, ==, end);
	} else {
		dprintf("ZFS: (DEBUG) %s:%d: inval %lld - %lld (%lld), resid %lld , file %s\n",
		    __func__, __LINE__, start, end, size,
		    resid_msync_off, zp->z_name_cache);
	}
	return (retval_msync);
}

int
ubc_invalidate_range(vnode_t *vp, off_t start_byte, off_t end_byte)
{
	/*
	 * these roundings are done by ubc_msync_internal, but are
	 * useful for our own range debugging
	 */
	off_t start = trunc_page_64(start_byte);
	off_t end = round_page_64(end_byte);

	ASSERT3U(start, <=, start_byte);
	ASSERT3U(end, >=, end_byte);

	return(ubc_invalidate_range_impl(vp, start, end));
}

/*
 * When a file is memory mapped, we must keep the IO data synchronized
 * between the DMU cache and the memory mapped pages.  What this means:
 *
 * On Write:    If we find a memory mapped page, we write to *both*
 *              the page and the dmu buffer.
 */
static int fill_holes_in_range(vnode_t *vp, const off_t upl_file_offset, const size_t upl_size,
	boolean_t will_mod);

static void
update_pages(vnode_t *vp, int64_t nbytes, struct uio *uio,
    dmu_tx_t *tx, int oldstyle)
{
    znode_t *zp = VTOZ(vp);
    const char *filename = zp->z_name_cache;
    int error = 0;
    off_t upl_start;
    off_t upl_size;

    const off_t orig_offset = uio_offset(uio);
    upl_start = trunc_page_64(orig_offset);
    const off_t upl_start_align_offset = orig_offset - upl_start;
    ASSERT3S(upl_start_align_offset, >=, 0);
    upl_size = round_page_64(nbytes + upl_start_align_offset);

    ASSERT3U(zp->z_size, ==, ubc_getsize(vp));

    ASSERT3S(upl_size, <=, MAX_UPL_SIZE_BYTES);
    ASSERT3S(upl_size, >, 0);

    const off_t eof_page = trunc_page_64(zp->z_size) / PAGE_SIZE_64;

    dprintf("ZFS: %s:%d uiooff %llu sz %llu (pagesst %llu pgs %lld) EOF byte %lld eofpg %lld file %s \n",
	__func__, __LINE__,
	uio_offset(uio), nbytes, upl_start / PAGE_SIZE_64, upl_size / PAGE_SIZE_64,
	zp->z_size, eof_page, filename);

	 /*
	  * take a snapshot of the mapped state
	  */
	int mapped = spl_ubc_is_mapped(vp, NULL);

	/*
	 * We lock against zfs_vnops_pagein() for this file, as it may
	 * be trying to page in from the current file, which was
	 * mmap()ed at some point in the past (and may still be
	 * mmap()ed).
	 *
	 * We also lock against other writers to the same file,
	 * and new callers of zfs_vnop_mmap() or zfs_vnop_mnomap(),
	 * since those may update the file as well.
	 *
	 * While this penalizes writes to a file that has been mmap()ed,
	 * we can guarantee that whole zfs_write() updates or whole pageins
	 * complete, rather than interleaving them.
	 *
	 * Finally, we also lock against zfs_vnop_pageoutv2() and
	 * zfs_vnop_pageout() to this file.
	 */

	boolean_t need_release = B_FALSE;
	boolean_t need_upgrade = B_FALSE;
	if (mapped > 0 && !rw_write_held(&zp->z_map_lock)) {
		ASSERT(!MUTEX_HELD(&zp->z_lock));
		uint64_t tries = z_map_rw_lock(zp, &need_release, &need_upgrade, __func__);
		VNOPS_STAT_INCR(update_pages_want_lock, tries);
	} else if (mapped > 0) {
		ASSERT(!MUTEX_HELD(&zp->z_lock));
		printf("ZFS: %s: already holds z_map_lock\n", __func__);
	}

	/*
	 * Loop through the pages, looking for holes to fill.
	 */

	error = ubc_fill_holes_in_range(vp, upl_start, upl_start + upl_size, B_FALSE);
	if (error != 0) {
		printf("ZFS: %s: fill_holes_in_range error %d range [%lld, +%lld], filename %s\n",
		    __func__, error, upl_start, upl_size, filename);
		goto drop_and_exit;
	}

	/* There should be no holes in the range now */

	ASSERT3S(nbytes, <=, INT_MAX);
	ASSERT3S(nbytes, >, 0);

	int xfer_resid = nbytes;

	boolean_t unset_syncer = B_FALSE;
	if (spl_ubc_is_mapped(vp, NULL)) {
		ASSERT3P(zp->z_syncer_active, !=, curthread);
		mutex_enter(&zp->z_ubc_msync_lock);
		while (zp->z_syncer_active != NULL && zp->z_syncer_active != curthread) {
			cv_wait(&zp->z_ubc_msync_cv, &zp->z_ubc_msync_lock);
		}
		ASSERT3S(zp->z_syncer_active, ==, NULL);
		zp->z_syncer_active = curthread;
		mutex_exit(&zp->z_ubc_msync_lock);
		unset_syncer = B_TRUE;
	}

	error = cluster_copy_ubc_data(vp, uio, &xfer_resid, 0);

	if (unset_syncer) {
		ASSERT3S(zp->z_syncer_active, ==, curthread);
		mutex_enter(&zp->z_ubc_msync_lock);
		zp->z_syncer_active = NULL;
		cv_signal(&zp->z_ubc_msync_cv);
		mutex_exit(&zp->z_ubc_msync_lock);
	}

	if (error == 0) {
		if (xfer_resid != 0) {
			printf("ZFS: %s:%d nonzero xfer_resid %d ~ nbytes %lld, uioffs in %lld now %lld, file %s\n",
			    __func__, __LINE__, xfer_resid, nbytes, orig_offset, uio_offset(uio), filename);
		} else {
			xfer_resid = 0;
		}
		VNOPS_STAT_INCR(update_pages, nbytes - xfer_resid);
	}

drop_and_exit:

	/* release locks as necessary */
	z_map_drop_lock(zp, &need_release, &need_upgrade);

	ASSERT3S(error, ==, 0);
}

/* OSX UBC-aware implementation of zfs_read and mappedread follows */

/*
 * read bytes from file vp into a hole in a upl.
 *
 * 1. create a upl running from foffset
 *    with size dtermined by page_hole_start, page_hole_end.
 *
 * 2. map the UPL to user space
 *
 * 3. dmu_read into the mapped UPL
 *
 * 4. commit (or on error abort) the UPL
 */

static int
fill_hole(vnode_t *vp, const off_t foffset,
    int page_hole_start, int page_hole_end, const char *filename,
    boolean_t o_will_mod)
{
	ASSERT3S(page_hole_end - page_hole_start, >, 0);
	ASSERT3S(page_hole_end, >, 0);
	const int upl_pages = page_hole_end - page_hole_start;
	const off_t upl_size = (off_t)upl_pages * PAGE_SIZE_64;
	ASSERT3S(upl_size, >=, PAGE_SIZE_64);
	const off_t upl_start = foffset + (page_hole_start * PAGE_SIZE_64);
	upl_t upl;
	upl_page_info_t *pl = NULL;

	znode_t *zp = VTOZ(vp);
	VERIFY3P(zp, !=, NULL);
	VERIFY3P(zp->z_zfsvfs, !=, NULL);
	VERIFY3P(zp->z_sa_hdl, !=, NULL);

	ASSERT3S(upl_start, <=, zp->z_size);

	int err = 0;

	int upl_flags = UPL_UBC_PAGEIN | UPL_RET_ONLY_ABSENT;

	err = ubc_create_upl(vp, upl_start, upl_size, &upl, &pl, upl_flags);

	if (err != KERN_SUCCESS) {
		printf("ZFS: %s:%d failed to create upl: err %d flags %d for file %s\n",
		    __func__, __LINE__, err, upl_flags, filename);
		return (err);
	}

	for (int pg = 0; pg < upl_pages; pg++) {
		if (upl_valid_page(pl, pg)) {
			printf("ZFS: %s:%d pg %d of (upl_size = %lld, upl_start = %lld) of file %s is VALID"
			    " upl_flags %d, is_mapped %d, is_mapped_writable %d\n",
			    __func__, __LINE__, pg, upl_size, upl_start, filename,
			    upl_flags, spl_ubc_is_mapped(vp, NULL),
			    spl_ubc_is_mapped_writable(vp));
			(void) ubc_upl_abort(upl, UPL_ABORT_RESTART | UPL_ABORT_FREE_ON_EMPTY);
			return (EAGAIN);
		}
		if (upl_dirty_page(pl, pg)) {
			printf("ZFS: %s%d: pg %d of (upl_size %lld upl_start %lld) file %s is DIRTY"
			    " upl_flags %d, is_mapped %d, is_mapped_writable %d\n",
			    __func__, __LINE__, pg, upl_size, upl_start, filename,
			    upl_flags, spl_ubc_is_mapped(vp, NULL),
			    spl_ubc_is_mapped_writable(vp));
			(void) ubc_upl_abort(upl, UPL_ABORT_RESTART | UPL_ABORT_FREE_ON_EMPTY);
			return (EAGAIN);
		}
	}

	vm_offset_t vaddr = 0;
	err = ubc_upl_map(upl, &vaddr);
	if (err != KERN_SUCCESS) {
		printf("ZFS: %s:%d failed to ubc_map_upl: err %d, mapped %d\n", __func__, __LINE__,
		    err, spl_ubc_is_mapped(vp, NULL));
		(void) ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR);
		return (err);
	}

	if (spl_ubc_is_mapped(vp, NULL))
		zp->z_mod_while_mapped = 1;

	err = dmu_read_dbuf(sa_get_db(zp->z_sa_hdl),
	    upl_start, upl_size, (caddr_t)vaddr, DMU_READ_PREFETCH);

	if (err != 0) {
		printf("ZFS: %s:%d dmu_read error %d reading %llu bytes offs %llu from file %s\n",
		    __func__, __LINE__, err, upl_size, upl_start, filename);
		(void) ubc_upl_unmap(upl);
		(void) ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR | UPL_ABORT_DUMP_PAGES);
		if (err == EAGAIN) {
			printf("ZFS: %s: WARNING converting EAGAIN from dmu_read into EIO\n", __func__);
			err = EIO;
		}
		return (err);
	}

	err = ubc_upl_unmap(upl);
	if (err != 0) {
		printf("ZFS: %s: error %d unmapping upl\n", __func__, err);
		(void) ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR | UPL_ABORT_DUMP_PAGES);
		return (err);
	}

	ASSERT3S(zp->z_size, ==, ubc_getsize(vp));
	if (zp->z_size < round_page_64(upl_start + upl_size)) {
		dprintf("ZFS: %s:%d: file size %lld is inside upl [%lld..%lld],"
		    " NOT ZEROING tail of block, file %s\n", __func__, __LINE__,
		    zp->z_size, upl_start, upl_start + upl_size,
		    zp->z_name_cache);
	}
	ASSERT3U(upl_size, <=, INT_MAX);
	ASSERT3U(upl_size, >, 0);

	kern_return_t commit_ret = ubc_upl_commit(upl);

	if (commit_ret != KERN_SUCCESS) {
		printf("ZFS: %s: error %d committing range [0, %d] (vs %lld) for file %s\n",
		    __func__, commit_ret, (int)upl_size, upl_size, filename);
		return (commit_ret);
	}

	return (err);
}

/*
 * Read bytes from a range of the specified file into supplied uio
 *
 * 0. hold the dnode
 * 1. create a UPL covering the range as with dmu_read_uio
 * 2. fill in ranges of the non-resident pages with data from
 *    the DMU layer
 * 3. commit the UPL
 * 4. cluster_copy_ubc_data(vp, uio, &numbytes, 0);
 * 5. complain if &resid is not 0
 * 6. release the dnode, return
 */

static int
fill_holes_in_range(vnode_t *vp, const off_t upl_file_offset, const size_t upl_size, boolean_t o_will_mod)
{

	/* the range should be page aligned */
	ASSERT3S((upl_file_offset % PAGE_SIZE), ==, 0);
	ASSERT3S((upl_size % PAGE_SIZE), ==, 0);
	ASSERT3S(upl_size, >, 0);
	ASSERT3S(upl_size, <=, MAX_UPL_SIZE_BYTES);

	znode_t *zp = VTOZ(vp);
	const char *filename = zp->z_name_cache;
	int err = 0;
	upl_t upl = NULL;
	upl_page_info_t *pl = NULL;

	/* the sizes should be identical */
	ASSERT3S(zp->z_size, ==, ubc_getsize(vp));
	ASSERT3S(upl_file_offset, <=, zp->z_size);

	const off_t upl_first_page = trunc_page_64(upl_file_offset) / PAGE_SIZE_64;
	const off_t upl_last_page = round_page_64(upl_file_offset + upl_size) / PAGE_SIZE_64;
	const off_t eof_page = trunc_page_64(zp->z_size) / PAGE_SIZE_64;

	if (upl_last_page >= eof_page) {
		dprintf("ZFS: %s:%d: fill @ %lld sz %ld bytes"
		    " pages [%lld, %lld] will read eof @ %lld / %lld\n",
		    __func__, __LINE__,
		    upl_file_offset, upl_size,
		    upl_first_page, upl_last_page,
		    zp->z_size, eof_page);
	}

	uint64_t present_pages_skipped = 0, absent_pages_filled = 0;
	off_t cur_upl_file_offset = upl_file_offset;
	size_t cur_upl_size = upl_size;

	/* see if we can skip over a few pages at the start */
	int skip_bytes = 0;
	int rop_retval = ubc_range_op(vp, cur_upl_file_offset, cur_upl_file_offset + cur_upl_size,
	    UPL_ROP_PRESENT, &skip_bytes);
	if (rop_retval != KERN_SUCCESS) {
		printf("ZFS: %s:%d: error %d from ubc_range_op(vp, %lld, %lld, UPL_ROP_PRESENT, *)"
		    " (skip bytes %d) for file %s\n", __func__, __LINE__, rop_retval,
		    cur_upl_file_offset, cur_upl_file_offset + cur_upl_size,
		    skip_bytes, zp->z_name_cache);
	} else if (skip_bytes > 0) {
		VNOPS_STAT_INCR(fill_holes_rop_present_bytes_skipped, skip_bytes);
		if (skip_bytes >= cur_upl_size) {
			VNOPS_STAT_BUMP(fill_holes_rop_present_total_skip);
			return (0);
		}
		cur_upl_file_offset += skip_bytes;
		cur_upl_size -= skip_bytes;
	}

	/*
	 * loop around, create a upl to find holes, exit loop when no
	 * holes are found.
	 *
	 * this loop is linear with the number of holes.
	 */

	for (int i = 0; err == 0 && cur_upl_size > 0; i++) {
		ASSERT3P(upl, ==, NULL);
		ASSERT3P(pl, ==, NULL);
		pl = NULL;
		upl = NULL;

		if (cur_upl_size <= 0)
			break;

		if (cur_upl_file_offset > zp->z_size) {
			printf("ZFS: %s:%d: cur upl foff %lld starts past %lld (pass %d, args %lld %ld)\n",
			    __func__, __LINE__, cur_upl_file_offset, zp->z_size, i,
			    upl_file_offset, upl_size);
			break;
		}

		ASSERT3S(err, ==, 0);

		int uplcflags = UPL_FILE_IO | UPL_SET_LITE;

		err = ubc_create_upl(vp, cur_upl_file_offset, cur_upl_size, &upl, &pl, uplcflags);


		if (err != KERN_SUCCESS || (upl == NULL)) {
			printf("ZFS: %s: failed to create upl: err %d (pass %d, curoff %lld,"
			    " cursz %ld, file %s)\n",
			    __func__, err, i, cur_upl_file_offset, cur_upl_size, filename);
			return (EIO);
		} else {
			ASSERT3S(err, ==, 0);
			err = 0;
		}

		const int upl_num_pages = round_page_64(cur_upl_size) / PAGE_SIZE_64;
		ASSERT3S(upl_num_pages, >, 0);
		ASSERT3S(upl_num_pages, <=, MAX_UPL_SIZE_BYTES/PAGE_SIZE_64);

		int page_index = 0, page_index_hole_start, page_index_hole_end;

		/*
		 * Loop until we find a hole, or reach the end of the UPL.
		 * If we find a hole, we fill it, then exit the loop.
		 * We also exit the loop on error.
		 */

		while (page_index < upl_num_pages && err == 0) {
			VERIFY3P(upl, !=, NULL);
			VERIFY3P(pl, !=, NULL);
			if (upl_valid_page(pl, page_index)) {
				page_index++;
				/* don't count pages not present during first pass */
				if (i == 0) present_pages_skipped++;
				continue;
			} else if (upl_dirty_page(pl, page_index)) {
				/* don't count dirty pages during first pass either */
				if (i == 0) present_pages_skipped++;
				printf("ZFS: %s:%d: skipping DIRTY,!VALID page %d in range"
				    " [off %lld len %ld] of file %s uplcflags %d"
				    " mapped %d mapped_write %d\n", __func__, __LINE__,
				    page_index, cur_upl_file_offset, cur_upl_size,
				    zp->z_name_cache, uplcflags,
				    spl_ubc_is_mapped(vp, NULL),
				    spl_ubc_is_mapped_writable(vp));
				page_index++;
				continue;
			}
			/* this is a hole.  find its end */
			page_index_hole_start = page_index;
			for (page_index_hole_end = page_index + 1;
			     page_index_hole_end < upl_num_pages;
			     page_index_hole_end++) {
				if (upl_valid_page(pl, page_index_hole_end) ||
				    upl_dirty_page(pl, page_index_hole_end))
					break;
			}

			/*
			 *since we are calling fill_hole and it creates a UPL within
			 * the pagerange of our upl, we need to release our upl
			 * or there will be a hang when one of its pages is touched
			 * e.g. by dmu_read's bzero.
			 *
			 * upl_abort(upl, ... | UPL_FREE_ON_EMPTY) does this.
			 *
			 * maybe we will chose to add UPL_ABORT_REFERENCE, which
			 * boosts the presesnt pages in the page LRU, but looping
			 * will in any event bring them back in
			 */

			err = ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
			if (err != 0) {
				printf("ZFS: %s: upl_abort failed (err: %d, pass: %d, file: %s)\n",
				    __func__, err, i, filename);
				upl = NULL;
				pl = NULL;
				break;
			}

			upl = NULL;
			pl = NULL;

			/*
			 * the hole runs from page_index_hole_start to ..._end
			 * fill hole makes a sub upl and commits within that
			 */

			err = fill_hole(vp, cur_upl_file_offset, page_index_hole_start, page_index_hole_end,
			    filename, o_will_mod);

			if (err == EAGAIN) {
				printf("ZFS: %s:%d: EAGAIN curoff %lld pist %d pien %d pass %d file %s\n",
				    __func__, __LINE__, cur_upl_file_offset,
				    page_index_hole_start, page_index_hole_end, i, filename);
				break;
			}
			if (err != 0) {
				printf("ZFS: %s:%d fill_hole failed with err %d\n", __func__, __LINE__, err);
				break;
			}

			/* count the absent pages that fill_page filled */
			absent_pages_filled += (page_index_hole_end - page_index_hole_start);

			cur_upl_file_offset += (page_index_hole_end - page_index_hole_start) * PAGE_SIZE_64;
			cur_upl_size -= (page_index_hole_end - page_index_hole_start) * PAGE_SIZE_64;
			page_index = page_index_hole_end;

			break;
		}

		/* out of while loop, still in for loop */
		/* the UPL may either be NULL or still alive (NULL it below) */

		if (page_index >= upl_num_pages) {
			/* no holes left */
			if (upl != NULL) {
				err = ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
				if (err != 0) {
					printf("ZFS: %s: no holes left, but upl_abort failed"
					    " with error %d, file %s\n",
					    __func__, err, filename);
				}
				upl = NULL;
				pl = NULL;
			}
			break;
		}

		if (err == EAGAIN && i < 16384)
			continue;

		if (err != 0 || i >= 16384) {
			// 16k is the maximum number of UPL pages possible, so
			// we should only see about 8k holes; this could be improved
			// after some experience is gained
			if (err == 0) {
				printf("ZFS: %s: aborting hole-filling loop after %d passes, file: %s\n",
				    __func__, i, filename);
				err = EIO;
			} else {
				printf("ZFS: %s: error %d in hole-filling loop after %d passes, file %s\n",
				    __func__, err, i, filename);
			}
			if (upl != NULL) {
				int error = ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
				if (error != 0) {
					printf("ZFS: %s: while aborting loop, upl_abort error %d\n",
					    __func__, error);
				}
				upl = NULL;
				pl = NULL;
			}
			break;
		}

		if (upl != NULL) {
			printf("ZFS: %s: WOAH: why are we here? Aborting non-NULL UPL.\n", __func__);
			int error = ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
			if (error != 0) {
				printf("ZFS: %s in woah, error %d aborting upl for file %s\n",
				    __func__, error, filename);
				break;
			}
			upl = NULL;
			pl = NULL;
			continue;
		}
	}

	ASSERT3P(upl, ==, NULL);
	ASSERT3P(pl, ==, NULL);

	VNOPS_STAT_INCR(fill_holes_upl_present_pages_skipped, present_pages_skipped);
	VNOPS_STAT_INCR(fill_holes_upl_absent_pages_filled, absent_pages_filled);

	if (err == 0) {
		if (absent_pages_filled == 0 && upl_size > 0)
			VNOPS_STAT_BUMP(fill_holes_ubc_satisfied_all);
	}

	return (err);
}

int
ubc_fill_holes_in_range(vnode_t *vp, off_t start_byte, off_t end_byte, boolean_t will_mod)
{

	ASSERT3S(start_byte, <=, end_byte);
	ASSERT3S(end_byte, <=, round_page_64(ubc_getsize(vp)));
	ASSERT3S(start_byte, <=, round_page_64(ubc_getsize(vp)));

	const off_t aligned_file_offset = trunc_page_64(start_byte);
	const off_t aligned_file_end = round_page_64(end_byte);
	const size_t total_size = aligned_file_end - aligned_file_offset;

	ASSERT3S(total_size, >, 0);

	off_t cur_off = aligned_file_offset;
	off_t size_done = 0;

	for (int i = 0; size_done < total_size; i++) {
		const off_t todo = total_size - size_done;
		const off_t cur_size = MIN(todo, MAX_UPL_SIZE_BYTES);

		int err = fill_holes_in_range(vp, cur_off, cur_size, will_mod);
		if (err) {
			printf("ZFS: %s:%d: error %d from fill_holes_in_range(vp, %lld, %lld) todo %lld iter %d\n",
			    __func__, __LINE__, err, cur_off, cur_size, todo, i);
			return (err);
		}
		cur_off += cur_size;
		size_done += cur_size;
	}
	return (0);
}

int
ubc_refresh_range(vnode_t *vp, off_t start_byte, off_t end_byte)
{

#ifdef __UNDEFINED__
	znode_t *zp = VTOZ(vp);
	const char *filename = zp->z_name_cache;

#if 0
	int inval_err = ubc_invalidate_range(vp, start_byte, end_byte);
	if (inval_err) {
		printf("ZFS: %s: error from ubc_invalidate_range [%lld, %lld], file %s\n",
		    __func__, start_byte, end_byte, filename);
	}
#endif

	int fill_err = ubc_fill_holes_in_range(vp, start_byte, end_byte, B_FALSE);
	if (fill_err) {
		printf("ZFS: %s: error filling holes [%lld, %lld], file %s\n",
		    __func__, start_byte, end_byte, filename);
	}

#if 0
	if (inval_err != 0 || fill_err != 0) {
		return (1);
	}
#else
	if (fill_err != 0) {
		return (1);
	}
#endif
#endif //__UNDEFINED__

	return (0);
}

static int
mappedread_new(vnode_t *vp, int arg_bytes, struct uio *uio)
{
	znode_t *zp = VTOZ(vp);
        VERIFY3P(zp, !=, NULL);
        VERIFY3P(zp->z_zfsvfs, !=, NULL);
        VERIFY3P(zp->z_zfsvfs->z_os, !=, NULL);

	ASSERT3S(arg_bytes, <=, MAX_UPL_SIZE_BYTES);

	/*
	 * we are called under z_map_lock to make sure that
	 * other pager activity or writes don't interfere with our
	 * manipulation of the vnode pager object
	 */
	ASSERT(rw_write_held(&zp->z_map_lock));

	objset_t *os = zp->z_zfsvfs->z_os;
        uint64_t object = zp->z_id;
        const char *filename = zp->z_name_cache;

	/* make sure the file doesn't go away */
        dnode_t *dn;
	int err = dnode_hold(os, object, FTAG, &dn);
        if (err != 0) {
                printf("ZFS: %s: unable to dnode_hold %s\n",
                    __func__, filename);
		return (EIO);
        }

	/* useful variables and sanity checking */
        const uint64_t inbytes = arg_bytes;
        int64_t inbytes_remaining = inbytes;
        const size_t filesize = zp->z_size;
        const size_t usize = ubc_getsize(vp);

	ASSERT3U(filesize, ==, usize);
        ASSERT3S(inbytes_remaining, >, 0);
        ASSERT3S(uio_offset(uio), <=, filesize);
        ASSERT3S(ubc_getsize(vp), ==, filesize);

        const user_ssize_t orig_resid = uio_resid(uio);
        const off_t orig_offset = uio_offset(uio);

        ASSERT3S(orig_resid, >=, 0);
        ASSERT3S(inbytes_remaining, <=, orig_resid + orig_offset);
        const int MAX_UPL_SIZE_BYTES = 64*1024*1024;
        ASSERT3S(inbytes_remaining, <=, MAX_UPL_SIZE_BYTES);

        /* check against file size */
        if (orig_resid + orig_offset > filesize &&
            inbytes_remaining > filesize) {
                const char *fn = vnode_getname(vp);
                const char *pn = (fn == NULL) ? "<NULL>" : fn;
                printf("ZFS: %s either orig_nbytes(%lld) or"
                    " [orig_resid(%lld)+orig_offset(%lld)](%lld) >"
                    " filesize(%lu)"
                    " [vnode name: %s cache name: %s]\n",
                    __func__, inbytes_remaining,
                    orig_resid, orig_offset, orig_resid + orig_offset,
                    filesize, pn, filename);
        }

        ASSERT3S(orig_resid + orig_offset, >=, inbytes_remaining);
        ASSERT3S(inbytes, <=, orig_resid);

	/* The file range we are interested in runs from
	 * the uio offset to the uio offset plus inbytes.
	 * There is no guaranteed alignment.
         *
	 * The upl is a page-aligned range enclosing that
	 * file range.
	 *
	 * Thanks to our caller, inbytes does not go past
	 * the end of the file or the end of the uio_resid,
	 * however either may be non-page-aligned, so our
	 * UPL's final page may be partial.
	 */

	// where in the file the UPL starts, page aligned bytes
	const off_t upl_file_offset = trunc_page_64(orig_offset);
	const off_t upl_sz_vs_fsize = orig_offset - upl_file_offset;
	// size of the UPL, page-aligned bytes
	const size_t upl_size = round_page_64(inbytes + upl_sz_vs_fsize);

	ASSERT3S(upl_file_offset + upl_size, <=, round_page_64(zp->z_size));
	ASSERT3S(upl_size, >=, PAGE_SIZE_64);
	ASSERT3S(upl_size, >=, inbytes);

	err = fill_holes_in_range(vp, upl_file_offset, upl_size, B_FALSE);

	if (err != 0) {
		printf("ZFS: %s: fill_holes_in_range (%lld, %ld) error %d file %s\n",
		    __func__, upl_file_offset, upl_size, err, filename);
	}

	/* now we copy from the vnode pager object to the uio */

	int cache_resid = arg_bytes;
	if (err == 0) {
		boolean_t unset_syncer = B_FALSE;
		if (spl_ubc_is_mapped(vp, NULL)) {
			ASSERT3P(zp->z_syncer_active, !=, curthread);
			mutex_enter(&zp->z_ubc_msync_lock);
			while (zp->z_syncer_active != NULL && zp->z_syncer_active != curthread)
				cv_wait(&zp->z_ubc_msync_cv, &zp->z_ubc_msync_lock);
			ASSERT3S(zp->z_syncer_active, ==, NULL);
			zp->z_syncer_active = curthread;
			mutex_exit(&zp->z_ubc_msync_lock);
			unset_syncer = B_TRUE;
		}

		err = cluster_copy_ubc_data(vp, uio, &cache_resid, 0);

		if (unset_syncer) {
			ASSERT3P(zp->z_syncer_active, ==, curthread);
			mutex_enter(&zp->z_ubc_msync_lock);
			zp->z_syncer_active = NULL;
			cv_signal(&zp->z_ubc_msync_cv);
			mutex_exit(&zp->z_ubc_msync_lock);
		}
		if (err != 0) {
			printf("ZFS: %s: cluster_copy_ubc_data returned error %d,"
			    " cache_resid now %d, arg_bytes was %d orig offset %lld filname %s\n",
			    __func__, err, cache_resid, arg_bytes, orig_offset, filename);
		} else if (cache_resid != 0) {
			printf("ZFS: %s: cluster_copy_ubc_data short read,"
			    " arg_bytes was %d cache_resid now %d orig offset %lld filename %s\n",
			    __func__, arg_bytes, cache_resid, orig_offset, filename);
		}
	}

	dnode_rele(dn, FTAG);

	return (err);
}

offset_t zfs_read_chunk_size = MAX_UPL_TRANSFER * PAGE_SIZE; /* Tunable */

/*
 * Read bytes from specified file into supplied buffer.
 *
 *	IN:	vp	- vnode of file to be read from.
 *		uio	- structure supplying read location, range info,
 *			  and return buffer.
 *		ioflag	- SYNC flags; used to provide FRSYNC semantics.
 *		cr	- credentials of caller.
 *		ct	- caller context
 *
 *	OUT:	uio	- updated offset and range, buffer filled.
 *
 *	RETURN:	0 on success, error code on failure.
 *
 * Side Effects:
 *	vp - atime updated if byte count > 0
 */
/* ARGSUSED */
int
zfs_read(vnode_t *vp, uio_t *uio, int ioflag, cred_t *cr, caller_context_t *ct)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	objset_t	*os;
	ssize_t		n, nbytes;
	int		error = 0;
	rl_t		*rl;

	VNOPS_STAT_BUMP(zfs_read_calls);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	const size_t initial_z_size = zp->z_size;
	const size_t initial_u_size = ubc_getsize(vp);
	ASSERT3U(initial_z_size, ==, initial_u_size);

	os = zfsvfs->z_os;

	if (zp->z_pflags & ZFS_AV_QUARANTINED) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EACCES));
	}

	/*
	 * Validate file offset
	 */
	if (uio_offset(uio) < (offset_t)0) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EINVAL));
	}

	/*
	 * Fasttrack empty reads
	 */
	if (uio_resid(uio) == 0) {
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	/*
	 * Note: In Mac OS X, mandatory lock checking occurs up in VFS layer.
	 * Check for mandatory locks
	 */
#ifndef __APPLE__
	if (MANDMODE(zp->z_mode)) {
		if (error = chklock(vp, FREAD,
                            uio_offset(uio), uio_resid(uio),
                            uio->uio_fmode, ct)) {
			ZFS_EXIT(zfsvfs);
            return (SET_ERROR(EAGAIN));
		}
	}
#endif

#ifndef __APPLE__
	/*
	 * If we're in FRSYNC mode, sync out this znode before reading it.
	 */
	if (zfsvfs->z_log &&
	    (ioflag & FRSYNC || zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS))
		zil_commit(zfsvfs->z_log, zp->z_id);
#else
	/*
	 * if we are in ZFS_SYNC_ALWAYS or we are in FDSYNC or FSYNC,
	 * sync out this znode before readng it.
	 */
	if (zfsvfs->z_log &&
	    zfsvfs->z_os->os_sync != ZFS_SYNC_DISABLED &&
	    (ioflag & (FSYNC | FDSYNC) || zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS) &&
	    !spl_ubc_is_mapped(vp, NULL) &&
	    ubc_getsize(vp) != 0 &&
	    is_file_clean(vp, ubc_getsize(vp))) {
		// remember that is_file_clean returns EINVAL if there are dirty pages
		boolean_t sync = (ioflag & (/*FRSYNC |*/ FDSYNC | FSYNC)) ||
		    zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS;
		if (sync) {
			off_t ubcsize = ubc_getsize(vp);
			ASSERT3S(zp->z_size, ==, ubcsize);
			off_t resid_off = 0;
			boolean_t need_release = B_FALSE, need_upgrade = B_FALSE;
                        uint64_t tries = z_map_rw_lock(zp, &need_release, &need_upgrade, __func__);
			int flags = UBC_PUSHDIRTY | UBC_SYNC;
			if (spl_ubc_is_mapped(vp, NULL))
				flags = UBC_PUSHDIRTY | UBC_SYNC;
			int retval = zfs_ubc_msync(vp, 0, ubcsize, &resid_off, flags);
			z_map_drop_lock(zp, &need_release, &need_upgrade);
			ASSERT3S(tries, <=, 2);
			ASSERT3S(retval, ==, 0);
			if (retval != 0)
				ASSERT3S(resid_off, ==, ubcsize);
			zil_commit(zfsvfs->z_log, zp->z_id);
			VNOPS_STAT_BUMP(zfs_read_clean_on_read);
		}

	}
#endif

	/*
	 * Lock the range against changes.
	 */
	rl = zfs_range_lock(zp, trunc_page_64(uio_offset(uio)), round_page_64(uio_resid(uio)), RL_READER);

	/*
	 * If we are reading past end-of-file we can skip
	 * to the end; but we might still need to set atime.
	 */

	if (uio_offset(uio) >= zp->z_size) {
		// can we?: think about truncation and pages
		ASSERT3S(zp->z_size, ==, ubc_getsize(vp));
		error = 0;
		goto out;
	}

	ASSERT3S(uio_offset(uio), <, zp->z_size); // at least one byte will be read
	n = MIN(uio_resid(uio), zp->z_size - uio_offset(uio));

	while (n > 0) {
		nbytes = MIN(n, zfs_read_chunk_size -
                     P2PHASE(uio_offset(uio), zfs_read_chunk_size));

		boolean_t need_release = B_FALSE;
		boolean_t need_upgrade = B_FALSE;
		uint64_t tries = z_map_rw_lock(zp, &need_release, &need_upgrade, __func__);
		if (tries > 0)
			VNOPS_STAT_INCR(mappedread_lock_tries, tries);
		boolean_t was_mapped = spl_ubc_is_mapped(vp, NULL);
		error = mappedread_new(vp, nbytes, uio);
		z_map_drop_lock(zp, &need_release, &need_upgrade);
		ASSERT3S(error, ==, 0);
		if (error == 0 && nbytes > 0) {
			if (was_mapped)
				VNOPS_STAT_INCR(zfs_read_mappedread_mapped_file_bytes, nbytes);
			else
				VNOPS_STAT_INCR(zfs_read_mappedread_unmapped_file_bytes, nbytes);
		}

		if (error == ERANGE) {
			/* return short read */
			error = 0;
			break;
		}

		if (error) {
			/* convert checksum errors into IO errors */
			if (error == ECKSUM)
				error = SET_ERROR(EIO);
			break;
		}

		n -= nbytes;
	}

	ASSERT3U(initial_z_size, ==, zp->z_size);
	ASSERT3U(initial_u_size, ==, ubc_getsize(vp));
out:
	zfs_range_unlock(rl);

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
	ZFS_EXIT(zfsvfs);

    if (error) dprintf("zfs_read returning error %d\n", error);
	return (error);
}

static off_t
zfs_safe_dbuf_write_size(znode_t *zp, uio_t *uio, off_t length)
{

	/*
	 * modify logic from dmu_buf_hold_array_by_dnode() which
	 * turns the printf into a panic
	 */

	off_t offset = uio_offset(uio);
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)sa_get_db(zp->z_sa_hdl);
	dnode_t *dn;
	uint64_t nblks;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	if (dn->dn_datablkshift) {
		int blkshift = dn->dn_datablkshift;
		nblks = (P2ROUNDUP(offset + length, 1ULL << blkshift) -
		    P2ALIGN(offset, 1ULL << blkshift)) >> blkshift;
	} else {
		if (offset + length > dn->dn_datablksz) {
			int64_t safe_len = dn->dn_datablksz - offset;
			if (safe_len > 0) {
				dprintf("ZFS: %s:%d (would be) accessing past end of object "
				    "(size=%u access=%llu+%llu), try using %lld instead, file %s\n",
				    __func__, __LINE__,
				    dn->dn_datablksz,
				    (longlong_t)offset, (longlong_t)length,
				    safe_len, zp->z_name_cache);
			}
			else {
				dprintf("ZFS: %s:%d would access past end of object (size=%u,"
				    " access %llu+%llu), AND safe_len is %lld, so returning 0,"
				    " file %s\n",
				    __func__, __LINE__,
				    dn->dn_datablksz,
				    (longlong_t)offset, (longlong_t)length,
				    safe_len, zp->z_name_cache);
				safe_len = 0;
			}
			rw_exit(&dn->dn_struct_rwlock);
			DB_DNODE_EXIT(db);
			return (safe_len);
		}
		nblks = 1;
	}
	rw_exit(&dn->dn_struct_rwlock);
	DB_DNODE_EXIT(db);
	ASSERT3S(nblks, >, 0);
	return (length);
}

/*
 * Structure and function to do a ubc_msync in a taskq task
 *
 * We can't ubc_msync in the zfs_write context without risking
 * a zfs_panic_recover for bluster_pageout writing past the end
 * of the object.
 *
 * We also have to ZFS_ENTER etc, and so the helper function is
 * needed in order for those macros to return an int result; the
 * taskq function must return nothing.
 */

boolean_t
dmu_write_is_safe(znode_t *zp, off_t woff, off_t end_range)
{
	/* debug the past-end-of-file problem */
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)sa_get_db(zp->z_sa_hdl);
	dnode_t        *dn;

	boolean_t is_safe;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	rw_enter(&dn->dn_struct_rwlock, RW_READER);

	if (!dn->dn_datablkshift && end_range > dn->dn_datablksz) {
		is_safe = B_FALSE;
		ASSERT3S(dn->dn_datablksz, ==, zp->z_blksz);
	} else {
		is_safe = B_TRUE;
	}

	rw_exit(&dn->dn_struct_rwlock);
	DB_DNODE_EXIT(db);

	return (is_safe);
}


int
dmu_write_wait_safe(znode_t *zp, off_t woff, off_t end_range)
{
	/* debug the past-end-of-file problem */
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)sa_get_db(zp->z_sa_hdl);
	dnode_t        *dn;
	vnode_t        *vp = ZTOV(zp);

	int error = 0;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	int i = 0;
	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	if (!dn->dn_datablkshift && end_range > dn->dn_datablksz) {
		hrtime_t ptime = 0;
		hrtime_t etime = gethrtime() + SEC2NSEC(60);
		uint32_t dsz   = dn->dn_datablksz;
		uint8_t  dshft = dn->dn_datablkshift;
		extern void IOSleep(unsigned milliseconds);
		extern void IODelay(unsigned microseconds);
		for (i = 0; end_range > dsz && !dshft; i++) {
			rw_exit(&dn->dn_struct_rwlock);
			DB_DNODE_EXIT(db);
			hrtime_t curtime = gethrtime();
			if (curtime > etime) {
				printf("%s:%d: could not safely msync file %s\n",
				    __func__, __LINE__, zp->z_name_cache);
				error = EIO;
				goto out;
			}
			if (zp->z_size < woff || ubc_getsize(vp) < woff) {
				ASSERT3S(zp->z_size, ==, ubc_getsize(vp));
				printf("ZFS: %s:%d: woff is %lld but z_size is smaller at %lld"
				    " (ubcsize %lld) for file %s, abandoning wait.\n",
				    __func__, __LINE__,
				    woff, zp->z_size, ubc_getsize(vp),
				    zp->z_name_cache);
				IOSleep(1);
				error = EIO;
				goto out;
			}
			if (ptime < curtime) {
				ptime = curtime + SEC2NSEC(1);
				printf("ZFS: %s:%d waiting to sync %lld to %lld,"
				    " dn->datablksz == %d z_datablksz %d (pass %d) z_size %lld"
				    " ubcsize %lld file %s\n",
				    __func__, __LINE__, woff, end_range,
				    dsz, zp->z_blksz, i, zp->z_size, ubc_getsize(vp), zp->z_name_cache);
			}
			if (i < 10000) {
				IODelay(1);
			} else {
				IOSleep(1);
			}
			DB_DNODE_ENTER(db);
			dn = DB_DNODE(db);
			rw_enter(&dn->dn_struct_rwlock, RW_READER);
			dsz   = dn->dn_datablksz;
			dshft = dn->dn_datablkshift;
		}
		printf("ZFS: %s:%d after %d now syncing file %s\n", __func__, __LINE__,
		    i, zp->z_name_cache);
	}
	rw_exit(&dn->dn_struct_rwlock);
	DB_DNODE_EXIT(db);

out:
	if (i > 0) { VNOPS_STAT_INCR(zfs_write_helper_iters, i); }

	return (error);
}

typedef struct sync_range {
	vnode_t  *vp;
	off_t     start;
	off_t     end;
	size_t    start_resid;
	boolean_t sync;
	boolean_t range_lock;
	boolean_t safety_check;
} sync_range_t;

static int
zfs_write_sync_range_helper(vnode_t *vp, off_t woff, off_t end_range,
    size_t start_resid, boolean_t do_sync, boolean_t range_lock, boolean_t safety_check)
{
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int       error = 0;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	rl_t *rl = NULL;

	if (range_lock) {
		/*
		 * wait until the range_lock in zfs_write is dropped,
		 * and protect against other sub-page activity
		 */
		rl = zfs_range_lock(zp, trunc_page_64(woff),
		    round_page_64(end_range), RL_WRITER);
	}

	if (safety_check) {
		error = dmu_write_wait_safe(zp, woff, end_range);
		printf("ZFS: %s:%d safety_check failed with error %d for file %s\n",
		    __func__, __LINE__, error, zp->z_name_cache);
		if (range_lock)
			zfs_range_unlock(rl);
		ZFS_EXIT(zfsvfs);
		return (EDEADLK);
	}

	off_t ubcsize = ubc_getsize(vp);
	off_t msync_resid = 0;

	if (range_lock) {
		/*
		 * ubc_msync may call down to pageoutv2, which will
		 * take this range lock
		 */
		zfs_range_unlock(rl);
	}
	int msync_flags = 0;

	if (!spl_ubc_is_mapped(vp, NULL)) {
		msync_flags |= UBC_PUSHDIRTY;
	} else {
		msync_flags |= UBC_PUSHDIRTY | UBC_SYNC;
	}
	if (do_sync) {
		msync_flags |= UBC_SYNC;
	}

	error = zfs_ubc_msync(vp, woff, end_range, &msync_resid, msync_flags);

	if (error != 0) {
		printf("ZFS: %s:%d: ubc_msync error %d msync_resid %lld"
		    " woff %lld start_resid %ld end_range %lld"
		    " ubcsize %lld msync_flasg 0x%x file %s\n",
		    __func__, __LINE__, error, msync_resid,
		    woff, start_resid, end_range,
		    ubcsize, msync_flags, zp->z_name_cache);
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

static void
zfs_write_sync_range(void *arg)
{
	sync_range_t *sync_range = arg;

	off_t     woff         = sync_range->start;
	off_t     end_range    = sync_range->end;
	size_t    start_resid  = sync_range->start_resid;
	vnode_t   *vp          = sync_range->vp;
	boolean_t do_sync      = sync_range->sync;
	boolean_t range_lock   = sync_range->range_lock;
	boolean_t safety_check = sync_range->safety_check;

	int error = zfs_write_sync_range_helper(vp, woff, end_range,
	    start_resid, do_sync, range_lock, safety_check);

	if (error != 0) {
		znode_t *zp = VTOZ(vp);
		if (do_sync) {
			zfs_panic_recover("%s:%d failed with error %d file %s",
			    __func__, __LINE__, error, zp->z_name_cache);
		} else {
			printf("ZFS: %s:%d sync failed, error %d file %s\n",
			    __func__, __LINE__, error, zp->z_name_cache);
		}
	}

	kmem_free(sync_range, sizeof(sync_range_t));
}

int
zfs_write_possibly_msync(znode_t *zp, off_t woff, off_t start_resid, int ioflag)
{
	vnode_t *vp = ZTOV(zp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	rl_t *rlock;
	int error = 0;

	ASSERT3S(start_resid, >, 0);
	const off_t aoff = trunc_page_64(woff);
	const off_t alen = round_page_64(start_resid);

	/*
	 * if this file is NOT now mmapped and there are dirty pages,
	 * in our range, then unless sync is disabled, if we are in
	 * sync read mode, then call zfs_ubc_msync.
	 */
	if (zfsvfs->z_log &&
	    (zfsvfs->z_os->os_sync != ZFS_SYNC_DISABLED) &&
	    (ioflag & (FSYNC|FDSYNC)) &&
	    !spl_ubc_is_mapped(vp, NULL) &&
	    ubc_getsize(vp) != 0 &&
	    (is_file_clean(vp, ubc_getsize(vp)))) {
		//remember that is_file_clean() reports EINVAL if there are dirty pages
		if (ioflag & FAPPEND) {
			rlock = zfs_range_lock(zp, 0, alen, RL_APPEND);
			woff = rlock->r_off;
		} else {
			rlock = zfs_range_lock(zp, aoff, alen, RL_WRITER);
		}
		if (rlock->r_len == UINT64_MAX) {
			off_t end_size = woff + start_resid;
			int  max_blksz = zfsvfs->z_max_blksz;
			dmu_tx_t *tx;
			woff = zp->z_size;
			tx = dmu_tx_create(zfsvfs->z_os);
			dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
			dmu_tx_hold_write(tx, zp->z_id, woff, start_resid);
			zfs_sa_upgrade_txholds(tx, zp);
			error = dmu_tx_assign(tx, TXG_WAIT);
			if (error) {
				dmu_tx_abort(tx);
				zfs_range_unlock(rlock);
				printf("ZFS: %s:%d: dmu_tx_assign error %d\n",
				    __func__, __LINE__, error);
				return(error);
			}
			uint64_t new_blksz;
			if (zp->z_blksz > max_blksz) {
				new_blksz = MIN(end_size,
				    1 << highbit64(zp->z_blksz));
			} else {
				new_blksz = MIN(end_size, max_blksz);
			}
			zfs_grow_blocksize(zp, new_blksz, tx);
			zfs_range_reduce(rlock, aoff, alen);
			dmu_tx_commit(tx);
		}
		off_t ubcsize = ubc_getsize(vp);
		ASSERT3S(ubcsize, ==, zp->z_size);
		if (ubcsize == 0 || woff >= ubcsize) {
			zfs_range_unlock(rlock);
			return (0);
		}
		boolean_t sync = (ioflag & (FSYNC | FDSYNC)) ||
		    zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS;

		if (sync && !spl_ubc_is_mapped(vp, NULL)) {
			ASSERT3S(zp->z_size, ==, ubcsize);
			ASSERT3S(ubcsize, >, 0);
			off_t resid_off = 0;
			const off_t aend = MIN(aoff + alen, ubcsize);
			ASSERT3S(aend, >, aoff);
			int msync_flags = UBC_PUSHDIRTY;
			if (spl_ubc_is_mapped(vp, NULL))
				msync_flags = UBC_PUSHDIRTY | UBC_SYNC;
			if (sync)
				msync_flags |= UBC_SYNC;
			zfs_range_unlock(rlock);
			int retval = zfs_ubc_msync(vp, aoff, aend, &resid_off, msync_flags);
			ASSERT3S(retval, ==, 0);
			if (retval != 0) {
				ASSERT3S(resid_off, ==, aend);
				error = retval;
				printf("ZFS: %s:%d: returning error %d for [%lld, %lld] flags %d file %s\n",
				    __func__, __LINE__, error, aoff, aend, msync_flags, zp->z_name_cache);
			} else {
				ASSERT3P(zp->z_sa_hdl, !=, NULL);
				if (sync == B_TRUE) {
					zil_commit(zfsvfs->z_log, zp->z_id);
					VNOPS_STAT_BUMP(zfs_write_clean_on_write_sync);
				}
				VNOPS_STAT_BUMP(zfs_write_clean_on_write);
			}
		} else {
			zfs_range_unlock(rlock);
		}

		rlock = NULL;
	}
	return (error);
}

int
zfs_write_maybe_extend_file(znode_t *zp, off_t woff, off_t start_resid, rl_t *rl)
{
	vnode_t *vp = ZTOV(zp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	dmu_tx_t *tx;
	int error = 0;

	/* extend the file if necessary */
	off_t end = woff + start_resid;

	if (rl->r_len == UINT64_MAX ||
	    (end > zp->z_blksz &&
		(!ISP2(zp->z_blksz || zp->z_blksz < zfsvfs->z_max_blksz))) ||
	    (end > zp->z_blksz && !dmu_write_is_safe(zp, woff, end))) {
		uint64_t newblksz = 0;
		const int max_blksz = zfsvfs->z_max_blksz;
		/* start a transaction */
		tx = dmu_tx_create(zfsvfs->z_os);
		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
		dmu_tx_hold_write(tx, zp->z_id, woff, start_resid);
		zfs_sa_upgrade_txholds(tx, zp);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			zfs_range_unlock(rl);
			printf("ZFS: %s:%d: dmu_tx_assign error %d\n",
			    __func__, __LINE__, error);
			return(error);
		}
		if (zp->z_blksz > max_blksz) {
			ASSERT(!ISP2(zp->z_blksz));
			newblksz = MIN(end, 1 << highbit64(zp->z_blksz));
		} else {
			newblksz = MIN(end, zp->z_zfsvfs->z_max_blksz);
		}
		if (ISP2(newblksz) && newblksz < max_blksz && newblksz != 1) {
			uint64_t new_new_blksz = newblksz + 1;
			dprintf("ZFS: %s:%d: bumping new_blksz from %lld to %lld, file %s\n",
			    __func__, __LINE__, newblksz, new_new_blksz, zp->z_name_cache);
			if (ISP2(new_new_blksz)) {
				printf("ZFS: %s:%d !ISP2(%lld) failed"
				    " (newblksz = %lld) file %s!\n",
				    __func__, __LINE__, new_new_blksz, newblksz,
				    zp->z_name_cache);
			}
			newblksz = new_new_blksz;
		}
		if (newblksz > zp->z_blksz)
			zfs_grow_blocksize(zp, newblksz, tx);

		zfs_range_reduce(rl, woff, start_resid);

		/*
		 * uint64_t pre = zp->z_size;
		 * zp->z_size = woff; ////////NO!
		 */

		ASSERT3S(zp->z_size, ==, ubc_getsize(vp));

		VERIFY(0 == sa_update(zp->z_sa_hdl, SA_ZPL_SIZE(zp->z_zfsvfs),
			&zp->z_size,
			sizeof (zp->z_size), tx));

		/* end the tx */
		dmu_tx_commit(tx);

		/*
		 * if (zp->z_size != ubc_getsize(vp)) {
		 * 	printf("ZFS: %s:%d: restoring z_size from %lld to ubc size %lld"
		 * 	    "(woff = %lld, end = %lld, pre = %lld) file %s\n",
		 * 	    __func__, __LINE__, zp->z_size, ubc_getsize(vp), woff, end, pre,
		 * 	    zp->z_name_cache);
		 * 	zp->z_size = ubc_getsize(vp);
		 * }
		 */
	}
	return (error);
}

static int
zfs_write_modify_write(vnode_t *vp, znode_t *zp, zfsvfs_t *zfsvfs, uio_t *uio,
    int ioflags,
    const off_t resid_at_break,
    const off_t recov_off,
    const off_t recov_off_page_offset,
    const int recov_resid_int,
    const off_t upl_f_off)
{

	/* Modify the page: "leave pages busy
	 * in the original object, if a page list
	 * structure was specified." (vm_pageout.c)
	 *
	 * So let's not supply a page list!
	 */
	upl_t mupl = NULL;
	kern_return_t muplret = ubc_create_upl(vp, upl_f_off, PAGE_SIZE, &mupl, NULL,
	    UPL_WILL_MODIFY);
	ASSERT3S(muplret, ==, KERN_SUCCESS);
	if (muplret != KERN_SUCCESS) {
		printf("ZFS: %s:%d: failed to create UPL error %d! foff %lld file %s\n",
		    __func__, __LINE__, muplret, upl_f_off, zp->z_name_cache);
		return (muplret);
	}
	int ccupl_ioresid = recov_resid_int;

	boolean_t unset_syncer = B_FALSE;
	if (spl_ubc_is_mapped(vp, NULL)) {
		mutex_enter(&zp->z_ubc_msync_lock);
		while (zp->z_syncer_active != NULL && zp->z_syncer_active != curthread)
			cv_wait(&zp->z_ubc_msync_cv, &zp->z_ubc_msync_lock);
		ASSERT3S(zp->z_syncer_active, ==, NULL);
		zp->z_syncer_active = curthread;
		mutex_exit(&zp->z_ubc_msync_lock);
		unset_syncer = B_TRUE;
	}

	int ccupl_retval = cluster_copy_upl_data(uio, mupl,
	    recov_off_page_offset, &ccupl_ioresid);

	if (unset_syncer) {
		ASSERT3S(zp->z_syncer_active, ==, curthread);
		mutex_enter(&zp->z_ubc_msync_lock);
		zp->z_syncer_active = NULL;
		cv_signal(&zp->z_ubc_msync_cv);
		mutex_exit(&zp->z_ubc_msync_lock);
	}

	if (ccupl_retval != 0) {
		printf("ZFS: %s:%d: error %d from"
		    " cluster_copy_upl_data for file %s"
		    " resid_in = %d, resid_out = %d"
		    " now: uio_off %lld, uio_res %lld\n",
		    __func__, __LINE__, ccupl_retval,
		    zp->z_name_cache,
		    recov_resid_int, ccupl_ioresid,
		    uio_offset(uio), uio_resid(uio));
		/* abort the page */
		int kret_abort = ubc_upl_abort(mupl, UPL_ABORT_ERROR);
		if (kret_abort != KERN_SUCCESS) {
			printf("ZFS: %s:%d: error %d from ubc_upl_abort\n",
			    __func__, __LINE__, kret_abort);
			return (kret_abort);
		}
		return (ccupl_retval);
	}
	/* commit the modified page */
	kern_return_t commitret =
	    ubc_upl_commit_range(mupl,
		0, PAGE_SIZE,
		UPL_COMMIT_SET_DIRTY |
		UPL_COMMIT_FREE_ON_EMPTY);
	if (commitret != KERN_SUCCESS) {
		printf("ZFS: %s:%d ERROR %d committing UPL"
		    " for file %s XXX continuing\n",
		    __func__, __LINE__, commitret,
 		    zp->z_name_cache);
	}
	printf("ZFS: %s:%d cluster_copy_upl and commit successful for file %s,"
	    " cc_ioresid_in %d cc_ioresid_out %d\n",
	    __func__, __LINE__, zp->z_name_cache,
	    recov_resid_int, ccupl_ioresid);
	ASSERT3S(ubc_getsize(vp), ==, zp->z_size);
	ASSERT3S(resid_at_break, >, uio_resid(uio));
	ASSERT3S(zp->z_size, >=, recov_off + (resid_at_break - uio_resid(uio)));
	ASSERT3S(ccupl_retval, ==, 0);
	return (0);
}

static inline
int zfs_write_isreg(vnode_t *vp, znode_t *zp, zfsvfs_t *zfsvfs, uio_t *uio, int ioflag,
    rl_t *rl, const ssize_t start_resid, const off_t start_off, const off_t start_size,
    off_t woff, int error)
{
	dmu_tx_t *tx;
	off_t end_size;
	ASSERT3S(error, ==, 0);

	ASSERT3S(start_resid, <=, INT_MAX);
	ASSERT3S(zp->z_size, ==, ubc_getsize(vp));

	const off_t ubcsize_at_entry = ubc_getsize(vp);

	const off_t loop_start_off = uio_offset(uio);
	off_t sync_resid = start_resid;

	boolean_t do_sync = zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS ||
	    ((ioflag & (FDSYNC | FSYNC)) && zfsvfs->z_os->os_sync != ZFS_SYNC_DISABLED);

	/* grab the map lock, protecting against other zfs UBC users */
	boolean_t need_release = B_FALSE;
	boolean_t need_upgrade = B_FALSE;
	uint64_t tries = z_map_rw_lock(zp, &need_release, &need_upgrade, __func__);
	VNOPS_STAT_INCR(update_pages_want_lock, tries);

	/* break the work into reasonable sized chunks */
	const off_t chunk_size = (off_t)SPA_MAXBLOCKSIZE;
	const int proj_chunks = howmany(start_resid, chunk_size);

	for (int c = proj_chunks ; uio_resid(uio) > 0; c--) {
		ASSERT3S(c, >=, 0);

		const off_t this_z_size_start = zp->z_size;

		const off_t this_off = uio_offset(uio);
		ASSERT3S(this_off, >=, 0);

		const size_t this_chunk = MIN(uio_resid(uio),
		    chunk_size - P2PHASE(this_off, chunk_size));
		ASSERT3S(this_chunk, <=, SPA_MAXBLOCKSIZE);
		ASSERT3S(this_chunk, >, 0);

		/* increase ubc size if we are growing the file */
		end_size = MAX(ubc_getsize(vp), this_off + this_chunk);
		ASSERT3S(ubc_getsize(vp), ==, zp->z_size);
		if (end_size > ubc_getsize(vp)) {
			ASSERT3S(end_size, >=, ubcsize_at_entry);
			int setsize_retval = ubc_setsize(vp, end_size);
			if (setsize_retval == 0) {
				// ubc_setsize returns TRUE on success
				printf("ZFS: %s:%d: ubc_setsize(vp, %lld) failed for file %s\n",
				    __func__, __LINE__, end_size, zp->z_name_cache);
			}
		}
		if (end_size > zp->z_size || ubc_getsize(vp) > zp->z_size) {
			uint64_t size_update_ctr = 0;
			uint64_t prev_size = zp->z_size;
			uint64_t n_end_size;
			while ((n_end_size = zp->z_size) < end_size) {
				size_update_ctr++;
				(void) atomic_cas_64(&zp->z_size, n_end_size,
				    end_size);
				ASSERT3S(error, ==, 0);
			}
			if (size_update_ctr > 1) {
				printf("ZFS: %s:%d: %llu tries to increase zp->z_size to end_size"
				    "  %lld (it is now %lld, and was %lld)\n",
				    __func__, __LINE__, size_update_ctr,
				    end_size, zp->z_size, prev_size);
			}
		}

		ASSERT3S(ubc_getsize(vp), ==, zp->z_size);
		ASSERT3S(ubc_getsize(vp), ==, end_size);

		ASSERT3S(uio_offset(uio), ==, this_off);
		ASSERT3S(ubc_getsize(vp), >, uio_offset(uio));
		ASSERT3S(ubc_getsize(vp), >=, uio_offset(uio) + this_chunk);
		ASSERT3S(ubc_getsize(vp), >=, ubcsize_at_entry);

		const uint64_t ubcsize_before_cluster_ops = ubc_getsize(vp);

		/* fill any holes */
		int fill_err = ubc_fill_holes_in_range(vp, this_off, this_off + this_chunk, B_FALSE);
		if (fill_err) {
			printf("ZFS: %s:%d: error filling holes [%lld, %lld] file %s\n",
			    __func__, __LINE__, this_off, this_off + this_chunk, zp->z_name_cache);
		}

		ASSERT3S(ubcsize_before_cluster_ops, ==, ubc_getsize(vp));
		int xfer_resid = (int) this_chunk;

		boolean_t unset_syncer = B_FALSE;
		if (spl_ubc_is_mapped(vp, NULL)) {
			ASSERT3P(zp->z_syncer_active, !=, curthread);
			mutex_enter(&zp->z_ubc_msync_lock);
			while (zp->z_syncer_active != NULL && zp->z_syncer_active != curthread)
				cv_wait(&zp->z_ubc_msync_cv, &zp->z_ubc_msync_lock);
			ASSERT3S(zp->z_syncer_active, ==, NULL);
			zp->z_syncer_active = curthread;
			mutex_exit(&zp->z_ubc_msync_lock);
			unset_syncer = B_TRUE;
		}


		if (spl_ubc_is_mapped(vp, NULL)) {
			ASSERT3S(unset_syncer, ==, B_TRUE);
		} else {
			ASSERT3S(unset_syncer, ==, B_FALSE);
		}


		const off_t ubcsize = ubc_getsize(vp);
		off_t target_postwrite_ubcsize;
		boolean_t reset_ubcsize = B_FALSE;

		if (spl_ubc_is_mapped(vp, NULL)) {
			/* round the ubc size up to a multiple of PAGE_SIZE */
			const off_t cur_woff = uio_offset(uio);
			const off_t cur_wend = cur_woff + uio_resid(uio);
			target_postwrite_ubcsize = cur_wend;
			const off_t round_cur_wend = round_page_64(cur_wend);
			if (ubc_getsize(vp) < round_cur_wend) {
				printf("ZFS: %s:%d: mapped file, ends before end of page, rounding:"
				    " ubcsize %lld cur_woff %lld cur_wend %lld round_cur_wend %lld,"
				    " ioflag %d file %s\n",
				    __func__, __LINE__,
				    ubcsize, cur_woff, cur_wend, round_cur_wend,
				    ioflag, zp->z_name_cache);
				int setsize_retval = ubc_setsize(vp, round_cur_wend);
				if (setsize_retval == 0) {
					// ubc_setsize returns TRUE on success, 0 on failure
					printf("ZFS: %s:%d rounding up: ubc_setsize(vp, %lld)"
					    " from %lld failed for file %s\n",
					    __func__, __LINE__, round_cur_wend, ubcsize,
					    zp->z_name_cache);
				}
				reset_ubcsize = B_TRUE;
			}
		}

		error = cluster_copy_ubc_data(vp, uio, &xfer_resid, 1);

		if (reset_ubcsize) {
			ASSERT(spl_ubc_is_mapped(vp, NULL));
			ASSERT(unset_syncer);
			int setsize_retval = ubc_setsize(vp, target_postwrite_ubcsize);
			if (setsize_retval == 0) {
				// ubc_setsize returns TRUE on success, 0 on failure
				printf("ZFS: %s:%d resetting from round up: ubc_setsize(vp, %lld)"
				    " from cur ubc_getsize %lld"
				    " ubcsize before copy %lld"
				    " failed for file %s\n",
				    __func__, __LINE__, target_postwrite_ubcsize, ubc_getsize(vp),
				    ubcsize,
				    zp->z_name_cache);
			}
		}

		ASSERT3S(ubc_getsize(vp), ==, ubcsize);

		if (unset_syncer) {
			ASSERT3S(zp->z_syncer_active, ==, curthread);
			mutex_enter(&zp->z_ubc_msync_lock);
			zp->z_syncer_active = NULL;
			cv_signal(&zp->z_ubc_msync_cv);
			mutex_exit(&zp->z_ubc_msync_lock);
		}
		if (error == 0) {
			VNOPS_STAT_BUMP(zfs_write_cluster_copy_ok);
			if (xfer_resid != 0) {
				ASSERT3S(this_chunk, >=, xfer_resid);
				IMPLY(xfer_resid == this_chunk, uio_offset(uio) == this_off);
				printf("ZFS: %s:%d incomplete (or no)progress on file %s,"
				    " short write, c %d, woff %lld,"
				    " this_off %lld uio_offset %lld uio_resid %lld"
				    " this_chunk %ld xfer_resid %d file_size %lld %lld"
				    " ioflag %d - punting to update pages function"
				    " (mapped %d mappedwrite %d)"
				    " start_off %lld start_resid %ld"
				    " ubc_size_at_entry %lld start_size %lld\n",
				    __func__, __LINE__, zp->z_name_cache, c,
				    woff, this_off, uio_offset(uio), uio_resid(uio),
				    this_chunk, xfer_resid,
				    zp->z_size, ubc_getsize(vp), ioflag,
				    spl_ubc_is_mapped(vp, NULL),
				    spl_ubc_is_mapped_writable(vp),
				    start_off, start_resid, ubcsize_at_entry, start_size);
				if (xfer_resid == this_chunk) {
					/*
					 * We have written nothing at all.
					 * This seems to be because the first (or only)
					 * page is condition that memory_object_control_uiomove
					 * does not want to deal with (cur_run == 0 at line
					 * 463 of osfmk/vm/bsd_vm.c), or possibly because
					 * of the mark_dirty test at line 388.
					 *
					 * We want to only do this for the range
					 * from uio_offset(uio) to the end of the page;
					 * if uio_resid crosses that end, then we will
					 * want to go through the main loop again, in
					 * order to exhaust the uio (or find a proper error).
					 */
					const off_t resid_at_break = uio_resid(uio);
					const off_t recov_off = uio_offset(uio);
					const off_t recov_resid_max = MIN(resid_at_break,
					    PAGE_SIZE_64);
					const off_t recov_off_page_offset = recov_off & PAGE_MASK_64;
					const off_t recov_bytes_left_in_page = PAGE_SIZE_64 -
					    recov_off_page_offset;
					const off_t recov_resid = MIN(recov_resid_max,
					    recov_bytes_left_in_page);
					ASSERT3S(recov_resid, <=, PAGE_SIZE_64);
					ASSERT3S(((recov_off + recov_resid) & PAGE_MASK_64), <, 4096LL);
					ASSERT3S(recov_resid, >, 0);
					ASSERT3S(recov_resid, <=, resid_at_break);
					const int recov_resid_int = (int) recov_resid;
					ASSERT3S(recov_resid_int, ==, recov_resid);

					/* is the page we're interested in dirty ? */
					const off_t pop_q_off = trunc_page_64(recov_off);
					int pop_q_op = 0;
					int pop_q_flags = 0;
					kern_return_t pop_q_result =
					    ubc_page_op(vp, pop_q_off, pop_q_op,
						NULL, &pop_q_flags);
					ASSERT3S(pop_q_result, ==, KERN_SUCCESS);
					ASSERT3S(pop_q_flags, ==, 0);

					printf("ZFS: %s:%d no progress made, c == %d,"
					    " attempting to overwrite %d bytes:"
					    " (recoff %lld uio_resid %lld xfer_resid was %d)"
					    " page flags 0%o for file %s\n",
					    __func__, __LINE__, c, recov_resid_int,
					    recov_off, resid_at_break, xfer_resid, pop_q_flags,
					    zp->z_name_cache);

					/* write out the old page, then modify it from the uio */

					int zwmwret = zfs_write_modify_write(vp, zp, zfsvfs, uio,
					    ioflag, resid_at_break, recov_off, recov_off_page_offset,
					    recov_resid_int, pop_q_off);

					if (zwmwret != 0) {
						printf("ZFS: %s:%d: error %d from"
						    " zfs_write_modify_write for page at %lld of"
						    " file %s, uio_offset %lld, uio_resid %lld\n",
						    __func__, __LINE__, zwmwret,
						    pop_q_off,
						    zp->z_name_cache,
						    uio_offset(uio), uio_resid(uio));
						if (uio_resid(uio) < resid_at_break) {
							const uint64_t bytes_progressed =
							    resid_at_break - uio_resid(uio);
							ASSERT3S(uio_offset(uio), >, recov_off);
							printf("ZFS: %s:%d: uio progressed by"
							    " %lld bytes, XXX continuing"
							    " file %s\n",
							    __func__, __LINE__,
							    bytes_progressed,
							    zp->z_name_cache);
							continue;
						} else {
							printf("ZFS: %s:%d uio not progressed for"
							    " file %s, resid_at_break %lld"
							    " uio_resid %lld\n",
							    __func__, __LINE__, zp->z_name_cache,
							    resid_at_break, uio_resid(uio));
							goto drop_and_return_to_retry;
						}
					}
					/* successfully returned from zfs_write_modify_write */
					ASSERT3S(zwmwret, ==, 0);
					const off_t uioresid = uio_resid(uio);
					ASSERT3S(resid_at_break, >=, uio_resid(uio));
					const off_t bytes_moved = resid_at_break - uio_resid(uio);
					ASSERT3S(uioresid, <, resid_at_break);
					printf("ZFS: %s:%d: successfully moved %lld bytes,"
					    " for file %s continuing,"
					    " uio_resid now %lld\n",
					    __func__, __LINE__, resid_at_break - uioresid,
					    zp->z_name_cache, uioresid);
					ASSERT3S(ubc_getsize(vp), ==, zp->z_size);
                                        ASSERT3S(zp->z_size, >=, recov_off + bytes_moved);
					continue;
				drop_and_return_to_retry:
					/*
					 * if we are here that we made no progress in
					 * in the most recent cluster_copy_ubc_data.
					 *
					 * we are not tearing a write here
					 * as long as we have made no progress
					 * on the uio in an early cluster_copy_ubc_data.
					 */
					ASSERT3S(uio_resid(uio), ==, start_resid);
					ASSERT3S(uio_offset(uio), ==, loop_start_off);
					/*
					 * if the above assertions fail, we should probably
					 * jump down to skip_sync telling it to sync only
					 * the work we did do.
					 */
					printf("ZFS: %s:%d error %d file %s\n",
					    __func__, __LINE__, error, zp->z_name_cache);
					z_map_drop_lock(zp,
					    &need_release, &need_upgrade);
					zfs_range_unlock(rl);
					ZFS_EXIT(zfsvfs);
					ASSERT3S(error, ==, 0);
					return (error);
				} else {
					// wrote a little: xfer_resid == 0, xfer_resid != this_chunk
					printf("ZFS: %s:%d we had written a little:"
					    " xfer_resid %d this_chunk %ld uio_resid %lld"
					    " file %s\n",
					    __func__, __LINE__,
					    xfer_resid, this_chunk, uio_resid(uio),
					    zp->z_name_cache);
					VNOPS_STAT_BUMP(zfs_write_cluster_copy_short_write);
					off_t uioresid = uio_resid(uio);
					ASSERT3S(start_resid, >, uioresid);
					sync_resid = start_resid - uioresid;
					ASSERT3S(sync_resid, >, 0);
					ASSERT3S(sync_resid, <, start_resid);
				}
			} else {
				ASSERT3S(xfer_resid, ==, 0);
				// complete copy, error == 0, xfer_resid == 0
				VNOPS_STAT_BUMP(zfs_write_cluster_copy_complete);
			}
			VNOPS_STAT_INCR(zfs_write_cluster_copy_bytes, this_chunk - xfer_resid);
		} else {
			printf("ZFS: %s:%d: error %d from cluster_copy_ubc_data"
			    " (woff %lld, resid %ld) (now %lld %lld) c %d file %s\n",
			    __func__, __LINE__, error, woff, start_resid,
			    uio_offset(uio), uio_resid(uio), c,
			    zp->z_name_cache);
			z_map_drop_lock(zp, &need_release, &need_upgrade);
			zfs_range_unlock(rl);
			VNOPS_STAT_BUMP(zfs_write_cluster_copy_error);
			ZFS_EXIT(zfsvfs);
			return(error);
		}
		ASSERT3S(error, ==, 0);

		ASSERT3S(ubcsize_before_cluster_ops, ==, ubc_getsize(vp));
		ASSERT3S(zp->z_size, >=, uio_offset(uio));
		ASSERT3S(zp->z_size, ==, ubc_getsize(vp));
		ASSERT3S(zp->z_size, ==, ubc_getsize(vp));

		const uint64_t def_z_size = zp->z_size;
		const uint64_t resid_dispatched =
		    (start_resid > uio_resid(uio))
		    ? start_resid - uio_resid(uio)
		    : 0;
		ASSERT3S(start_resid - uio_resid(uio), >=, 0);
		const uint64_t def_woff_plus_resid_dispatched = woff + resid_dispatched;

		const int64_t  def_deficit =
		    (def_z_size < def_woff_plus_resid_dispatched)
		    ? def_woff_plus_resid_dispatched - def_z_size
		    : 0;

		if (zp->z_size < def_woff_plus_resid_dispatched) {
			printf("ZFS: %s:%d: z_size %lld should be at least"
			    " woff+resid_dispatched %lld, resid_dispatched %lld,"
			    " size deficit %lld"
			    " uio_off %lld uio_resid %lld file %s\n",
			    __func__, __LINE__,
			    def_z_size, def_woff_plus_resid_dispatched, resid_dispatched,
			    def_deficit,
			    uio_offset(uio), uio_resid(uio),
			    zp->z_name_cache);
			if (uio_resid(uio) == 0) {
				uint64_t end_size = MAX(zp->z_size, def_woff_plus_resid_dispatched);
				uint64_t size_update_ctr = 0;
				uint64_t n_end_size;
				while ((n_end_size = zp->z_size) < end_size) {
					size_update_ctr++;
					(void) atomic_cas_64(&zp->z_size, n_end_size,
					    end_size);
					ASSERT3S(error, ==, 0);
				}
				if (size_update_ctr > 0) {
					printf("ZFS: %s:%d: %llu tries to increase"
					    " zp->z_size to end_size"
					    "  %lld (it is now %lld)\n",
					    __func__, __LINE__, size_update_ctr,
					    end_size, zp->z_size);
				}
				ASSERT3S(zp->z_size, >=, ubcsize_at_entry);
				int setsize_retval = ubc_setsize(vp, zp->z_size);
				ASSERT3S(setsize_retval, !=, 0);
			}
		}


		/*  as we have completed a uio_move, commit the size change */

		/* commit the znode change */
		if (zp->z_size > this_z_size_start) {
			tx = dmu_tx_create(zfsvfs->z_os);
			dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
			zfs_sa_upgrade_txholds(tx, zp);
			error = dmu_tx_assign(tx, TXG_WAIT);
			if (error) {
				printf("ZFS: %s:%d: error %d from dmu_tx_assign\n",
				    __func__, __LINE__, error);
				dmu_tx_abort(tx);
			} else {
				error = sa_update(zp->z_sa_hdl, SA_ZPL_SIZE(zfsvfs),
				    (void *)&zp->z_size, sizeof (uint64_t), tx);
				if (error) {
					printf("ZFS: %s:%d sa_update returned error %d\n",
					    __func__, __LINE__, error);
				}
				dmu_tx_commit(tx);
			}
		}

	} // for

	z_map_drop_lock(zp, &need_release, &need_upgrade);

	//ASSERT(!rw_write_held(&zp->z_map_lock));
	ASSERT3S(error, ==, 0);
	ASSERT3S(ubc_getsize(vp), ==, zp->z_size);

	/*
	 * Give up the range lock now, since our msync here may lead
	 * to a dmu_write in pageoutv2 in this thread
	 */
#if 1
	/*
	 * The taskq task zfs_write_sync_range needs some information
	 * in its *arg argument; it is responsible for freeing the
	 * communications structure, not us.
	 */
	const boolean_t is_safe = dmu_write_is_safe(zp, woff, woff + sync_resid);
	if (!is_safe) {
		printf("ZFS: %s:%d: sending %s write [%lld, %lld] to task file %s\n",
		    __func__, __LINE__,
		    (do_sync) ? "sync" : "standard",
		    woff, woff + sync_resid, zp->z_name_cache);
		sync_range_t *sync_range = kmem_zalloc(sizeof(sync_range_t), KM_SLEEP);

		if (sync_range == NULL) {
			if (do_sync) {
				zfs_panic_recover("cannot sync as kmem_zalloc returned NULL"
				    " to %s:%d file %s\n",
				    __func__, __LINE__, zp->z_name_cache);
				goto skip_sync;
			} else {
				printf("ZFS: %s:%d: kmem_zalloc returned NULL!"
				    " could not push file %s\n",
				    __func__, __LINE__, zp->z_name_cache);
				goto skip_sync;
			}
		}

		sync_range->safety_check = B_TRUE;
		sync_range->range_lock   = B_TRUE;
		sync_range->sync         = do_sync;
		sync_range->end          = woff + sync_resid;
		sync_range->start        = woff;
		sync_range->start_resid  = sync_resid;
		sync_range->vp           = vp;

		VERIFY3U(taskq_dispatch(system_taskq, zfs_write_sync_range, sync_range,
			TQ_SLEEP), !=, 0);
	}

skip_sync:
	zfs_range_unlock(rl);

	/* we can become unsafe here */

	if (is_safe) {
		error = zfs_write_sync_range_helper(vp, woff, woff + sync_resid,
		    sync_resid, do_sync, B_TRUE, B_FALSE);
		if (error != 0) {
			if (do_sync) {
				printf("%s:%d BAD! ERROR! (do_sync) zfs_write_sync_range_helper"
				    " returned error %d for range [%lld, %lld], file %s\n",
				    __func__, __LINE__, error,
				    woff, woff+sync_resid, zp->z_name_cache);
			} else {
				printf("%s:%d (not do_sync) zfs_write_sync_range_helper"
				    " returned error %d for range [%lld, %lld], file %s\n",
				    __func__, __LINE__, error,
				    woff, woff+sync_resid, zp->z_name_cache);
			}
		}

	}
#else
	zfs_range_unlock(rl);
	error = zfs_write_sync_range_helper(vp, woff, woff + sync_resid,
	    sync_resid, do_sync);
	if (error != 0) {
		zfs_panic_recover("%s:%d zfs_write_sync_range_helper"
		    " returned error %d for range [%lld, %lld], file %s\n",
		    __func__, __LINE__, error,
		    woff, woff+sync_resid, zp->z_name_cache);
	}
#endif
	ASSERT3S(ubc_getsize(vp), >=, ubcsize_at_entry);

	ZFS_EXIT(zfsvfs);
	/*
	 * strictly speaking, in the do_sync == TRUE case we
	 * should not return here until the zfs_write_sync_range
	 * operation has completed successfully.
	 *
	 * this could be done with e.g. a condvar, however we
	 * could also wait on is_file_clean if we don't want to
	 * worry about direct synchronization from the taskq
	 * task, especially since it may be dropping and
	 * reacquiring all sorts of locks.
	 *
	 * Another option is that we could turn the taskq_dispatch
	 * into an in-this-thread call for the do_sync case (or inded
	 * for both cases; it is also not clear that in the non-do_sync
	 * case that we actually have to do a ubc_msync here (but we do
	 * for the do_sync case!)).
	 */
	return (error);
}

/*
 * Write the bytes to a file.
 *
 *	IN:	vp	- vnode of file to be written to.
 *		uio	- structure supplying write location, range info,
 *			  and data buffer.
 *		ioflag	- FAPPEND flag set if in append mode.
 *		cr	- credentials of caller.
 *		ct	- caller context (NFS/CIFS fem monitor only)
 *
 *	OUT:	uio	- updated offset and range.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - ctime|mtime updated if byte count > 0
 */

/* ARGSUSED */
int
zfs_write(vnode_t *vp, uio_t *uio, int ioflag, cred_t *cr, caller_context_t *ct,
    char **file_name, boolean_t old_style)
{
	znode_t		*zp = VTOZ(vp);
	rlim64_t	limit = MAXOFFSET_T;
	const ssize_t	start_resid = uio_resid(uio);
	const off_t     start_off = uio_offset(uio);
	ssize_t		tx_bytes;
	uint64_t	end_size;
	dmu_tx_t	*tx;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog;
	offset_t	woff;
	ssize_t		n, nbytes;
	rl_t		*rl;
	int		max_blksz = zfsvfs->z_max_blksz;
	int		error = 0;
	int		write_eof;
	int		count = 0;
	sa_bulk_attr_t	bulk[4];
	uint64_t	mtime[2], ctime[2];
	struct uio      *uio_copy = NULL;


    VNOPS_STAT_BUMP(zfs_write_calls);
	/*
	 * Fasttrack empty write
	 */
	n = start_resid;
	if (n == 0) {
		VNOPS_STAT_BUMP(zfs_zero_length_write);
		return (0);
	}

	if (limit == RLIM64_INFINITY || limit > MAXOFFSET_T)
		limit = MAXOFFSET_T;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	*file_name = zp->z_name_cache;
	const off_t ubcsize_at_entry = ubc_getsize(vp);
	const off_t start_size = zp->z_size;
	ASSERT3S(start_size, ==, ubcsize_at_entry);

	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL, &mtime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL, &ctime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_SIZE(zfsvfs), NULL,
	    &zp->z_size, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
	    &zp->z_pflags, 8);

	/*
	 * In a case vp->v_vfsp != zp->z_zfsvfs->z_vfs (e.g. snapshots) our
	 * callers might not be able to detect properly that we are read-only,
	 * so check it explicitly here.
	 */
	if (vfs_flags(zfsvfs->z_vfs) & MNT_RDONLY) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EROFS));
	}

	/*
	 * If immutable or not appending then return EPERM.
	 * Intentionally allow ZFS_READONLY through here.
	 * See zfs_zaccess_common()
	 */
	if ((zp->z_pflags & ZFS_IMMUTABLE) ||
	    ((zp->z_pflags & ZFS_APPENDONLY) && !(ioflag & FAPPEND) &&
		(uio_offset(uio) < zp->z_size))) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EPERM));
	}

	zilog = zfsvfs->z_log;

	/*
	 * Validate file offset
	 */
	woff = ioflag & FAPPEND ? zp->z_size : uio_offset(uio);
	if (woff < 0) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EINVAL));
	}

	if (vnode_isreg(vp) && (ioflag & FAPPEND) == 0) {
		error = zfs_write_possibly_msync(zp, woff, start_resid, ioflag);
		if (error) {
			ZFS_EXIT(zfsvfs);
			printf("ZFS: %s:%d: (early msync fail) returning error %d\n",
			    __func__, __LINE__, error);
			return (error);
		}
	}

	/*
	 * The range lock principally protects us against
	 * pageoutv2, which takes an RL and then the z_map_lock.
	 */

	/* if we are appending, bump woff to the end of file */
	if (ioflag & FAPPEND) {
		const off_t old_woff = woff;
		rl = zfs_range_lock(zp, 0, n, RL_APPEND);
		woff = rl->r_off;
		if (rl->r_len == UINT64_MAX) {
			woff = zp->z_size;
		}
		if (woff != old_woff) {
			printf("ZFS: %s:%d: append range lock says set woff to %lld from %lld"
			    " rl->r_len %lld uio_offset %lld uio_resid %lld file %s\n",
			    __func__, __LINE__, woff, old_woff, rl->r_len,
			    uio_offset(uio), uio_resid(uio), zp->z_name_cache);
		}
		ASSERT3S(woff, ==, ubc_getsize(vp));
		uio_setoffset(uio, woff);
	} else {
		rl = zfs_range_lock(zp, woff, start_resid, RL_WRITER);
	}


	if (woff >= limit) {
		zfs_range_unlock(rl);
		ZFS_EXIT(zfsvfs);
		return ((EFBIG));
	}

        error = zfs_write_maybe_extend_file(zp, woff, start_resid, rl);
	if (error) {
		ZFS_EXIT(zfsvfs);
		printf("ZFS: %s:%d: (extend fail) returning error %d\n", __func__, __LINE__, error);
		return (error);
	}
	if (woff > zp->z_size) {
		printf("ZFS: %s:%d: woff %lld is past EOF %lld file %s\n",
		    __func__, __LINE__, woff, zp->z_size, zp->z_name_cache);
	}
	ASSERT3S(ubc_getsize(vp), ==, zp->z_size);

	/*
	 * Regular files get handled in a new way
	 */

	if (vnode_isreg(vp) && old_style != B_TRUE) {
		/* Important: tail call: we use no actual stack space here */
		return(zfs_write_isreg(vp, zp, zfsvfs, uio, ioflag,
			rl, start_resid, start_off, start_size,
			woff, error));
	}

	/*
	 * If we are called with the old_style flag true, or if we are
	 * called on a non-regular file, carry on below.  This should
	 * happen approximately never.
	 */
	if (old_style == B_FALSE) {
		VERIFY(!vnode_isreg(vp));
	}
	EQUIV(old_style == B_TRUE, vnode_isreg(vp));

	/* Illumos here checks for mandatory locks; OSX (and Linux) do this elsewhere */

	/*
	 * Illumos and ZOL here do page-prefaulting on the uio so that
	 * if the uio has been paged out of RAM, it will be back in RAM
	 * before the tx_* calls.  In the unlikely event that this
	 * happens to XNU in the real world, we could build a
	 * prefaulting function that walks through a copy of the uio.
	 */

#if 0 // we do this above

	/*
	 * If in append mode, set the io offset pointer to eof.
	 */
	if (ioflag & FAPPEND) {
		/*
		 * Obtain an appending range lock to guarantee file append
		 * semantics.  We reset the write offset once we have the lock.
		 */
		rl = zfs_range_lock(zp, 0, n, RL_APPEND);
		woff = rl->r_off;
		if (rl->r_len == UINT64_MAX) {
			/*
			 * We overlocked the file because this write will cause
			 * the file block size to increase.
			 * Note that zp_size cannot change with this lock held.
			 */
			woff = zp->z_size;
			/*** NOTE: this erases the block change in the while loop ***/
			/***       That is, if there is a block size change required
			 ***       for a file in append mode, the test for overlocking
			 ***       in the first pass of the while (n > 0) loop will
			 ***       not succeed.    We could either break DRY here, or
			 ***       also test for a block size change in FAPPEND mode,
			 ***       if indeed this is the cause of unsafe write sizes.
			 ***/
		}
		uio_setoffset(uio, woff);
	} else {
		/*
		 * Note that if the file block size will change as a result of
		 * this write, then this range lock will lock the entire file
		 * so that we can re-write the block safely.
		 */
		rl = zfs_range_lock(zp, woff, n,  RL_WRITER);
	}

	if (woff >= limit) {
		zfs_range_unlock(rl);
		ZFS_EXIT(zfsvfs);
		return ((EFBIG));
	}
#endif

	/*
	 * here we are old_style, most likely recovering from a stuck
	 * ubc page, and up above we have already taken a range lock,
	 * done any requisite pushing, and set woff correctly
	 */

	if ((woff + n) > limit || woff > (limit - n))
		n = limit - woff;

	/* Will this write extend the file length? */
	write_eof = (woff + n > zp->z_size);

	end_size = MAX(zp->z_size, woff + n);

	/*
	 * Write the file in reasonable size chunks.  Each chunk is written
	 * in a separate transaction; this keeps the intent log records small
	 * and allows us to do more fine-grained space accounting.
	 */
	printf("ZFS: %s:%d: (old_style) resid/n %lu : offset %llu (rl_len %llu) blksz %u fn %s\n",
	    __func__,__LINE__,n,uio_offset(uio), rl->r_len, zp->z_blksz, zp->z_name_cache );

	while (n > 0) {
		woff = uio_offset(uio);

		if (zfs_owner_overquota(zfsvfs, zp, B_FALSE) ||
		    zfs_owner_overquota(zfsvfs, zp, B_TRUE)) {
			error = SET_ERROR(EDQUOT);
			break;
		}

		/*
		 * Start a transaction.
		 */
		tx = dmu_tx_create(zfsvfs->z_os);
		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);

		dmu_tx_hold_write(tx, zp->z_id, woff, MIN(n, max_blksz));
		zfs_sa_upgrade_txholds(tx, zp);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			break;
		}

#if 0 // we have done this above already
		/*
		 * If zfs_range_lock() over-locked we grow the blocksize
		 * and then reduce the lock range.  This will only happen
		 * on the first iteration since zfs_range_reduce() will
		 * shrink down r_len to the appropriate size.
		 */
		/* XXX: we may want to retest here for a file that was opened
		 *      with ioflag & FAPPEND, as r->r_len was reset above.
		 *      Alternatively, we may not want to do the reduce range
		 *      in the F_APPEND case
		 */
		uint64_t new_blksz = 0;
		if (rl->r_len == UINT64_MAX) {
			if (zp->z_blksz > max_blksz) {
				/*
				 * File's blocksize is already larger than the
				 * "recordsize" property.  Only let it grow to
				 * the next power of 2.
				 */
				ASSERT(!ISP2(zp->z_blksz));
				new_blksz = MIN(end_size, SPA_MAXBLOCKSIZE);
			} else {
				new_blksz = MIN(end_size, max_blksz);
			}
			if (vnode_isreg(vp)) {
				off_t max_max_n = MIN(SPA_MAXBLOCKSIZE, MAX_UPL_SIZE_BYTES);
				off_t max_n = MIN(n, max_max_n);
				off_t safe_write_n = zfs_safe_dbuf_write_size(zp, uio, max_n);
				nbytes = MIN(safe_write_n, max_max_n - P2PHASE(woff, max_max_n));
				if (nbytes < 1) {
					dprintf("ZFS: %s:%d:"
					    " growing buffer from %d to %llu file %s\n",
					    __func__, __LINE__,
					    zp->z_blksz, new_blksz, zp->z_name_cache);

				}
			}
			zfs_grow_blocksize(zp, new_blksz, tx);
			zfs_range_reduce(rl, woff, n);
		}
#endif

#ifdef __APPLE__
		boolean_t write_with_dbuf = B_TRUE;

		/* Pick the size of the write we hand to the DMU/DBUF layer */

		off_t safe_write_n = INT_MAX;
		if (vnode_isreg(vp)) {
			/*
			 * regular files will have update_pages invoked
			 * on them.  the dbuf must be able to hold the
			 * write, or we will trigger "accessing past end
			 * of object" panic in dmu_buf_array_by_dnode.
			 * However, we are not limited to max_blksz, we
			 * can write any size chunk we like less than
			 * SPA_MAXBLOCKSIZE
			 */
			off_t max_max_n = MIN(SPA_MAXBLOCKSIZE, MAX_UPL_SIZE_BYTES);
			off_t max_n = MIN(n, max_max_n);
			safe_write_n = zfs_safe_dbuf_write_size(zp, uio, max_n);
			nbytes = MIN(safe_write_n, max_max_n - P2PHASE(woff, max_max_n));
			if (nbytes < 1) {
				printf("ZFS: %s:%d: WARNING nbytes == %ld, safe_write_n == %lld,"
				    " n == %ld, file %s\n", __func__, __LINE__,
				    nbytes, safe_write_n, n, zp->z_name_cache);
				nbytes = MIN(n, max_blksz - P2PHASE(woff, max_blksz));
				write_with_dbuf = B_FALSE;
			}
		} else {
                        /* use the logic from openzfs */
			nbytes = MIN(n, max_blksz - P2PHASE(woff, max_blksz));
			/* but check that we won't paneek! */
			ASSERT3S(nbytes, <=, zfs_safe_dbuf_write_size(zp, uio, nbytes));
		}
#else
		/*
		 * XXX - should we really limit each write to z_max_blksz?
		 * Perhaps we should use SPA_MAXBLOCKSIZE chunks?
		 */
		nbytes = MIN(n, max_blksz - P2PHASE(woff, max_blksz));
#endif

		if  (vnode_isreg(vp))  {
			uio_copy = uio_duplicate(uio);
		}

		/* set tx_bytes to the amount we hope to write in this tx */
		tx_bytes = uio_resid(uio);

		/*
		 * For regular files, we have two write cases:
		 *
		 * i) borrow, fill, and assign an arcbuf, which we do in
		 *    the case where weare at the end of the file and
		 *    are extending it and are max_blksz-aligned
		 *
		 * ii) dmu_write_uio, which we do if it is safe
		 *
		 * If we can't do either, print a warning and this will end
		 * up being a short write.
		 */
		if (n >= max_blksz && woff >= zp->z_size &&
		    P2PHASE(woff, max_blksz) == 0 && zp->z_blksz == max_blksz) {
			ASSERT(ISP2(max_blksz));
			/*
			 * reset nbytes, so we don't trip an assert at the
			 * end of the whlie loop below
			 */
			nbytes = max_blksz;
			tx_bytes = nbytes;
			/* here we are growing the file and don't have a
			 * buffer of the correct size in z_sa_hdl, so
			 * borrow, fill, and assign an arcbuf of the
			 * right size.
			 */
			ASSERT(write_eof);
			ASSERT(vnode_isreg(vp));
			size_t cbytes;
			arc_buf_t *arcbuf = dmu_request_arcbuf(sa_get_db(zp->z_sa_hdl),
                            max_blksz);
			ASSERT3P(arcbuf, !=, NULL);
			if (arcbuf == NULL) {
				tx_bytes = 0;
				error = ENOMEM;
				break;
			}
			ASSERT3S(arc_buf_size(arcbuf), ==, max_blksz);
			if (arc_buf_size(arcbuf) < max_blksz) {
				tx_bytes = 0;
				error = ENOMEM;
				dmu_return_arcbuf(arcbuf);
				break;
			}
			int assign_path_uiocopy_err;
			if ((assign_path_uiocopy_err = uiocopy(arcbuf->b_data, tx_bytes,
				    UIO_WRITE, uio, &cbytes))) {
				error = assign_path_uiocopy_err;
				ASSERT3S(assign_path_uiocopy_err, ==, 0); // emit an assertion
                                dmu_return_arcbuf(arcbuf);
                                break;
                        }
			ASSERT3S(cbytes, ==, tx_bytes);
			dmu_assign_arcbuf_by_dbuf(sa_get_db(zp->z_sa_hdl), woff, arcbuf, tx);
			ASSERT3S(tx_bytes, <=, uio_resid(uio));
			uioskip(uio, tx_bytes);
			VNOPS_STAT_BUMP(zfs_write_arcbuf_assign);
			VNOPS_STAT_INCR(zfs_write_arcbuf_assign_bytes, tx_bytes);
		} else if (write_with_dbuf == B_TRUE || !vnode_isreg(vp)) {
			/* set tx_bytes to what the uio still wants */
			tx_bytes = uio_resid(uio);
			error = dmu_write_uio_dbuf(sa_get_db(zp->z_sa_hdl),
			    uio, nbytes, tx);
			ASSERT3S(error, ==, 0);
			/* dmu_write_uio_dbuf updated the uio */
			VNOPS_STAT_BUMP(zfs_write_uio_dbufs);
			VNOPS_STAT_INCR(zfs_write_uio_dbuf_bytes, tx_bytes - uio_resid(uio));
			tx_bytes -= uio_resid(uio);
		} else {
			ASSERT(vnode_isreg(vp));
			printf("ZFS: %s:%d: fell through ioflag %d end_size %lld"
			    " offset %lld nbytes %ld"
			    " n %ld max_blksz %d filesz %lld safe_write_n %lld"
			    " z_blksz %d@file %s\n",
			    __func__, __LINE__, ioflag, end_size,
			    woff, nbytes, n, max_blksz,
			    zp->z_size, safe_write_n, zp->z_blksz, zp->z_name_cache);

			ASSERT3S(zp->z_size, ==, ubc_getsize(vp));

			/* arrrrgh, what to do here?
			 *
			 * returning and letting there be short write
			 * leads to problems.  an option might be to
			 * stuff a dirty page into UBC and let the vm
			 * sort it all out.  another might be to invoke
			 * zfs_extend logic (some of which is already in
			 * zfs_write, notably the sa update, the
			 * we now do in the retry_count continue below.
			 *
			 * what we're missing is the ubc size update.
			 */

			if (end_size >= zp->z_size) {
				tx_bytes -= uio_resid(uio);
				nbytes = tx_bytes;
				ASSERT3S(tx_bytes, ==, 0);
			} else {
				/* make the file bigger and continue */
				/* maybe bump the block size again */
				uint64_t n_new_blksz = 0;
				if (end_size > zp->z_blksz &&
				    (!ISP2(zp->z_blksz) || zp->z_blksz < zfsvfs->z_max_blksz)) {
					// growing file past current block size
					if (zp->z_blksz > zp->z_zfsvfs->z_max_blksz) {
						// already larger than recordsize
						ASSERT(!ISP2(zp->z_blksz));
						n_new_blksz = MIN(end_size, SPA_MAXBLOCKSIZE);
					} else {
						n_new_blksz = MIN(end_size, max_blksz);
					}
				}
				if (n_new_blksz > 0) {
					zfs_grow_blocksize(zp, n_new_blksz, tx);
				}
				uint64_t size_update_ctr = 0;
				uint64_t n_end_size;
				while ((n_end_size = zp->z_size) < end_size) {
					size_update_ctr++;
					(void) atomic_cas_64(&zp->z_size, n_end_size,
					    end_size);
					ASSERT3S(error, ==, 0);
				}
				if (size_update_ctr > 0) {
					printf("ZFS: %s:%d: %llu tries to increase zp->z_size to end_size"
					    "  %lld (it is now %lld)\n",
					    __func__, __LINE__, size_update_ctr,
					    end_size, zp->z_size);
				}

				/*
				 * If we are replaying and eof is non zero then force
				 * the file size to the specified eof. Note, there's no
				 * concurrency during replay.
				 */
				if (zfsvfs->z_replay && zfsvfs->z_replay_eof != 0)
					zp->z_size = zfsvfs->z_replay_eof;

				VERIFY3S(0, ==, sa_update(zp->z_sa_hdl, SA_ZPL_SIZE(zp->z_zfsvfs),
					&zp->z_size, sizeof(zp->z_size), tx));

				dmu_tx_commit(tx);
				continue;
			}
		}

                /* If we've written anything to a regular file, we have
		 * to update the UBC.
		 *
		 * Note: 10a286 does this the other way around; it marks
		 *       the buffers in the (UBC) UPL as DIRTY and then
		 *       uses its cluster write now function to write
		 *       them out to disk, doing no DMU work at all in
		 *       its zfs_vnop_write.
		 *
		 *       Illumos on the other hand updates its pages after
		 *       the write (or dmu assignment of an arcbuf if the write
		 *       is the same as the file's current maximum record
		 *       size (which is no more than the dataset recordsize).
		 */
		if (tx_bytes > 0 && uio_copy != NULL) {
			ASSERT(vnode_isreg(vp));
			/*
			 * Although we repeat this below, since we have
			 * changed the file size we need to feed
			 * the new filesize to xnu so that VM operations
			 * below update_pages work correctly.
			 *
			 * ubc_setsize will correctly handle a partially
			 * filled final page, zero-filling it after
			 * between the EOF and the final page boundary.
			 */

			/*
			 * Bump zp->z_size to be bigger than the
			 * present uio_offset.
			 */
			uint64_t size_update_ctr = 0;
			uint64_t starting_uioffset = uio_offset(uio);
			while ((end_size = zp->z_size) < uio_offset(uio)) {
				size_update_ctr++;
				(void) atomic_cas_64(&zp->z_size, end_size,
				    uio_offset(uio));
				ASSERT3S(error, ==, 0);
			}
			if (size_update_ctr > 1) {
				printf("ZFS: %s:%d: %llu tries to increase zp->z_size above"
				    " uio_offset %lld (which is now %lld)\n",
				    __func__, __LINE__, size_update_ctr, starting_uioffset, uio_offset(uio));
			}
			ASSERT3U(starting_uioffset, ==, uio_offset(uio));

			/*
			 * Now that zp->z_size is correct, let's update UBC's size.
			 * Again, this is repeated verbatim below, but we
			 * want to do this before update_pages.
			 */

			boolean_t need_release = B_FALSE, need_upgrade = B_FALSE;
                        uint64_t tries = z_map_rw_lock(zp, &need_release, &need_upgrade, __func__);
			ASSERT3S(zp->z_size, >=, ubc_getsize(vp));
			ASSERT3S(zp->z_size, >=, ubcsize_at_entry);
			int setsize_retval = ubc_setsize(vp, zp->z_size);
			z_map_drop_lock(zp, &need_release, &need_upgrade);
			ASSERT3S(tries, <=, 2);

			ASSERT3S(setsize_retval, !=, 0); // ubc_setsize returns true on success

			/* actually update the UBC pages */
			update_pages(vp, tx_bytes, uio_copy, tx, 0);

			uio_free(uio_copy);
			uio_copy = NULL;
		}

		/*
		 * we may have made a uio copy, but were unable to do
		 * any write or update_pages work
		 */
		if (uio_copy != NULL) {
			uio_free(uio_copy);
			uio_copy = NULL;
		}

		/*
		 * If we made no progress, we're done.
		 */
		if (tx_bytes == 0) {
			ASSERT3S(n, >, 0);
			(void) sa_update(zp->z_sa_hdl, SA_ZPL_SIZE(zfsvfs),
			    (void *)&zp->z_size, sizeof (uint64_t), tx);
			dmu_tx_commit(tx);
			ASSERT3S(error, ==, 0);
			break;
		}
		/*
		 * If we made even partial progress, update the znode
		 * and ZIL accordingly.
		 */

		/*
		 * Clear Set-UID/Set-GID bits on successful write if not
		 * privileged and at least one of the excute bits is set.
		 *
		 * It would be nice to to this after all writes have
		 * been done, but that would still expose the ISUID/ISGID
		 * to another app after the partial write is committed.
		 *
		 * Note: we don't call zfs_fuid_map_id() here because
		 * user 0 is not an ephemeral uid.
		 *
		 * NOTE: This has no effect on OSX.
		 */
		mutex_enter(&zp->z_acl_lock);
		if ((zp->z_mode & (S_IXUSR | (S_IXUSR >> 3) |
		    (S_IXUSR >> 6))) != 0 &&
		    (zp->z_mode & (S_ISUID | S_ISGID)) != 0 &&
		    secpolicy_vnode_setid_retain(vp, cr,
		    (zp->z_mode & S_ISUID) != 0 && zp->z_uid == 0) != 0) {
			uint64_t newmode;
			zp->z_mode &= ~(S_ISUID | S_ISGID);
			newmode = zp->z_mode;
			(void) sa_update(zp->z_sa_hdl, SA_ZPL_MODE(zfsvfs),
			    (void *)&newmode, sizeof (uint64_t), tx);
		}
		mutex_exit(&zp->z_acl_lock);

		zfs_tstamp_update_setup(zp, CONTENT_MODIFIED, mtime, ctime,
		    B_TRUE);

		/*
		 * Update the file size (zp_size) if it has changed;
		 * account for possible concurrent updates.
		 *
		 * We did this above in the case of tx_bytes > 0 and
		 * a regular file with UBC data.    This might be omittable
		 * in the case that it was done above.    However,
		 * this is a cheap couple of tests when z_size is up to date.
		 */
		uint64_t size_update_ctr = 0;
		uint64_t starting_uioffset = uio_offset(uio);
		while ((end_size = zp->z_size) < uio_offset(uio)) {
			size_update_ctr++;
			(void) atomic_cas_64(&zp->z_size, end_size,
                                 uio_offset(uio));
			ASSERT3S(error, ==, 0);
		}
		if (size_update_ctr > 1) {
			printf("ZFS: %s:%d: %llu tries to increase zp->z_size above"
			    " uio_offset %lld (which is now %lld)\n",
			    __func__, __LINE__, size_update_ctr, starting_uioffset, uio_offset(uio));
		}
		ASSERT3U(starting_uioffset, ==, uio_offset(uio));

		/*
		 * If we are replaying and eof is non zero then force
		 * the file size to the specified eof. Note, there's no
		 * concurrency during replay.
		 */
		if (zfsvfs->z_replay && zfsvfs->z_replay_eof != 0)
			zp->z_size = zfsvfs->z_replay_eof;

		error = sa_bulk_update(zp->z_sa_hdl, bulk, count, tx);

		zfs_log_write(zilog, tx, TX_WRITE, zp, woff, tx_bytes, ioflag,
		    NULL, NULL);
		dmu_tx_commit(tx);

		if (error != 0)
			break;
		/* dmu_write_uio should have done nbytes of work */
		ASSERT3S(tx_bytes, ==, nbytes);
		n -= nbytes;
		/* loop around and try to commit another fraction of our write call */
	}

	// n could be nonzero, we are allowed to do partial writes by VNOP_WRITE rules
	printf("ZFS: %s:%d (old_style) done remainder %lu\n", __func__, __LINE__,  n);

	zfs_range_unlock(rl);

	/*
	 * If we're in replay mode, or we made no progress, return error.
	 * Otherwise, it's at least a partial write, so it's successful.
	 */
	if (zfsvfs->z_replay || uio_resid(uio) == start_resid) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	boolean_t do_ubc_sync = B_FALSE;
	if (ioflag & (FSYNC | FDSYNC) ||
	    zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS) {
		zil_commit(zilog, zp->z_id);
		do_ubc_sync = B_TRUE;
	}

	/*
	 * OS X: pageout requires that the UBC file size be current.
	 * Note: we may have done the ubc_setsize above already in the event that
	 *       the file had UBC data associated with it in the first
	 *       place.
	 *       However, we have not yet done a ubc_msync, so let's do that now.
	 */
        if (tx_bytes != 0) {
		boolean_t need_release = B_FALSE, need_upgrade = B_FALSE;
		uint64_t tries = z_map_rw_lock(zp, &need_release, &need_upgrade, __func__);
		ASSERT3S(zp->z_size, >=, ubc_getsize(vp));
		ASSERT3S(zp->z_size, >=, ubcsize_at_entry);
                int setsize_retval = ubc_setsize(vp, zp->z_size);
		z_map_drop_lock(zp, &need_release, &need_upgrade);
		ASSERT3S(tries, <=, 2);
		ASSERT3S(setsize_retval, !=, 0); // ubc_setsize returns true on success

		if (vnode_isreg(vp)) {
			int ubc_msync_err = 0;
			off_t resid_off = 0;
			off_t ubcsize = ubc_getsize(vp);
			int clean_before = is_file_clean(vp, ubcsize);
			if (clean_before != 0) {
				ASSERT3U(ubcsize, >, 0);
				int flag = UBC_PUSHDIRTY;
				if (spl_ubc_is_mapped(vp, NULL))
					flag = UBC_PUSHDIRTY | UBC_SYNC;
				if (do_ubc_sync == B_TRUE)
					flag |= UBC_SYNC;
				boolean_t need_release = B_FALSE, need_upgrade = B_FALSE;
				uint64_t tries = z_map_rw_lock(zp, &need_release, &need_upgrade, __func__);
				ubc_msync_err = zfs_ubc_msync(vp, 0, ubc_getsize(vp), &resid_off, flag);
				z_map_drop_lock(zp, &need_release, &need_upgrade);
				ASSERT3S(tries, <=, 2);
				VNOPS_STAT_BUMP(zfs_write_msync);
				if (ubc_msync_err != 0 &&
				    !(ubc_msync_err == EINVAL && resid_off == ubcsize)) {
					/* we can get back spurious EINVALs here even though the full
					   amount has been pushed */
					printf("ZFS: %s:%d: ubc_msync returned error %d resid_off %lld"
					    " ubcsize was %lld (sync == %d) (dirty before, after %d, %d)\n",
					    __func__, __LINE__, ubc_msync_err, resid_off, ubcsize,
					    do_ubc_sync, clean_before, is_file_clean(vp, ubcsize));
				}
			}
		}
        }

	ZFS_EXIT(zfsvfs);
	return (0);
}

void
zfs_get_done(zgd_t *zgd, int error)
{
	//znode_t *zp = zgd->zgd_private;
	//objset_t *os = zp->z_zfsvfs->z_os;

	if (zgd->zgd_db)
		dmu_buf_rele(zgd->zgd_db, zgd);

	zfs_range_unlock(zgd->zgd_rl);

	/*
	 * Release the vnode asynchronously as we currently have the
	 * txg stopped from syncing.
	 */
	/*
	 * We only need to release the vnode if zget took the path to call
	 * vnode_get() with already existing vnodes. If zget (would) call to
	 * allocate new vnode, we don't (ZGET_FLAG_WITHOUT_VNODE), and it is
	 * attached after zfs_get_data() is finished (and immediately released).
	 */
#if 0
	if (ZTOV(zp)) {
		printf("vn_rele_async\n");
		VN_RELE_ASYNC(ZTOV(zp), dsl_pool_vnrele_taskq(dmu_objset_pool(os)));
	}
#endif
	if (error == 0 && zgd->zgd_bp)
		zil_add_block(zgd->zgd_zilog, zgd->zgd_bp);

	kmem_free(zgd, sizeof (zgd_t));
}

#ifdef DEBUG
static int zil_fault_io = 0;
#endif

/*
 * Get data to generate a TX_WRITE intent log record.
 */
int
zfs_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio,
			 znode_t *zp, rl_t *rl)
{
	zfsvfs_t *zfsvfs = arg;
	objset_t *os = zfsvfs->z_os;
	uint64_t object = lr->lr_foid;
	uint64_t offset = lr->lr_offset;
	uint64_t size = lr->lr_length;
	dmu_buf_t *db;
	zgd_t *zgd;
	int error = 0;

	ASSERT(zio != NULL);
	ASSERT(size != 0);

#ifndef __APPLE__
	/*
	 * Nothing to do if the file has been removed
	 */
	if (zfs_zget(zfsvfs, object, &zp) != 0)
		return (SET_ERROR(ENOENT));
	if (zp->z_unlinked) {
		/*
		 * Release the vnode asynchronously as we currently have the
		 * txg stopped from syncing.
		 */
		VN_RELE_ASYNC(ZTOV(zp),
		    dsl_pool_vnrele_taskq(dmu_objset_pool(os)));
		return (SET_ERROR(ENOENT));
	}
#endif

	zgd = (zgd_t *)kmem_zalloc(sizeof (zgd_t), KM_SLEEP);
	zgd->zgd_zilog = zfsvfs->z_log;
	zgd->zgd_private = zp;
	zgd->zgd_rl = rl;

	/*
	 * Write records come in two flavors: immediate and indirect.
	 * For small writes it's cheaper to store the data with the
	 * log record (immediate); for large writes it's cheaper to
	 * sync the data and get a pointer to it (indirect) so that
	 * we don't have to write the data twice.
	 */
	if (buf != NULL) { /* immediate write */

#ifndef __APPLE__
		zgd->zgd_rl = zfs_range_lock(zp, offset, size, RL_READER);
#endif

		/* test for truncation needs to be done while range locked */
		if (offset >= zp->z_size) {
			error = SET_ERROR(ENOENT);
		} else {
			error = dmu_read(os, object, offset, size, buf,
			    DMU_READ_NO_PREFETCH);
		}
		ASSERT(error == 0 || error == ENOENT);
	} else { /* indirect write */
		/*
		 * Have to lock the whole block to ensure when it's
		 * written out and it's checksum is being calculated
		 * that no one can change the data. We need to re-check
		 * blocksize after we get the lock in case it's changed!
		 */
		for (;;) {
			uint64_t blkoff;
			size = zp->z_blksz;
			blkoff = ISP2(size) ? P2PHASE(offset, size) : offset;
			offset -= blkoff;
#ifndef __APPLE__
			zgd->zgd_rl = zfs_range_lock(zp, offset, size,
			    RL_READER);
#endif
			if (zp->z_blksz == size)
				break;
			offset += blkoff;
			zfs_range_unlock(zgd->zgd_rl);
		}
		/* test for truncation needs to be done while range locked */
		if (lr->lr_offset >= zp->z_size)
			error = SET_ERROR(ENOENT);
#ifdef DEBUG
		if (zil_fault_io) {
			error = SET_ERROR(EIO);
			zil_fault_io = 0;
		}
#endif
		if (error == 0)
			error = dmu_buf_hold(os, object, offset, zgd, &db,
			    DMU_READ_NO_PREFETCH);

		if (error == 0) {
			blkptr_t *bp = &lr->lr_blkptr;

			zgd->zgd_db = db;
			zgd->zgd_bp = bp;

			ASSERT(db->db_offset == offset);
			ASSERT(db->db_size == size);

			error = dmu_sync(zio, lr->lr_common.lrc_txg,
			    zfs_get_done, zgd);
			ASSERT(error || lr->lr_length <= size);

			/*
			 * On success, we need to wait for the write I/O
			 * initiated by dmu_sync() to complete before we can
			 * release this dbuf.  We will finish everything up
			 * in the zfs_get_done() callback.
			 */
			if (error == 0)
				return (0);

			if (error == EALREADY) {
				lr->lr_common.lrc_txtype = TX_WRITE2;
				error = 0;
			}
		}
	}

	zfs_get_done(zgd, error);

	return (error);
}

/*ARGSUSED*/
int
zfs_access(vnode_t *vp, int mode, int flag, cred_t *cr,
    caller_context_t *ct)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	if (flag & V_ACE_MASK)
		error = zfs_zaccess(zp, mode, flag, B_FALSE, cr);
	else
		error = zfs_zaccess_rwx(zp, mode, flag, cr);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * If vnode is for a device return a specfs vnode instead.
 */
static int
specvp_check(vnode_t **vpp, cred_t *cr)
{
	int error = 0;

	if (IS_DEVVP(*vpp)) {
#ifndef __APPLE__
		struct vnode *svp;
		svp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type, cr);
		VN_RELE(*vpp);
		if (svp == NULL)
			error = (ENOSYS);
		*vpp = svp;
#endif
	}
	return (error);
}


/*
 * Lookup an entry in a directory, or an extended attribute directory.
 * If it exists, return a held vnode reference for it.
 *
 *	IN:	dvp	- vnode of directory to search.
 *		nm	- name of entry to lookup.
 *		pnp	- full pathname to lookup [UNUSED].
 *		flags	- LOOKUP_XATTR set if looking for an attribute.
 *		rdir	- root directory vnode [UNUSED].
 *		cr	- credentials of caller.
 *		ct	- caller context
 *		direntflags - directory lookup flags
 *		realpnp - returned pathname.
 *
 *	OUT:	vpp	- vnode of located entry, NULL if not found.
 *
 *	RETURN:	0 on success, error code on failure.
 *
 * Timestamps:
 *	NA
 */
/* ARGSUSED */
int
zfs_lookup(vnode_t *dvp, char *nm, vnode_t **vpp, struct componentname *cnp,
    int nameiop, cred_t *cr, int flags)
{
	znode_t *zdp = VTOZ(dvp);
	zfsvfs_t *zfsvfs = zdp->z_zfsvfs;
	int	error = 0;
	int *direntflags = NULL;
	void *realpnp = NULL;

#ifndef __APPLE__
	/* fast path */
	if (!(flags & (LOOKUP_XATTR | FIGNORECASE))) {

		if (dvp->v_type != VDIR) {
			return (SET_ERROR(ENOTDIR));
		} else if (zdp->z_sa_hdl == NULL) {
			return (SET_ERROR(EIO));
		}

		if (nm[0] == 0 || (nm[0] == '.' && nm[1] == '\0')) {
			error = zfs_fastaccesschk_execute(zdp, cr);
			if (!error) {
				*vpp = dvp;
				VN_HOLD(*vpp);
				return (0);
			}
			return (error);
		} else if (!zdp->z_zfsvfs->z_norm &&
		    (zdp->z_zfsvfs->z_case == ZFS_CASE_SENSITIVE)) {

			vnode_t *tvp = dnlc_lookup(dvp, nm);

			if (tvp) {
				error = zfs_fastaccesschk_execute(zdp, cr);
				if (error) {
					VN_RELE(tvp);
					return (error);
				}
				if (tvp == DNLC_NO_VNODE) {
					VN_RELE(tvp);
					return (SET_ERROR(ENOENT));
				} else {
					*vpp = tvp;
					return (specvp_check(vpp, cr));
				}
			}
		}
	}
#endif
	DTRACE_PROBE2(zfs__fastpath__lookup__miss, vnode_t *, dvp, char *, nm);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zdp);

	*vpp = NULL;


#ifndef __APPLE__
	if (flags & LOOKUP_XATTR) {
#ifdef TODO
		/*
		 * If the xattr property is off, refuse the lookup request.
		 */
		if (!(zfsvfs->z_vfs->vfs_flag & VFS_XATTR)) {
			ZFS_EXIT(zfsvfs);
			return ((EINVAL));
		}
#endif

		/*
		 * We don't allow recursive attributes..
		 * Maybe someday we will.
		 */
		if (zdp->z_pflags & ZFS_XATTR) {
			ZFS_EXIT(zfsvfs);
			return (SET_ERROR(EINVAL));
		}

		if (error = zfs_get_xattrdir(VTOZ(dvp), vpp, cr, flags)) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}

		/*
		 * Do we have permission to get into attribute directory?
		 */

		if (error = zfs_zaccess(VTOZ(*vpp), ACE_EXECUTE, 0,
		    B_FALSE, cr)) {
			VN_RELE(*vpp);
			*vpp = NULL;
		}

		ZFS_EXIT(zfsvfs);
		return (error);
	}
#endif


	if (!vnode_isdir(dvp)) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(ENOTDIR));
	}

	/*
	 * Check accessibility of directory.
	 */

	if ((error = zfs_zaccess(zdp, ACE_EXECUTE, 0, B_FALSE, cr))) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (zfsvfs->z_utf8 && u8_validate(nm, strlen(nm),
	    NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EILSEQ));
	}

	error = zfs_dirlook(zdp, nm, vpp, flags, direntflags, realpnp);
	if (error == 0)
		error = specvp_check(vpp, cr);

	/* Translate errors and add SAVENAME when needed. */
	if (cnp->cn_flags & ISLASTCN) {
		switch (nameiop) {
		case CREATE:
		case RENAME:
			if (error == ENOENT) {
				error = EJUSTRETURN;
				//cnp->cn_flags |= SAVENAME;
				break;
			}
			/* FALLTHROUGH */
		case DELETE:
			if (error == 0)
				;//cnp->cn_flags |= SAVENAME;
			break;
		}
	}
	if (error == 0 && (nm[0] != '.' || nm[1] != '\0')) {
		int ltype = 0;

#ifndef __APPLE__
		if (cnp->cn_flags & ISDOTDOT) {
			ltype = VOP_ISLOCKED(dvp);
			VOP_UNLOCK(dvp, 0);
		}
#endif
		ZFS_EXIT(zfsvfs);
		error = zfs_vnode_lock(*vpp, 0/*cnp->cn_lkflags*/);
		if (cnp->cn_flags & ISDOTDOT)
			vn_lock(dvp, ltype | LK_RETRY);
		if (error != 0) {
			VN_RELE(*vpp);
			*vpp = NULL;
			return (error);
		}
	} else {
		ZFS_EXIT(zfsvfs);
	}

#if defined (FREEBSD_NAMECACHE)
	/*
	 * Insert name into cache (as non-existent) if appropriate.
	 */
	if (error == ENOENT && (cnp->cn_flags & MAKEENTRY) && nameiop != CREATE)
		cache_enter(dvp, *vpp, cnp);
	/*
	 * Insert name into cache if appropriate.
	 */
	if (error == 0 && (cnp->cn_flags & MAKEENTRY)) {
		if (!(cnp->cn_flags & ISLASTCN) ||
		    (nameiop != DELETE && nameiop != RENAME)) {
			cache_enter(dvp, *vpp, cnp);
		}
	}
#endif

	return (error);
}

/*
 * Attempt to create a new entry in a directory.  If the entry
 * already exists, truncate the file if permissible, else return
 * an error.  Return the vp of the created or trunc'd file.
 *
 *	IN:	dvp	- vnode of directory to put new file entry in.
 *		name	- name of new file entry.
 *		vap	- attributes of new file.
 *		excl	- flag indicating exclusive or non-exclusive mode.
 *		mode	- mode to open file with.
 *		cr	- credentials of caller.
 *		flag	- large file flag [UNUSED].
 *		ct	- caller context
 *		vsecp 	- ACL to be set
 *
 *	OUT:	vpp	- vnode of created or trunc'd entry.
 *
 *	RETURN:	0 on success, error code on failure.
 *
 * Timestamps:
 *	dvp - ctime|mtime updated if new entry created
 *	 vp - ctime|mtime always, atime if new
 */

/* ARGSUSED */
int
zfs_create(vnode_t *dvp, char *name, vattr_t *vap, int excl, int mode,
    vnode_t **vpp, cred_t *cr)
{
	znode_t		*zp, *dzp = VTOZ(dvp);
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog;
	objset_t	*os;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	int		error;
	ksid_t		*ksid;
	uid_t		uid;
	gid_t		gid = crgetgid(cr);
	zfs_acl_ids_t   acl_ids;
	boolean_t	fuid_dirtied;
	boolean_t	have_acl = B_FALSE;
	void		*vsecp = NULL;
	int		flag = 0;
	boolean_t	waited = B_FALSE;

	/*
	 * If we have an ephemeral id, ACL, or XVATTR then
	 * make sure file system is at proper version
	 */

	ksid = crgetsid(cr, KSID_OWNER);
	if (ksid)
		uid = ksid_getid(ksid);
	else
		uid = crgetuid(cr);

	if (zfsvfs->z_use_fuids == B_FALSE &&
	    (vsecp || (vap->va_mask & AT_XVATTR) ||
	    IS_EPHEMERAL(uid) || IS_EPHEMERAL(gid)))
		return (SET_ERROR(EINVAL));

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(dzp);
	os = zfsvfs->z_os;
	zilog = zfsvfs->z_log;

	if (zfsvfs->z_utf8 && u8_validate(name, strlen(name),
	    NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EILSEQ));
	}

	if (vap->va_mask & AT_XVATTR) {
		if ((error = secpolicy_xvattr(dvp, vap,
		    crgetuid(cr), cr, vap->va_type)) != 0) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}
	}
top:
	*vpp = NULL;

	if ((vap->va_mode & S_ISVTX) && secpolicy_vnode_stky_modify(cr))
		vap->va_mode &= ~S_ISVTX;

	if (*name == '\0') {
		/*
		 * Null component name refers to the directory itself.
		 */
		VN_HOLD(dvp);
		zp = dzp;
		dl = NULL;
		error = 0;
	} else {
		/* possible VN_HOLD(zp) */
		int zflg = 0;

		if (flag & FIGNORECASE)
			zflg |= ZCILOOK;

		error = zfs_dirent_lock(&dl, dzp, name, &zp, zflg,
		    NULL, NULL);
		if (error) {
			if (have_acl)
				zfs_acl_ids_free(&acl_ids);
			if (strcmp(name, "..") == 0)
				error = SET_ERROR(EISDIR);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
	}

	if (zp == NULL) {
		uint64_t txtype;

		/*
		 * Create a new file object and update the directory
		 * to reference it.
		 */
		if ((error = zfs_zaccess(dzp, ACE_ADD_FILE, 0, B_FALSE, cr))) {
			if (have_acl)
				zfs_acl_ids_free(&acl_ids);
			goto out;
		}

		/*
		 * We only support the creation of regular files in
		 * extended attribute directories.
		 */

		if ((dzp->z_pflags & ZFS_XATTR) &&
		    (vap->va_type != VREG)) {
			if (have_acl)
				zfs_acl_ids_free(&acl_ids);
			error = SET_ERROR(EINVAL);
			goto out;
		}

		if (!have_acl && (error = zfs_acl_ids_create(dzp, 0, vap,
		    cr, vsecp, &acl_ids)) != 0)
			goto out;
		have_acl = B_TRUE;

		if (zfs_acl_ids_overquota(zfsvfs, &acl_ids)) {
			zfs_acl_ids_free(&acl_ids);
			error = SET_ERROR(EDQUOT);
			goto out;
		}

		tx = dmu_tx_create(os);

		dmu_tx_hold_sa_create(tx, acl_ids.z_aclp->z_acl_bytes +
		    ZFS_SA_BASE_ATTR_SIZE);

		fuid_dirtied = zfsvfs->z_fuid_dirty;
		if (fuid_dirtied)
			zfs_fuid_txhold(zfsvfs, tx);
		dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
		dmu_tx_hold_sa(tx, dzp->z_sa_hdl, B_FALSE);
		if (!zfsvfs->z_use_sa &&
		    acl_ids.z_aclp->z_acl_bytes > ZFS_ACE_SPACE) {
			dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
			    0, acl_ids.z_aclp->z_acl_bytes);
		}
		error = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
		if (error) {
			zfs_dirent_unlock(dl);
			if (error == ERESTART) {
				waited = B_TRUE;
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				goto top;
			}
			zfs_acl_ids_free(&acl_ids);
			dmu_tx_abort(tx);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		zfs_mknode(dzp, vap, tx, cr, 0, &zp, &acl_ids);

		if (fuid_dirtied)
			zfs_fuid_sync(zfsvfs, tx);

		(void) zfs_link_create(dl, zp, tx, ZNEW);
		txtype = zfs_log_create_txtype(Z_FILE, vsecp, vap);
		if (flag & FIGNORECASE)
			txtype |= TX_CI;
		zfs_log_create(zilog, tx, txtype, dzp, zp, name,
		    vsecp, acl_ids.z_fuidp, vap);
		zfs_acl_ids_free(&acl_ids);
		dmu_tx_commit(tx);

		/*
		 * OS X - attach the vnode _after_ committing the transaction
		 */
		zfs_znode_getvnode(zp, zfsvfs);

	} else {
		int aflags = (flag & FAPPEND) ? V_APPEND : 0;

		if (have_acl)
			zfs_acl_ids_free(&acl_ids);
		have_acl = B_FALSE;

		/*
		 * A directory entry already exists for this name.
		 */
		/*
		 * Can't truncate an existing file if in exclusive mode.
		 */
		if (excl) {
			error = SET_ERROR(EEXIST);
			goto out;
		}
		/*
		 * Can't open a directory for writing.
		 */
		if ((vnode_isdir(ZTOV(zp))) && (mode & S_IWRITE)) {
			error = SET_ERROR(EISDIR);
			goto out;
		}
		/*
		 * Verify requested access to file.
		 */
		if (mode && (error = zfs_zaccess_rwx(zp, mode, aflags, cr))) {
			goto out;
		}

		mutex_enter(&dzp->z_lock);
		dzp->z_seq++;
		mutex_exit(&dzp->z_lock);

		/*
		 * Truncate regular files if requested.
		 */
		if ((vnode_isreg(ZTOV(zp))) &&
		    (vap->va_mask & AT_SIZE) && (vap->va_size == 0)) {
			/* we can't hold any locks when calling zfs_freesp() */
			zfs_dirent_unlock(dl);
			dl = NULL;
			error = zfs_freesp(zp, 0, 0, mode, TRUE);
			if (error == 0) {
				vnevent_create(ZTOV(zp), ct);
			}
		}
	}
out:
	if (dl)
		zfs_dirent_unlock(dl);

	if (error) {
		if (zp)
			VN_RELE(ZTOV(zp));
	} else {
		*vpp = ZTOV(zp);
		error = specvp_check(vpp, cr);
	}

	if (zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		zil_commit(zilog, 0);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Remove an entry from a directory.
 *
 *	IN:	dvp	- vnode of directory to remove entry from.
 *		name	- name of entry to remove.
 *		cr	- credentials of caller.
 *		ct	- caller context
 *		flags	- case flags
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime
 *	 vp - ctime (if nlink > 0)
 */

uint64_t null_xattr = 0;

/*ARGSUSED*/
int
zfs_remove(vnode_t *dvp, char *name, cred_t *cr, caller_context_t *ct,
    int flags)
{
	znode_t		*zp, *dzp = VTOZ(dvp);
	znode_t		*xzp;
	vnode_t		*vp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog;
	uint64_t	acl_obj, xattr_obj;
	uint64_t 	xattr_obj_unlinked = 0;
	uint64_t	obj = 0;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	boolean_t	may_delete_now = FALSE, delete_now = FALSE;
	boolean_t	unlinked, toobig = FALSE;
	uint64_t	txtype;
	pathname_t	*realnmp = NULL;
	pathname_t	realnm;
	int		error;
	int		zflg = ZEXISTS;
	boolean_t	waited = B_FALSE;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(dzp);
	zilog = zfsvfs->z_log;

	if (flags & FIGNORECASE) {
		zflg |= ZCILOOK;
		pn_alloc(&realnm);
		realnmp = &realnm;
	}

top:
	xattr_obj = 0;
	xzp = NULL;
	/*
	 * Attempt to lock directory; fail if entry doesn't exist.
	 */
	if ((error = zfs_dirent_lock(&dl, dzp, name, &zp, zflg,
                                 NULL, realnmp))) {
		if (realnmp)
			pn_free(realnmp);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	vp = ZTOV(zp);

	if ((error = zfs_zaccess_delete(dzp, zp, cr))) {
		goto out;
	}

	/*
	 * Need to use rmdir for removing directories.
	 */
	if (vnode_isdir(vp)) {
		error = SET_ERROR(EPERM);
		goto out;
	}

	vnevent_remove(vp, dvp, name, ct);

	if (realnmp)
		dnlc_remove(dvp, realnmp->pn_buf);
	else
		dnlc_remove(dvp, name);
	/*
	 * On Mac OSX, we lose the option of having this optimization because
	 * the VFS layer holds the last reference on the vnode whereas in
	 * Solaris this code holds the last ref.  Hence, it's sketchy
	 * business(not to mention hackish) to start deleting the znode
	 * and clearing out the vnode when the VFS still has a reference
	 * open on it, even though it's dropping it shortly.
	 */
#ifdef __APPLE__
	may_delete_now = !vnode_isinuse(vp, 0) && !vn_has_cached_data(vp);

	if (may_delete_now && ubc_pages_resident(vp) != 0) {
		// zfs_unlinked_drain's zfs_zget may bring in pages
		// we should report and invalidate any
		dprintf("ZFS: %s:%d: may_delete_now but ubc_pages_resident is true (z_drain %d) file %s\n",
		    __func__, __LINE__, zp->z_drain, zp->z_name_cache);
		int inval_err = ubc_invalidate_range(vp, 0, ubc_getsize(vp));
		ASSERT3S(inval_err, ==, 0);
		ASSERT0(is_file_clean(vp, ubc_getsize(vp))); // is_file_clean is 0 if clean
		ASSERT0(vnode_isinuse(vp, 0));
		if (is_file_clean(vp, ubc_getsize(vp)) != 0 || vnode_isinuse(vp, 0))
			may_delete_now = 0;
	}
#else
	VI_LOCK(vp);
	may_delete_now = vp->v_count == 1 && !vn_has_cached_data(vp) && !spl_ubc_is_mapped(vp, NULL);
	VI_UNLOCK(vp);
#endif

#ifdef LINUX
	mutex_enter(&zp->z_lock);
	may_delete_now = atomic_read(&ip->i_count) == 1 && !(zp->z_is_mapped); // LINUX
	mutex_exit(&zp->z_lock);
#endif

	/*
	 * We may delete the znode now, or we may put it in the unlinked set;
	 * it depends on whether we're the last link, and on whether there are
	 * other holds on the vnode.  So we dmu_tx_hold() the right things to
	 * allow for either case.
	 */
	obj = zp->z_id;
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, name);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	zfs_sa_upgrade_txholds(tx, zp);
	zfs_sa_upgrade_txholds(tx, dzp);
	if (may_delete_now) {
		toobig =
		    zp->z_size > zp->z_blksz * DMU_MAX_DELETEBLKCNT;
		/* if the file is too big, only hold_free a token amount */
		dmu_tx_hold_free(tx, zp->z_id, 0,
		    (toobig ? DMU_MAX_ACCESS : DMU_OBJECT_END));
	}

	/* are there any extended attributes? */
	error = sa_lookup(zp->z_sa_hdl, SA_ZPL_XATTR(zfsvfs),
	    &xattr_obj, sizeof (xattr_obj));
	if (error == 0 && xattr_obj) {
		error = zfs_zget(zfsvfs, xattr_obj, &xzp);
		ASSERT(error==0);
		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_TRUE);
		dmu_tx_hold_sa(tx, xzp->z_sa_hdl, B_FALSE);
	}

	mutex_enter(&zp->z_lock);
	if ((acl_obj = zfs_external_acl(zp)) != 0 && may_delete_now)
		dmu_tx_hold_free(tx, acl_obj, 0, DMU_OBJECT_END);
	mutex_exit(&zp->z_lock);

	/* charge as an update -- would be nice not to charge at all */
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);

	/*
	 * Mark this transaction as typically resulting in a net free of
	 * space, unless object removal will be delayed indefinitely
	 * (due to active holds on the vnode due to the file being open).
	 */
	if (may_delete_now)
		dmu_tx_mark_netfree(tx);

	/*
	 * Mark this transaction as typically resulting in a net free of space
	 */
	dmu_tx_mark_netfree(tx);

	error = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
	if (error) {
		zfs_dirent_unlock(dl);
		VN_RELE(vp);
		if (xzp)
			VN_RELE(ZTOV(xzp));
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		if (realnmp)
			pn_free(realnmp);
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * Remove the directory entry.
	 */
	error = zfs_link_destroy(dl, zp, tx, zflg, &unlinked);

	if (error) {
		dmu_tx_commit(tx);
		goto out;
	}

	if (unlinked) {
		/*
		 * Hold z_lock so that we can make sure that the ACL obj
		 * hasn't changed.  Could have been deleted due to
		 * zfs_sa_upgrade().
		 */
		mutex_enter(&zp->z_lock);
#ifndef __APPLE__
		VI_LOCK(vp);
#endif
		(void) sa_lookup(zp->z_sa_hdl, SA_ZPL_XATTR(zfsvfs),
		    &xattr_obj_unlinked, sizeof (xattr_obj_unlinked));
		delete_now = may_delete_now && !toobig &&
		    !vnode_isinuse(vp,0) && !vn_has_cached_data(vp) &&
		    xattr_obj == xattr_obj_unlinked && zfs_external_acl(zp) ==
		    acl_obj;
#ifndef __APPLE__
		VI_UNLOCK(vp);
#else
		IMPLY(delete_now, (is_file_clean(vp, ubc_getsize(vp)) == 0));
#endif
	}

	dprintf("vnop_remove: may_delete_now is %d, delete_now %d\n",
		   may_delete_now, delete_now);

	if (delete_now) {
		if (xattr_obj_unlinked) {
			ASSERT3U(xzp->z_links, ==, 2);
			mutex_enter(&xzp->z_lock);
			xzp->z_unlinked = 1;
			xzp->z_links = 0;
			error = sa_update(xzp->z_sa_hdl, SA_ZPL_LINKS(zfsvfs),
			    &xzp->z_links, sizeof (xzp->z_links), tx);
			ASSERT3U(error,  ==,  0);
			mutex_exit(&xzp->z_lock);
			zfs_unlinked_add(xzp, tx);

			if (zp->z_is_sa)
				error = sa_remove(zp->z_sa_hdl,
				    SA_ZPL_XATTR(zfsvfs), tx);
			else
				error = sa_update(zp->z_sa_hdl,
				    SA_ZPL_XATTR(zfsvfs), &null_xattr,
				    sizeof (uint64_t), tx);
			ASSERT(error==0);
		}

#ifndef __APPLE__
		VI_LOCK(vp);
		vp->v_count--;
		ASSERT0(vp->v_count);
		VI_UNLOCK(vp);
#endif
		mutex_exit(&zp->z_lock);
		/* modify this under the lock to avoid interfering
		 * with mappedread_new etc
		 */
#if 0
		boolean_t need_release = B_FALSE, need_upgrade = B_FALSE;
		uint64_t tries = z_map_rw_lock(zp, &need_release, &need_upgrade, __func__);
		int setsize_retval;
		if (ubc_getsize(vp) != 0)
			setsize_retval = ubc_setsize(vp, 0);
		else
			setsize_retval = 1;
		z_map_drop_lock(zp, &need_release, &need_upgrade);
		ASSERT3S(tries, <=, 2);
		ASSERT3S(setsize_retval, !=, 0); // setsize returns true on success
#endif
		VN_RELE(vp);
		/*
		 * Call recycle which will call vnop_reclaim directly if it can
		 * so tell reclaim to not do anything with this node, so we can
		 * release it directly. If recycle/reclaim didn't work out, defer
		 * it by placing it on the unlinked list.
		 */

		zp->z_fastpath = B_TRUE;
		if (vnode_recycle(vp) == 1) {
			/* recycle/reclaim is done, so we can just release now */
			zfs_znode_delete(zp, tx);
		} else {
			/* failed to recycle, so just place it on the unlinked list */
			zp->z_fastpath = B_FALSE;
			zfs_unlinked_add(zp, tx);
		}
		vp = NULL;
		zp = NULL;

	} else if (unlinked) {
		mutex_exit(&zp->z_lock);
		zfs_unlinked_add(zp, tx);
	}

	txtype = TX_REMOVE;
	if (flags & FIGNORECASE)
		txtype |= TX_CI;
	zfs_log_remove(zilog, tx, txtype, dzp, name, obj);

	dmu_tx_commit(tx);
out:
	if (realnmp)
		pn_free(realnmp);

	zfs_dirent_unlock(dl);

    if (xzp) {
		VN_RELE(ZTOV(xzp));
		vnode_recycle(ZTOV(xzp));
	}
	if (!delete_now) {
		VN_RELE(vp);
	}
	if (zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		zil_commit(zilog, 0);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Create a new directory and insert it into dvp using the name
 * provided.  Return a pointer to the inserted directory.
 *
 *	IN:	dvp	- vnode of directory to add subdir to.
 *		dirname	- name of new directory.
 *		vap	- attributes of new directory.
 *		cr	- credentials of caller.
 *		ct	- caller context
 *		vsecp	- ACL to be set
 *
 *	OUT:	vpp	- vnode of created directory.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime updated
 *	 vp - ctime|mtime|atime updated
 */
/*ARGSUSED*/
int
zfs_mkdir(vnode_t *dvp, char *dirname, vattr_t *vap, vnode_t **vpp, cred_t *cr,
    caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	znode_t		*zp, *dzp = VTOZ(dvp);
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog;
	zfs_dirlock_t	*dl;
	uint64_t	txtype;
	dmu_tx_t	*tx;
	int		error;
	int		zf = ZNEW;
	ksid_t		*ksid;
	uid_t		uid;
	gid_t		gid = crgetgid(cr);
	zfs_acl_ids_t   acl_ids;
	boolean_t	fuid_dirtied;
	boolean_t	waited = B_FALSE;

	ASSERT(vap->va_type == VDIR);

	/*
	 * If we have an ephemeral id, ACL, or XVATTR then
	 * make sure file system is at proper version
	 */

	ksid = crgetsid(cr, KSID_OWNER);
	if (ksid)
		uid = ksid_getid(ksid);
	else
		uid = crgetuid(cr);

	if (zfsvfs->z_use_fuids == B_FALSE &&
	    (vsecp || IS_EPHEMERAL(uid) || IS_EPHEMERAL(gid)))
		return (SET_ERROR(EINVAL));

	if (zfsvfs->z_use_fuids == B_FALSE &&
	    (vsecp || (vap->va_mask & AT_XVATTR) ||
	    IS_EPHEMERAL(uid) || IS_EPHEMERAL(gid)))
		return ((EINVAL));

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(dzp);
	zilog = zfsvfs->z_log;

	if (dzp->z_pflags & ZFS_XATTR) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EINVAL));
	}

	if (zfsvfs->z_utf8 && u8_validate(dirname,
	    strlen(dirname), NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EILSEQ));
	}
	if (flags & FIGNORECASE)
		zf |= ZCILOOK;

	if (vap->va_mask & AT_XVATTR) {
		if ((error = secpolicy_xvattr(dvp, (vattr_t *)vap,
		    crgetuid(cr), cr, vap->va_type)) != 0) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}
	}

	if ((error = zfs_acl_ids_create(dzp, 0, vap, cr,
	    vsecp, &acl_ids)) != 0) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * First make sure the new directory doesn't exist.
	 *
	 * Existence is checked first to make sure we don't return
	 * EACCES instead of EEXIST which can cause some applications
	 * to fail.
	 */
top:
	*vpp = NULL;

	if ((error = zfs_dirent_lock(&dl, dzp, dirname, &zp, zf,
                                 NULL, NULL))) {
		zfs_acl_ids_free(&acl_ids);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if ((error = zfs_zaccess(dzp, ACE_ADD_SUBDIRECTORY, 0, B_FALSE, cr))) {
		zfs_acl_ids_free(&acl_ids);
		zfs_dirent_unlock(dl);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (zfs_acl_ids_overquota(zfsvfs, &acl_ids)) {
		zfs_acl_ids_free(&acl_ids);
		zfs_dirent_unlock(dl);
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EDQUOT));
	}

	/*
	 * Add a new entry to the directory.
	 */
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, dirname);
	dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, FALSE, NULL);
	fuid_dirtied = zfsvfs->z_fuid_dirty;
	if (fuid_dirtied)
		zfs_fuid_txhold(zfsvfs, tx);
	if (!zfsvfs->z_use_sa && acl_ids.z_aclp->z_acl_bytes > ZFS_ACE_SPACE) {
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0,
		    acl_ids.z_aclp->z_acl_bytes);
	}

	dmu_tx_hold_sa_create(tx, acl_ids.z_aclp->z_acl_bytes +
	    ZFS_SA_BASE_ATTR_SIZE);

	error = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		zfs_acl_ids_free(&acl_ids);
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * Create new node.
	 */
	zfs_mknode(dzp, vap, tx, cr, 0, &zp, &acl_ids);

	if (fuid_dirtied)
		zfs_fuid_sync(zfsvfs, tx);

	/*
	 * Now put new name in parent dir.
	 */
	(void) zfs_link_create(dl, zp, tx, ZNEW);

	*vpp = ZTOV(zp);

	txtype = zfs_log_create_txtype(Z_DIR, vsecp, vap);
	if (flags & FIGNORECASE)
		txtype |= TX_CI;
	zfs_log_create(zilog, tx, txtype, dzp, zp, dirname, vsecp,
	    acl_ids.z_fuidp, vap);

	zfs_acl_ids_free(&acl_ids);

	dmu_tx_commit(tx);

	/*
	 * OS X - attach the vnode _after_ committing the transaction
	 */
	zfs_znode_getvnode(zp, zfsvfs);
	*vpp = ZTOV(zp);

	zfs_dirent_unlock(dl);

	if (zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		zil_commit(zilog, 0);

	ZFS_EXIT(zfsvfs);
	return (0);
}

/*
 * Remove a directory subdir entry.  If the current working
 * directory is the same as the subdir to be removed, the
 * remove will fail.
 *
 *	IN:	dvp	- vnode of directory to remove from.
 *		name	- name of directory to be removed.
 *		cwd	- vnode of current working directory.
 *		cr	- credentials of caller.
 *		ct	- caller context
 *		flags	- case flags
 *
 *	RETURN:	0 on success, error code on failure.
 *
 * Timestamps:
 *	dvp - ctime|mtime updated
 */
/*ARGSUSED*/
int
zfs_rmdir(vnode_t *dvp, char *name, vnode_t *cwd, cred_t *cr,
    caller_context_t *ct, int flags)
{
	znode_t		*dzp = VTOZ(dvp);
	znode_t		*zp;
	vnode_t		*vp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	int		error;
	int		zflg = ZEXISTS;
	boolean_t	waited = B_FALSE;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(dzp);
	zilog = zfsvfs->z_log;

	if (flags & FIGNORECASE)
		zflg |= ZCILOOK;
top:
	zp = NULL;

	/*
	 * Attempt to lock directory; fail if entry doesn't exist.
	 */
	if ((error = zfs_dirent_lock(&dl, dzp, name, &zp, zflg,
                                 NULL, NULL))) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	vp = ZTOV(zp);

	if ((error = zfs_zaccess_delete(dzp, zp, cr))) {
		goto out;
	}

	if (!vnode_isdir(vp)) {
		error = SET_ERROR(ENOTDIR);
		goto out;
	}

	if (vp == cwd) {
		error = SET_ERROR(EINVAL);
		goto out;
	}

	vnevent_rmdir(vp, dvp, name, ct);

	/*
	 * Grab a lock on the directory to make sure that noone is
	 * trying to add (or lookup) entries while we are removing it.
	 */
	rw_enter(&zp->z_name_lock, RW_WRITER);

	/*
	 * Grab a lock on the parent pointer to make sure we play well
	 * with the treewalk and directory rename code.
	 */
	rw_enter(&zp->z_parent_lock, RW_WRITER);

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, name);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);
	zfs_sa_upgrade_txholds(tx, zp);
	zfs_sa_upgrade_txholds(tx, dzp);
	dmu_tx_mark_netfree(tx);
	error = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
	if (error) {
		rw_exit(&zp->z_parent_lock);
		rw_exit(&zp->z_name_lock);
		zfs_dirent_unlock(dl);
		VN_RELE(vp);
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

#if defined (FREEBSD_NAMECACHE)
	cache_purge(dvp);
#endif

	error = zfs_link_destroy(dl, zp, tx, zflg, NULL);

	if (error == 0) {
		uint64_t txtype = TX_RMDIR;
		if (flags & FIGNORECASE)
			txtype |= TX_CI;
		zfs_log_remove(zilog, tx, txtype, dzp, name, ZFS_NO_OBJECT);
	}

	dmu_tx_commit(tx);

	rw_exit(&zp->z_parent_lock);
	rw_exit(&zp->z_name_lock);
#if defined (FREEBSD_NAMECACHE)
	cache_purge(vp);
#endif
out:
	zfs_dirent_unlock(dl);

	VN_RELE(vp);

	if (zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		zil_commit(zilog, 0);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Read as many directory entries as will fit into the provided
 * buffer from the given directory cursor position (specified in
 * the uio structure.
 *
 *	IN:	vp	- vnode of directory to read.
 *		uio	- structure supplying read location, range info,
 *			  and return buffer.
 *		cr	- credentials of caller.
 *		ct	- caller context
 *		flags	- case flags
 *
 *	OUT:	uio	- updated offset and range, buffer filled.
 *		eofp	- set to true if end-of-file detected.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - atime updated
 *
 * Note that the low 4 bits of the cookie returned by zap is always zero.
 * This allows us to use the low range for "special" directory entries:
 * We use 0 for '.', and 1 for '..'.  If this is the root of the filesystem,
 * we use the offset 2 for the '.zfs' directory.
 */
/* ARGSUSED */
int
zfs_readdir(vnode_t *vp, uio_t *uio, cred_t *cr, int *eofp, int flags, int *a_numdirent)
{
	znode_t		*zp = VTOZ(vp);
#ifndef __APPLE__
	iovec_t		*iovp;
#endif
	dirent64_t	*eodp;
	dirent_t	*odp;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	objset_t	*os;
	caddr_t		outbuf;
	size_t		bufsize;
	zap_cursor_t	zc;
	zap_attribute_t	zap;
	uint_t		bytes_wanted;
	uint64_t	offset; /* must be unsigned; checks for < 1 */
	uint64_t	parent;
	int		local_eof;
	int		outcount;
	int		error;
	uint8_t		prefetch;
	boolean_t	check_sysattrs;
	uint8_t		type;
    boolean_t	extended = (flags & VNODE_READDIR_EXTENDED);
    int		numdirent = 0;
    char		*bufptr;
    boolean_t	isdotdir = B_TRUE;

    dprintf("+zfs_readdir (extended %d)\n", extended);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	if ((error = sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs),
	    &parent, sizeof (parent))) != 0) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * If we are not given an eof variable,
	 * use a local one.
	 */
	if (eofp == NULL)
		eofp = &local_eof;

	/*
	 * Check for valid iov_len.
	 */
	if (uio_curriovlen(uio) <= 0) {
		ZFS_EXIT(zfsvfs);
		return ((EINVAL));
	}

	/*
	 * Quit if directory has been removed (posix)
	 */
	if ((*eofp = zp->z_unlinked) != 0) {
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	error = 0;
	os = zfsvfs->z_os;
	offset = uio_offset(uio);
	prefetch = zp->z_zn_prefetch;

	/*
	 * Initialize the iterator cursor.
	 */
	if (offset <= 3) {
		/*
		 * Start iteration from the beginning of the directory.
		 */
		zap_cursor_init(&zc, os, zp->z_id);
	} else {
		/*
		 * The offset is a serialized cursor.
		 */
		zap_cursor_init_serialized(&zc, os, zp->z_id, offset);
	}

	/*
	 * Get space to change directory entries into fs independent format.
	 */
#ifdef __APPLE__
	bytes_wanted = uio_curriovlen(uio);
	bufsize = (size_t)bytes_wanted;
	outbuf = kmem_alloc(bufsize, KM_SLEEP);
	bufptr = (char *)outbuf;
#else
	iovp = uio_curriovbase(uio);
	bytes_wanted = iovp->iov_len;
	if (uio->uio_segflg != UIO_SYSSPACE || uio_iovcnt(uio) != 1) {
		bufsize = bytes_wanted;
		outbuf = kmem_alloc(bufsize, KM_SLEEP);
		odp = (struct dirent64 *)outbuf;
	} else {
		bufsize = bytes_wanted;
		outbuf = NULL;
		odp = (struct dirent64 *)iovp->iov_base;
	}
	eodp = (struct edirent *)odp;
#endif

	/*
	 * If this VFS supports the system attribute view interface; and
	 * we're looking at an extended attribute directory; and we care
	 * about normalization conflicts on this vfs; then we must check
	 * for normalization conflicts with the sysattr name space.
	 */
#ifdef TODO
	check_sysattrs = vfs_has_feature(vp->v_vfsp, VFSFT_SYSATTR_VIEWS) &&
	    (vp->v_flag & V_XATTRDIR) && zfsvfs->z_norm &&
	    (flags & V_RDDIR_ENTFLAGS);
#else
	check_sysattrs = 0;
#endif

	/*
	 * Transform to file-system independent format
	 */
	//zfsvfs->z_show_ctldir = ZFS_SNAPDIR_VISIBLE;

	outcount = 0;
	while (outcount < bytes_wanted) {
		ino64_t objnum;
		ushort_t reclen;
		uint64_t *next = NULL;
		uint8_t dtype;
		size_t namelen;
		int force_formd_normalized_output;
        size_t  nfdlen;


		/*
		 * Special case `.', `..', and `.zfs'.
		 */
		if (offset == 0) {
			(void) strlcpy(zap.za_name, ".", MAXNAMELEN);
			zap.za_normalization_conflict = 0;
			objnum = (zp->z_id == zfsvfs->z_root) ? 2 : zp->z_id;
			type = DT_DIR;
		} else if (offset == 1) {
			(void) strlcpy(zap.za_name, "..", MAXNAMELEN);
			zap.za_normalization_conflict = 0;
			objnum = (parent == zfsvfs->z_root) ? 2 : parent;
			objnum = (zp->z_id == zfsvfs->z_root) ? 1 : objnum;
			type = DT_DIR;
#if 1
		} else if (offset == 2 && zfs_show_ctldir(zp)) {
			(void) strlcpy(zap.za_name, ZFS_CTLDIR_NAME, MAXNAMELEN);
			zap.za_normalization_conflict = 0;
			objnum = ZFSCTL_INO_ROOT;
			type = DT_DIR;
#endif
		} else {
#ifdef __APPLE__
			/* This is not a special case directory */
			isdotdir = B_FALSE;
#endif /* __APPLE__ */

			/*
			 * Grab next entry.
			 */
			if ((error = zap_cursor_retrieve(&zc, &zap))) {
				if ((*eofp = (error == ENOENT)) != 0)
					break;
				else
					goto update;
			}

			if (zap.za_integer_length != 8 ||
			    zap.za_num_integers != 1) {
				cmn_err(CE_WARN, "zap_readdir: bad directory "
				    "entry, obj = %lld, offset = %lld\n",
				    (u_longlong_t)zp->z_id,
				    (u_longlong_t)offset);
				error = SET_ERROR(ENXIO);
				goto update;
			}

			objnum = ZFS_DIRENT_OBJ(zap.za_first_integer);
			/*
			 * MacOS X can extract the object type here such as:
			 * uint8_t type = ZFS_DIRENT_TYPE(zap.za_first_integer);
			 */
			type = ZFS_DIRENT_TYPE(zap.za_first_integer);

			if (check_sysattrs && !zap.za_normalization_conflict) {
#ifdef TODO
				zap.za_normalization_conflict =
				    xattr_sysattr_casechk(zap.za_name);
#else
				panic("%s:%u: TODO", __func__, __LINE__);
#endif
			}
		}

#ifndef __APPLE__
		if (flags & V_RDDIR_ACCFILTER) {
			/*
			 * If we have no access at all, don't include
			 * this entry in the returned information
			 */
			znode_t	*ezp;
			if (zfs_zget(zp->z_zfsvfs, objnum, &ezp) != 0)
				goto skip_entry;
			if (!zfs_has_access(ezp, cr)) {
				VN_RELE(ZTOV(ezp));
				goto skip_entry;
			}
			VN_RELE(ZTOV(ezp));
		}
#endif

#ifdef __APPLE__
		/* Extract the object type for OSX to use */
		if (isdotdir)
			dtype = DT_DIR;
		else
			dtype = ZFS_DIRENT_TYPE(zap.za_first_integer);

		/*
		 * Check if name will fit.
		 *
		 * Note: non-ascii names may expand (up to 3x) when converted to NFD
		 */
		namelen = strlen(zap.za_name);

		/* sysctl to force formD normalization of vnop output */
		if (zfs_vnop_force_formd_normalized_output &&
		    !is_ascii_str(zap.za_name))
			force_formd_normalized_output = 1;
		else
			force_formd_normalized_output = 0;

		if (force_formd_normalized_output)
			namelen = MIN(extended ? MAXPATHLEN-1 : MAXNAMLEN, namelen * 3);

		reclen = DIRENT_RECLEN(namelen, extended);
#else
		if (flags & V_RDDIR_ENTFLAGS)
			reclen = EDIRENT_RECLEN(strlen(zap.za_name));
		else
			reclen = DIRENT64_RECLEN(strlen(zap.za_name));
#endif

		/*
		 * Will this entry fit in the buffer?
		 */
		if (outcount + reclen > bufsize) {
			/*
			 * Did we manage to fit anything in the buffer?
			 */
			if (!outcount) {
				error = (EINVAL);
				goto update;
			}
			break;
		}

        //printf("readdir '%s' ext %d\n", zap.za_name, extended);

		if (extended) {
			/*
			 * Add extended flag entry:
			 */
			eodp = (dirent64_t  *)bufptr;
			/* NOTE: d_seekoff is the offset for the *next* entry */
			next = &(eodp->d_seekoff);
			eodp->d_ino = objnum;
			eodp->d_type = dtype;

			/*
			 * Mac OS X: non-ascii names are UTF-8 NFC on disk
			 * so convert to NFD before exporting them.
			 */
			namelen = strlen(zap.za_name);
			if (!force_formd_normalized_output ||
			    utf8_normalizestr((const u_int8_t *)zap.za_name, namelen,
			                      (u_int8_t *)eodp->d_name, &nfdlen,
			                      MAXPATHLEN-1, UTF_DECOMPOSED) != 0) {
				/* ASCII or normalization failed, just copy zap name. */
                if ((namelen > 0))
                    (void) bcopy(zap.za_name, eodp->d_name, namelen + 1);
			} else {
				/* Normalization succeeded (already in buffer). */
				namelen = nfdlen;
			}
			eodp->d_namlen = namelen;
			eodp->d_reclen = reclen = DIRENT_RECLEN(namelen, extended);

		} else {
			/*
			 * Add normal entry:
			 */

			odp = (dirent_t  *)bufptr;
			//odp = (dirent64_t  *)bufptr;
			odp->d_ino = objnum;
			odp->d_type = dtype;

			/*
			 * Mac OS X: non-ascii names are UTF-8 NFC on disk
			 * so convert to NFD before exporting them.
			 */
			namelen = strlen(zap.za_name);
			if (!force_formd_normalized_output ||
			    utf8_normalizestr((const u_int8_t *)zap.za_name, namelen,
			                      (u_int8_t *)odp->d_name, &nfdlen,
			                      MAXNAMLEN, UTF_DECOMPOSED) != 0) {
				/* ASCII or normalization failed, just copy zap name. */
                if ((namelen > 0))
                    (void) bcopy(zap.za_name, odp->d_name, namelen + 1);
			} else {
				/* Normalization succeeded (already in buffer). */
				namelen = nfdlen;
			}
			odp->d_namlen = namelen;
			odp->d_reclen = reclen = DIRENT_RECLEN(namelen, extended);
		}

		outcount += reclen;
		bufptr += reclen;
		numdirent++;

		ASSERT(outcount <= bufsize);

		/* Prefetch znode */
		if (prefetch)
			dmu_prefetch(os, objnum, 0, 0, 0, ZIO_PRIORITY_SYNC_READ);

		/*
		 * Move to the next entry, fill in the previous offset.
		 */
		if (offset > 2 || (offset == 2 && !zfs_show_ctldir(zp))) {
			zap_cursor_advance(&zc);
			offset = zap_cursor_serialize(&zc);
		} else {
			offset += 1;
		}

		if (extended)
            *next = offset;
	}
	zp->z_zn_prefetch = B_FALSE; /* a lookup will re-enable pre-fetching */


    if ((error = uiomove(outbuf, (long)outcount, UIO_READ, uio))) {
		/*
		 * Reset the pointer.
		 */
		offset = uio_offset(uio);
    }


update:
	zap_cursor_fini(&zc);
	if (outbuf) {
		kmem_free(outbuf, bufsize);
	}

	if (error == ENOENT)
		error = 0;

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	uio_setoffset(uio, offset);
	if (a_numdirent)
        *a_numdirent = numdirent;
	ZFS_EXIT(zfsvfs);

    dprintf("-zfs_readdir: num %d\n", numdirent);

	return (error);
}

ulong_t zfs_fsync_sync_cnt = 4;


int
zfs_fsync(vnode_t *vp, int syncflag, cred_t *cr, caller_context_t *ct)
{
        znode_t *zp = VTOZ(vp);
        zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	if (zfsvfs->z_os->os_sync == ZFS_SYNC_DISABLED) {
		VNOPS_STAT_BUMP(zfs_fsync_disabled);
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	if (!vnode_isreg(vp)) {
		dprintf("ZFS: %s:%d: not a regular file %s\n", __func__, __LINE__,
		    zp->z_name_cache);
		zil_commit(zfsvfs->z_log, zp->z_id);
		VNOPS_STAT_BUMP(zfs_fsync_non_isreg);
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	if (spl_ubc_is_mapped(vp, NULL) && is_file_clean(vp, ubc_getsize(vp))) {
		printf("ZFS: %s:%d: fsync called on mapped file (writable? %d) (dirty? %d)"
		    " (size %lld) %s\n",
		    __func__, __LINE__, spl_ubc_is_mapped_writable(vp),
		    is_file_clean(vp, ubc_getsize(vp)),
		    zp->z_size, zp->z_name_cache);
	}

	boolean_t do_zil_commit = B_FALSE;

	/*
	 * msync almost certainly won't do anything if the file is
	 * empty, wholly-nonresident, or clean now; otherwise it will
	 * almost certainly cause pageoutv2 to do a zil_commit.
	 *
	 */
	if (ubc_getsize(vp) == 0 || ubc_pages_resident(vp) == 0 ||
	    is_file_clean(vp, ubc_getsize(vp)) == 0) {
		// remember the semantics error = is_file_clean()
		// in particular is_file_clean is EINVAL if the
		// file has any dirty pages
		do_zil_commit = B_TRUE;
	}

	off_t resid_off = 0;
	int flags = UBC_PUSHALL | UBC_SYNC | ZFS_UBC_FORCE_MSYNC;
	int retval = zfs_ubc_msync(vp, 0, ubc_getsize(vp), &resid_off, flags);
	if (retval != 0) {
		printf("ZFS: %s:%d: error %d from force msync of (size %lld) file %s\n",
		    __func__, __LINE__, retval, zp->z_size, zp->z_name_cache);
		VNOPS_STAT_BUMP(zfs_ubc_msync_error);
	}

	VNOPS_STAT_BUMP(zfs_fsync_ubc_msync);
	if (do_zil_commit == B_TRUE) {
		VNOPS_STAT_BUMP(zfs_fsync_zil_commit_reg_vn);
		zil_commit(zfsvfs->z_log, zp->z_id);
	}
	ZFS_EXIT(zfsvfs);
        return (retval);
}

/*
 * Get the requested file attributes and place them in the provided
 * vattr structure.
 *
 *	IN:	vp	- vnode of file.
 *		vap	- va_mask identifies requested attributes.
 *			  If AT_XVATTR set, then optional attrs are requested
 *		flags	- ATTR_NOACLCHECK (CIFS server context)
 *		cr	- credentials of caller.
 *		ct	- caller context
 *
 *	OUT:	vap	- attribute values.
 *
 *	RETURN:	0 (always succeeds)
 */
/* ARGSUSED */
int
zfs_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int	error = 0;
#ifndef __APPLE__
	uint32_t blksize;
	u_longlong_t nblocks;
#endif
	uint64_t links;
	uint64_t mtime[2], ctime[2], crtime[2], rdev;
	xvattr_t *xvap = (xvattr_t *)vap;	/* vap may be an xvattr_t * */
	xoptattr_t *xoap = NULL;
	boolean_t skipaclchk = /*(flags & ATTR_NOACLCHECK) ? B_TRUE :*/ B_FALSE;
	sa_bulk_attr_t bulk[4];
	int count = 0;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	zfs_fuid_map_ids(zp, cr, &vap->va_uid, &vap->va_gid);

	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL, &mtime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL, &ctime, 16);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CRTIME(zfsvfs), NULL, &crtime, 16);
	if (vnode_isblk(vp) || vnode_ischr(vp))
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_RDEV(zfsvfs), NULL,
		    &rdev, 8);

	if ((error = sa_bulk_lookup(zp->z_sa_hdl, bulk, count)) != 0) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * If ACL is trivial don't bother looking for ACE_READ_ATTRIBUTES.
	 * Also, if we are the owner don't bother, since owner should
	 * always be allowed to read basic attributes of file.
	 */
	if (!(zp->z_pflags & ZFS_ACL_TRIVIAL) &&
	    (vap->va_uid != crgetuid(cr))) {
		if ((error = zfs_zaccess(zp, ACE_READ_ATTRIBUTES, 0,
                                 skipaclchk, cr))) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}
	}

	/*
	 * Return all attributes.  It's cheaper to provide the answer
	 * than to determine whether we were asked the question.
	 */

	mutex_enter(&zp->z_lock);
	vap->va_type = IFTOVT(zp->z_mode);
	vap->va_mode = zp->z_mode & ~S_IFMT;
#ifndef __APPLE__
#ifdef sun
	vap->va_fsid = zp->z_zfsvfs->z_vfs->vfs_dev;
#else
	vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];
#endif
#endif
	vap->va_nodeid = zp->z_id;
	if (vnode_isvroot((vp)) && zfs_show_ctldir(zp))
		links = zp->z_links + 1;
	else
		links = zp->z_links;
	vap->va_nlink = MIN(links, LINK_MAX);	/* nlink_t limit! */
	vap->va_size = zp->z_size;
#ifdef sun
	vap->va_rdev = vp->v_rdev;
#else
	if (vnode_isblk(vp) || vnode_ischr(vp))
		vap->va_rdev = zfs_cmpldev(rdev);
#endif
	//vap->va_seq = zp->z_seq;
	vap->va_flags = 0;	/* FreeBSD: Reset chflags(2) flags. */

	/*
	 * Add in any requested optional attributes and the create time.
	 * Also set the corresponding bits in the returned attribute bitmap.
	 */
	if ((xoap = xva_getxoptattr(xvap)) != NULL && zfsvfs->z_use_fuids) {
		if (XVA_ISSET_REQ(xvap, XAT_ARCHIVE)) {
			xoap->xoa_archive =
			    ((zp->z_pflags & ZFS_ARCHIVE) != 0);
			XVA_SET_RTN(xvap, XAT_ARCHIVE);
		}

		if (XVA_ISSET_REQ(xvap, XAT_READONLY)) {
			xoap->xoa_readonly =
			    ((zp->z_pflags & ZFS_READONLY) != 0);
			XVA_SET_RTN(xvap, XAT_READONLY);
		}

		if (XVA_ISSET_REQ(xvap, XAT_SYSTEM)) {
			xoap->xoa_system =
			    ((zp->z_pflags & ZFS_SYSTEM) != 0);
			XVA_SET_RTN(xvap, XAT_SYSTEM);
		}

		if (XVA_ISSET_REQ(xvap, XAT_HIDDEN)) {
			xoap->xoa_hidden =
			    ((zp->z_pflags & ZFS_HIDDEN) != 0);
			XVA_SET_RTN(xvap, XAT_HIDDEN);
		}

		if (XVA_ISSET_REQ(xvap, XAT_NOUNLINK)) {
			xoap->xoa_nounlink =
			    ((zp->z_pflags & ZFS_NOUNLINK) != 0);
			XVA_SET_RTN(xvap, XAT_NOUNLINK);
		}

		if (XVA_ISSET_REQ(xvap, XAT_IMMUTABLE)) {
			xoap->xoa_immutable =
			    ((zp->z_pflags & ZFS_IMMUTABLE) != 0);
			XVA_SET_RTN(xvap, XAT_IMMUTABLE);
		}

		if (XVA_ISSET_REQ(xvap, XAT_APPENDONLY)) {
			xoap->xoa_appendonly =
			    ((zp->z_pflags & ZFS_APPENDONLY) != 0);
			XVA_SET_RTN(xvap, XAT_APPENDONLY);
		}

		if (XVA_ISSET_REQ(xvap, XAT_NODUMP)) {
			xoap->xoa_nodump =
			    ((zp->z_pflags & ZFS_NODUMP) != 0);
			XVA_SET_RTN(xvap, XAT_NODUMP);
		}

		if (XVA_ISSET_REQ(xvap, XAT_OPAQUE)) {
			xoap->xoa_opaque =
			    ((zp->z_pflags & ZFS_OPAQUE) != 0);
			XVA_SET_RTN(xvap, XAT_OPAQUE);
		}

		if (XVA_ISSET_REQ(xvap, XAT_AV_QUARANTINED)) {
			xoap->xoa_av_quarantined =
			    ((zp->z_pflags & ZFS_AV_QUARANTINED) != 0);
			XVA_SET_RTN(xvap, XAT_AV_QUARANTINED);
		}

		if (XVA_ISSET_REQ(xvap, XAT_AV_MODIFIED)) {
			xoap->xoa_av_modified =
			    ((zp->z_pflags & ZFS_AV_MODIFIED) != 0);
			XVA_SET_RTN(xvap, XAT_AV_MODIFIED);
		}

		if (XVA_ISSET_REQ(xvap, XAT_AV_SCANSTAMP) &&
		    vnode_isreg(vp)) {
			zfs_sa_get_scanstamp(zp, xvap);
		}

		if (XVA_ISSET_REQ(xvap, XAT_CREATETIME)) {
			uint64_t times[2];

			(void) sa_lookup(zp->z_sa_hdl, SA_ZPL_CRTIME(zfsvfs),
			    times, sizeof (times));
			ZFS_TIME_DECODE(&xoap->xoa_createtime, times);
			XVA_SET_RTN(xvap, XAT_CREATETIME);
		}

		if (XVA_ISSET_REQ(xvap, XAT_REPARSE)) {
			xoap->xoa_reparse = ((zp->z_pflags & ZFS_REPARSE) != 0);
			XVA_SET_RTN(xvap, XAT_REPARSE);
		}
		if (XVA_ISSET_REQ(xvap, XAT_GEN)) {
			xoap->xoa_generation = zp->z_gen;
			XVA_SET_RTN(xvap, XAT_GEN);
		}

		if (XVA_ISSET_REQ(xvap, XAT_OFFLINE)) {
			xoap->xoa_offline =
			    ((zp->z_pflags & ZFS_OFFLINE) != 0);
			XVA_SET_RTN(xvap, XAT_OFFLINE);
		}

		if (XVA_ISSET_REQ(xvap, XAT_SPARSE)) {
			xoap->xoa_sparse =
			    ((zp->z_pflags & ZFS_SPARSE) != 0);
			XVA_SET_RTN(xvap, XAT_SPARSE);
		}
	}

	ZFS_TIME_DECODE(&vap->va_atime, zp->z_atime);
	ZFS_TIME_DECODE(&vap->va_mtime, mtime);
	ZFS_TIME_DECODE(&vap->va_ctime, ctime);
	ZFS_TIME_DECODE(&vap->va_crtime, crtime);

	mutex_exit(&zp->z_lock);

#ifdef __APPLE__

	/* If we are told to ignore owners, we scribble over the uid and gid here
	 * unless root.
	 */
	if (((unsigned int)vfs_flags(zfsvfs->z_vfs)) & MNT_IGNORE_OWNERSHIP) {
		if (kauth_cred_getuid(cr) != 0) {
			vap->va_uid = UNKNOWNUID;
			vap->va_gid = UNKNOWNGID;
		}
	}

#else
    uint64_t blksize, nblocks;

	sa_object_size(zp->z_sa_hdl, &blksize, &nblocks);
	vap->va_blksize = blksize;
	vap->va_bytes = nblocks << 9;	/* nblocks * 512 */

	if (zp->z_blksz == 0) {
		/*
		 * Block size hasn't been set; suggest maximal I/O transfers.
		 */
		vap->va_blksize = zfsvfs->z_max_blksz;
	}
#endif

	ZFS_EXIT(zfsvfs);
	return (0);
}

#ifdef LINUX
/*
 * Get the basic file attributes and place them in the provided kstat
 * structure.  The inode is assumed to be the authoritative source
 * for most of the attributes.  However, the znode currently has the
 * authoritative atime, blksize, and block count.
 *
 *	IN:	ip	- inode of file.
 *
 *	OUT:	sp	- kstat values.
 *
 *	RETURN:	0 (always succeeds)
 */
/* ARGSUSED */
int
zfs_getattr_fast(struct inode *ip, struct kstat *sp)
{
	znode_t *zp = ITOZ(ip);
	zfs_sb_t *zsb = ITOZSB(ip);
	uint32_t blksize;
	u_longlong_t nblocks;

	ZFS_ENTER(zsb);
	ZFS_VERIFY_ZP(zp);

	mutex_enter(&zp->z_lock);

	generic_fillattr(ip, sp);
	ZFS_TIME_DECODE(&sp->atime, zp->z_atime);

	sa_object_size(zp->z_sa_hdl, &blksize, &nblocks);
	sp->blksize = blksize;
	sp->blocks = nblocks;

	if (unlikely(zp->z_blksz == 0)) {
		/*
		 * Block size hasn't been set; suggest maximal I/O transfers.
		 */
		sp->blksize = zsb->z_max_blksz;
	}
}
#endif


/*
 * Set the file attributes to the values contained in the
 * vattr structure.
 *
 *	IN:	vp	- vnode of file to be modified.
 *		vap	- new attribute values.
 *			  If AT_XVATTR set, then optional attrs are being set
 *		flags	- ATTR_UTIME set if non-default time values provided.
 *			- ATTR_NOACLCHECK (CIFS context only).
 *		cr	- credentials of caller.
 *		ct	- caller context
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - ctime updated, mtime updated if size changed.
 */
/* ARGSUSED */
int
zfs_setattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog;
	dmu_tx_t	*tx;
	vattr_t		oldva;
	xvattr_t	*tmpxvattr;
	uint_t		mask = vap->va_mask;
	uint_t		saved_mask = 0;
	uint64_t	saved_mode;
	int		trim_mask = 0;
	uint64_t	new_mode;
	uint64_t	new_uid, new_gid;
	uint64_t	xattr_obj;
	uint64_t	mtime[2], ctime[2], crtime[2];
	znode_t		*attrzp;
	int		need_policy = FALSE;
	int		err, err2;
	zfs_fuid_info_t *fuidp = NULL;
	xvattr_t *xvap = (xvattr_t *)vap;	/* vap may be an xvattr_t * */
	xoptattr_t	*xoap;
	zfs_acl_t	*aclp;
	boolean_t skipaclchk = /*(flags & ATTR_NOACLCHECK) ? B_TRUE :*/ B_FALSE;
	boolean_t	fuid_dirtied = B_FALSE;
#define _NUM_BULK 10
	sa_bulk_attr_t	*bulk, *xattr_bulk;
	int		count = 0, xattr_count = 0;
	vsecattr_t      vsecattr;
	int seen_type = 0;
	int		aclbsize;	/* size of acl list in bytes */
	ace_t	*aaclp;
	struct kauth_acl *kauth;

	if (mask == 0)
		return (0);

	if (mask & AT_NOSET)
		return ((EINVAL));

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

    dprintf("+setattr: zp %p, vp %p\n", zp, vp);

	zilog = zfsvfs->z_log;

	/*
	 * Make sure that if we have ephemeral uid/gid or xvattr specified
	 * that file system is at proper version level
	 */

	if (zfsvfs->z_use_fuids == B_FALSE &&
	    (((mask & AT_UID) && IS_EPHEMERAL(vap->va_uid)) ||
	    ((mask & AT_GID) && IS_EPHEMERAL(vap->va_gid)) ||
	    (mask & AT_XVATTR))) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EINVAL));
	}

	if (mask & AT_SIZE && vnode_isdir(vp)) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EISDIR));
	}

	if (mask & AT_SIZE && !vnode_isreg(vp) && !vnode_isfifo(vp)) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EINVAL));
	}

	/*
	 * If this is an xvattr_t, then get a pointer to the structure of
	 * optional attributes.  If this is NULL, then we have a vattr_t.
	 */
	xoap = xva_getxoptattr(xvap);

	tmpxvattr = kmem_alloc(sizeof (xvattr_t), KM_SLEEP);
	xva_init(tmpxvattr);

	bulk = kmem_alloc(sizeof (sa_bulk_attr_t) * _NUM_BULK, KM_SLEEP);
	xattr_bulk = kmem_alloc(sizeof (sa_bulk_attr_t) * _NUM_BULK, KM_SLEEP);

	/*
	 * Immutable files can only alter immutable bit and atime
	 */
#ifndef __APPLE__
	if ((zp->z_pflags & ZFS_IMMUTABLE) &&
	    ((mask & (AT_SIZE|AT_UID|AT_GID|AT_MTIME|AT_MODE)) ||
	    ((mask & AT_XVATTR) && XVA_ISSET_REQ(xvap, XAT_CREATETIME)))) {
		err = SET_ERROR(EPERM);
		goto out3;
	}
#else
	//chflags uchg sends AT_MODE on OS X, so allow AT_MODE to be in the mask.
	if ((zp->z_pflags & ZFS_IMMUTABLE) &&
	    ((mask & (AT_SIZE|AT_UID|AT_GID|AT_MTIME)) ||
	    ((mask & AT_XVATTR) && XVA_ISSET_REQ(xvap, XAT_CREATETIME)))) {
		err = SET_ERROR(EPERM);
		goto out3;
	}
#endif

	/*
	 * Note: ZFS_READONLY is handled in zfs_zaccess_common.
	 */

	/*
	 * Verify timestamps doesn't overflow 32 bits.
	 * ZFS can handle large timestamps, but 32bit syscalls can't
	 * handle times greater than 2039.  This check should be removed
	 * once large timestamps are fully supported.
	 */

    /*
     * This test now hinders NFS from working as expected. Most like the
     * 32bit timestamp issues have already been fixed.
     */
#if 0
	if (mask & (AT_ATIME | AT_MTIME)) {
		if (((mask & AT_ATIME) && TIMESPEC_OVERFLOW(&vap->va_atime)) ||
		    ((mask & AT_MTIME) && TIMESPEC_OVERFLOW(&vap->va_mtime))) {
			err = SET_ERROR(EOVERFLOW);
			goto out3;
		}
	}
#endif

top:
	attrzp = NULL;
	aclp = NULL;

	/* Can this be moved to before the top label? */
	if (vfs_isrdonly(zfsvfs->z_vfs)) {
		err = SET_ERROR(EROFS);
		goto out3;
	}

	/*
	 * First validate permissions
	 */

        if (VATTR_IS_ACTIVE(vap, va_data_size)) {
                /*
                 * XXX - Note, we are not providing any open
                 * mode flags here (like FNDELAY), so we may
                 * block if there are locks present... this
                 * should be addressed in openat().
                 */
                /* XXX - would it be OK to generate a log record here? */
                err = zfs_freesp(zp, vap->va_size, 0, 0, FALSE);
                if (err) {
			goto out3;
		}

                VATTR_SET_SUPPORTED(vap, va_data_size);
        }

	if (mask & AT_SIZE) {
		err = zfs_zaccess(zp, ACE_WRITE_DATA, 0, skipaclchk, cr);
		if (err)
			goto out3;

		/*
		 * XXX - Note, we are not providing any open
		 * mode flags here (like FNDELAY), so we may
		 * block if there are locks present... this
		 * should be addressed in openat().
		 */
		/* XXX - would it be OK to generate a log record here? */
		err = zfs_freesp(zp, vap->va_size, 0, 0, FALSE);
		if (err)
			goto out3;
	}

	if (mask & (AT_ATIME|AT_MTIME) ||
	    ((mask & AT_XVATTR) && (XVA_ISSET_REQ(xvap, XAT_HIDDEN) ||
	    XVA_ISSET_REQ(xvap, XAT_READONLY) ||
	    XVA_ISSET_REQ(xvap, XAT_ARCHIVE) ||
	    XVA_ISSET_REQ(xvap, XAT_OFFLINE) ||
	    XVA_ISSET_REQ(xvap, XAT_SPARSE) ||
	    XVA_ISSET_REQ(xvap, XAT_CREATETIME) ||
	    XVA_ISSET_REQ(xvap, XAT_SYSTEM)))) {
		need_policy = zfs_zaccess(zp, ACE_WRITE_ATTRIBUTES, 0,
		    skipaclchk, cr);
	}

	if (mask & (AT_UID|AT_GID)) {
		int	idmask = (mask & (AT_UID|AT_GID));
		int	take_owner;
		int	take_group;

		/*
		 * NOTE: even if a new mode is being set,
		 * we may clear S_ISUID/S_ISGID bits.
		 */

		if (!(mask & AT_MODE))
			vap->va_mode = zp->z_mode;

		/*
		 * Take ownership or chgrp to group we are a member of
		 */

		take_owner = (mask & AT_UID) && (vap->va_uid == crgetuid(cr));
		take_group = (mask & AT_GID) &&
		    zfs_groupmember(zfsvfs, vap->va_gid, cr);

		/*
		 * If both AT_UID and AT_GID are set then take_owner and
		 * take_group must both be set in order to allow taking
		 * ownership.
		 *
		 * Otherwise, send the check through secpolicy_vnode_setattr()
		 *
		 */

		if (((idmask == (AT_UID|AT_GID)) && take_owner && take_group) ||
		    ((idmask == AT_UID) && take_owner) ||
		    ((idmask == AT_GID) && take_group)) {
			if (zfs_zaccess(zp, ACE_WRITE_OWNER, 0,
			    skipaclchk, cr) == 0) {
				/*
				 * Remove setuid/setgid for non-privileged users
				 */
				secpolicy_setid_clear(vap, vp, cr);
				trim_mask = (mask & (AT_UID|AT_GID));
			} else {
				need_policy =  TRUE;
			}
		} else {
			need_policy =  TRUE;
		}
	}

	mutex_enter(&zp->z_lock);
	oldva.va_mode = zp->z_mode;
	zfs_fuid_map_ids(zp, cr, &oldva.va_uid, &oldva.va_gid);
	if (mask & AT_XVATTR) {
		/*
		 * Update xvattr mask to include only those attributes
		 * that are actually changing.
		 *
		 * the bits will be restored prior to actually setting
		 * the attributes so the caller thinks they were set.
		 */
		if (XVA_ISSET_REQ(xvap, XAT_APPENDONLY)) {
			if (xoap->xoa_appendonly !=
			    ((zp->z_pflags & ZFS_APPENDONLY) != 0)) {
				need_policy = TRUE;
			} else {
				XVA_CLR_REQ(xvap, XAT_APPENDONLY);
				XVA_SET_REQ(tmpxvattr, XAT_APPENDONLY);
			}
		}

		if (XVA_ISSET_REQ(xvap, XAT_NOUNLINK)) {
			if (xoap->xoa_nounlink !=
			    ((zp->z_pflags & ZFS_NOUNLINK) != 0)) {
				need_policy = TRUE;
			} else {
				XVA_CLR_REQ(xvap, XAT_NOUNLINK);
				XVA_SET_REQ(tmpxvattr, XAT_NOUNLINK);
			}
		}

		if (XVA_ISSET_REQ(xvap, XAT_IMMUTABLE)) {
			if (xoap->xoa_immutable !=
			    ((zp->z_pflags & ZFS_IMMUTABLE) != 0)) {
				need_policy = TRUE;
			} else {
				XVA_CLR_REQ(xvap, XAT_IMMUTABLE);
				XVA_SET_REQ(tmpxvattr, XAT_IMMUTABLE);
			}
		}

		if (XVA_ISSET_REQ(xvap, XAT_NODUMP)) {
			if (xoap->xoa_nodump !=
			    ((zp->z_pflags & ZFS_NODUMP) != 0)) {
				need_policy = TRUE;
			} else {
				XVA_CLR_REQ(xvap, XAT_NODUMP);
				XVA_SET_REQ(tmpxvattr, XAT_NODUMP);
			}
		}

		if (XVA_ISSET_REQ(xvap, XAT_AV_MODIFIED)) {
			if (xoap->xoa_av_modified !=
			    ((zp->z_pflags & ZFS_AV_MODIFIED) != 0)) {
				need_policy = TRUE;
			} else {
				XVA_CLR_REQ(xvap, XAT_AV_MODIFIED);
				XVA_SET_REQ(tmpxvattr, XAT_AV_MODIFIED);
			}
		}

		if (XVA_ISSET_REQ(xvap, XAT_AV_QUARANTINED)) {
			if ((!vnode_isreg(vp) &&
			    xoap->xoa_av_quarantined) ||
			    xoap->xoa_av_quarantined !=
			    ((zp->z_pflags & ZFS_AV_QUARANTINED) != 0)) {
				need_policy = TRUE;
			} else {
				XVA_CLR_REQ(xvap, XAT_AV_QUARANTINED);
				XVA_SET_REQ(tmpxvattr, XAT_AV_QUARANTINED);
			}
		}

		if (XVA_ISSET_REQ(xvap, XAT_REPARSE)) {
			mutex_exit(&zp->z_lock);
			err = SET_ERROR(EPERM);
			goto out3;
		}

		if (need_policy == FALSE &&
		    (XVA_ISSET_REQ(xvap, XAT_AV_SCANSTAMP) ||
		    XVA_ISSET_REQ(xvap, XAT_OPAQUE))) {
			need_policy = TRUE;
		}
	}

	mutex_exit(&zp->z_lock);

	if (mask & AT_MODE) {
		if (zfs_zaccess(zp, ACE_WRITE_ACL, 0, skipaclchk, cr) == 0) {
			err = secpolicy_setid_setsticky_clear(vp, vap,
			    &oldva, cr);
			if (err) {
				ZFS_EXIT(zfsvfs);
				return (err);
			}
			trim_mask |= AT_MODE;
		} else {
			need_policy = TRUE;
		}
	}

	if (need_policy) {
		/*
		 * If trim_mask is set then take ownership
		 * has been granted or write_acl is present and user
		 * has the ability to modify mode.  In that case remove
		 * UID|GID and or MODE from mask so that
		 * secpolicy_vnode_setattr() doesn't revoke it.
		 */

		if (trim_mask) {
			saved_mask = vap->va_mask;
			vap->va_mask &= ~trim_mask;
			if (trim_mask & AT_MODE) {
				/*
				 * Save the mode, as secpolicy_vnode_setattr()
				 * will overwrite it with ova.va_mode.
				 */
				saved_mode = vap->va_mode;
			}
		}
		err = secpolicy_vnode_setattr(cr, vp, vap, &oldva, flags,
		    (int (*)(void *, int, cred_t *))zfs_zaccess_unix, zp);
		if (err)
			goto out3;

		if (trim_mask) {
			vap->va_mask |= saved_mask;
			if (trim_mask & AT_MODE) {
				/*
				 * Recover the mode after
				 * secpolicy_vnode_setattr().
				 */
				vap->va_mode = saved_mode;
			}
		}
	}

	/*
	 * secpolicy_vnode_setattr, or take ownership may have
	 * changed va_mask
	 */
	mask = vap->va_mask;

	if ((mask & (AT_UID | AT_GID))) {
		err = sa_lookup(zp->z_sa_hdl, SA_ZPL_XATTR(zfsvfs),
		    &xattr_obj, sizeof (xattr_obj));

		if (err == 0 && xattr_obj) {
			err = zfs_zget(zp->z_zfsvfs, xattr_obj, &attrzp);
			if (err)
				goto out2;
		}
		if (mask & AT_UID) {
			new_uid = zfs_fuid_create(zfsvfs,
			    (uint64_t)vap->va_uid, cr, ZFS_OWNER, &fuidp);
			if (new_uid != zp->z_uid &&
			    zfs_fuid_overquota(zfsvfs, B_FALSE, new_uid)) {
				if (attrzp)
					VN_RELE(ZTOV(attrzp));
				err = (EDQUOT);
				goto out2;
			}
		}

		if (mask & AT_GID) {
			new_gid = zfs_fuid_create(zfsvfs, (uint64_t)vap->va_gid,
			    cr, ZFS_GROUP, &fuidp);
			if (new_gid != zp->z_gid &&
			    zfs_fuid_overquota(zfsvfs, B_TRUE, new_gid)) {
				if (attrzp)
					VN_RELE(ZTOV(attrzp));
				err = (EDQUOT);
				goto out2;
			}
		}
	}
	tx = dmu_tx_create(zfsvfs->z_os);

    /*
     * ACLs are currently not working, there appears to be two implementations
     * here, one is old MacZFS "zfs_setacl" and the other is ZFS (FBSD?)
     * with zfs_external_acl().
     */

	if (mask & AT_ACL) {

        if ((vap->va_acl != (kauth_acl_t) KAUTH_FILESEC_NONE) &&
            (vap->va_acl->acl_entrycount > 0) &&
            (vap->va_acl->acl_entrycount != KAUTH_FILESEC_NOACL)) {

            vsecattr.vsa_mask = VSA_ACE;

            kauth = vap->va_acl;

#if HIDE_TRIVIAL_ACL
			// We might have to add <up to> 3 trivial acls, depending on
			// what was handed to us.
            aclbsize = ( 3 + kauth->acl_entrycount ) * sizeof(ace_t);
            dprintf("Given %d ACLs, adding 3\n", kauth->acl_entrycount);
#else
            aclbsize = kauth->acl_entrycount * sizeof(ace_t);
            dprintf("Given %d ACLs\n", kauth->acl_entrycount);
#endif

			vsecattr.vsa_aclentp = kmem_zalloc(aclbsize, KM_SLEEP);
            aaclp = vsecattr.vsa_aclentp;
            vsecattr.vsa_aclentsz = aclbsize;

#if HIDE_TRIVIAL_ACL
			// Add in the trivials, keep "seen_type" as a bit pattern of
			// which trivials we have seen
			seen_type = 0;

            dprintf("aces_from_acl %d entries\n", kauth->acl_entrycount);
            aces_from_acl(vsecattr.vsa_aclentp,
						  &vsecattr.vsa_aclcnt, kauth, &seen_type);

			// Add in trivials at end, based on the "seen_type".
			zfs_addacl_trivial(zp, vsecattr.vsa_aclentp, &vsecattr.vsa_aclcnt,
				seen_type);
			dprintf("together at last: %d\n", vsecattr.vsa_aclcnt);
#else
            aces_from_acl(vsecattr.vsa_aclentp, &vsecattr.vsa_aclcnt, kauth);
#endif

			err = zfs_setacl(zp, &vsecattr, B_TRUE, cr);
            kmem_free(aaclp, aclbsize);

        } else {

			seen_type = 0;
            vsecattr.vsa_mask = VSA_ACE;
			vsecattr.vsa_aclcnt = 0;
            aclbsize = ( 3 ) * sizeof(ace_t);
			vsecattr.vsa_aclentp = kmem_zalloc(aclbsize, KM_SLEEP);
			aaclp = vsecattr.vsa_aclentp;
            vsecattr.vsa_aclentsz = aclbsize;
			// Clearing, we need to pass in the trivials only
			zfs_addacl_trivial(zp, vsecattr.vsa_aclentp, &vsecattr.vsa_aclcnt,
				seen_type);

            if ((err = zfs_setacl(zp, &vsecattr, B_TRUE, cr)))
                dprintf("setattr: setacl failed: %d\n", err);

            kmem_free(aaclp, aclbsize);

        } // blank ACL?
	} // ACL


	if (mask & AT_MODE) {
		uint64_t pmode = zp->z_mode;
		uint64_t acl_obj;

        if(!(mask & AT_ACL)) {
            new_mode = (pmode & S_IFMT) | (vap->va_mode & ~S_IFMT);
        } else {
            new_mode = pmode;
        }

		if (zp->z_zfsvfs->z_acl_mode == ZFS_ACL_RESTRICTED &&
		    !(zp->z_pflags & ZFS_ACL_TRIVIAL)) {
			err = (EPERM);
			goto out;
		}

		if ((err = zfs_acl_chmod_setattr(zp, &aclp, new_mode)))
			goto out;

		mutex_enter(&zp->z_lock);
		if (!zp->z_is_sa && ((acl_obj = zfs_external_acl(zp)) != 0)) {
			/*
			 * Are we upgrading ACL from old V0 format
			 * to V1 format?
			 */
			if (zfsvfs->z_version >= ZPL_VERSION_FUID &&
			    zfs_znode_acl_version(zp) ==
			    ZFS_ACL_VERSION_INITIAL) {
				dmu_tx_hold_free(tx, acl_obj, 0,
				    DMU_OBJECT_END);
				dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
				    0, aclp->z_acl_bytes);
			} else {
				dmu_tx_hold_write(tx, acl_obj, 0,
				    aclp->z_acl_bytes);
			}
		} else if (!zp->z_is_sa && aclp->z_acl_bytes > ZFS_ACE_SPACE) {
			dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
			    0, aclp->z_acl_bytes);
		}
		mutex_exit(&zp->z_lock);
		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_TRUE);
	} else {
		if ((mask & AT_XVATTR) &&
		    XVA_ISSET_REQ(xvap, XAT_AV_SCANSTAMP))
			dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_TRUE);
		else
			dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	}

	if (attrzp) {
		dmu_tx_hold_sa(tx, attrzp->z_sa_hdl, B_FALSE);
	}

	fuid_dirtied = zfsvfs->z_fuid_dirty;
	if (fuid_dirtied)
		zfs_fuid_txhold(zfsvfs, tx);

	zfs_sa_upgrade_txholds(tx, zp);

	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err)
		goto out;

	count = 0;
	/*
	 * Set each attribute requested.
	 * We group settings according to the locks they need to acquire.
	 *
	 * Note: you cannot set ctime directly, although it will be
	 * updated as a side-effect of calling this function.
	 */


	if (mask & (AT_UID|AT_GID|AT_MODE))
		mutex_enter(&zp->z_acl_lock);
	mutex_enter(&zp->z_lock);

	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
	    &zp->z_pflags, sizeof (zp->z_pflags));

	if (attrzp) {
		if (mask & (AT_UID|AT_GID|AT_MODE))
			mutex_enter(&attrzp->z_acl_lock);
		mutex_enter(&attrzp->z_lock);
		SA_ADD_BULK_ATTR(xattr_bulk, xattr_count,
		    SA_ZPL_FLAGS(zfsvfs), NULL, &attrzp->z_pflags,
		    sizeof (attrzp->z_pflags));
	}

	if (mask & (AT_UID|AT_GID)) {

		if (mask & AT_UID) {
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_UID(zfsvfs), NULL,
			    &new_uid, sizeof (new_uid));
			zp->z_uid = new_uid;
			if (attrzp) {
				SA_ADD_BULK_ATTR(xattr_bulk, xattr_count,
				    SA_ZPL_UID(zfsvfs), NULL, &new_uid,
				    sizeof (new_uid));
				attrzp->z_uid = new_uid;
			}
		}

		if (mask & AT_GID) {
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_GID(zfsvfs),
			    NULL, &new_gid, sizeof (new_gid));
			zp->z_gid = new_gid;
			if (attrzp) {
				SA_ADD_BULK_ATTR(xattr_bulk, xattr_count,
				    SA_ZPL_GID(zfsvfs), NULL, &new_gid,
				    sizeof (new_gid));
				attrzp->z_gid = new_gid;
			}
		}
		if (!(mask & AT_MODE)) {
			SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MODE(zfsvfs),
			    NULL, &new_mode, sizeof (new_mode));
			new_mode = zp->z_mode;
		}
		err = zfs_acl_chown_setattr(zp);
		ASSERT(err == 0);
		if (attrzp) {
			err = zfs_acl_chown_setattr(attrzp);
			ASSERT(err == 0);
		}

        /*
         * When importing ZEVO volumes, and 'chown' is used, we end up calling
         * SA_LOOKUP with 'sa_addr' == NULL. Unsure why this happens, for
         * now, we shall stick a plaster over this open-fracture
         */
        if (err == 2) {
            printf("setattr: triggered SA_LOOKUP == NULL problem\n");
            err = 0;
        }

	}

	if (mask & AT_MODE) {
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MODE(zfsvfs), NULL,
		    &new_mode, sizeof (new_mode));
		zp->z_mode = new_mode;
		/*
         	 * Mode change needs to trigger corresponding update to trivial ACLs.
         	 * ACL change already does this, and another call to zfs_aclset_common
		 * would overwrite our explicit ACL changes.
         	 */
		if(!(mask & AT_ACL)) {
                       ASSERT3U((uintptr_t)aclp, !=, 0);
                       err = zfs_aclset_common(zp, aclp, cr, tx);
                       ASSERT(err==0);
                       if (zp->z_acl_cached)
                       zfs_acl_free(zp->z_acl_cached);
                       zp->z_acl_cached = aclp;
                       aclp = NULL;
		}
	}

	if (mask & AT_ATIME) {
		ZFS_TIME_ENCODE(&vap->va_atime, zp->z_atime);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_ATIME(zfsvfs), NULL,
		    &zp->z_atime, sizeof (zp->z_atime));
	}

	if (mask & AT_MTIME) {
		ZFS_TIME_ENCODE(&vap->va_mtime, mtime);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL,
		    mtime, sizeof (mtime));
	}

#ifdef __APPLE__
    /* CTIME overloaded to mean CRTIME */
	if (mask & AT_CTIME) {
		ZFS_TIME_ENCODE(&vap->va_crtime, crtime);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CRTIME(zfsvfs), NULL,
		    crtime, sizeof (crtime));
	}
#endif

	/* XXX - shouldn't this be done *before* the ATIME/MTIME checks? */
	if (mask & AT_SIZE && !(mask & AT_MTIME)) {
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs),
		    NULL, mtime, sizeof (mtime));
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL,
		    &ctime, sizeof (ctime));
		zfs_tstamp_update_setup(zp, CONTENT_MODIFIED, mtime, ctime,
		    B_TRUE);
	} else if (mask != 0) {
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL,
		    &ctime, sizeof (ctime));
		zfs_tstamp_update_setup(zp, STATE_CHANGED, mtime, ctime,
		    B_TRUE);
		if (attrzp) {
			SA_ADD_BULK_ATTR(xattr_bulk, xattr_count,
			    SA_ZPL_CTIME(zfsvfs), NULL,
			    &ctime, sizeof (ctime));
			zfs_tstamp_update_setup(attrzp, STATE_CHANGED,
			    mtime, ctime, B_TRUE);
		}
	}
	/*
	 * Do this after setting timestamps to prevent timestamp
	 * update from toggling bit
	 */

	if (xoap && (mask & AT_XVATTR)) {

		/*
		 * restore trimmed off masks
		 * so that return masks can be set for caller.
		 */

		if (XVA_ISSET_REQ(tmpxvattr, XAT_APPENDONLY)) {
			XVA_SET_REQ(xvap, XAT_APPENDONLY);
		}
		if (XVA_ISSET_REQ(tmpxvattr, XAT_NOUNLINK)) {
			XVA_SET_REQ(xvap, XAT_NOUNLINK);
		}
		if (XVA_ISSET_REQ(tmpxvattr, XAT_IMMUTABLE)) {
			XVA_SET_REQ(xvap, XAT_IMMUTABLE);
		}
		if (XVA_ISSET_REQ(tmpxvattr, XAT_NODUMP)) {
			XVA_SET_REQ(xvap, XAT_NODUMP);
		}
		if (XVA_ISSET_REQ(tmpxvattr, XAT_AV_MODIFIED)) {
			XVA_SET_REQ(xvap, XAT_AV_MODIFIED);
		}
		if (XVA_ISSET_REQ(tmpxvattr, XAT_AV_QUARANTINED)) {
			XVA_SET_REQ(xvap, XAT_AV_QUARANTINED);
		}

/*
		if (XVA_ISSET_REQ(xvap, XAT_AV_SCANSTAMP))
			ASSERT(vp->v_type == VREG);
*/

		zfs_xvattr_set(zp, xvap, tx);
	}

	if (fuid_dirtied)
		zfs_fuid_sync(zfsvfs, tx);

	if (mask != 0)
		zfs_log_setattr(zilog, tx, TX_SETATTR, zp, vap, mask, fuidp);

	mutex_exit(&zp->z_lock);
	if (mask & (AT_UID|AT_GID|AT_MODE))
		mutex_exit(&zp->z_acl_lock);

	if (attrzp) {
		if (mask & (AT_UID|AT_GID|AT_MODE))
			mutex_exit(&attrzp->z_acl_lock);
		mutex_exit(&attrzp->z_lock);
	}
out:

	if (err == 0 && attrzp) {
		err2 = sa_bulk_update(attrzp->z_sa_hdl, xattr_bulk,
		    xattr_count, tx);
		ASSERT(err2 == 0);
	}

	if (attrzp)
		VN_RELE(ZTOV(attrzp));
	if (aclp)
		zfs_acl_free(aclp);

	if (fuidp) {
		zfs_fuid_info_free(fuidp);
		fuidp = NULL;
	}

	if (err) {
		dmu_tx_abort(tx);
		if (err == ERESTART)
			goto top;
	} else {
		err2 = sa_bulk_update(zp->z_sa_hdl, bulk, count, tx);
		dmu_tx_commit(tx);
	}

out2:
	if (zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		zil_commit(zilog, 0);

out3:
    dprintf("-setattr: zp %p size %llu\n", zp, zp->z_size);

	kmem_free(xattr_bulk, sizeof (sa_bulk_attr_t) * _NUM_BULK);
	kmem_free(bulk, sizeof (sa_bulk_attr_t) * _NUM_BULK);
	kmem_free(tmpxvattr, sizeof (xvattr_t));
#undef _NUM_BULK

	ZFS_EXIT(zfsvfs);
	return (err);
}

typedef struct zfs_zlock {
	krwlock_t	*zl_rwlock;	/* lock we acquired */
	znode_t		*zl_znode;	/* znode we held */
	struct zfs_zlock *zl_next;	/* next in list */
} zfs_zlock_t;

/*
 * Drop locks and release vnodes that were held by zfs_rename_lock().
 */
static void
zfs_rename_unlock(zfs_zlock_t **zlpp)
{
	zfs_zlock_t *zl;

	while ((zl = *zlpp) != NULL) {
		if (zl->zl_znode != NULL)
			VN_RELE(ZTOV(zl->zl_znode));
		rw_exit(zl->zl_rwlock);
		*zlpp = zl->zl_next;
		kmem_free(zl, sizeof (*zl));
	}
}

/*
 * Search back through the directory tree, using the ".." entries.
 * Lock each directory in the chain to prevent concurrent renames.
 * Fail any attempt to move a directory into one of its own descendants.
 * XXX - z_parent_lock can overlap with map or grow locks
 */
static int
zfs_rename_lock(znode_t *szp, znode_t *tdzp, znode_t *sdzp, zfs_zlock_t **zlpp)
{
	zfs_zlock_t	*zl;
	znode_t		*zp = tdzp;
	uint64_t	rootid = zp->z_zfsvfs->z_root;
	uint64_t	oidp = zp->z_id;
	krwlock_t	*rwlp = &szp->z_parent_lock;
	krw_t		rw = RW_WRITER;

	/*
	 * First pass write-locks szp and compares to zp->z_id.
	 * Later passes read-lock zp and compare to zp->z_parent.
	 */
	do {
		if (!rw_tryenter(rwlp, rw)) {
			/*
			 * Another thread is renaming in this path.
			 * Note that if we are a WRITER, we don't have any
			 * parent_locks held yet.
			 */
			if (rw == RW_READER && zp->z_id > szp->z_id) {
				/*
				 * Drop our locks and restart
				 */
				zfs_rename_unlock(&zl);
				*zlpp = NULL;
				zp = tdzp;
				oidp = zp->z_id;
				rwlp = &szp->z_parent_lock;
				rw = RW_WRITER;
				continue;
			} else {
				/*
				 * Wait for other thread to drop its locks
				 */
				rw_enter(rwlp, rw);
			}
		}

		zl = kmem_alloc(sizeof (*zl), KM_SLEEP);
		zl->zl_rwlock = rwlp;
		zl->zl_znode = NULL;
		zl->zl_next = *zlpp;
		*zlpp = zl;

		if (oidp == szp->z_id)		/* We're a descendant of szp */
			return (SET_ERROR(EINVAL));

		if (oidp == rootid)		/* We've hit the top */
			return (0);

		if (rw == RW_READER) {		/* i.e. not the first pass */
			int error = zfs_zget(zp->z_zfsvfs, oidp, &zp);
			if (error)
				return (error);
			zl->zl_znode = zp;
		}
		(void) sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zp->z_zfsvfs),
		    &oidp, sizeof (oidp));
		rwlp = &zp->z_parent_lock;
		rw = RW_READER;

	} while (zp->z_id != sdzp->z_id);

	return (0);
}

/*
 * Move an entry from the provided source directory to the target
 * directory.  Change the entry name as indicated.
 *
 *	IN:	sdvp	- Source directory containing the "old entry".
 *		snm	- Old entry name.
 *		tdvp	- Target directory to contain the "new entry".
 *		tnm	- New entry name.
 *		cr	- credentials of caller.
 *		ct	- caller context
 *		flags	- case flags
 *
 *	RETURN:	0 on success, error code on failure.
 *
 * Timestamps:
 *	sdvp,tdvp - ctime|mtime updated
 */
/*ARGSUSED*/
int
zfs_rename(vnode_t *sdvp, char *snm, vnode_t *tdvp, char *tnm, cred_t *cr,
    caller_context_t *ct, int flags)
{
	znode_t		*tdzp, *szp, *tzp;
	znode_t		*sdzp = VTOZ(sdvp);
	zfsvfs_t	*zfsvfs = sdzp->z_zfsvfs;
	zilog_t		*zilog;
#ifndef __APPLE__
	vnode_t		*realvp;
#endif
	uint64_t addtime[2];
	zfs_dirlock_t	*sdl, *tdl;
	dmu_tx_t	*tx;
	zfs_zlock_t	*zl;
	int		cmp, serr, terr;
	int		error = 0;
	int		zflg = 0;
	boolean_t	waited = B_FALSE;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(sdzp);
	zilog = zfsvfs->z_log;

#ifndef __APPLE__
	/*
	 * Make sure we have the real vp for the target directory.
	 */
	if (VOP_REALVP(tdvp, &realvp, ct) == 0)
		tdvp = realvp;

	if (tdvp->v_vfsp != sdvp->v_vfsp || zfsctl_is_node(tdvp)) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EXDEV));
	}
#endif

	tdzp = VTOZ(tdvp);
	ZFS_VERIFY_ZP(tdzp);
	if (zfsvfs->z_utf8 && u8_validate(tnm,
	    strlen(tnm), NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EILSEQ));
	}

	if (flags & FIGNORECASE)
		zflg |= ZCILOOK;

top:
	szp = NULL;
	tzp = NULL;
	zl = NULL;

	/*
	 * This is to prevent the creation of links into attribute space
	 * by renaming a linked file into/outof an attribute directory.
	 * See the comment in zfs_link() for why this is considered bad.
	 */
	if ((tdzp->z_pflags & ZFS_XATTR) != (sdzp->z_pflags & ZFS_XATTR)) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EINVAL));
	}

	/*
	 * Lock source and target directory entries.  To prevent deadlock,
	 * a lock ordering must be defined.  We lock the directory with
	 * the smallest object id first, or if it's a tie, the one with
	 * the lexically first name.
	 */
	if (sdzp->z_id < tdzp->z_id) {
		cmp = -1;
	} else if (sdzp->z_id > tdzp->z_id) {
		cmp = 1;
	} else {
		/*
		 * First compare the two name arguments without
		 * considering any case folding.
		 */
		int nofold = (zfsvfs->z_norm & ~U8_TEXTPREP_TOUPPER);

		cmp = u8_strcmp(snm, tnm, 0, nofold, U8_UNICODE_LATEST, &error);
		ASSERT(error == 0 || !zfsvfs->z_utf8);
		if (cmp == 0) {
			/*
			 * POSIX: "If the old argument and the new argument
			 * both refer to links to the same existing file,
			 * the rename() function shall return successfully
			 * and perform no other action."
			 */
			ZFS_EXIT(zfsvfs);
			return (0);
		}
		/*
		 * If the file system is case-folding, then we may
		 * have some more checking to do.  A case-folding file
		 * system is either supporting mixed case sensitivity
		 * access or is completely case-insensitive.  Note
		 * that the file system is always case preserving.
		 *
		 * In mixed sensitivity mode case sensitive behavior
		 * is the default.  FIGNORECASE must be used to
		 * explicitly request case insensitive behavior.
		 *
		 * If the source and target names provided differ only
		 * by case (e.g., a request to rename 'tim' to 'Tim'),
		 * we will treat this as a special case in the
		 * case-insensitive mode: as long as the source name
		 * is an exact match, we will allow this to proceed as
		 * a name-change request.
		 */
		if ((zfsvfs->z_case == ZFS_CASE_INSENSITIVE ||
		    (zfsvfs->z_case == ZFS_CASE_MIXED &&
		    flags & FIGNORECASE)) &&
		    u8_strcmp(snm, tnm, 0, zfsvfs->z_norm, U8_UNICODE_LATEST,
		    &error) == 0) {
			/*
			 * case preserving rename request, require exact
			 * name matches
			 */
			zflg |= ZCIEXACT;
			zflg &= ~ZCILOOK;
		}
	}

	/*
	 * If the source and destination directories are the same, we should
	 * grab the z_name_lock of that directory only once.
	 */
	if (sdzp == tdzp) {
		zflg |= ZHAVELOCK;
		rw_enter(&sdzp->z_name_lock, RW_READER);
	}

	if (cmp < 0) {
		serr = zfs_dirent_lock(&sdl, sdzp, snm, &szp,
		    ZEXISTS | zflg, NULL, NULL);
		terr = zfs_dirent_lock(&tdl,
		    tdzp, tnm, &tzp, ZRENAMING | zflg, NULL, NULL);
	} else {
		terr = zfs_dirent_lock(&tdl,
		    tdzp, tnm, &tzp, zflg, NULL, NULL);
		serr = zfs_dirent_lock(&sdl,
		    sdzp, snm, &szp, ZEXISTS | ZRENAMING | zflg,
		    NULL, NULL);
	}

	if (serr) {
		/*
		 * Source entry invalid or not there.
		 */
		if (!terr) {
			zfs_dirent_unlock(tdl);
			if (tzp)
				VN_RELE(ZTOV(tzp));
		}

		if (sdzp == tdzp)
			rw_exit(&sdzp->z_name_lock);

		/*
		 * FreeBSD: In OpenSolaris they only check if rename source is
		 * ".." here, because "." is handled in their lookup. This is
		 * not the case for FreeBSD, so we check for "." explicitly.
		 */
		if (strcmp(snm, ".") == 0 || strcmp(snm, "..") == 0)
			serr = (EINVAL);
		ZFS_EXIT(zfsvfs);
		return (serr);
	}
	if (terr) {
		zfs_dirent_unlock(sdl);
		VN_RELE(ZTOV(szp));

		if (sdzp == tdzp)
			rw_exit(&sdzp->z_name_lock);

		if (strcmp(tnm, "..") == 0)
			terr = (EINVAL);
		ZFS_EXIT(zfsvfs);
		return (terr);
	}

	/*
	 * Must have write access at the source to remove the old entry
	 * and write access at the target to create the new entry.
	 * Note that if target and source are the same, this can be
	 * done in a single check.
	 */

	if ((error = zfs_zaccess_rename(sdzp, szp, tdzp, tzp, cr)))
		goto out;

	if (vnode_isdir(ZTOV(szp))) {
		/*
		 * Check to make sure rename is valid.
		 * Can't do a move like this: /usr/a/b to /usr/a/b/c/d
		 */
		if ((error = zfs_rename_lock(szp, tdzp, sdzp, &zl)))
			goto out;
	}

	/*
	 * Does target exist?
	 */
	if (tzp) {
		/*
		 * Source and target must be the same type.
		 */
		if (vnode_isdir(ZTOV(szp))) {
			if (!vnode_isdir(ZTOV(tzp))) {
				error = SET_ERROR(ENOTDIR);
				goto out;
			}
		} else {
			if (vnode_isdir(ZTOV(tzp))) {
				error = SET_ERROR(EISDIR);
				goto out;
			}
		}
		/*
		 * POSIX dictates that when the source and target
		 * entries refer to the same file object, rename
		 * must do nothing and exit without error.
		 */
		if (szp->z_id == tzp->z_id) {
			error = 0;
			goto out;
		}
	}

	vnevent_rename_src(ZTOV(szp), sdvp, snm, ct);
	if (tzp)
		vnevent_rename_dest(ZTOV(tzp), tdvp, tnm, ct);

	/*
	 * notify the target directory if it is not the same
	 * as source directory.
	 */
	if (tdvp != sdvp) {
		vnevent_rename_dest_dir(tdvp, ct);
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_sa(tx, szp->z_sa_hdl, B_FALSE);
	dmu_tx_hold_sa(tx, sdzp->z_sa_hdl, B_FALSE);
	dmu_tx_hold_zap(tx, sdzp->z_id, FALSE, snm);
	dmu_tx_hold_zap(tx, tdzp->z_id, TRUE, tnm);
	if (sdzp != tdzp) {
		dmu_tx_hold_sa(tx, tdzp->z_sa_hdl, B_FALSE);
		zfs_sa_upgrade_txholds(tx, tdzp);
	}
	if (tzp) {
		dmu_tx_hold_sa(tx, tzp->z_sa_hdl, B_FALSE);
		zfs_sa_upgrade_txholds(tx, tzp);
	}

	zfs_sa_upgrade_txholds(tx, szp);
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);
	error = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
	if (error) {
		if (zl != NULL)
			zfs_rename_unlock(&zl);
		zfs_dirent_unlock(sdl);
		zfs_dirent_unlock(tdl);

		if (sdzp == tdzp)
			rw_exit(&sdzp->z_name_lock);

		VN_RELE(ZTOV(szp));
		if (tzp)
			VN_RELE(ZTOV(tzp));
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (tzp)	/* Attempt to remove the existing target */
		error = zfs_link_destroy(tdl, tzp, tx, zflg, NULL);

	if (error == 0) {
		error = zfs_link_create(tdl, szp, tx, ZRENAMING);
		if (error == 0) {
			szp->z_pflags |= ZFS_AV_MODIFIED;

			error = sa_update(szp->z_sa_hdl, SA_ZPL_FLAGS(zfsvfs),
			    (void *)&szp->z_pflags, sizeof (uint64_t), tx);
			ASSERT(error==0);

#ifdef __APPLE__
			/* If we moved an entry into a different directory (sdzp != tdzp)
			 * then we also need to update ADDEDTIME (ADDTIME) property for
			 * FinderInfo. We are already inside error == 0 conditional
			 */
			if ((sdzp != tdzp) &&
				zfsvfs->z_use_sa == B_TRUE) {
				timestruc_t	now;
				gethrestime(&now);
				ZFS_TIME_ENCODE(&now, addtime);
				error = sa_update(szp->z_sa_hdl, SA_ZPL_ADDTIME(zfsvfs),
								  (void *)&addtime, sizeof (addtime), tx);
				dprintf("ZFS: Updating ADDEDTIME on zp/vp %p/%p: %llu\n",
						szp, ZTOV(szp), addtime[0]);
			}
#endif


			error = zfs_link_destroy(sdl, szp, tx, ZRENAMING, NULL);
			if (error == 0) {
				zfs_log_rename(zilog, tx, TX_RENAME |
				    (flags & FIGNORECASE ? TX_CI : 0), sdzp,
				    sdl->dl_name, tdzp, tdl->dl_name, szp);

				/*
				 * Update path information for the target vnode
				 */
				vn_renamepath(tdvp, ZTOV(szp), tnm,
				    strlen(tnm));

#ifdef __APPLE__
				/* Update cached name - for vget, and access without
				 * calling vnop_lookup first - it is easier to clear
				 * it out and let getattr look it up if needed.
				 */
				if (tzp) {
					mutex_enter(&tzp->z_lock);
					tzp->z_name_cache[0] = 0;
					mutex_exit(&tzp->z_lock);
				}
				if (szp) {
					mutex_enter(&szp->z_lock);
					szp->z_name_cache[0] = 0;
					mutex_exit(&szp->z_lock);
				}
#endif

			} else {
				/*
				 * At this point, we have successfully created
				 * the target name, but have failed to remove
				 * the source name.  Since the create was done
				 * with the ZRENAMING flag, there are
				 * complications; for one, the link count is
				 * wrong.  The easiest way to deal with this
				 * is to remove the newly created target, and
				 * return the original error.  This must
				 * succeed; fortunately, it is very unlikely to
				 * fail, since we just created it.
				 */
				VERIFY3U(zfs_link_destroy(tdl, szp, tx,
				    ZRENAMING, NULL), ==, 0);
			}
		}


#if defined (FREEBSD_NAMECACHE)
		if (error == 0) {
			cache_purge(sdvp);
			cache_purge(tdvp);
			cache_purge(ZTOV(szp));
			if (tzp)
				cache_purge(ZTOV(tzp));
		}
#endif
	}

	dmu_tx_commit(tx);
out:
	if (zl != NULL)
		zfs_rename_unlock(&zl);

	zfs_dirent_unlock(sdl);
	zfs_dirent_unlock(tdl);

	if (sdzp == tdzp)
		rw_exit(&sdzp->z_name_lock);


	VN_RELE(ZTOV(szp));
	if (tzp)
		VN_RELE(ZTOV(tzp));

	if (zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		zil_commit(zilog, 0);

	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Insert the indicated symbolic reference entry into the directory.
 *
 *	IN:	dvp	- Directory to contain new symbolic link.
 *		link	- Name for new symlink entry.
 *		vap	- Attributes of new entry.
 *		target	- Target path of new symlink.
 *		cr	- credentials of caller.
 *		ct	- caller context
 *		flags	- case flags
 *
 *	RETURN:	0 on success, error code on failure.
 *
 * Timestamps:
 *	dvp - ctime|mtime updated
 */
/*ARGSUSED*/
int
zfs_symlink(vnode_t *dvp, vnode_t **vpp, char *name, vattr_t *vap, char *link,
            cred_t *cr)
{
	znode_t		*zp, *dzp = VTOZ(dvp);
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog;
	uint64_t	len = strlen(link);
	int		error;
	int		zflg = ZNEW;
	zfs_acl_ids_t	acl_ids;
	boolean_t	fuid_dirtied;
	uint64_t	txtype = TX_SYMLINK;
	int		flags = 0;
	boolean_t	waited = B_FALSE;

	ASSERT(vap->va_type == VLNK);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(dzp);
	zilog = zfsvfs->z_log;

	if (zfsvfs->z_utf8 && u8_validate(name, strlen(name),
	    NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EILSEQ));
	}
	if (flags & FIGNORECASE)
		zflg |= ZCILOOK;

	if (len > MAXPATHLEN) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(ENAMETOOLONG));
	}

	if ((error = zfs_acl_ids_create(dzp, 0,
	    vap, cr, NULL, &acl_ids)) != 0) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}
top:
	/*
	 * Attempt to lock directory; fail if entry already exists.
	 */
	error = zfs_dirent_lock(&dl, dzp, name, &zp, zflg, NULL, NULL);
	if (error) {
		zfs_acl_ids_free(&acl_ids);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if ((error = zfs_zaccess(dzp, ACE_ADD_FILE, 0, B_FALSE, cr))) {
		zfs_acl_ids_free(&acl_ids);
		zfs_dirent_unlock(dl);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (zfs_acl_ids_overquota(zfsvfs, &acl_ids)) {
		zfs_acl_ids_free(&acl_ids);
		zfs_dirent_unlock(dl);
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EDQUOT));
	}
	tx = dmu_tx_create(zfsvfs->z_os);
	fuid_dirtied = zfsvfs->z_fuid_dirty;
	dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, MAX(1, len));
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
	dmu_tx_hold_sa_create(tx, acl_ids.z_aclp->z_acl_bytes +
	    ZFS_SA_BASE_ATTR_SIZE + len);
	dmu_tx_hold_sa(tx, dzp->z_sa_hdl, B_FALSE);
	if (!zfsvfs->z_use_sa && acl_ids.z_aclp->z_acl_bytes > ZFS_ACE_SPACE) {
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0,
		    acl_ids.z_aclp->z_acl_bytes);
	}
	if (fuid_dirtied)
		zfs_fuid_txhold(zfsvfs, tx);
	error = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		zfs_acl_ids_free(&acl_ids);
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * Create a new object for the symlink.
	 * for version 4 ZPL datsets the symlink will be an SA attribute
	 */
	zfs_mknode(dzp, vap, tx, cr, 0, &zp, &acl_ids);

	if (fuid_dirtied)
		zfs_fuid_sync(zfsvfs, tx);

	mutex_enter(&zp->z_lock);
	if (zp->z_is_sa)
		error = sa_update(zp->z_sa_hdl, SA_ZPL_SYMLINK(zfsvfs),
		    link, len, tx);
	else
		zfs_sa_symlink(zp, link, len, tx);
	mutex_exit(&zp->z_lock);

	zp->z_size = len;
	(void) sa_update(zp->z_sa_hdl, SA_ZPL_SIZE(zfsvfs),
	    &zp->z_size, sizeof (zp->z_size), tx);
	/*
	 * Insert the new object into the directory.
	 */
	(void) zfs_link_create(dl, zp, tx, ZNEW);

	if (flags & FIGNORECASE)
		txtype |= TX_CI;
	zfs_log_symlink(zilog, tx, txtype, dzp, zp, name, link);
	*vpp = ZTOV(zp);

	zfs_acl_ids_free(&acl_ids);

	dmu_tx_commit(tx);

	/*
	 * OS X - attach the vnode _after_ committing the transaction
	 */
	zfs_znode_getvnode(zp, zfsvfs);
	*vpp = ZTOV(zp);

	zfs_dirent_unlock(dl);

	if (zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		zil_commit(zilog, 0);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Return, in the buffer contained in the provided uio structure,
 * the symbolic path referred to by vp.
 *
 *	IN:	vp	- vnode of symbolic link.
 *		uoip	- structure to contain the link path.
 *		cr	- credentials of caller.
 *		ct	- caller context
 *
 *	OUT:	uio	- structure to contain the link path.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - atime updated
 */
/* ARGSUSED */
int
zfs_readlink(vnode_t *vp, uio_t *uio, cred_t *cr, caller_context_t *ct)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	int		error;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	mutex_enter(&zp->z_lock);
	if (zp->z_is_sa)
		error = sa_lookup_uio(zp->z_sa_hdl,
		    SA_ZPL_SYMLINK(zfsvfs), uio);
	else
		error = zfs_sa_readlink(zp, uio);
	mutex_exit(&zp->z_lock);

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Insert a new entry into directory tdvp referencing svp.
 *
 *	IN:	tdvp	- Directory to contain new entry.
 *		svp	- vnode of new entry.
 *		name	- name of new entry.
 *		cr	- credentials of caller.
 *		ct	- caller context
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	tdvp - ctime|mtime updated
 *	 svp - ctime updated
 */
/* ARGSUSED */
int
zfs_link(vnode_t *tdvp, vnode_t *svp, char *name, cred_t *cr,
    caller_context_t *ct, int flags)
{
	znode_t		*dzp = VTOZ(tdvp);
	znode_t		*tzp, *szp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
#ifndef __APPLE__
	vnode_t		*realvp;
#endif
	int		error;
	int		zf = ZNEW;
	uint64_t	parent;
	uid_t		owner;
	boolean_t	waited = B_FALSE;

    ASSERT(vnode_isdir(tdvp));

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(dzp);
	zilog = zfsvfs->z_log;

#ifdef __APPLE__
        if (vnode_mount(svp) != vnode_mount(tdvp)) {
                ZFS_EXIT(zfsvfs);
                return (EXDEV);
        }
#else

	if (VOP_REALVP(svp, &realvp, ct) == 0)
		svp = realvp;

#endif

	/*
	 * POSIX dictates that we return EPERM here.
	 * Better choices include ENOTSUP or EISDIR.
	 */
	if (vnode_isdir(svp)) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EPERM));
	}

#ifndef __APPLE__
	if (svp->v_vfsp != tdvp->v_vfsp || zfsctl_is_node(svp)) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EXDEV));
	}
#endif

	szp = VTOZ(svp);
	ZFS_VERIFY_ZP(szp);

	/* Prevent links to .zfs/shares files */

	if ((error = sa_lookup(szp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs),
	    &parent, sizeof (uint64_t))) != 0) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}
	if (parent == zfsvfs->z_shares_dir) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EPERM));
	}

	if (zfsvfs->z_utf8 && u8_validate(name,
	    strlen(name), NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EILSEQ));
	}
	if (flags & FIGNORECASE)
		zf |= ZCILOOK;

	/*
	 * We do not support links between attributes and non-attributes
	 * because of the potential security risk of creating links
	 * into "normal" file space in order to circumvent restrictions
	 * imposed in attribute space.
	 */
	if ((szp->z_pflags & ZFS_XATTR) != (dzp->z_pflags & ZFS_XATTR)) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EINVAL));
	}


	owner = zfs_fuid_map_id(zfsvfs, szp->z_uid, cr, ZFS_OWNER);
	if (owner != crgetuid(cr) && secpolicy_basic_link(svp, cr) != 0) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EPERM));
	}

	if ((error = zfs_zaccess(dzp, ACE_ADD_FILE, 0, B_FALSE, cr))) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

top:
	/*
	 * Attempt to lock directory; fail if entry already exists.
	 */
	error = zfs_dirent_lock(&dl, dzp, name, &tzp, zf, NULL, NULL);
	if (error) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_sa(tx, szp->z_sa_hdl, B_FALSE);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
	zfs_sa_upgrade_txholds(tx, szp);
	zfs_sa_upgrade_txholds(tx, dzp);
	error = dmu_tx_assign(tx, waited ? TXG_WAITED : TXG_NOWAIT);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART) {
			waited = B_TRUE;
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	error = zfs_link_create(dl, szp, tx, 0);

	if (error == 0) {
		uint64_t txtype = TX_LINK;
		if (flags & FIGNORECASE)
			txtype |= TX_CI;
		zfs_log_link(zilog, tx, txtype, dzp, szp, name);
	}

	dmu_tx_commit(tx);

	zfs_dirent_unlock(dl);

	if (error == 0) {
		vnevent_link(svp, ct);
	}

	if (zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		zil_commit(zilog, 0);

	ZFS_EXIT(zfsvfs);
	return (error);
}

#ifdef sun
/*
 * zfs_null_putapage() is used when the file system has been force
 * unmounted. It just drops the pages.
 */
/* ARGSUSED */
static int
zfs_null_putapage(vnode_t *vp, page_t **pp, u_offset_t *offp,
		size_t *lenp, int flags, cred_t *cr)
{
	pvn_write_done(pp, B_INVAL|B_FORCE|B_ERROR);
	return (0);
}

/*
 * Push a page out to disk, klustering if possible.
 *
 *	IN:	vp	- file to push page to.
 *		pp	- page to push.
 *		flags	- additional flags.
 *		cr	- credentials of caller.
 *
 *	OUT:	offp	- start of range pushed.
 *		lenp	- len of range pushed.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * NOTE: callers must have locked the page to be pushed.  On
 * exit, the page (and all other pages in the kluster) must be
 * unlocked.
 */
/* ARGSUSED */
static int
zfs_putapage(vnode_t *vp, page_t **pp, u_offset_t *offp,
		size_t *lenp, int flags, cred_t *cr)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	dmu_tx_t	*tx;
	u_offset_t	off, koff;
	size_t		len, klen;
	int		err;

	off = pp->p_offset;
	len = PAGESIZE;
	/*
	 * If our blocksize is bigger than the page size, try to kluster
	 * multiple pages so that we write a full block (thus avoiding
	 * a read-modify-write).
	 */
	if (off < zp->z_size && zp->z_blksz > PAGESIZE) {
		klen = P2ROUNDUP((ulong_t)zp->z_blksz, PAGESIZE);
		koff = ISP2(klen) ? P2ALIGN(off, (u_offset_t)klen) : 0;
		ASSERT(koff <= zp->z_size);
		if (koff + klen > zp->z_size)
			klen = P2ROUNDUP(zp->z_size - koff, (uint64_t)PAGESIZE);
		pp = pvn_write_kluster(vp, pp, &off, &len, koff, klen, flags);
	}
	ASSERT3U(btop(len), ==, btopr(len));

	/*
	 * The ordering here is critical and must adhere to the following
	 * rules in order to avoid deadlocking in either zfs_read() or
	 * zfs_free_range() due to a lock inversion.
	 *
	 * 1) The page must be unlocked prior to acquiring the range lock.
	 *    This is critical because zfs_read() calls find_lock_page()
	 *    which may block on the page lock while holding the range lock.
	 *
	 * 2) Before setting or clearing write back on a page the range lock
	 *    must be held in order to prevent a lock inversion with the
	 *    zfs_free_range() function.
	 *
	 * This presents a problem because upon entering this function the
	 * page lock is already held.  To safely acquire the range lock the
	 * page lock must be dropped.  This creates a window where another
	 * process could truncate, invalidate, dirty, or write out the page.
	 *
	 * Therefore, after successfully reacquiring the range and page locks
	 * the current page state is checked.  In the common case everything
	 * will be as is expected and it can be written out.  However, if
	 * the page state has changed it must be handled accordingly.
	 */
	mapping = pp->mapping;
	redirty_page_for_writepage(wbc, pp);
	unlock_page(pp);

	rl = zfs_range_lock(zp, pgoff, pglen, RL_WRITER);
	lock_page(pp);

	/* Page mapping changed or it was no longer dirty, we're done */
	if (unlikely((mapping != pp->mapping) || !PageDirty(pp))) {
		unlock_page(pp);
		zfs_range_unlock(rl);
		ZFS_EXIT(zsb);
		return (0);
	}

	/* Another process started write block if required */
	if (PageWriteback(pp)) {
		unlock_page(pp);
		zfs_range_unlock(rl);

		if (wbc->sync_mode != WB_SYNC_NONE)
			wait_on_page_writeback(pp);

		ZFS_EXIT(zsb);
		return (0);
	}

	/* Clear the dirty flag the required locks are held */
	if (!clear_page_dirty_for_io(pp)) {
		unlock_page(pp);
		zfs_range_unlock(rl);
		ZFS_EXIT(zsb);
		return (0);
	}

	/*
	 * Counterpart for redirty_page_for_writepage() above.  This page
	 * was in fact not skipped and should not be counted as if it were.
	 */
	wbc->pages_skipped--;
	set_page_writeback(pp);
	unlock_page(pp);

	tx = dmu_tx_create(zsb->z_os);
	dmu_tx_hold_write(tx, zp->z_id, pgoff, pglen);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	zfs_sa_upgrade_txholds(tx, zp);

	err = dmu_tx_assign(tx, TXG_NOWAIT);
	if (err != 0) {
		if (err == ERESTART) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		goto out;
	}

	if (zp->z_blksz <= PAGESIZE) {
		caddr_t va = zfs_map_page(pp, S_READ);
		ASSERT3U(len, <=, PAGESIZE);
		dmu_write(zfsvfs->z_os, zp->z_id, off, len, va, tx);
		zfs_unmap_page(pp, va);
	} else {
		err = dmu_write_pages(zfsvfs->z_os, zp->z_id, off, len, pp, tx);
	}

	if (err == 0) {
		uint64_t mtime[2], ctime[2];
		sa_bulk_attr_t bulk[3];
		int count = 0;

		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL,
		    &mtime, 16);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL,
		    &ctime, 16);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
		    &zp->z_pflags, 8);
		zfs_tstamp_update_setup(zp, CONTENT_MODIFIED, mtime, ctime,
		    B_TRUE);
		err = sa_bulk_update(zp->z_sa_hdl, bulk, count, tx);
		ASSERT0(err);
		zfs_log_write(zfsvfs->z_log, tx, TX_WRITE, zp, off, len, 0);
	}
	dmu_tx_commit(tx);

out:
	pvn_write_done(pp, (err ? B_ERROR : 0) | flags);
	if (offp)
		*offp = off;
	if (lenp)
		*lenp = len;
	zfs_range_unlock(rl);

	if (wbc->sync_mode != WB_SYNC_NONE) {
		/*
		 * Note that this is rarely called under writepages(), because
		 * writepages() normally handles the entire commit for
		 * performance reasons.
		 */
		if (zsb->z_log != NULL)
			zil_commit(zsb->z_log, zp->z_id);
	}

	return (err);
}

/*
 * Copy the portion of the file indicated from pages into the file.
 * The pages are stored in a page list attached to the files vnode.
 *
 *	IN:	vp	- vnode of file to push page data to.
 *		off	- position in file to put data.
 *		len	- amount of data to write.
 *		flags	- flags to control the operation.
 *		cr	- credentials of caller.
 *		ct	- caller context.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - ctime|mtime updated
 */
/*ARGSUSED*/
static int
zfs_putpage(vnode_t *vp, offset_t off, size_t len, int flags, cred_t *cr,
    caller_context_t *ct)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	page_t		*pp;
	size_t		io_len;
	u_offset_t	io_off;
	uint_t		blksz;
	rl_t		*rl;
	int		error = 0;

	if (zfs_is_readonly(zfsvfs) || dmu_objset_is_snapshot(zfsvfs->z_os))
		return (0);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	/*
	 * Align this request to the file block size in case we kluster.
	 * XXX - this can result in pretty aggresive locking, which can
	 * impact simultanious read/write access.  One option might be
	 * to break up long requests (len == 0) into block-by-block
	 * operations to get narrower locking.
	 */
	blksz = zp->z_blksz;
	if (ISP2(blksz))
		io_off = P2ALIGN_TYPED(off, blksz, u_offset_t);
	else
		io_off = 0;
	if (len > 0 && ISP2(blksz))
		io_len = P2ROUNDUP_TYPED(len + (off - io_off), blksz, size_t);
	else
		io_len = 0;

	if (io_len == 0) {
		/*
		 * Search the entire vp list for pages >= io_off.
		 */
		rl = zfs_range_lock(zp, io_off, UINT64_MAX, RL_WRITER);
		error = pvn_vplist_dirty(vp, io_off, zfs_putapage, flags, cr);
		goto out;
	}
	rl = zfs_range_lock(zp, io_off, io_len, RL_WRITER);

	if (off > zp->z_size) {
		/* past end of file */
		zfs_range_unlock(rl);
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	len = MIN(io_len, P2ROUNDUP(zp->z_size, PAGESIZE) - io_off);

	for (off = io_off; io_off < off + len; io_off += io_len) {
		if ((flags & B_INVAL) || ((flags & B_ASYNC) == 0)) {
			pp = page_lookup(vp, io_off,
			    (flags & (B_INVAL | B_FREE)) ? SE_EXCL : SE_SHARED);
		} else {
			pp = page_lookup_nowait(vp, io_off,
			    (flags & B_FREE) ? SE_EXCL : SE_SHARED);
		}

		if (pp != NULL && pvn_getdirty(pp, flags)) {
			int err;

			/*
			 * Found a dirty page to push
			 */
			err = zfs_putapage(vp, pp, &io_off, &io_len, flags, cr);
			if (err)
				error = err;
		} else {
			io_len = PAGESIZE;
		}
	}
out:
	zfs_range_unlock(rl);
	if ((flags & B_ASYNC) == 0 || zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		zil_commit(zfsvfs->z_log, zp->z_id);
	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif	/* sun */

/*ARGSUSED*/
void
zfs_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);

	if (ubc_pages_resident(vp) || spl_ubc_is_mapped(vp, NULL)) {
		ASSERT3P(zp->z_sa_hdl, !=, NULL);
		ASSERT3S(zp->z_size, ==, ubc_getsize(vp));
		ASSERT3S(ubc_getsize(ZTOV(zp)), >, 0);
		if (is_file_clean(ZTOV(zp), ubc_getsize(vp)) != 0 ||
		    vnode_isinuse(vp, 0) != 0) {
			printf("ZFS: %s:%d: ubc_pages_resident true, is_file_clean %d (0==clean),"
			    " isinuse %d  mapped? %d write? %d file %s -- RETURNING\n",
			    __func__, __LINE__, is_file_clean(ZTOV(zp), ubc_getsize(vp)),
			    vnode_isinuse(vp, 0),
			    spl_ubc_is_mapped(vp, NULL), spl_ubc_is_mapped_writable(vp),
			    zp->z_name_cache);
			goto atime_check;
		}
	} else if (vnode_isinuse(vp, 0)) {
		printf("ZFS: %s:%d: (note) vnode_isinuse(vp, 0) true clean? %d (ubcsize %lld)"
		    " for file %s\n",
		    __func__, __LINE__, is_file_clean(ZTOV(zp), ubc_getsize(vp)),
		    ubc_getsize(vp),
		    zp->z_name_cache);
	}

	// see above - rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);
	if (zp->z_sa_hdl == NULL) {
		/*
		 * The fs has been unmounted, or we did a
		 * suspend/resume and this file no longer exists.
		 */
		rw_exit(&zfsvfs->z_teardown_inactive_lock);
		vnode_recycle(vp);
		return;
	}

	mutex_enter(&zp->z_lock);
	if (zp->z_unlinked) {
		/*
		 * Fast path to recycle a vnode of a removed file.
		 */
		mutex_exit(&zp->z_lock);
		rw_exit(&zfsvfs->z_teardown_inactive_lock);
		vnode_recycle(vp);
		return;
	}
	mutex_exit(&zp->z_lock);

atime_check:
	if (zp->z_atime_dirty && zp->z_unlinked == 0) {
		dmu_tx_t *tx = dmu_tx_create(zfsvfs->z_os);

		dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
		zfs_sa_upgrade_txholds(tx, zp);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
		} else {
			mutex_enter(&zp->z_lock);
			(void) sa_update(zp->z_sa_hdl, SA_ZPL_ATIME(zfsvfs),
			    (void *)&zp->z_atime, sizeof (zp->z_atime), tx);
			zp->z_atime_dirty = 0;
			mutex_exit(&zp->z_lock);
			dmu_tx_commit(tx);
		}
	}
	rw_exit(&zfsvfs->z_teardown_inactive_lock);
}

#ifdef sun
/*
 * Bounds-check the seek operation.
 *
 *	IN:	vp	- vnode seeking within
 *		ooff	- old file offset
 *		noffp	- pointer to new file offset
 *		ct	- caller context
 *
 *	RETURN:	0 if success
 *		EINVAL if new offset invalid
 */
/* ARGSUSED */
static int
zfs_seek(vnode_t *vp, offset_t ooff, offset_t *noffp,
    caller_context_t *ct)
{
	if (vp->v_type == VDIR)
		return (0);
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}

/*
 * Pre-filter the generic locking function to trap attempts to place
 * a mandatory lock on a memory mapped file.
 */
static int
zfs_frlock(vnode_t *vp, int cmd, flock64_t *bfp, int flag, offset_t offset,
    flk_callback_t *flk_cbp, cred_t *cr, caller_context_t *ct)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	/*
	 * We are following the UFS semantics with respect to mapcnt
	 * here: If we see that the file is mapped already, then we will
	 * return an error, but we don't worry about races between this
	 * function and zfs_map().
	 */
	if (zp->z_mapcnt > 0 && MANDMODE(zp->z_mode)) {
		ZFS_EXIT(zfsvfs);
		return ((EAGAIN));
	}
	ZFS_EXIT(zfsvfs);
	return (fs_frlock(vp, cmd, bfp, flag, offset, flk_cbp, cr, ct));
}

/*
 * If we can't find a page in the cache, we will create a new page
 * and fill it with file data.  For efficiency, we may try to fill
 * multiple pages at once (klustering) to fill up the supplied page
 * list.  Note that the pages to be filled are held with an exclusive
 * lock to prevent access by other threads while they are being filled.
 */
static int
zfs_fillpage(vnode_t *vp, u_offset_t off, struct seg *seg,
    caddr_t addr, page_t *pl[], size_t plsz, enum seg_rw rw)
{
	znode_t *zp = VTOZ(vp);
	page_t *pp, *cur_pp;
	objset_t *os = zp->z_zfsvfs->z_os;
	u_offset_t io_off, total;
	size_t io_len;
	int err;

	if (plsz == PAGESIZE || zp->z_blksz <= PAGESIZE) {
		/*
		 * We only have a single page, don't bother klustering
		 */
		io_off = off;
		io_len = PAGESIZE;
		pp = page_create_va(vp, io_off, io_len,
		    PG_EXCL | PG_WAIT, seg, addr);
	} else {
		/*
		 * Try to find enough pages to fill the page list
		 */
		pp = pvn_read_kluster(vp, off, seg, addr, &io_off,
		    &io_len, off, plsz, 0);
	}
	if (pp == NULL) {
		/*
		 * The page already exists, nothing to do here.
		 */
		*pl = NULL;
		return (0);
	}

	/*
	 * Fill the pages in the kluster.
	 */
	cur_pp = pp;
	for (total = io_off + io_len; io_off < total; io_off += PAGESIZE) {
		caddr_t va;

		ASSERT3U(io_off, ==, cur_pp->p_offset);
		va = zfs_map_page(cur_pp, S_WRITE);
		err = dmu_read(os, zp->z_id, io_off, PAGESIZE, va,
		    DMU_READ_PREFETCH);
		zfs_unmap_page(cur_pp, va);
		if (err) {
			/* On error, toss the entire kluster */
			pvn_read_done(pp, B_ERROR);
			/* convert checksum errors into IO errors */
			if (err == ECKSUM)
				err = SET_ERROR(EIO);
			return (err);
		}
		cur_pp = cur_pp->p_next;
	}

	/*
	 * Fill in the page list array from the kluster starting
	 * from the desired offset `off'.
	 * NOTE: the page list will always be null terminated.
	 */
	pvn_plist_init(pp, pl, plsz, off, io_len, rw);
	ASSERT(pl == NULL || (*pl)->p_offset == off);

	return (0);
}

/*
 * Return pointers to the pages for the file region [off, off + len]
 * in the pl array.  If plsz is greater than len, this function may
 * also return page pointers from after the specified region
 * (i.e. the region [off, off + plsz]).  These additional pages are
 * only returned if they are already in the cache, or were created as
 * part of a klustered read.
 *
 *	IN:	vp	- vnode of file to get data from.
 *		off	- position in file to get data from.
 *		len	- amount of data to retrieve.
 *		plsz	- length of provided page list.
 *		seg	- segment to obtain pages for.
 *		addr	- virtual address of fault.
 *		rw	- mode of created pages.
 *		cr	- credentials of caller.
 *		ct	- caller context.
 *
 *	OUT:	protp	- protection mode of created pages.
 *		pl	- list of pages created.
 *
 *	RETURN:	0 on success, error code on failure.
 *
 * Timestamps:
 *	vp - atime updated
 */
/* ARGSUSED */
static int
zfs_getpage(vnode_t *vp, offset_t off, size_t len, uint_t *protp,
	page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, cred_t *cr, caller_context_t *ct)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	page_t		**pl0 = pl;
	int		err = 0;

	/* we do our own caching, faultahead is unnecessary */
	if (pl == NULL)
		return (0);
	else if (len > plsz)
		len = plsz;
	else
		len = P2ROUNDUP(len, PAGESIZE);
	ASSERT(plsz >= len);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	if (protp)
		*protp = PROT_ALL;

	/*
	 * Loop through the requested range [off, off + len) looking
	 * for pages.  If we don't find a page, we will need to create
	 * a new page and fill it with data from the file.
	 */
	while (len > 0) {
		if (*pl = page_lookup(vp, off, SE_SHARED))
			*(pl+1) = NULL;
		else if (err = zfs_fillpage(vp, off, seg, addr, pl, plsz, rw))
			goto out;
		while (*pl) {
			ASSERT3U((*pl)->p_offset, ==, off);
			off += PAGESIZE;
			addr += PAGESIZE;
			if (len > 0) {
				ASSERT3U(len, >=, PAGESIZE);
				len -= PAGESIZE;
			}
			ASSERT3U(plsz, >=, PAGESIZE);
			plsz -= PAGESIZE;
			pl++;
		}
	}

	/*
	 * Fill out the page array with any pages already in the cache.
	 */
	while (plsz > 0 &&
	    (*pl++ = page_lookup_nowait(vp, off, SE_SHARED))) {
			off += PAGESIZE;
			plsz -= PAGESIZE;
	}
out:
	if (err) {
		/*
		 * Release any pages we have previously locked.
		 */
		while (pl > pl0)
			page_unlock(*--pl);
	} else {
		ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
	}

	*pl = NULL;

	ZFS_EXIT(zfsvfs);
	return (err);
}

/*
 * Request a memory map for a section of a file.  This code interacts
 * with common code and the VM system as follows:
 *
 *	common code calls mmap(), which ends up in smmap_common()
 *
 *	this calls VOP_MAP(), which takes you into (say) zfs
 *
 *	zfs_map() calls as_map(), passing segvn_create() as the callback
 *
 *	segvn_create() creates the new segment and calls VOP_ADDMAP()
 *
 *	zfs_addmap() updates z_mapcnt
 */
/*ARGSUSED*/
/* Apple version is in zfs_vnops_osx.c */
#ifdef __FreeBSD__
static int
zfs_map(vnode_t *vp, offset_t off, struct as *as, caddr_t *addrp,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	segvn_crargs_t	vn_a;
	int		error;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	/*
	 * Note: ZFS_READONLY is handled in zfs_zaccess_common.
	 */

	if ((prot & PROT_WRITE) && (zp->z_pflags &
	    (ZFS_IMMUTABLE | ZFS_APPENDONLY))) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EPERM));
	}

	if ((prot & (PROT_READ | PROT_EXEC)) &&
	    (zp->z_pflags & ZFS_AV_QUARANTINED)) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EACCES));
	}

	if (vp->v_flag & VNOMAP) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(ENOSYS));
	}

	if (off < 0 || len > MAXOFFSET_T - off) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(ENXIO));
	}

	if (vp->v_type != VREG) {
		ZFS_EXIT(zfsvfs);
		return ((ENODEV));
	}

	/*
	 * If file is locked, disallow mapping.
	 */
	if (MANDMODE(zp->z_mode) && vn_has_flocks(vp)) {
		ZFS_EXIT(zfsvfs);
		return ((EAGAIN));
	}

	as_rangelock(as);
	error = choose_addr(as, addrp, len, off, ADDR_VACALIGN, flags);
	if (error != 0) {
		as_rangeunlock(as);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	vn_a.vp = vp;
	vn_a.offset = (u_offset_t)off;
	vn_a.type = flags & MAP_TYPE;
	vn_a.prot = prot;
	vn_a.maxprot = maxprot;
	vn_a.cred = cr;
	vn_a.amp = NULL;
	vn_a.flags = flags & ~MAP_TYPE;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	error = as_map(as, *addrp, len, segvn_create, &vn_a);

	as_rangeunlock(as);
	ZFS_EXIT(zfsvfs);
	return (error);
}
#endif

/* ARGSUSED */
static int
zfs_addmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	uint64_t pages = btopr(len);

	atomic_add_64(&VTOZ(vp)->z_mapcnt, pages);
	return (0);
}

/*
 * The reason we push dirty pages as part of zfs_delmap() is so that we get a
 * more accurate mtime for the associated file.  Since we don't have a way of
 * detecting when the data was actually modified, we have to resort to
 * heuristics.  If an explicit msync() is done, then we mark the mtime when the
 * last page is pushed.  The problem occurs when the msync() call is omitted,
 * which by far the most common case:
 *
 * 	open()
 * 	mmap()
 * 	<modify memory>
 * 	munmap()
 * 	close()
 * 	<time lapse>
 * 	putpage() via fsflush
 *
 * If we wait until fsflush to come along, we can have a modification time that
 * is some arbitrary point in the future.  In order to prevent this in the
 * common case, we flush pages whenever a (MAP_SHARED, PROT_WRITE) mapping is
 * torn down.
 */
/* ARGSUSED */
static int
zfs_delmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cr,
    caller_context_t *ct)
{
	uint64_t pages = btopr(len);

	ASSERT3U(VTOZ(vp)->z_mapcnt, >=, pages);
	atomic_add_64(&VTOZ(vp)->z_mapcnt, -pages);

	if ((flags & MAP_SHARED) && (prot & PROT_WRITE) &&
	    vn_has_cached_data(vp))
		(void) VOP_PUTPAGE(vp, off, len, B_ASYNC, cr, ct);

	return (0);
}
#endif	/* sun */

/*
 * Free or allocate space in a file.  Currently, this function only
 * supports the `F_FREESP' command.  However, this command is somewhat
 * misnamed, as its functionality includes the ability to allocate as
 * well as free space.
 *
 *	IN:	vp	- vnode of file to free data in.
 *		cmd	- action to take (only F_FREESP supported).
 *		bfp	- section of file to free/alloc.
 *		flag	- current file open mode flags.
 *		offset	- current file offset.
 *		cr	- credentials of caller [UNUSED].
 *		ct	- caller context.
 *
 *	RETURN:	0 on success, error code on failure.
 *
 * Timestamps:
 *	vp - ctime|mtime updated
 */
/* ARGSUSED */
int
zfs_space(vnode_t *vp, int cmd, struct flock *bfp, int flag,
    offset_t offset, cred_t *cr, caller_context_t *ct)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	uint64_t	off, len;
	int		error;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	if (cmd != F_FREESP) {
		printf("ZFS: fallocate() called for non F_FREESP method!\n");
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(ENOTSUP));
	}
#ifndef __APPLE__
	if (error = convoff(vp, bfp, 0, offset)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}
#endif

	if (bfp->l_len < 0) {
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EINVAL));
	}

	/*
	 * Permissions aren't checked on Solaris because on this OS
	 * zfs_space() can only be called with an opened file handle.
	 * On Linux we can get here through truncate_range() which
	 * operates directly on inodes, so we need to check access rights.
	 */
	if ((error = zfs_zaccess(zp, ACE_WRITE_DATA, 0, B_FALSE, cr))) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	off = bfp->l_start;
	len = bfp->l_len; /* 0 means from off to end of file */

	error = zfs_freesp(zp, off, len, flag, TRUE);

	ZFS_EXIT(zfsvfs);
	return (error);
}

#if sun
CTASSERT(sizeof(struct zfid_short) <= sizeof(struct fid));
CTASSERT(sizeof(struct zfid_long) <= sizeof(struct fid));
#endif

#ifndef __APPLE__
/*ARGSUSED*/
static int
zfs_fid(vnode_t *vp, fid_t *fidp, caller_context_t *ct)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	uint32_t	gen;
	uint64_t	gen64;
	uint64_t	object = zp->z_id;
	zfid_short_t	*zfid;
	int		size, i, error;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	if ((error = sa_lookup(zp->z_sa_hdl, SA_ZPL_GEN(zfsvfs),
	    &gen64, sizeof (uint64_t))) != 0) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	gen = (uint32_t)gen64;

	size = (zfsvfs->z_parent != zfsvfs) ? LONG_FID_LEN : SHORT_FID_LEN;

#ifdef illumos
	if (fidp->fid_len < size) {
		fidp->fid_len = size;
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(ENOSPC));
	}
#else
	fidp->fid_len = size;
#endif

	zfid = (zfid_short_t *)fidp;

	zfid->zf_len = size;

	for (i = 0; i < sizeof (zfid->zf_object); i++)
		zfid->zf_object[i] = (uint8_t)(object >> (8 * i));

	/* Must have a non-zero generation number to distinguish from .zfs */
	if (gen == 0)
		gen = 1;
	for (i = 0; i < sizeof (zfid->zf_gen); i++)
		zfid->zf_gen[i] = (uint8_t)(gen >> (8 * i));

	if (size == LONG_FID_LEN) {
		uint64_t	objsetid = dmu_objset_id(zfsvfs->z_os);
		zfid_long_t	*zlfid;

		zlfid = (zfid_long_t *)fidp;

		for (i = 0; i < sizeof (zlfid->zf_setid); i++)
			zlfid->zf_setid[i] = (uint8_t)(objsetid >> (8 * i));

		/* XXX - this should be the generation number for the objset */
		for (i = 0; i < sizeof (zlfid->zf_setgen); i++)
			zlfid->zf_setgen[i] = 0;
	}

	ZFS_EXIT(zfsvfs);
	return (0);
}
#endif

#ifndef __APPLE__
static int
zfs_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
    caller_context_t *ct)
{
	znode_t		*zp, *xzp;
	zfsvfs_t	*zfsvfs;
	zfs_dirlock_t	*dl;
	int		error;

	switch (cmd) {
	case _PC_LINK_MAX:
		*valp = INT_MAX;
		return (0);

	case _PC_FILESIZEBITS:
		*valp = 64;
		return (0);
#ifdef sun
	case _PC_XATTR_EXISTS:
		zp = VTOZ(vp);
		zfsvfs = zp->z_zfsvfs;
		ZFS_ENTER(zfsvfs);
		ZFS_VERIFY_ZP(zp);
		*valp = 0;
		error = zfs_dirent_lock(&dl, zp, "", &xzp,
		    ZXATTR | ZEXISTS | ZSHARED, NULL, NULL);
		if (error == 0) {
			zfs_dirent_unlock(dl);
			if (!zfs_dirempty(xzp))
				*valp = 1;
			VN_RELE(ZTOV(xzp));
		} else if (error == ENOENT) {
			/*
			 * If there aren't extended attributes, it's the
			 * same as having zero of them.
			 */
			error = 0;
		}
		ZFS_EXIT(zfsvfs);
		return (error);

	case _PC_SATTR_ENABLED:
	case _PC_SATTR_EXISTS:
		*valp = vfs_has_feature(vp->v_vfsp, VFSFT_SYSATTR_VIEWS) &&
		    (vp->v_type == VREG || vp->v_type == VDIR);
		return (0);

	case _PC_ACCESS_FILTERING:
		*valp = vfs_has_feature(vp->v_vfsp, VFSFT_ACCESS_FILTER) &&
		    vp->v_type == VDIR;
		return (0);

	case _PC_ACL_ENABLED:
		*valp = _ACL_ACE_ENABLED;
		return (0);
#endif	/* sun */
	case _PC_MIN_HOLE_SIZE:
		*valp = (int)SPA_MINBLOCKSIZE;
		return (0);
#ifdef sun
	case _PC_TIMESTAMP_RESOLUTION:
		/* nanosecond timestamp resolution */
		*valp = 1L;
		return (0);
#endif	/* sun */
	case _PC_ACL_EXTENDED:
		*valp = 0;
		return (0);

	case _PC_ACL_NFS4:
		*valp = 1;
		return (0);

	case _PC_ACL_PATH_MAX:
		*valp = ACL_MAX_ENTRIES;
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}
#endif

#ifndef __APPLE__
/*ARGSUSED*/
static int
zfs_getsecattr(vnode_t *vp, vsecattr_t *vsecp, int flag, cred_t *cr,
    caller_context_t *ct)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;
	boolean_t skipaclchk = (flag & ATTR_NOACLCHECK) ? B_TRUE : B_FALSE;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);
	error = zfs_getacl(zp, vsecp, skipaclchk, cr);
	ZFS_EXIT(zfsvfs);

	return (error);
}
#endif


/*ARGSUSED*/
int
zfs_setsecattr(vnode_t *vp, vsecattr_t *vsecp, int flag, cred_t *cr,
    caller_context_t *ct)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;
	boolean_t skipaclchk = /*(flag & ATTR_NOACLCHECK) ? B_TRUE :*/ B_FALSE;
	zilog_t	*zilog = zfsvfs->z_log;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	error = zfs_setacl(zp, vsecp, skipaclchk, cr); // struct kauth_acl *?

	if (zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		zil_commit(zilog, 0);

	ZFS_EXIT(zfsvfs);
	return (error);
}

#ifdef sun
/*
 * Tunable, both must be a power of 2.
 *
 * zcr_blksz_min: the smallest read we may consider to loan out an arcbuf
 * zcr_blksz_max: if set to less than the file block size, allow loaning out of
 *                an arcbuf for a partial block read
 */
int zcr_blksz_min = (1 << 10);	/* 1K */
int zcr_blksz_max = (1 << 17);	/* 128K */

/*ARGSUSED*/
static int
zfs_reqzcbuf(vnode_t *vp, enum uio_rw ioflag, xuio_t *xuio, cred_t *cr,
    caller_context_t *ct)
{
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int max_blksz = zfsvfs->z_max_blksz;
	uio_t *uio = &xuio->xu_uio;
	ssize_t size = uio->uio_resid;
	offset_t offset = uio->uio_loffset;
	int blksz;
	int fullblk, i;
	arc_buf_t *abuf;
	ssize_t maxsize;
	int preamble, postamble;

	if (xuio->xu_type != UIOTYPE_ZEROCOPY)
		return (SET_ERROR(EINVAL));

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);
	switch (ioflag) {
	case UIO_WRITE:
		/*
		 * Loan out an arc_buf for write if write size is bigger than
		 * max_blksz, and the file's block size is also max_blksz.
		 */
		blksz = max_blksz;
		if (size < blksz || zp->z_blksz != blksz) {
			ZFS_EXIT(zfsvfs);
			return (SET_ERROR(EINVAL));
		}
		/*
		 * Caller requests buffers for write before knowing where the
		 * write offset might be (e.g. NFS TCP write).
		 */
		if (offset == -1) {
			preamble = 0;
		} else {
			preamble = P2PHASE(offset, blksz);
			if (preamble) {
				preamble = blksz - preamble;
				size -= preamble;
			}
		}

		postamble = P2PHASE(size, blksz);
		size -= postamble;

		fullblk = size / blksz;
		(void) dmu_xuio_init(xuio,
		    (preamble != 0) + fullblk + (postamble != 0));
		DTRACE_PROBE3(zfs_reqzcbuf_align, int, preamble,
		    int, postamble, int,
		    (preamble != 0) + fullblk + (postamble != 0));

		/*
		 * Have to fix iov base/len for partial buffers.  They
		 * currently represent full arc_buf's.
		 */
		if (preamble) {
			/* data begins in the middle of the arc_buf */
			abuf = dmu_request_arcbuf(sa_get_db(zp->z_sa_hdl),
			    blksz);
			ASSERT(abuf);
			(void) dmu_xuio_add(xuio, abuf,
			    blksz - preamble, preamble);
		}

		for (i = 0; i < fullblk; i++) {
			abuf = dmu_request_arcbuf(sa_get_db(zp->z_sa_hdl),
			    blksz);
			ASSERT(abuf);
			(void) dmu_xuio_add(xuio, abuf, 0, blksz);
		}

		if (postamble) {
			/* data ends in the middle of the arc_buf */
			abuf = dmu_request_arcbuf(sa_get_db(zp->z_sa_hdl),
			    blksz);
			ASSERT(abuf);
			(void) dmu_xuio_add(xuio, abuf, 0, postamble);
		}
		break;
	case UIO_READ:
		/*
		 * Loan out an arc_buf for read if the read size is larger than
		 * the current file block size.  Block alignment is not
		 * considered.  Partial arc_buf will be loaned out for read.
		 */
		blksz = zp->z_blksz;
		if (blksz < zcr_blksz_min)
			blksz = zcr_blksz_min;
		if (blksz > zcr_blksz_max)
			blksz = zcr_blksz_max;
		/* avoid potential complexity of dealing with it */
		if (blksz > max_blksz) {
			ZFS_EXIT(zfsvfs);
			return (SET_ERROR(EINVAL));
		}

		maxsize = zp->z_size - uio->uio_loffset;
		if (size > maxsize)
			size = maxsize;

		if (size < blksz || vn_has_cached_data(vp)) {
			ZFS_EXIT(zfsvfs);
			return (SET_ERROR(EINVAL));
		}
		break;
	default:
		ZFS_EXIT(zfsvfs);
		return (SET_ERROR(EINVAL));
	}

	uio->uio_extflg = UIO_XUIO;
	XUIO_XUZC_RW(xuio) = ioflag;
	ZFS_EXIT(zfsvfs);
	return (0);
}

/*ARGSUSED*/
static int
zfs_retzcbuf(vnode_t *vp, xuio_t *xuio, cred_t *cr, caller_context_t *ct)
{
	int i;
	arc_buf_t *abuf;
	int ioflag = XUIO_XUZC_RW(xuio);

	ASSERT(xuio->xu_type == UIOTYPE_ZEROCOPY);

	i = dmu_xuio_cnt(xuio);
	while (i-- > 0) {
		abuf = dmu_xuio_arcbuf(xuio, i);
		/*
		 * if abuf == NULL, it must be a write buffer
		 * that has been returned in zfs_write().
		 */
		if (abuf)
			dmu_return_arcbuf(abuf);
		ASSERT(abuf || ioflag == UIO_WRITE);
	}

	dmu_xuio_fini(xuio);
	return (0);
}

/*
 * Predeclare these here so that the compiler assumes that
 * this is an "old style" function declaration that does
 * not include arguments => we won't get type mismatch errors
 * in the initializations that follow.
 */
static int zfs_inval();
static int zfs_isdir();

static int
zfs_inval()
{
	return ((EINVAL));
}

static int
zfs_isdir()
{
	return ((EISDIR));
}

/*
 * Directory vnode operations template
 */
vnodeops_t *zfs_dvnodeops;
const fs_operation_def_t zfs_dvnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = zfs_open },
	VOPNAME_CLOSE,		{ .vop_close = zfs_close },
	VOPNAME_READ,		{ .error = zfs_isdir },
	VOPNAME_WRITE,		{ .error = zfs_isdir },
	VOPNAME_IOCTL,		{ .vop_ioctl = zfs_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = zfs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = zfs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = zfs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = zfs_lookup },
	VOPNAME_CREATE,		{ .vop_create = zfs_create },
	VOPNAME_REMOVE,		{ .vop_remove = zfs_remove },
	VOPNAME_LINK,		{ .vop_link = zfs_link },
	VOPNAME_RENAME,		{ .vop_rename = zfs_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = zfs_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = zfs_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = zfs_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = zfs_symlink },
	VOPNAME_FSYNC,		{ .vop_fsync = zfs_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = zfs_inactive },
	VOPNAME_FID,		{ .vop_fid = zfs_fid },
	VOPNAME_SEEK,		{ .vop_seek = zfs_seek },
	VOPNAME_PATHCONF,	{ .vop_pathconf = zfs_pathconf },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = zfs_getsecattr },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = zfs_setsecattr },
	VOPNAME_VNEVENT, 	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};

/*
 * Regular file vnode operations template
 */
vnodeops_t *zfs_fvnodeops;
const fs_operation_def_t zfs_fvnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = zfs_open },
	VOPNAME_CLOSE,		{ .vop_close = zfs_close },
	VOPNAME_READ,		{ .vop_read = zfs_read },
	VOPNAME_WRITE,		{ .vop_write = zfs_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = zfs_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = zfs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = zfs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = zfs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = zfs_lookup },
	VOPNAME_RENAME,		{ .vop_rename = zfs_rename },
	VOPNAME_FSYNC,		{ .vop_fsync = zfs_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = zfs_inactive },
	VOPNAME_FID,		{ .vop_fid = zfs_fid },
	VOPNAME_SEEK,		{ .vop_seek = zfs_seek },
	VOPNAME_FRLOCK,		{ .vop_frlock = zfs_frlock },
	VOPNAME_SPACE,		{ .vop_space = zfs_space },
	VOPNAME_GETPAGE,	{ .vop_getpage = zfs_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = zfs_putpage },
	VOPNAME_MAP,		{ .vop_map = zfs_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = zfs_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = zfs_delmap },
	VOPNAME_PATHCONF,	{ .vop_pathconf = zfs_pathconf },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = zfs_getsecattr },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = zfs_setsecattr },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	VOPNAME_REQZCBUF, 	{ .vop_reqzcbuf = zfs_reqzcbuf },
	VOPNAME_RETZCBUF, 	{ .vop_retzcbuf = zfs_retzcbuf },
	NULL,			NULL
};

/*
 * Symbolic link vnode operations template
 */
vnodeops_t *zfs_symvnodeops;
const fs_operation_def_t zfs_symvnodeops_template[] = {
	VOPNAME_GETATTR,	{ .vop_getattr = zfs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = zfs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = zfs_access },
	VOPNAME_RENAME,		{ .vop_rename = zfs_rename },
	VOPNAME_READLINK,	{ .vop_readlink = zfs_readlink },
	VOPNAME_INACTIVE,	{ .vop_inactive = zfs_inactive },
	VOPNAME_FID,		{ .vop_fid = zfs_fid },
	VOPNAME_PATHCONF,	{ .vop_pathconf = zfs_pathconf },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};

/*
 * special share hidden files vnode operations template
 */
vnodeops_t *zfs_sharevnodeops;
const fs_operation_def_t zfs_sharevnodeops_template[] = {
	VOPNAME_GETATTR,	{ .vop_getattr = zfs_getattr },
	VOPNAME_ACCESS,		{ .vop_access = zfs_access },
	VOPNAME_INACTIVE,	{ .vop_inactive = zfs_inactive },
	VOPNAME_FID,		{ .vop_fid = zfs_fid },
	VOPNAME_PATHCONF,	{ .vop_pathconf = zfs_pathconf },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = zfs_getsecattr },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = zfs_setsecattr },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};

/*
 * Extended attribute directory vnode operations template
 *	This template is identical to the directory vnodes
 *	operation template except for restricted operations:
 *		VOP_MKDIR()
 *		VOP_SYMLINK()
 * Note that there are other restrictions embedded in:
 *	zfs_create()	- restrict type to VREG
 *	zfs_link()	- no links into/out of attribute space
 *	zfs_rename()	- no moves into/out of attribute space
 */
vnodeops_t *zfs_xdvnodeops;
const fs_operation_def_t zfs_xdvnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = zfs_open },
	VOPNAME_CLOSE,		{ .vop_close = zfs_close },
	VOPNAME_IOCTL,		{ .vop_ioctl = zfs_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = zfs_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = zfs_setattr },
	VOPNAME_ACCESS,		{ .vop_access = zfs_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = zfs_lookup },
	VOPNAME_CREATE,		{ .vop_create = zfs_create },
	VOPNAME_REMOVE,		{ .vop_remove = zfs_remove },
	VOPNAME_LINK,		{ .vop_link = zfs_link },
	VOPNAME_RENAME,		{ .vop_rename = zfs_rename },
	VOPNAME_MKDIR,		{ .error = zfs_inval },
	VOPNAME_RMDIR,		{ .vop_rmdir = zfs_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = zfs_readdir },
	VOPNAME_SYMLINK,	{ .error = zfs_inval },
	VOPNAME_FSYNC,		{ .vop_fsync = zfs_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = zfs_inactive },
	VOPNAME_FID,		{ .vop_fid = zfs_fid },
	VOPNAME_SEEK,		{ .vop_seek = zfs_seek },
	VOPNAME_PATHCONF,	{ .vop_pathconf = zfs_pathconf },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = zfs_getsecattr },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = zfs_setsecattr },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};

/*
 * Error vnode operations template
 */
vnodeops_t *zfs_evnodeops;
const fs_operation_def_t zfs_evnodeops_template[] = {
	VOPNAME_INACTIVE,	{ .vop_inactive = zfs_inactive },
	VOPNAME_PATHCONF,	{ .vop_pathconf = zfs_pathconf },
	NULL,			NULL
};
#endif	/* sun */

#if 0 // unused function
static int
ioflags(int ioflags)
{
	int flags = 0;

	if (ioflags & IO_APPEND)
		flags |= FAPPEND;
	if (ioflags & IO_NDELAY)
        	flags |= FNONBLOCK;
	if (ioflags & IO_SYNC)
		flags |= (FSYNC | FDSYNC | FRSYNC);

	return (flags);
}
#endif


#ifdef __FreeBSD__
static int
zfs_getpages(struct vnode *vp, page_t *m, int count, int reqpage)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	objset_t *os = zp->z_zfsvfs->z_os;
	page_t mfirst, mlast, mreq;
	vm_object_t object;
	caddr_t va;
	struct sf_buf *sf;
	off_t startoff, endoff;
	int i, error;
	vm_pindex_t reqstart, reqend;
	int pcount, lsize, reqsize, size;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	pcount = OFF_TO_IDX(round_page(count));
	mreq = m[reqpage];
	object = mreq->object;
	error = 0;

	KASSERT(vp->v_object == object, ("mismatching object"));

	if (pcount > 1 && zp->z_blksz > PAGESIZE) {
		startoff = rounddown(IDX_TO_OFF(mreq->pindex), zp->z_blksz);
		reqstart = OFF_TO_IDX(round_page(startoff));
		if (reqstart < m[0]->pindex)
			reqstart = 0;
		else
			reqstart = reqstart - m[0]->pindex;
		endoff = roundup(IDX_TO_OFF(mreq->pindex) + PAGE_SIZE,
		    zp->z_blksz);
		reqend = OFF_TO_IDX(trunc_page(endoff)) - 1;
		if (reqend > m[pcount - 1]->pindex)
			reqend = m[pcount - 1]->pindex;
		reqsize = reqend - m[reqstart]->pindex + 1;
		KASSERT(reqstart <= reqpage && reqpage < reqstart + reqsize,
		    ("reqpage beyond [reqstart, reqstart + reqsize[ bounds"));
	} else {
		reqstart = reqpage;
		reqsize = 1;
	}
	mfirst = m[reqstart];
	mlast = m[reqstart + reqsize - 1];

	zfs_vmobject_wlock(object);

	for (i = 0; i < reqstart; i++) {
		vm_page_lock(m[i]);
		vm_page_free(m[i]);
		vm_page_unlock(m[i]);
	}
	for (i = reqstart + reqsize; i < pcount; i++) {
		vm_page_lock(m[i]);
		vm_page_free(m[i]);
		vm_page_unlock(m[i]);
	}

	if (mreq->valid && reqsize == 1) {
		if (mreq->valid != VM_PAGE_BITS_ALL)
			vm_page_zero_invalid(mreq, TRUE);
		zfs_vmobject_wunlock(object);
		ZFS_EXIT(zfsvfs);
		return (zfs_vm_pagerret_ok);
	}

	PCPU_INC(cnt.v_vnodein);
	PCPU_ADD(cnt.v_vnodepgsin, reqsize);

	if (IDX_TO_OFF(mreq->pindex) >= object->un_pager.vnp.vnp_size) {
		for (i = reqstart; i < reqstart + reqsize; i++) {
			if (i != reqpage) {
				vm_page_lock(m[i]);
				vm_page_free(m[i]);
				vm_page_unlock(m[i]);
			}
		}
		zfs_vmobject_wunlock(object);
		ZFS_EXIT(zfsvfs);
		return (zfs_vm_pagerret_bad);
	}

	lsize = PAGE_SIZE;
	if (IDX_TO_OFF(mlast->pindex) + lsize > object->un_pager.vnp.vnp_size)
		lsize = object->un_pager.vnp.vnp_size - IDX_TO_OFF(mlast->pindex);

	zfs_vmobject_wunlock(object);

	for (i = reqstart; i < reqstart + reqsize; i++) {
		size = PAGE_SIZE;
		if (i == (reqstart + reqsize - 1))
			size = lsize;
		va = zfs_map_page(m[i], &sf);
		error = dmu_read(os, zp->z_id, IDX_TO_OFF(m[i]->pindex),
		    size, va, DMU_READ_PREFETCH);
		if (size != PAGE_SIZE)
			bzero(va + size, PAGE_SIZE - size);
		zfs_unmap_page(sf);
		if (error != 0)
			break;
	}

	zfs_vmobject_wlock(object);

	for (i = reqstart; i < reqstart + reqsize; i++) {
		if (!error)
			m[i]->valid = VM_PAGE_BITS_ALL;
		KASSERT(m[i]->dirty == 0, ("zfs_getpages: page %p is dirty", m[i]));
		if (i != reqpage)
			vm_page_readahead_finish(m[i]);
	}

	zfs_vmobject_wunlock(object);

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
	ZFS_EXIT(zfsvfs);
	return (error ? zfs_vm_pagerret_error : zfs_vm_pagerret_ok);
}

static int
zfs_freebsd_getpages(ap)
	struct vop_getpages_args /* {
		struct vnode *a_vp;
		page_t *a_m;
		int a_count;
		int a_reqpage;
		vm_ooffset_t a_offset;
	} */ *ap;
{

	return (zfs_getpages(ap->a_vp, ap->a_m, ap->a_count, ap->a_reqpage));
}

static int
zfs_freebsd_bmap(ap)
	struct vop_bmap_args /* {
		struct vnode *a_vp;
		daddr_t  a_bn;
		struct bufobj **a_bop;
		daddr_t *a_bnp;
		int *a_runp;
		int *a_runb;
	} */ *ap;
{

	if (ap->a_bop != NULL)
		*ap->a_bop = &ap->a_vp->v_bufobj;
	if (ap->a_bnp != NULL)
		*ap->a_bnp = ap->a_bn;
	if (ap->a_runp != NULL)
		*ap->a_runp = 0;
	if (ap->a_runb != NULL)
		*ap->a_runb = 0;

	return (0);
}

static int
zfs_freebsd_open(ap)
	struct vop_open_args /* {
		struct vnode *a_vp;
		int a_mode;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
{
	vnode_t	*vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	int error;

	error = zfs_open(&vp, ap->a_mode, ap->a_cred, NULL);
	if (error == 0)
		vnode_create_vobject(vp, zp->z_size, ap->a_td);
	return (error);
}

static int
zfs_freebsd_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
{

	return (zfs_close(ap->a_vp, ap->a_fflag, 1, 0, ap->a_cred, NULL));
}

static int
zfs_freebsd_ioctl(ap)
	struct vop_ioctl_args /* {
		struct vnode *a_vp;
		u_long a_command;
		caddr_t a_data;
		int a_fflag;
		struct ucred *cred;
		struct thread *td;
	} */ *ap;
{

	return (zfs_ioctl(ap->a_vp, ap->a_command, (intptr_t)ap->a_data,
	    ap->a_fflag, ap->a_cred, NULL, NULL));
}

static int
zfs_freebsd_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{

	return (zfs_read(ap->a_vp, ap->a_uio, ioflags(ap->a_ioflag),
	    ap->a_cred, NULL));
}

static int
zfs_freebsd_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{

	return (zfs_write(ap->a_vp, ap->a_uio, ioflags(ap->a_ioflag),
	    ap->a_cred, NULL));
}

static int
zfs_freebsd_access(ap)
	struct vop_access_args /* {
		struct vnode *a_vp;
		accmode_t a_accmode;
		struct ucred *a_cred;
		struct thread *a_td;
	} */ *ap;
{
	vnode_t *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	accmode_t accmode;
	int error = 0;

	/*
	 * ZFS itself only knowns about VREAD, VWRITE, VEXEC and VAPPEND,
	 */
	accmode = ap->a_accmode & (VREAD|VWRITE|VEXEC|VAPPEND);
	if (accmode != 0)
		error = zfs_access(ap->a_vp, accmode, 0, ap->a_cred, NULL);

	/*
	 * VADMIN has to be handled by vaccess().
	 */
	if (error == 0) {
		accmode = ap->a_accmode & ~(VREAD|VWRITE|VEXEC|VAPPEND);
		if (accmode != 0) {
			error = vaccess(vp->v_type, zp->z_mode, zp->z_uid,
			    zp->z_gid, accmode, ap->a_cred, NULL);
		}
	}

	/*
	 * For VEXEC, ensure that at least one execute bit is set for
	 * non-directories.
	 */
	if (error == 0 && (ap->a_accmode & VEXEC) != 0 && vp->v_type != VDIR &&
	    (zp->z_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
		error = EACCES;
	}

	return (error);
}

static int
zfs_freebsd_lookup(ap)
	struct vop_lookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap;
{
	struct componentname *cnp = ap->a_cnp;
	char nm[NAME_MAX + 1];

	ASSERT(cnp->cn_namelen < sizeof(nm));
	strlcpy(nm, cnp->cn_nameptr, MIN(cnp->cn_namelen + 1, sizeof(nm)));

	return (zfs_lookup(ap->a_dvp, nm, ap->a_vpp, cnp, cnp->cn_nameiop,
	    cnp->cn_cred, cnp->cn_thread, 0));
}

static int
zfs_freebsd_create(ap)
	struct vop_create_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap;
{
	struct componentname *cnp = ap->a_cnp;
	vattr_t *vap = ap->a_vap;
	int mode;

	ASSERT(cnp->cn_flags & SAVENAME);

	vattr_init_mask(vap);
	mode = vap->va_mode & ALLPERMS;

	return (zfs_create(ap->a_dvp, cnp->cn_nameptr, vap, !EXCL, mode,
	    ap->a_vpp, cnp->cn_cred, cnp->cn_thread));
}

static int
zfs_freebsd_remove(ap)
	struct vop_remove_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap;
{

	ASSERT(ap->a_cnp->cn_flags & SAVENAME);

	return (zfs_remove(ap->a_dvp, ap->a_cnp->cn_nameptr,
	    ap->a_cnp->cn_cred, NULL, 0));
}

static int
zfs_freebsd_mkdir(ap)
	struct vop_mkdir_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap;
{
	vattr_t *vap = ap->a_vap;

	ASSERT(ap->a_cnp->cn_flags & SAVENAME);

	vattr_init_mask(vap);

	return (zfs_mkdir(ap->a_dvp, ap->a_cnp->cn_nameptr, vap, ap->a_vpp,
	    ap->a_cnp->cn_cred, NULL, 0, NULL));
}

static int
zfs_freebsd_rmdir(ap)
	struct vop_rmdir_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap;
{
	struct componentname *cnp = ap->a_cnp;

	ASSERT(cnp->cn_flags & SAVENAME);

	return (zfs_rmdir(ap->a_dvp, cnp->cn_nameptr, NULL, cnp->cn_cred, NULL, 0));
}

static int
zfs_freebsd_readdir(ap)
	struct vop_readdir_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
		int *a_eofflag;
		int *a_ncookies;
		u_long **a_cookies;
	} */ *ap;
{

	return (zfs_readdir(ap->a_vp, ap->a_uio, ap->a_cred, ap->a_eofflag,
	    ap->a_ncookies, ap->a_cookies));
}

static int
zfs_freebsd_fsync(ap)
	struct vop_fsync_args /* {
		struct vnode *a_vp;
		int a_waitfor;
		struct thread *a_td;
	} */ *ap;
{

	vop_stdfsync(ap);
	return (zfs_fsync(ap->a_vp, 0, ap->a_td->td_ucred, NULL));
}

static int
zfs_freebsd_getattr(ap)
	struct vop_getattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
	} */ *ap;
{
	vattr_t *vap = ap->a_vap;
	xvattr_t xvap;
	u_long fflags = 0;
	int error;

	xva_init(&xvap);
	xvap.xva_vattr = *vap;
	xvap.xva_vattr.va_mask |= AT_XVATTR;

	/* Convert chflags into ZFS-type flags. */
	/* XXX: what about SF_SETTABLE?. */
	XVA_SET_REQ(&xvap, XAT_IMMUTABLE);
	XVA_SET_REQ(&xvap, XAT_APPENDONLY);
	XVA_SET_REQ(&xvap, XAT_NOUNLINK);
	XVA_SET_REQ(&xvap, XAT_NODUMP);
	error = zfs_getattr(ap->a_vp, (vattr_t *)&xvap, 0, ap->a_cred, NULL);
	if (error != 0)
		return (error);

	/* Convert ZFS xattr into chflags. */
#define	FLAG_CHECK(fflag, xflag, xfield)	do {			\
	if (XVA_ISSET_RTN(&xvap, (xflag)) && (xfield) != 0)		\
		fflags |= (fflag);					\
} while (0)
	FLAG_CHECK(SF_IMMUTABLE, XAT_IMMUTABLE,
	    xvap.xva_xoptattrs.xoa_immutable);
	FLAG_CHECK(SF_APPEND, XAT_APPENDONLY,
	    xvap.xva_xoptattrs.xoa_appendonly);
	FLAG_CHECK(SF_NOUNLINK, XAT_NOUNLINK,
	    xvap.xva_xoptattrs.xoa_nounlink);
	FLAG_CHECK(UF_NODUMP, XAT_NODUMP,
	    xvap.xva_xoptattrs.xoa_nodump);
#undef	FLAG_CHECK
	*vap = xvap.xva_vattr;
	vap->va_flags = fflags;
	return (0);
}

static int
zfs_freebsd_setattr(ap)
	struct vop_setattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
	} */ *ap;
{
	vnode_t *vp = ap->a_vp;
	vattr_t *vap = ap->a_vap;
	cred_t *cred = ap->a_cred;
	xvattr_t xvap;
	u_long fflags;
	uint64_t zflags;

	vattr_init_mask(vap);
	vap->va_mask &= ~AT_NOSET;

	xva_init(&xvap);
	xvap.xva_vattr = *vap;

	zflags = VTOZ(vp)->z_pflags;

	if (vap->va_flags != VNOVAL) {
		zfsvfs_t *zfsvfs = VTOZ(vp)->z_zfsvfs;
		int error;

		if (zfsvfs->z_use_fuids == B_FALSE)
			return (EOPNOTSUPP);

		fflags = vap->va_flags;
		if ((fflags & ~(SF_IMMUTABLE|SF_APPEND|SF_NOUNLINK|UF_NODUMP)) != 0)
			return (EOPNOTSUPP);
		/*
		 * Unprivileged processes are not permitted to unset system
		 * flags, or modify flags if any system flags are set.
		 * Privileged non-jail processes may not modify system flags
		 * if securelevel > 0 and any existing system flags are set.
		 * Privileged jail processes behave like privileged non-jail
		 * processes if the security.jail.chflags_allowed sysctl is
		 * is non-zero; otherwise, they behave like unprivileged
		 * processes.
		 */
		if (secpolicy_fs_owner(vp->v_mount, cred) == 0 ||
		    priv_check_cred(cred, PRIV_VFS_SYSFLAGS, 0) == 0) {
			if (zflags &
			    (ZFS_IMMUTABLE | ZFS_APPENDONLY | ZFS_NOUNLINK)) {
				error = securelevel_gt(cred, 0);
				if (error != 0)
					return (error);
			}
		} else {
			/*
			 * Callers may only modify the file flags on objects they
			 * have VADMIN rights for.
			 */
			if ((error = VOP_ACCESS(vp, VADMIN, cred, curthread)) != 0)
				return (error);
			if (zflags &
			    (ZFS_IMMUTABLE | ZFS_APPENDONLY | ZFS_NOUNLINK)) {
				return (EPERM);
			}
			if (fflags &
			    (SF_IMMUTABLE | SF_APPEND | SF_NOUNLINK)) {
				return (EPERM);
			}
		}

#define	FLAG_CHANGE(fflag, zflag, xflag, xfield)	do {		\
	if (((fflags & (fflag)) && !(zflags & (zflag))) ||		\
	    ((zflags & (zflag)) && !(fflags & (fflag)))) {		\
		XVA_SET_REQ(&xvap, (xflag));				\
		(xfield) = ((fflags & (fflag)) != 0);			\
	}								\
} while (0)
		/* Convert chflags into ZFS-type flags. */
		/* XXX: what about SF_SETTABLE?. */
		FLAG_CHANGE(SF_IMMUTABLE, ZFS_IMMUTABLE, XAT_IMMUTABLE,
		    xvap.xva_xoptattrs.xoa_immutable);
		FLAG_CHANGE(SF_APPEND, ZFS_APPENDONLY, XAT_APPENDONLY,
		    xvap.xva_xoptattrs.xoa_appendonly);
		FLAG_CHANGE(SF_NOUNLINK, ZFS_NOUNLINK, XAT_NOUNLINK,
		    xvap.xva_xoptattrs.xoa_nounlink);
		FLAG_CHANGE(UF_NODUMP, ZFS_NODUMP, XAT_NODUMP,
		    xvap.xva_xoptattrs.xoa_nodump);
#undef	FLAG_CHANGE
	}
	return (zfs_setattr(vp, (vattr_t *)&xvap, 0, cred, NULL));
}

static int
zfs_freebsd_rename(ap)
	struct vop_rename_args  /* {
		struct vnode *a_fdvp;
		struct vnode *a_fvp;
		struct componentname *a_fcnp;
		struct vnode *a_tdvp;
		struct vnode *a_tvp;
		struct componentname *a_tcnp;
	} */ *ap;
{
	vnode_t *fdvp = ap->a_fdvp;
	vnode_t *fvp = ap->a_fvp;
	vnode_t *tdvp = ap->a_tdvp;
	vnode_t *tvp = ap->a_tvp;
	int error;

	ASSERT(ap->a_fcnp->cn_flags & (SAVENAME|SAVESTART));
	ASSERT(ap->a_tcnp->cn_flags & (SAVENAME|SAVESTART));

	error = zfs_rename(fdvp, ap->a_fcnp->cn_nameptr, tdvp,
	    ap->a_tcnp->cn_nameptr, ap->a_fcnp->cn_cred, NULL, 0);

	if (tdvp == tvp)
		VN_RELE(tdvp);
	else
		VN_URELE(tdvp);
	if (tvp)
		VN_URELE(tvp);
	VN_RELE(fdvp);
	VN_RELE(fvp);

	return (error);
}

static int
zfs_freebsd_symlink(ap)
	struct vop_symlink_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
		char *a_target;
	} */ *ap;
{
	struct componentname *cnp = ap->a_cnp;
	vattr_t *vap = ap->a_vap;

	ASSERT(cnp->cn_flags & SAVENAME);

	vap->va_type = VLNK;	/* FreeBSD: Syscall only sets va_mode. */
	vattr_init_mask(vap);

	return (zfs_symlink(ap->a_dvp, ap->a_vpp, cnp->cn_nameptr, vap,
	    ap->a_target, cnp->cn_cred, cnp->cn_thread));
}

static int
zfs_freebsd_readlink(ap)
	struct vop_readlink_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
	} */ *ap;
{

	return (zfs_readlink(ap->a_vp, ap->a_uio, ap->a_cred, NULL));
}

static int
zfs_freebsd_link(ap)
	struct vop_link_args /* {
		struct vnode *a_tdvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap;
{
	struct componentname *cnp = ap->a_cnp;

	ASSERT(cnp->cn_flags & SAVENAME);

	return (zfs_link(ap->a_tdvp, ap->a_vp, cnp->cn_nameptr, cnp->cn_cred, NULL, 0));
}

static int
zfs_freebsd_inactive(ap)
	struct vop_inactive_args /* {
		struct vnode *a_vp;
		struct thread *a_td;
	} */ *ap;
{
	vnode_t *vp = ap->a_vp;

	zfs_inactive(vp, ap->a_td->td_ucred, NULL);
	return (0);
}

static int
zfs_freebsd_reclaim(ap)
	struct vop_reclaim_args /* {
		struct vnode *a_vp;
		struct thread *a_td;
	} */ *ap;
{
	vnode_t	*vp = ap->a_vp;
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	ASSERT(zp != NULL);

	/* Destroy the vm object and flush associated pages. */
	vnode_destroy_vobject(vp);

	/*
	 * z_teardown_inactive_lock protects from a race with
	 * zfs_znode_dmu_fini in zfsvfs_teardown during
	 * force unmount.
	 */
	rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);
	if (zp->z_sa_hdl == NULL)
		zfs_znode_free(zp);
	else
		zfs_zinactive(zp);
	rw_exit(&zfsvfs->z_teardown_inactive_lock);

	vp->v_data = NULL;
	return (0);
}

static int
zfs_freebsd_fid(ap)
	struct vop_fid_args /* {
		struct vnode *a_vp;
		struct fid *a_fid;
	} */ *ap;
{

	return (zfs_fid(ap->a_vp, (void *)ap->a_fid, NULL));
}

static int
zfs_freebsd_pathconf(ap)
	struct vop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		register_t *a_retval;
	} */ *ap;
{
	ulong_t val;
	int error;

	error = zfs_pathconf(ap->a_vp, ap->a_name, &val, curthread->td_ucred, NULL);
	if (error == 0)
		*ap->a_retval = val;
	else if (error == EOPNOTSUPP)
		error = vop_stdpathconf(ap);
	return (error);
}

static int
zfs_freebsd_fifo_pathconf(ap)
	struct vop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		register_t *a_retval;
	} */ *ap;
{

	switch (ap->a_name) {
	case _PC_ACL_EXTENDED:
	case _PC_ACL_NFS4:
	case _PC_ACL_PATH_MAX:
	case _PC_MAC_PRESENT:
		return (zfs_freebsd_pathconf(ap));
	default:
		return (fifo_specops.vop_pathconf(ap));
	}
}

/*
 * FreeBSD's extended attributes namespace defines file name prefix for ZFS'
 * extended attribute name:
 *
 *	NAMESPACE	PREFIX
 *	system		freebsd:system:
 *	user		(none, can be used to access ZFS fsattr(5) attributes
 *			created on Solaris)
 */
static int
zfs_create_attrname(int attrnamespace, const char *name, char *attrname,
    size_t size)
{
	const char *namespace, *prefix, *suffix;

	/* We don't allow '/' character in attribute name. */
	if (strchr(name, '/') != NULL)
		return (EINVAL);
	/* We don't allow attribute names that start with "freebsd:" string. */
	if (strncmp(name, "freebsd:", 8) == 0)
		return (EINVAL);

	bzero(attrname, size);

	switch (attrnamespace) {
	case EXTATTR_NAMESPACE_USER:
#if 0
		prefix = "freebsd:";
		namespace = EXTATTR_NAMESPACE_USER_STRING;
		suffix = ":";
#else
		/*
		 * This is the default namespace by which we can access all
		 * attributes created on Solaris.
		 */
		prefix = namespace = suffix = "";
#endif
		break;
	case EXTATTR_NAMESPACE_SYSTEM:
		prefix = "freebsd:";
		namespace = EXTATTR_NAMESPACE_SYSTEM_STRING;
		suffix = ":";
		break;
	case EXTATTR_NAMESPACE_EMPTY:
	default:
		return (EINVAL);
	}
	if (snprintf(attrname, size, "%s%s%s%s", prefix, namespace, suffix,
	    name) >= size) {
		return (ENAMETOOLONG);
	}
	return (0);
}

/*
 * Vnode operating to retrieve a named extended attribute.
 */
static int
zfs_getextattr(struct vop_getextattr_args *ap)
/*
vop_getextattr {
	IN struct vnode *a_vp;
	IN int a_attrnamespace;
	IN const char *a_name;
	INOUT struct uio *a_uio;
	OUT size_t *a_size;
	IN struct ucred *a_cred;
	IN struct thread *a_td;
};
*/
{
	zfsvfs_t *zfsvfs = VTOZ(ap->a_vp)->z_zfsvfs;
	struct thread *td = ap->a_td;
	struct nameidata nd;
	char attrname[255];
	struct vattr va;
	vnode_t *xvp = NULL, *vp;
	int error, flags;

	error = extattr_check_cred(ap->a_vp, ap->a_attrnamespace,
	    ap->a_cred, ap->a_td, VREAD);
	if (error != 0)
		return (error);

	error = zfs_create_attrname(ap->a_attrnamespace, ap->a_name, attrname,
	    sizeof(attrname));
	if (error != 0)
		return (error);

	ZFS_ENTER(zfsvfs);

	error = zfs_lookup(ap->a_vp, NULL, &xvp, NULL, 0, ap->a_cred, td,
	    LOOKUP_XATTR);
	if (error != 0) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	flags = FREAD;
	NDINIT_ATVP(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, attrname,
	    xvp, td);
	error = vn_open_cred(&nd, &flags, 0, 0, ap->a_cred, NULL);
	vp = nd.ni_vp;
	NDFREE(&nd, NDF_ONLY_PNBUF);
	if (error != 0) {
		ZFS_EXIT(zfsvfs);
		if (error == ENOENT)
			error = ENOATTR;
		return (error);
	}

	if (ap->a_size != NULL) {
		error = VOP_GETATTR(vp, &va, ap->a_cred);
		if (error == 0)
			*ap->a_size = (size_t)va.va_size;
	} else if (ap->a_uio != NULL)
		error = VOP_READ(vp, ap->a_uio, IO_UNIT, ap->a_cred);

	VOP_UNLOCK(vp, 0);
	vn_close(vp, flags, ap->a_cred, td);
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Vnode operation to remove a named attribute.
 */
int
zfs_deleteextattr(struct vop_deleteextattr_args *ap)
/*
vop_deleteextattr {
	IN struct vnode *a_vp;
	IN int a_attrnamespace;
	IN const char *a_name;
	IN struct ucred *a_cred;
	IN struct thread *a_td;
};
*/
{
	zfsvfs_t *zfsvfs = VTOZ(ap->a_vp)->z_zfsvfs;
	struct thread *td = ap->a_td;
	struct nameidata nd;
	char attrname[255];
	struct vattr va;
	vnode_t *xvp = NULL, *vp;
	int error, flags;

	error = extattr_check_cred(ap->a_vp, ap->a_attrnamespace,
	    ap->a_cred, ap->a_td, VWRITE);
	if (error != 0)
		return (error);

	error = zfs_create_attrname(ap->a_attrnamespace, ap->a_name, attrname,
	    sizeof(attrname));
	if (error != 0)
		return (error);

	ZFS_ENTER(zfsvfs);

	error = zfs_lookup(ap->a_vp, NULL, &xvp, NULL, 0, ap->a_cred, td,
	    LOOKUP_XATTR);
	if (error != 0) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	NDINIT_ATVP(&nd, DELETE, NOFOLLOW | LOCKPARENT | LOCKLEAF,
	    UIO_SYSSPACE, attrname, xvp, td);
	error = namei(&nd);
	vp = nd.ni_vp;
	NDFREE(&nd, NDF_ONLY_PNBUF);
	if (error != 0) {
		ZFS_EXIT(zfsvfs);
		if (error == ENOENT)
			error = ENOATTR;
		return (error);
	}
	error = VOP_REMOVE(nd.ni_dvp, vp, &nd.ni_cnd);

	vput(nd.ni_dvp);
	if (vp == nd.ni_dvp)
		vrele(vp);
	else
		vput(vp);
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Vnode operation to set a named attribute.
 */
static int
zfs_setextattr(struct vop_setextattr_args *ap)
/*
vop_setextattr {
	IN struct vnode *a_vp;
	IN int a_attrnamespace;
	IN const char *a_name;
	INOUT struct uio *a_uio;
	IN struct ucred *a_cred;
	IN struct thread *a_td;
};
*/
{
	zfsvfs_t *zfsvfs = VTOZ(ap->a_vp)->z_zfsvfs;
	struct thread *td = ap->a_td;
	struct nameidata nd;
	char attrname[255];
	struct vattr va;
	vnode_t *xvp = NULL, *vp;
	int error, flags;

	error = extattr_check_cred(ap->a_vp, ap->a_attrnamespace,
	    ap->a_cred, ap->a_td, VWRITE);
	if (error != 0)
		return (error);

	error = zfs_create_attrname(ap->a_attrnamespace, ap->a_name, attrname,
	    sizeof(attrname));
	if (error != 0)
		return (error);

	ZFS_ENTER(zfsvfs);

	error = zfs_lookup(ap->a_vp, NULL, &xvp, NULL, 0, ap->a_cred, td,
	    LOOKUP_XATTR | CREATE_XATTR_DIR);
	if (error != 0) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	flags = FFLAGS(O_WRONLY | O_CREAT);
	NDINIT_ATVP(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, attrname,
	    xvp, td);
	error = vn_open_cred(&nd, &flags, 0600, 0, ap->a_cred, NULL);
	vp = nd.ni_vp;
	NDFREE(&nd, NDF_ONLY_PNBUF);
	if (error != 0) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	VATTR_NULL(&va);
	va.va_size = 0;
	error = VOP_SETATTR(vp, &va, ap->a_cred);
	if (error == 0)
		VOP_WRITE(vp, ap->a_uio, IO_UNIT | IO_SYNC, ap->a_cred);

	VOP_UNLOCK(vp, 0);
	vn_close(vp, flags, ap->a_cred, td);
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Vnode operation to retrieve extended attributes on a vnode.
 */
static int
zfs_listextattr(struct vop_listextattr_args *ap)
/*
vop_listextattr {
	IN struct vnode *a_vp;
	IN int a_attrnamespace;
	INOUT struct uio *a_uio;
	OUT size_t *a_size;
	IN struct ucred *a_cred;
	IN struct thread *a_td;
};
*/
{
	zfsvfs_t *zfsvfs = VTOZ(ap->a_vp)->z_zfsvfs;
	struct thread *td = ap->a_td;
	struct nameidata nd;
	char attrprefix[16];
	u_char dirbuf[sizeof(struct dirent)];
	struct dirent *dp;
	struct iovec aiov;
	struct uio auio, *uio = ap->a_uio;
	size_t *sizep = ap->a_size;
	size_t plen;
	vnode_t *xvp = NULL, *vp;
	int done, error, eof, pos;

	error = extattr_check_cred(ap->a_vp, ap->a_attrnamespace,
	    ap->a_cred, ap->a_td, VREAD);
	if (error != 0)
		return (error);

	error = zfs_create_attrname(ap->a_attrnamespace, "", attrprefix,
	    sizeof(attrprefix));
	if (error != 0)
		return (error);
	plen = strlen(attrprefix);

	ZFS_ENTER(zfsvfs);

	if (sizep != NULL)
		*sizep = 0;

	error = zfs_lookup(ap->a_vp, NULL, &xvp, NULL, 0, ap->a_cred, td,
	    LOOKUP_XATTR);
	if (error != 0) {
		ZFS_EXIT(zfsvfs);
		/*
		 * ENOATTR means that the EA directory does not yet exist,
		 * i.e. there are no extended attributes there.
		 */
		if (error == ENOATTR)
			error = 0;
		return (error);
	}

	NDINIT_ATVP(&nd, LOOKUP, NOFOLLOW | LOCKLEAF | LOCKSHARED,
	    UIO_SYSSPACE, ".", xvp, td);
	error = namei(&nd);
	vp = nd.ni_vp;
	NDFREE(&nd, NDF_ONLY_PNBUF);
	if (error != 0) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_td = td;
	auio.uio_rw = UIO_READ;
	auio.uio_offset = 0;

	do {
		u_char nlen;

		aiov.iov_base = (void *)dirbuf;
		aiov.iov_len = sizeof(dirbuf);
		auio.uio_resid = sizeof(dirbuf);
		error = VOP_READDIR(vp, &auio, ap->a_cred, &eof, NULL, NULL);
		done = sizeof(dirbuf) - auio.uio_resid;
		if (error != 0)
			break;
		for (pos = 0; pos < done;) {
			dp = (struct dirent *)(dirbuf + pos);
			pos += dp->d_reclen;
			/*
			 * XXX: Temporarily we also accept DT_UNKNOWN, as this
			 * is what we get when attribute was created on Solaris.
			 */
			if (dp->d_type != DT_REG && dp->d_type != DT_UNKNOWN)
				continue;
			if (plen == 0 && strncmp(dp->d_name, "freebsd:", 8) == 0)
				continue;
			else if (strncmp(dp->d_name, attrprefix, plen) != 0)
				continue;
			nlen = dp->d_namlen - plen;
			if (sizep != NULL)
				*sizep += 1 + nlen;
			else if (uio != NULL) {
				/*
				 * Format of extattr name entry is one byte for
				 * length and the rest for name.
				 */
				error = uiomove(&nlen, 1, uio->uio_rw, uio);
				if (error == 0) {
					error = uiomove(dp->d_name + plen, nlen,
					    uio->uio_rw, uio);
				}
				if (error != 0)
					break;
			}
		}
	} while (!eof && error == 0);

	vput(vp);
	ZFS_EXIT(zfsvfs);

	return (error);
}

int
zfs_freebsd_getacl(ap)
	struct vop_getacl_args /* {
		struct vnode *vp;
		acl_type_t type;
		struct acl *aclp;
		struct ucred *cred;
		struct thread *td;
	} */ *ap;
{
	int		error;
	vsecattr_t      vsecattr;

	if (ap->a_type != ACL_TYPE_NFS4)
		return (EINVAL);

	vsecattr.vsa_mask = VSA_ACE | VSA_ACECNT;
	if (error = zfs_getsecattr(ap->a_vp, &vsecattr, 0, ap->a_cred, NULL))
		return (error);

	error = acl_from_aces(ap->a_aclp, vsecattr.vsa_aclentp, vsecattr.vsa_aclcnt);
	if (vsecattr.vsa_aclentp != NULL)
		kmem_free(vsecattr.vsa_aclentp, vsecattr.vsa_aclentsz);

	return (error);
}

int
zfs_freebsd_setacl(ap)
	struct vop_setacl_args /* {
		struct vnode *vp;
		acl_type_t type;
		struct acl *aclp;
		struct ucred *cred;
		struct thread *td;
	} */ *ap;
{
	int		error;
	vsecattr_t      vsecattr;
	int		aclbsize;	/* size of acl list in bytes */
	aclent_t	*aaclp;

	if (ap->a_type != ACL_TYPE_NFS4)
		return (EINVAL);

	if (ap->a_aclp->acl_cnt < 1 || ap->a_aclp->acl_cnt > MAX_ACL_ENTRIES)
		return (EINVAL);

	/*
	 * With NFSv4 ACLs, chmod(2) may need to add additional entries,
	 * splitting every entry into two and appending "canonical six"
	 * entries at the end.  Don't allow for setting an ACL that would
	 * cause chmod(2) to run out of ACL entries.
	 */
	if (ap->a_aclp->acl_cnt * 2 + 6 > ACL_MAX_ENTRIES)
		return (ENOSPC);

	error = acl_nfs4_check(ap->a_aclp, ap->a_vp->v_type == VDIR);
	if (error != 0)
		return (error);

	vsecattr.vsa_mask = VSA_ACE;
	aclbsize = ap->a_aclp->acl_cnt * sizeof(ace_t);
	vsecattr.vsa_aclentp = kmem_alloc(aclbsize, KM_SLEEP);
	aaclp = vsecattr.vsa_aclentp;
	vsecattr.vsa_aclentsz = aclbsize;

	aces_from_acl(vsecattr.vsa_aclentp, &vsecattr.vsa_aclcnt, ap->a_aclp);
	error = zfs_setsecattr(ap->a_vp, &vsecattr, 0, ap->a_cred, NULL);
	kmem_free(aaclp, aclbsize);

	return (error);
}

int
zfs_freebsd_aclcheck(ap)
	struct vop_aclcheck_args /* {
		struct vnode *vp;
		acl_type_t type;
		struct acl *aclp;
		struct ucred *cred;
		struct thread *td;
	} */ *ap;
{

	return (EOPNOTSUPP);
}

struct vop_vector zfs_vnodeops;
struct vop_vector zfs_fifoops;
struct vop_vector zfs_shareops;

struct vop_vector zfs_vnodeops = {
	.vop_default =		&default_vnodeops,
	.vop_inactive =		zfs_freebsd_inactive,
	.vop_reclaim =		zfs_freebsd_reclaim,
	.vop_access =		zfs_freebsd_access,
#ifdef FREEBSD_NAMECACHE
	.vop_lookup =		vfs_cache_lookup,
	.vop_cachedlookup =	zfs_freebsd_lookup,
#else
	.vop_lookup =		zfs_freebsd_lookup,
#endif
	.vop_getattr =		zfs_freebsd_getattr,
	.vop_setattr =		zfs_freebsd_setattr,
	.vop_create =		zfs_freebsd_create,
	.vop_mknod =		zfs_freebsd_create,
	.vop_mkdir =		zfs_freebsd_mkdir,
	.vop_readdir =		zfs_freebsd_readdir,
	.vop_fsync =		zfs_freebsd_fsync,
	.vop_open =		zfs_freebsd_open,
	.vop_close =		zfs_freebsd_close,
	.vop_rmdir =		zfs_freebsd_rmdir,
	.vop_ioctl =		zfs_freebsd_ioctl,
	.vop_link =		zfs_freebsd_link,
	.vop_symlink =		zfs_freebsd_symlink,
	.vop_readlink =		zfs_freebsd_readlink,
	.vop_read =		zfs_freebsd_read,
	.vop_write =		zfs_freebsd_write,
	.vop_remove =		zfs_freebsd_remove,
	.vop_rename =		zfs_freebsd_rename,
	.vop_pathconf =		zfs_freebsd_pathconf,
	.vop_bmap =		zfs_freebsd_bmap,
	.vop_fid =		zfs_freebsd_fid,
	.vop_getextattr =	zfs_getextattr,
	.vop_deleteextattr =	zfs_deleteextattr,
	.vop_setextattr =	zfs_setextattr,
	.vop_listextattr =	zfs_listextattr,
	.vop_getacl =		zfs_freebsd_getacl,
	.vop_setacl =		zfs_freebsd_setacl,
	.vop_aclcheck =		zfs_freebsd_aclcheck,
	.vop_getpages =		zfs_freebsd_getpages,
};

struct vop_vector zfs_fifoops = {
	.vop_default =		&fifo_specops,
	.vop_fsync =		zfs_freebsd_fsync,
	.vop_access =		zfs_freebsd_access,
	.vop_getattr =		zfs_freebsd_getattr,
	.vop_inactive =		zfs_freebsd_inactive,
	.vop_read =		VOP_PANIC,
	.vop_reclaim =		zfs_freebsd_reclaim,
	.vop_setattr =		zfs_freebsd_setattr,
	.vop_write =		VOP_PANIC,
	.vop_pathconf = 	zfs_freebsd_fifo_pathconf,
	.vop_fid =		zfs_freebsd_fid,
	.vop_getacl =		zfs_freebsd_getacl,
	.vop_setacl =		zfs_freebsd_setacl,
	.vop_aclcheck =		zfs_freebsd_aclcheck,
};

/*
 * special share hidden files vnode operations template
 */
struct vop_vector zfs_shareops = {
	.vop_default =		&default_vnodeops,
	.vop_access =		zfs_freebsd_access,
	.vop_inactive =		zfs_freebsd_inactive,
	.vop_reclaim =		zfs_freebsd_reclaim,
	.vop_fid =		zfs_freebsd_fid,
	.vop_pathconf =		zfs_freebsd_pathconf,
};


#endif /* FreeBSD */
