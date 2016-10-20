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
 * Based on Apple MacZFS source code
 * Copyright (c) 2014,2016 by Jorgen Lundman. All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/vdev_disk.h>
#include <sys/vdev_impl.h>
#include <sys/fs/zfs.h>
#include <sys/zio.h>
#ifdef __APPLE__
#include <sys/mount.h>
#else
#include <sys/sunldi.h>
#endif /* __APPLE__ */

#ifdef illumos
/*
 * Virtual device vector for disks.
 */

extern ldi_ident_t zfs_li;

static void vdev_disk_close(vdev_t *);

typedef struct vdev_disk_ldi_cb {
	list_node_t		lcb_next;
	ldi_callback_id_t	lcb_id;
} vdev_disk_ldi_cb_t;
#endif

static void
vdev_disk_alloc(vdev_t *vd)
{
	vdev_disk_t *dvd;

	dvd = vd->vdev_tsd = kmem_zalloc(sizeof (vdev_disk_t), KM_SLEEP);
#ifdef illumos
	/*
	 * Create the LDI event callback list.
	 */
	list_create(&dvd->vd_ldi_cbs, sizeof (vdev_disk_ldi_cb_t),
	    offsetof(vdev_disk_ldi_cb_t, lcb_next));
#endif
}

static void
vdev_disk_free(vdev_t *vd)
{
	vdev_disk_t *dvd = vd->vdev_tsd;
#ifdef illumos
	vdev_disk_ldi_cb_t *lcb;
#endif

	if (dvd == NULL)
		return;

#ifdef illumos
	/*
	 * We have already closed the LDI handle. Clean up the LDI event
	 * callbacks and free vd->vdev_tsd.
	 */
	while ((lcb = list_head(&dvd->vd_ldi_cbs)) != NULL) {
		list_remove(&dvd->vd_ldi_cbs, lcb);
		(void) ldi_ev_remove_callbacks(lcb->lcb_id);
		kmem_free(lcb, sizeof (vdev_disk_ldi_cb_t));
	}
	list_destroy(&dvd->vd_ldi_cbs);
#endif
	kmem_free(dvd, sizeof (vdev_disk_t));
	vd->vdev_tsd = NULL;
}

static int
vdev_disk_open(vdev_t *vd, uint64_t *psize, uint64_t *max_psize,
    uint64_t *ashift)
{
	spa_t *spa = vd->vdev_spa;
	vdev_disk_t *dvd = vd->vdev_tsd;
	ldi_ev_cookie_t ecookie;
	vdev_disk_ldi_cb_t *lcb;
	union {
		struct dk_minfo_ext ude;
		struct dk_minfo ud;
	} dks;
	struct dk_minfo_ext *dkmext = &dks.ude;
	struct dk_minfo *dkm = &dks.ud;
	int error;
/* XXX Apple - must leave devid unchanged */
#ifdef illumos
	dev_t dev;
	int otyp;
	boolean_t validate_devid = B_FALSE;
	ddi_devid_t devid;
#endif
	uint64_t capacity = 0, blksz = 0, pbsize;
#ifdef __APPLE__
	int isssd;
#endif

	/*
	 * We must have a pathname, and it must be absolute.
	 */
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/') {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (SET_ERROR(EINVAL));
	}

	/*
	 * Reopen the device if it's not currently open. Otherwise,
	 * just update the physical size of the device.
	 */
	if (dvd != NULL) {
	  if (dvd->vd_offline) {
	    /*
	     * If we are opening a device in its offline notify
	     * context, the LDI handle was just closed. Clean
	     * up the LDI event callbacks and free vd->vdev_tsd.
	     */
	    vdev_disk_free(vd);
	  } else {
	    ASSERT(vd->vdev_reopening);
		devvp = dvd->vd_devvp;
	    goto skip_open;
	  }
	}

	/*
	 * Create vd->vdev_tsd.
	 */
	vdev_disk_alloc(vd);
	dvd = vd->vdev_tsd;

	/*
	 * When opening a disk device, we want to preserve the user's original
	 * intent.  We always want to open the device by the path the user gave
	 * us, even if it is one of multiple paths to the same device.  But we
	 * also want to be able to survive disks being removed/recabled.
	 * Therefore the sequence of opening devices is:
	 *
	 * 1. Try opening the device by path.  For legacy pools without the
	 *    'whole_disk' property, attempt to fix the path by appending 's0'.
	 *
	 * 2. If the devid of the device matches the stored value, return
	 *    success.
	 *
	 * 3. Otherwise, the device may have moved.  Try opening the device
	 *    by the devid instead.
	 */
	/* ### APPLE TODO ### */
#ifdef illumos
	if (vd->vdev_devid != NULL) {
		if (ddi_devid_str_decode(vd->vdev_devid, &dvd->vd_devid,
		    &dvd->vd_minor) != 0) {
			vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
			return (SET_ERROR(EINVAL));
		}
	}
#endif

	v->vdev_tsd = vd;
	vd->vd_bdev = bdev;

skip_open:
	/*  Determine the physical block size */
	block_size = vdev_bdev_block_size(vd->vd_bdev);

	/* Clear the nowritecache bit, causes vdev_reopen() to try again. */
	v->vdev_nowritecache = B_FALSE;

	/* Inform the ZIO pipeline that we are non-rotational */
	v->vdev_nonrot = blk_queue_nonrot(bdev_get_queue(vd->vd_bdev));

	/* Physical volume size in bytes */
	*psize = bdev_capacity(vd->vd_bdev);

	/* TODO: report possible expansion size */
	*max_psize = *psize;

	/* Based on the minimum sector size set the block size */
	*ashift = highbit64(MAX(block_size, SPA_MINBLOCKSIZE)) - 1;

	if (vd->vdev_path != NULL) {

		context = vfs_context_create( spl_vfs_context_kernel() );

		/* Obtain an opened/referenced vnode for the device. */
		if ((error = vnode_open(vd->vdev_path, spa_mode(spa), 0, 0,
								&devvp, context))) {
			goto out;
		}
		if (!vnode_isblk(devvp)) {
			error = ENOTBLK;
			goto out;
		}
		/*
		 * ### APPLE TODO ###
		 * vnode_authorize devvp for KAUTH_VNODE_READ_DATA and
		 * KAUTH_VNODE_WRITE_DATA
		 */

		/*
		 * Disallow opening of a device that is currently in use.
		 * Flush out any old buffers remaining from a previous use.
		 */
		if ((error = vfs_mountedon(devvp))) {
			goto out;
		}
		if (VNOP_FSYNC(devvp, MNT_WAIT, context) != 0) {
			error = ENOTBLK;
			goto out;
		}
		if ((error = buf_invalidateblks(devvp, BUF_WRITE_DATA, 0, 0))) {
			goto out;
		}

	} else {
		goto out;
	}


	int len = MAXPATHLEN;
	if (vn_getpath(devvp, dvd->vd_readlinkname, &len) == 0) {
		dprintf("ZFS: '%s' resolved name is '%s'\n",
			   vd->vdev_path, dvd->vd_readlinkname);
	} else {
		dvd->vd_readlinkname[0] = 0;
	}



#if 0
	int len = MAXPATHLEN;
	if (vn_getpath(devvp, dvd->vd_readlinkname, &len) == 0) {
		dprintf("ZFS: '%s' resolved name is '%s'\n",
			   vd->vdev_path, dvd->vd_readlinkname);
	} else {
		dvd->vd_readlinkname[0] = 0;
	}
#endif

skip_open:
	/*
	 * Determine the actual size of the device.
	 */
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKSIZE, (caddr_t)&blksize, 0,
	    context) != 0 ||
	    VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt, 0,
	    context) != 0) {
		error = EINVAL;
		goto out;
	}

	*psize = blkcnt * (uint64_t)blksize;
	*max_psize = *psize;

	dvd->vd_ashift = highbit(blksize) - 1;
	dprintf("vdev_disk: Device %p ashift set to %d\n", devvp,
	    dvd->vd_ashift);


	*ashift = highbit(MAX(blksize, SPA_MINBLOCKSIZE)) - 1;

	/*
	 *  ### APPLE TODO ###
	 */
#ifdef illumos
	if (vd->vdev_wholedisk == 1) {
		int wce = 1;
		if (error == 0) {
			/*
			 * If we have the capability to expand, we'd have
			 * found out via success from DKIOCGMEDIAINFO{,EXT}.
			 * Adjust max_psize upward accordingly since we know
			 * we own the whole disk now.
			 */
			*max_psize = capacity * blksz;
		}

#ifndef HAVE_2ARGS_BIO_END_IO_T
	if (BIO_BI_SIZE(bio))
		return (1);
#endif /* HAVE_2ARGS_BIO_END_IO_T */

	/*
	 * Clear the nowritecache bit, so that on a vdev_reopen() we will
	 * try again.
	 */
	vd->vdev_nowritecache = B_FALSE;

#ifdef __APPLE__
	/* Inform the ZIO pipeline that we are non-rotational */
	vd->vdev_nonrot = B_FALSE;
#if 0
	if (VNOP_IOCTL(devvp, DKIOCISSOLIDSTATE, (caddr_t)&isssd, 0,
				   context) == 0) {
#else
	if (ldi_ioctl(dvd->vd_lh, DKIOCISSOLIDSTATE, (intptr_t)&isssd,
	    FKIOCTL, kcred, NULL) == 0) {
#endif
		vd->vdev_nonrot = (isssd ? B_TRUE : B_FALSE);
	}
	// smd - search static table in #if block above
	if(isssd == 0) {
	  if(vd->vdev_path) {
	    isssd = ssd_search(vd->vdev_path);
	  }
	}

	printf("ZFS: vdev_disk(%s) isSSD %d\n", vd->vdev_path ? vd->vdev_path : "",
			isssd);
#endif //__APPLE__

	return (0);
}

#if 0
/*
 * It appears on export/reboot, iokit can hold a lock, then call our
 * termination handler, and we end up locking-against-ourselves inside
 * IOKit. We are then forced to make the vnode_close() call be async.
 */
static void vdev_disk_close_thread(void *arg)
{
	struct vnode *vp = arg;

	(void) vnode_close(vp, 0,
					   spl_vfs_context_kernel());
	thread_exit();
}

/* Not static so zfs_osx.cpp can call it on device removal */
void
#endif

static void
vdev_disk_close(vdev_t *vd)
{
	vdev_disk_t *dvd = vd->vdev_tsd;

	if (vd->vdev_reopening || dvd == NULL)
		return;

#ifdef illumos
	if (dvd->vd_minor != NULL) {
		ddi_devid_str_free(dvd->vd_minor);
		dvd->vd_minor = NULL;
	}

	return (bio_size);
}

static inline void
vdev_submit_bio(int rw, struct bio *bio)
{
#ifdef HAVE_CURRENT_BIO_TAIL
	struct bio **bio_tail = current->bio_tail;
	current->bio_tail = NULL;
	submit_bio(rw, bio);
	current->bio_tail = bio_tail;
#else
	struct bio_list *bio_list = current->bio_list;
	current->bio_list = NULL;
	submit_bio(rw, bio);
	current->bio_list = bio_list;
#endif
}

static int
__vdev_disk_physio(struct block_device *bdev, zio_t *zio, caddr_t kbuf_ptr,
    size_t kbuf_size, uint64_t kbuf_offset, int flags)
{
	dio_request_t *dr;
	caddr_t bio_ptr;
	uint64_t bio_offset;
	int bio_size, bio_count = 16;
	int i = 0, error = 0;

	ASSERT3U(kbuf_offset + kbuf_size, <=, bdev->bd_inode->i_size);

	if (dvd->vd_lh != NULL) {
		(void) ldi_close(dvd->vd_lh, spa_mode(vd->vdev_spa), kcred);
		dvd->vd_lh = NULL;
	}
#endif

#ifdef __APPLE__
	if (dvd->vd_devvp != NULL) {
		/* vnode_close() can stall during removal, so clear vd_devvp now */
		struct vnode *vp = dvd->vd_devvp;
		dvd->vd_devvp = NULL;
		(void) thread_create(NULL, 0, vdev_disk_close_thread,
							 vp, 0, &p0,
							 TS_RUN, minclsyspri);
	}
#endif

	vd->vdev_delayed_close = B_FALSE;

	/*
	 * If we closed the LDI handle due to an offline notify from LDI,
	 * don't free vd->vdev_tsd or unregister the callbacks here;
	 * the offline finalize callback or a reopen will take care of it.
	 */
	if (dvd->vd_offline)
		return;

	/* Extra reference to protect dio_request during vdev_submit_bio */
	vdev_disk_dio_get(dr);
	if (zio)
		zio->io_delay = jiffies_64;

	/* Submit all bio's associated with this dio */
	for (i = 0; i < dr->dr_bio_count; i++)
		if (dr->dr_bio[i])
			vdev_submit_bio(dr->dr_rw, dr->dr_bio[i]);

	/*
	 * The rest of the zio stack only deals with EIO, ECKSUM, and ENXIO.
	 * Rather than teach the rest of the stack about other error
	 * possibilities (EFAULT, etc), we normalize the error value here.
	 */
	int error;
	error=buf_error(bp);

	zio->io_error = (error != 0 ? EIO : 0);
	if (zio->io_error == 0 && buf_resid(bp) != 0) {
		zio->io_error = EIO;
	}
	buf_free(bp);

	zio_delay_interrupt(zio);
}

static void
vdev_disk_ioctl_done(void *zio_arg, int error)
{
	zio_t *zio = zio_arg;

	zio->io_error = error;

	zio_delay_interrupt(zio);
}

static int
vdev_disk_io_flush(struct block_device *bdev, zio_t *zio)
{
	struct request_queue *q;
	struct bio *bio;

	q = bdev_get_queue(bdev);
	if (!q)
		return (ENXIO);

	bio = bio_alloc(GFP_NOIO, 0);
	/* bio_alloc() with __GFP_WAIT never returns NULL */
	if (unlikely(bio == NULL))
		return (ENOMEM);

	bio->bi_end_io = vdev_disk_io_flush_completion;
	bio->bi_private = zio;
	bio->bi_bdev = bdev;
	zio->io_delay = jiffies_64;
	vdev_submit_bio(VDEV_WRITE_FLUSH_FUA, bio);
	invalidate_bdev(bdev);

	return (0);
}

static void
vdev_disk_io_start(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_disk_t *dvd = vd->vdev_tsd;
	struct buf *bp;
	vfs_context_t context;
	int flags, error = 0;

	/*
	 * If the vdev is closed, it's likely in the REMOVED or FAULTED state.
	 * Nothing to be done here but return failure.
	 */
	if (dvd == NULL || (dvd->vd_offline) || dvd->vd_devvp == NULL) {
		zio->io_error = ENXIO;
		zio_interrupt(zio);
		return;
	}

	switch (zio->io_type) {
		case ZIO_TYPE_IOCTL:

			if (!vdev_readable(vd)) {
				zio->io_error = SET_ERROR(ENXIO);
				zio_interrupt(zio);
				return;
			}

			zio->io_error = error;

			break;

		default:
			zio->io_error = SET_ERROR(ENOTSUP);
		} /* io_cmd */

		zio_execute(zio);
		return;

	case ZIO_TYPE_WRITE:
		if (zio->io_priority == ZIO_PRIORITY_SYNC_WRITE)
			flags = B_WRITE;
		else
			flags = B_WRITE | B_ASYNC;
		break;

	case ZIO_TYPE_READ:
		if (zio->io_priority == ZIO_PRIORITY_SYNC_READ)
			flags = B_READ;
		else
			flags = B_READ | B_ASYNC;
		break;

		default:
			zio->io_error = SET_ERROR(ENOTSUP);
			zio_interrupt(zio);
			return;
	} /* io_type */

	ASSERT(zio->io_type == ZIO_TYPE_READ || zio->io_type == ZIO_TYPE_WRITE);

	/* Stop OSX from also caching our data */
	flags |= B_NOCACHE | B_PASSIVE; // smd: also do B_PASSIVE for anti throttling test

	zio->io_target_timestamp = zio_handle_io_delay(zio);

	vb = kmem_alloc(sizeof (vdev_buf_t), KM_SLEEP);

	/* Stop OSX from also caching our data */
	flags |= B_NOCACHE;

	ASSERT(bp != NULL);
	ASSERT(zio->io_data != NULL);
	ASSERT(zio->io_size != 0);

	bioinit(bp);
	bp->b_flags = B_BUSY | flags;
	if (!(zio->io_flags & (ZIO_FLAG_IO_RETRY | ZIO_FLAG_TRYHARD)))
		bp->b_flags |= B_FAILFAST;
	bp->b_bcount = zio->io_size;
	bp->b_un.b_addr = zio->io_data;
	bp->b_lblkno = lbtodb(zio->io_offset);
	bp->b_bufsize = zio->io_size;
	bp->b_iodone = (int (*)())vdev_disk_io_intr;

#if 0
	bp = buf_alloc(dvd->vd_devvp);

	buf_setflags(bp, flags);
	buf_setcount(bp, zio->io_size);
	buf_setdataptr(bp, (uintptr_t)zio->io_data);

	/*
	 * Map offset to blcknumber, based on physical block number.
	 * (512, 4096, ..). If we fail to map, default back to
	 * standard 512. lbtodb() is fixed at 512.
	 */
	buf_setblkno(bp, zio->io_offset >> dvd->vd_ashift);
	buf_setlblkno(bp, zio->io_offset >> dvd->vd_ashift);
#endif

#ifdef illumos
	/* ldi_strategy() will return non-zero only on programming errors */
	VERIFY(ldi_strategy(dvd->vd_lh, bp) == 0);
#else /* !illumos */

	bp = buf_alloc(dvd->vd_devvp);

	ASSERT(bp != NULL);
	ASSERT(zio->io_data != NULL);
	ASSERT(zio->io_size != 0);

	buf_setflags(bp, flags);
	buf_setcount(bp, zio->io_size);
	buf_setdataptr(bp, (uintptr_t)zio->io_data);

	/*
	 * Map offset to blcknumber, based on physical block number.
	 * (512, 4096, ..). If we fail to map, default back to
	 * standard 512. lbtodb() is fixed at 512.
	 */
	buf_setblkno(bp, zio->io_offset >> dvd->vd_ashift);
	buf_setlblkno(bp, zio->io_offset >> dvd->vd_ashift);

	buf_setsize(bp, zio->io_size);
	if (buf_setcallback(bp, vdev_disk_io_intr, zio) != 0)
		panic("vdev_disk_io_start: buf_setcallback failed\n");

	if (zio->io_type == ZIO_TYPE_WRITE) {
		vnode_startwrite(dvd->vd_devvp);
	}
	error = VNOP_STRATEGY(bp);
	ASSERT(error == 0);

	if (error) {
		zio->io_error = error;
		zio_interrupt(zio);
		return;
	}
}

static void
vdev_disk_io_done(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	/*
	 * If the device returned EIO, then attempt a DKIOCSTATE ioctl to see if
	 * the device has been removed. If this is the case, then we trigger an
	 * asynchronous removal of the device.
	 */
	if (zio->io_error == EIO && !vd->vdev_remove_wanted) {

		/* Apple handle device removal in zfs_osx.cpp - read errors etc
		 * should be retried by zio
		 */
#ifdef __APPLE__
		return;
#else
		state = DKIO_NONE;
		if (ldi_ioctl(dvd->vd_lh, DKIOCSTATE, (intptr_t)&state,
					  FKIOCTL, kcred, NULL) == 0 &&
			state != DKIO_INSERTED)
			{
				/*
				 * We post the resource as soon as possible, instead of
				 * when the async removal actually happens, because the
				 * DE is using this information to discard previous I/O
				 * errors.
				 */
				zfs_post_remove(zio->io_spa, vd);
				vd->vdev_remove_wanted = B_TRUE;
				spa_async_request(zio->io_spa, SPA_ASYNC_REMOVE);
				spa_async_dispatch(zio->io_spa);
			} else if (!vd->vdev_delayed_close) {
			vd->vdev_delayed_close = B_TRUE;
		}
#endif
	}
}

vdev_ops_t vdev_disk_ops = {
	vdev_disk_open,
	vdev_disk_close,
	vdev_default_asize,
	vdev_disk_io_start,
	vdev_disk_io_done,
	NULL	/* vdev_op_state_change */,
	NULL	/* vdev_op_hold */,
	NULL	/* vdev_op_rele */,
	VDEV_TYPE_DISK,	/* name of this vdev type */
	B_TRUE	/* leaf vdev */
};
