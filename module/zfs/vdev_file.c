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
 * Copyright (c) 2011, 2015 by Delphix. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/vdev_file.h>
#include <sys/vdev_impl.h>
#include <sys/zio.h>
#include <sys/fs/zfs.h>
#include <sys/fm/fs/zfs.h>
#include <sys/vnode.h>


/*
 * Virtual device vector for files.
 */

static taskq_t *vdev_file_taskq;

static void
vdev_file_hold(vdev_t *vd)
{
	ASSERT(vd->vdev_path != NULL);
}

static void
vdev_file_rele(vdev_t *vd)
{
	ASSERT(vd->vdev_path != NULL);
}

#ifdef _KERNEL
extern int VOP_GETATTR(struct vnode *vp, vattr_t *vap, int flags, void *x3, void *x4);
#endif

static int
vdev_file_open(vdev_t *vd, uint64_t *psize, uint64_t *max_psize,
    uint64_t *ashift)
{
#if _KERNEL
	static vattr_t vattr;
#endif
	vdev_file_t *vf;
	struct vnode *vp;
	int error = 0;
    struct vnode *rootdir;

    dprintf("vdev_file_open %p\n", vd->vdev_tsd);

	/* Rotational optimizations only make sense on block devices */
	vd->vdev_nonrot = B_TRUE;

	/*
	 * We must have a pathname, and it must be absolute.
	 */
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/') {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (SET_ERROR(EINVAL));
	}

	/*
	 * Reopen the device if it's not currently open.  Otherwise,
	 * just update the physical size of the device.
	 */
#ifdef _KERNEL
	if (vd->vdev_tsd != NULL) {
		ASSERT(vd->vdev_reopening);
		vf = vd->vdev_tsd;
        vnode_getwithvid(vf->vf_vnode, vf->vf_vid);
        dprintf("skip to open\n");
		goto skip_open;
	}
#endif

	vf = vd->vdev_tsd = kmem_zalloc(sizeof (vdev_file_t), KM_SLEEP);

	/*
	 * We always open the files from the root of the global zone, even if
	 * we're in a local zone.  If the user has gotten to this point, the
	 * administrator has already decided that the pool should be available
	 * to local zone users, so the underlying devices should be as well.
	 */
	ASSERT(vd->vdev_path != NULL && vd->vdev_path[0] == '/');

    /*
      vn_openat(char *pnamep,
      enum uio_seg seg,
      int filemode,
      int createmode,
      struct vnode **vpp,
      enum create crwhy,
      mode_t umask,
      struct vnode *startvp)
      extern int vn_openat(char *pnamep, enum uio_seg seg, int filemode,
      int createmode, struct vnode **vpp, enum create crwhy,
      mode_t umask, struct vnode *startvp);
    */

    rootdir = getrootdir();

    error = vn_openat(vd->vdev_path + 1,
                      UIO_SYSSPACE,
                      spa_mode(vd->vdev_spa) | FOFFMAX,
                      0,
                      &vp,
                      0,
                      0,
                      rootdir
                      );

	if (error) {
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (error);
	}

	vf->vf_vnode = vp;
#ifdef _KERNEL
    vf->vf_vid = vnode_vid(vp);
    dprintf("assigning vid %d\n", vf->vf_vid);

	/*
	 * Make sure it's a regular file.
	 */
	if (!vnode_isreg(vp)) {
        vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
        VN_RELE(vf->vf_vnode);
		return (SET_ERROR(ENODEV));
	}
#endif

#if _KERNEL
skip_open:
	/*
	 * Determine the physical size of the file.
	 */
	vattr.va_mask = AT_SIZE;
    vn_lock(vf->vf_vnode, LK_SHARED | LK_RETRY);
	error = VOP_GETATTR(vf->vf_vnode, &vattr, 0, kcred, NULL);
    VN_UNLOCK(vf->vf_vnode);
#endif
	if (error) {
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
        VN_RELE(vf->vf_vnode);
		return (error);
	}

#ifdef _KERNEL
	*max_psize = *psize = vattr.va_size;
#else
    /* userland's vn_open() will get the device size for us, so we can
     * just look it up - there is argument for a userland VOP_GETATTR to make
     * this function cleaner. */
	*max_psize = *psize = vp->v_size;
#endif
    *ashift = SPA_MINBLOCKSHIFT;
    VN_RELE(vf->vf_vnode);

	return (0);
}

static void
vdev_file_close(vdev_t *vd)
{
	vdev_file_t *vf = vd->vdev_tsd;

	if (vd->vdev_reopening || vf == NULL)
		return;

	if (vf->vf_vnode != NULL) {

        if (!vnode_getwithvid(vf->vf_vnode, vf->vf_vid)) {
        // Also commented out in MacZFS
		//(void) VOP_PUTPAGE(vf->vf_vnode, 0, 0, B_INVAL, kcred, NULL);
		(void) VOP_CLOSE(vf->vf_vnode, spa_mode(vd->vdev_spa), 1, 0,
		    kcred, NULL);
		}
	}

	vd->vdev_delayed_close = B_FALSE;
	kmem_free(vf, sizeof (vdev_file_t));
	vd->vdev_tsd = NULL;
}

static void
vdev_file_io_start(zio_t *zio)
{
    vdev_t *vd = zio->io_vd;
    vdev_file_t *vf = vd->vdev_tsd;
    ssize_t resid = 0;

    if (zio->io_type == ZIO_TYPE_IOCTL) {

        if (!vdev_readable(vd)) {
            zio->io_error = SET_ERROR(ENXIO);
			zio_interrupt(zio);
            return;
        }

        switch (zio->io_cmd) {
        case DKIOCFLUSHWRITECACHE:
            if (!vnode_getwithvid(vf->vf_vnode, vf->vf_vid)) {
                zio->io_error = VOP_FSYNC(vf->vf_vnode, FSYNC | FDSYNC,
                                          kcred, NULL);
                vnode_put(vf->vf_vnode);
            }
            break;
        default:
            zio->io_error = SET_ERROR(ENOTSUP);
        }

		zio_interrupt(zio);
        return;
    }

	ASSERT(zio->io_type == ZIO_TYPE_READ || zio->io_type == ZIO_TYPE_WRITE);
	zio->io_target_timestamp = zio_handle_io_delay(zio);

    if (!vnode_getwithvid(vf->vf_vnode, vf->vf_vid)) {

		/*
		VERIFY3U(taskq_dispatch(vdev_file_taskq, vdev_file_io_strategy, zio,
	    TQ_PUSHPAGE), !=, 0);
		*/

		void *data;
		uint64_t zio_size_in = zio->io_size;

		if (zio->io_type == ZIO_TYPE_READ) {
			ASSERT3S(zio->io_abd->abd_size,>=,zio->io_size);
			data =
				abd_borrow_buf_copy(zio->io_abd, zio->io_size);
		} else {
			ASSERT3S(zio->io_abd->abd_size,>=,zio->io_size);
			data =
				abd_borrow_buf_copy(zio->io_abd, zio->io_size);
		}

		zio->io_error = vn_rdwr(zio->io_type == ZIO_TYPE_READ ?
                           UIO_READ : UIO_WRITE, vf->vf_vnode, data,
                           zio->io_size, zio->io_offset, UIO_SYSSPACE,
                           0, RLIM64_INFINITY, kcred, &resid);

        vnode_put(vf->vf_vnode);

	ASSERT3U(zio-io_size,==,zio_size_in);

		if (zio->io_type == ZIO_TYPE_READ) {
			abd_return_buf_copy(zio->io_abd, data, zio->io_size);
		} else {
			abd_return_buf_copy(zio->io_abd, data, zio->io_size);
		}
    }

    if (resid != 0 && zio->io_error == 0)
        zio->io_error = SET_ERROR(ENOSPC);

    zio_delay_interrupt(zio);

    return;
}


/* ARGSUSED */
static void
vdev_file_io_done(zio_t *zio)
{
}

vdev_ops_t vdev_file_ops = {
	vdev_file_open,
	vdev_file_close,
	vdev_default_asize,
	vdev_file_io_start,
	vdev_file_io_done,
	NULL,
	vdev_file_hold,
	vdev_file_rele,
	VDEV_TYPE_FILE,		/* name of this vdev type */
	B_TRUE			/* leaf vdev */
};

void
vdev_file_init(void)
{
	vdev_file_taskq = taskq_create("vdev_file_taskq", 100, minclsyspri,
	    max_ncpus, INT_MAX, TASKQ_PREPOPULATE | TASKQ_THREADS_CPU_PCT);

	VERIFY(vdev_file_taskq);
}

void
vdev_file_fini(void)
{
	taskq_destroy(vdev_file_taskq);
}

/*
 * From userland we access disks just like files.
 */
#ifndef _KERNEL

vdev_ops_t vdev_disk_ops = {
	vdev_file_open,
	vdev_file_close,
	vdev_default_asize,
	vdev_file_io_start,
	vdev_file_io_done,
	NULL,
	vdev_file_hold,
	vdev_file_rele,
	VDEV_TYPE_DISK,		/* name of this vdev type */
	B_TRUE			/* leaf vdev */
};

#endif
