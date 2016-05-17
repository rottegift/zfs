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

// smd
#if 1
const char *devids[] = {
  "DT_HyperX_30-1C6F65C7B80DBCB131FB000D:1",
"DT_HyperX_30-1C6F65C7B80DBCB131FB000D:2",
  "DT_HyperX_30-1C6F65C7BF55BCB111D10001:2",
  "media-862B354A-1FA6-46B9-9E1E-3A141921EEC3",
  "media-09D41BB2-F9B4-43D8-9FDA-4343AAEE62ED",
  "media-913ACAC6-2F9B-4044-AC4D-7767757A39EA",
  "media-51E41B74-4B9C-44F4-9914-264BED4F86A2",
  "media-B1CFCE85-67DE-449F-8F6D-7AFE8FA347D4",
  "media-06B5B4F9-E348-77C0-06B5-B4F9E34877C0", // Quarto l2
  "media-06AFD533-6738-9440-06AF-D53367389440", // Quarto log0
  "media-06AFD556-769F-DB40-06AF-D556769FDB40", // Quarto log1
  "media-06B5B500-8B97-08C0-06B5-B5008B9708C0", // Safety l2
  "media-06AFD54C-50ED-A600-06AF-D54C50EDA600", // Safety log0
  "media-06AFD522-9139-D840-06AF-D5229139D840", // Safety log1
  "media-06B5B50B-0341-C900-06B5-B50B0341C900", // Trinity l2
  "media-06AFD52B-E487-6940-06AF-D52BE4876940", // Trinity log0
  "media-06AFD550-DBD1-7E40-06AF-D550DBD17E40", // Trinity log1
  "media-06B5ABA7-D6C1-F940-06B5-ABA7D6C1F940", // homepool vdev on 840
  "media-F375E0F6-CF0D-834E-9D67-9B97D632FEA1", // homepool vdev on 256 (wholedisk)
  "media-06B5C205-A171-4F40-06B5-C205A1714F40", // homepool log0
  "media-06B5C225-CA24-FAC0-06B5-C225CA24FAC0", // homepool log1
  "media-06B5C2F0-9123-5200-06B5-C2F091235200", // homepool l2
  "C400-MTFDDAC256MAM-0000000012290910996E:1", // homepool alt vdev on 256 (wholedisk)
  "media-06B5C239-A7B9-3E80-06B5-C239A7B93E80", // Dual log0
  "media-06B5D8FA-B893-09C0-06B5-D8FAB89309C0", // Dual log1
  "media-06B5C2DE-CF65-F440-06B5-C2DECF65F440", // Dual cache0
  "media-06B5C2B2-8B1A-1180-06B5-C2B28B1A1180", // Dual cache1
  "media-06AFD55B-F4EA-6E40-06AF-D55BF4EA6E40", // ssdpool mirror0
  "media-06AFD541-5320-07C0-06AF-D541532007C0", // ssdpool mirror1
  "media-E5A6E54B-236E-4D84-B15C-5EB57D362E9F", // ssedpool l2
  "media-06B5C2CB-ED7F-2600-06B5-C2CBED7F2600", // Newmis log0
  "media-06B5C2A4-7057-F100-06B5-C2A47057F100", // Newmis log1
  "DT_HyperX_30-1C6F65C7BF55BCB111D10001:1", // Newmis cache
"Patriot_Memory-070727D062444554:1",
"media-06435AE2-F97D-7100-0643-5AE2F97D7100",
"media-06435AEA-7E68-8E00-0643-5AEA7E688E00",
"media-06435B07-8095-9180-0643-5B0780959180",
"media-065BAEFF-FB1E-49C0-065B-AEFFFB1E49C0",
"media-065BAF0F-CE5A-7400-065B-AF0FCE5A7400",
"media-065BAF14-6020-7940-065B-AF1460207940",
"media-065BAF19-295F-CE00-065B-AF19295FCE00",
"media-065BAF21-0F98-F780-065B-AF210F98F780",
"media-065BF90D-6464-3880-065B-F90D64643880",
"media-065BF912-67CC-F440-065B-F91267CCF440",
"media-065BF919-1448-4AC0-065B-F91914484AC0",
"media-065BFA0C-15F3-B500-065B-FA0C15F3B500",
"media-065BFA1D-A7CA-E940-065B-FA1DA7CAE940",
"media-065BFA2B-16AD-57C0-065B-FA2B16AD57C0",
"media-065BFA34-D7DE-9000-065B-FA34D7DE9000",
"media-06AFDE29-2122-4980-06AF-DE2921224980",
"media-06AFDE30-8725-46C0-06AF-DE30872546C0",
"media-06AFDE38-897E-D540-06AF-DE38897ED540",
"media-06AFDE40-5D0C-CA80-06AF-DE405D0CCA80",
"media-06AFDF9B-AD66-6FC0-06AF-DF9BAD666FC0",
"media-06AFDFA2-B124-5640-06AF-DFA2B1245640",
"media-06AFDFAD-9862-CB00-06AF-DFAD9862CB00",
"media-06AFDFB4-AC1A-6E00-06AF-DFB4AC1A6E00",
"media-970A550F-BA71-4D05-8D02-E6D7C7489670",
"media-AC58DF37-2193-480D-9992-4ACD67D3E351",
  "media-1B6FCCEA-C35C-4F60-AC1D-1BA08408F143",
  "media-D3A240CA-AE2A-427C-83AD-87927C04B4E4",
  "media-048F8673-0403-4BF0-BC4F-E3F427B3242C",
  "media-ACFA2BBB-88DE-451C-8455-5D83F6F188B0",
  "media-5EDEE597-C7F6-4788-841A-790ECAD8FA26",
  "media-56FFB24C-E400-4FF0-8042-D86E0AD87F07",
  
NULL
};

// from http://www.opensource.apple.com/source/xnu/xnu-792.13.8/libsa/strstr.c

static inline char *
smd_strstr(const char *in, const char *str)
{
  char c;
  size_t len;

  c = *str++;
  if (!c)
    return (char *) in;	// Trivial empty string case

  len = strlen(str);
  do {
    char sc;

    do {
      sc = *in++;
      if (!sc)
	return (char *) 0;
    } while (sc != c);
  } while (strncmp(in, str, len) != 0);

  return (char *) (in - 1);
}


static inline int
ssd_search(const char a[]) {
  int i;
  char *p = NULL;

  for(i=0; devids[i] != NULL; i++) {
    if((p=smd_strstr(a, devids[i]))!=NULL) {
      printf("ZFS: smd: issid: %s\n", a);
      return 1;
    }
  }
  return 0;
}

#endif

static int
vdev_disk_open(vdev_t *vd, uint64_t *psize, uint64_t *max_psize,
    uint64_t *ashift)
{
	spa_t *spa = vd->vdev_spa;
	vdev_disk_t *dvd = vd->vdev_tsd;
	vnode_t *devvp = NULLVP;
	vfs_context_t context = NULL;
	uint64_t blkcnt;
	uint32_t blksize;
	int fmode = 0;
	int error = 0;
	int isssd;

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

	error = EINVAL;		/* presume failure */

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
			*max_psize += vdev_disk_get_space(vd, capacity, blksz);
			zfs_dbgmsg("capacity change: vdev %s, psize %llu, "
			    "max_psize %llu", vd->vdev_path, *psize,
			    *max_psize);
		}

		/*
		 * Since we own the whole disk, try to enable disk write
		 * caching.  We ignore errors because it's OK if we can't do it.
		 */
		(void) ldi_ioctl(dvd->vd_lh, DKIOCSETWCE, (intptr_t)&wce,
		    FKIOCTL, kcred, NULL);
	}
#endif

	/*
	 * Clear the nowritecache bit, so that on a vdev_reopen() we will
	 * try again.
	 */
	vd->vdev_nowritecache = B_FALSE;

	/* Inform the ZIO pipeline that we are non-rotational */
	vd->vdev_nonrot = B_FALSE;
	if (VNOP_IOCTL(devvp, DKIOCISSOLIDSTATE, (caddr_t)&isssd, 0,
				   context) == 0) {
		if (isssd)
			vd->vdev_nonrot = B_TRUE;
	}
	// smd - search static table in #if block above
	if(isssd == 0) {
	  if(vd->vdev_path) {
	    isssd = ssd_search(vd->vdev_path);
	  }
	}
	// smd: was dprintf
	printf("ZFS: vdev_disk(%s) isSSD %d\n", vd->vdev_path ? vd->vdev_path : "", 
			isssd);

	dvd->vd_devvp = devvp;
out:
	if (error) {
	  if (devvp) {
			vnode_close(devvp, fmode, context);
			dvd->vd_devvp = NULL;
	  }
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
	}
	if (context)
		(void) vfs_context_rele(context);

	if (error) printf("ZFS: vdev_disk_open('%s') failed error %d\n",
					  vd->vdev_path ? vd->vdev_path : "", error);
	return (error);
}

/* Not static so zfs_osx.cpp can call it on device removal */
void
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

	if (dvd->vd_devid != NULL) {
		ddi_devid_free(dvd->vd_devid);
		dvd->vd_devid = NULL;
	}

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
		(void) vnode_close(vp, spa_mode(vd->vdev_spa),
						   spl_vfs_context_kernel());
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

	vdev_disk_free(vd);
}

static void
vdev_disk_io_intr(struct buf *bp, void *arg)
{
	zio_t *zio = (zio_t *)arg;

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

	zio_interrupt(zio);
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

			switch (zio->io_cmd) {

				case DKIOCFLUSHWRITECACHE:

					if (zfs_nocacheflush)
						break;

					if (vd->vdev_nowritecache) {
						zio->io_error = SET_ERROR(ENOTSUP);
						break;
					}

					context = vfs_context_create(spl_vfs_context_kernel());
					error = VNOP_IOCTL(dvd->vd_devvp, DKIOCSYNCHRONIZECACHE,
									   NULL, FWRITE, context);
					(void) vfs_context_rele(context);

					if (error == 0)
						vdev_disk_ioctl_done(zio, error);
					else
						error = ENOTSUP;

					if (error == 0) {
						/*
						 * The ioctl will be done asychronously,
						 * and will call vdev_disk_ioctl_done()
						 * upon completion.
						 */
						return;
					} else if (error == ENOTSUP || error == ENOTTY) {
						/*
						 * If we get ENOTSUP or ENOTTY, we know that
						 * no future attempts will ever succeed.
						 * In this case we set a persistent bit so
						 * that we don't bother with the ioctl in the
						 * future.
						 */
						vd->vdev_nowritecache = B_TRUE;
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
	flags |= B_NOCACHE | B_PASSIVE; // also do B_PASSIVE for anti throttling test

	if (zio->io_flags & ZIO_FLAG_FAILFAST)
		flags |= B_FAILFAST;

	zio->io_target_timestamp = zio_handle_io_delay(zio);

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
