
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>

#include <sys/zfs_ioctl.h>
#include <sys/zfs_znode.h>
#include <sys/zvol.h>

#include <sys/zvolIO.h>

#include <sys/zfs_vnops.h>
#include <sys/taskq.h>

#include <libkern/version.h>

#include <libkern/sysctl.h>


extern "C" {
  extern kern_return_t _start(kmod_info_t *ki, void *data);
  extern kern_return_t _stop(kmod_info_t *ki, void *data);

};
  __attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(net.lundman.zfs, "1.0.0", _start, _stop)
  __private_extern__ kmod_start_func_t *_realmain = 0;
  __private_extern__ kmod_stop_func_t  *_antimain = 0;
  __private_extern__ int _kext_apple_cc = __APPLE_CC__ ;


/*
 * Can those with more C++ experience clean this up?
 */
static void *global_c_interface = NULL;

/* Notifier for disk removal */
static IONotifier *disk_remove_notifier = NULL;

static bool IOkit_disk_removed_callback(void* target, void* refCon, IOService* newService, IONotifier* notifier);


// Define the superclass.
#define super IOService

OSDefineMetaClassAndStructors(net_lundman_zfs_zvol, IOService)


/*
 * Some left over functions from zfs_osx.c, left as C until cleaned up
 */

extern "C" {

extern SInt32 zfs_active_fs_count;


#ifdef DEBUG
#define	ZFS_DEBUG_STR	" (DEBUG mode)"
#else
#define	ZFS_DEBUG_STR	""
#endif

static char kext_version[64] = ZFS_META_VERSION "-" ZFS_META_RELEASE ZFS_DEBUG_STR;

//struct sysctl_oid_list sysctl__zfs_children;
SYSCTL_DECL(_zfs);
SYSCTL_NODE( , OID_AUTO, zfs, CTLFLAG_RD, 0, "");
SYSCTL_STRING(_zfs, OID_AUTO, kext_version,
			  CTLFLAG_RD | CTLFLAG_LOCKED,
			  kext_version, 0, "ZFS KEXT Version");

#ifdef __APPLE__
extern int
zfs_vfs_sysctl(int *name, __unused u_int namelen, user_addr_t oldp, size_t *oldlenp,
               user_addr_t newp, size_t newlen, __unused vfs_context_t context)
{
#if 0
	int error;
	switch(name[0]) {
	case ZFS_SYSCTL_FOOTPRINT: {
		zfs_footprint_stats_t *footprint;
		size_t copyinsize;
		size_t copyoutsize;
		int max_caches;
		int act_caches;

		if (newp) {
			return (EINVAL);
		}
		if (!oldp) {
			*oldlenp = sizeof (zfs_footprint_stats_t);
			return (0);
		}
		copyinsize = *oldlenp;
		if (copyinsize < sizeof (zfs_footprint_stats_t)) {
			*oldlenp = sizeof (zfs_footprint_stats_t);
			return (ENOMEM);
		}
		footprint = kmem_alloc(copyinsize, KM_SLEEP);

		max_caches = copyinsize - sizeof (zfs_footprint_stats_t);
		max_caches += sizeof (kmem_cache_stats_t);
		max_caches /= sizeof (kmem_cache_stats_t);

		footprint->version = ZFS_FOOTPRINT_VERSION;

		footprint->memory_stats.current = zfs_footprint.current;
		footprint->memory_stats.target = zfs_footprint.target;
		footprint->memory_stats.highest = zfs_footprint.highest;
		footprint->memory_stats.maximum = zfs_footprint.maximum;

		arc_get_stats(&footprint->arc_stats);

		kmem_cache_stats(&footprint->cache_stats[0], max_caches, &act_caches);
		footprint->caches_count = act_caches;
		footprint->thread_count = zfs_threads;

		copyoutsize = sizeof (zfs_footprint_stats_t) +
		              ((act_caches - 1) * sizeof (kmem_cache_stats_t));

		error = ddi_copyout(footprint, oldp, copyoutsize, 0);

		kmem_free(footprint, copyinsize);

		return (error);
	    }

	case ZFS_SYSCTL_CONFIG_DEBUGMSG:
		error = sysctl_int(oldp, oldlenp, newp, newlen, &zfs_msg_buf_enabled);
		return error;

	case ZFS_SYSCTL_CONFIG_zdprintf:
#ifdef ZFS_DEBUG
		error = sysctl_int(oldp, oldlenp, newp, newlen, &zfs_zdprintf_enabled);
#else
		error = ENOTSUP;
#endif
		return error;
	}
#endif
	return (ENOTSUP);
}
#endif /* __APPLE__ */


#include <sys/utsname.h>
#include <string.h>


} // Extern "C"


bool net_lundman_zfs_zvol::init (OSDictionary* dict)
{
    bool res = super::init(dict);
    //IOLog("ZFS::init\n");
    global_c_interface = (void *)this;
    return res;
}


void net_lundman_zfs_zvol::free (void)
{
  //IOLog("ZFS::free\n");
    global_c_interface = NULL;
    super::free();
}


IOService* net_lundman_zfs_zvol::probe (IOService* provider, SInt32* score)
{
    IOService *res = super::probe(provider, score);
    //IOLog("ZFS::probe\n");
    return res;
}

bool net_lundman_zfs_zvol::start (IOService *provider)
{
    bool res = super::start(provider);


    IOLog("ZFS: Loading module ... \n");

    sysctl_register_oid(&sysctl__zfs);
    sysctl_register_oid(&sysctl__zfs_kext_version);

	/*
	 * Initialize /dev/zfs, this calls spa_init->dmu_init->arc_init-> etc
	 */
	zfs_ioctl_osx_init();

	/* registerService() allows zconfigd to match against the service */
	this->registerService();

	///sysctl_register_oid(&sysctl__debug_maczfs);
	//sysctl_register_oid(&sysctl__debug_maczfs_stalk);

    zfs_vfsops_init();

    /*
     * When is the best time to start the system_taskq? It is strictly
     * speaking not used by SPL, but by ZFS. ZFS should really start it?
     */
    system_taskq_init();


    /*
     * hostid is left as 0 on OSX, and left to be set if developers wish to
     * use it. If it is 0, we will hash the hardware.uuid into a 32 bit
     * value and set the hostid.
     */
    if (!zone_get_hostid(NULL)) {
      uint32_t myhostid = 0;
      IORegistryEntry *ioregroot =  IORegistryEntry::getRegistryRoot();
      if(ioregroot) {
        //IOLog("ioregroot is '%s'\n", ioregroot->getName(gIOServicePlane));
        IORegistryEntry *macmodel = ioregroot->getChildEntry(gIOServicePlane);
        if(macmodel) {
          //IOLog("macmodel is '%s'\n", macmodel->getName(gIOServicePlane));
          OSObject *ioplatformuuidobj;
          //ioplatformuuidobj = ioregroot->getProperty("IOPlatformUUID", gIOServicePlane, kIORegistryIterateRecursively);
          ioplatformuuidobj = macmodel->getProperty(kIOPlatformUUIDKey);
          if(ioplatformuuidobj) {
            OSString *ioplatformuuidstr = OSDynamicCast(OSString, ioplatformuuidobj);
            //IOLog("IOPlatformUUID is '%s'\n", ioplatformuuidstr->getCStringNoCopy());

            myhostid = fnv_32a_str(ioplatformuuidstr->getCStringNoCopy(),
                                   FNV1_32A_INIT);

            sysctlbyname("kern.hostid", NULL, NULL, &myhostid, sizeof(myhostid));
            printf("ZFS: hostid set to %08x from UUID '%s'\n",
                   myhostid, ioplatformuuidstr->getCStringNoCopy());
          }
        }
      }
    }

	disk_remove_notifier = addMatchingNotification(gIOTerminatedNotification,
						serviceMatching("IOMedia"),
						IOkit_disk_removed_callback,
						this, NULL, 0);

    return res;
}

void net_lundman_zfs_zvol::stop (IOService *provider)
{

	/* Stop being told about devices leaving */
	if (disk_remove_notifier) disk_remove_notifier->remove();

#if 0
  // You can not stop unload :(
	if (zfs_active_fs_count != 0 ||
	    spa_busy() ||
	    zvol_busy()) {

      IOLog("ZFS: Can not unload as we have filesystems mounted.\n");
      return;
	}
#endif
    IOLog("ZFS: Attempting to unload ...\n");

    super::stop(provider);


    system_taskq_fini();

    zfs_ioctl_osx_fini();
    zfs_vfsops_fini();

    sysctl_unregister_oid(&sysctl__zfs_kext_version);
    sysctl_unregister_oid(&sysctl__zfs);
    IOLog("ZFS: Unloaded module\n");

}


IOReturn net_lundman_zfs_zvol::doEjectMedia(void *arg1)
{
  zvol_state_t *nub = (zvol_state_t *)arg1;
  IOLog("block svc ejecting\n");
  if(nub) {

    // Only 10.6 needs special work to eject
    if ((version_major == 10) &&
	(version_minor == 8))
      destroyBlockStorageDevice(nub);

  }

  IOLog("block svc ejected\n");
  return kIOReturnSuccess;
}



bool net_lundman_zfs_zvol::createBlockStorageDevice (zvol_state_t *zv)
{
    net_lundman_zfs_zvol_device *nub = NULL;
    bool            result = false;

    if (!zv) goto bail;

    //IOLog("createBlock size %llu\n", zv->zv_volsize);

    // Allocate a new IOBlockStorageDevice nub.
    nub = new net_lundman_zfs_zvol_device;
    if (nub == NULL)
        goto bail;

    // Call the custom init method (passing the overall disk size).
    if (nub->init(zv) == false)
        goto bail;

    // Attach the IOBlockStorageDevice to the this driver.
    // This call increments the reference count of the nub object,
    // so we can release our reference at function exit.
    if (nub->attach(this) == false)
        goto bail;

    // Allow the upper level drivers to match against the IOBlockStorageDevice.
    /*
     * We here use Synchronous, so that all services are attached now, then
     * we can go look for the BSDName. We need this to create the correct
     * symlinks.
     */
    nub->registerService(kIOServiceSynchronous);

    if (nub->getBSDName() == 0) {
        if ((version_major != 10) &&
            (version_minor != 8))
            zvol_add_symlink(zv, &zv->zv_bsdname[1], zv->zv_bsdname);
            result = true;
    } else
        result = false;

 bail:
    // Unconditionally release the nub object.
    if (nub != NULL)
        nub->release();

   return result;
}

bool net_lundman_zfs_zvol::destroyBlockStorageDevice (zvol_state_t *zv)
{
    net_lundman_zfs_zvol_device *nub = NULL;
    bool            result = true;

    if (zv->zv_iokitdev) {

      //IOLog("removeBlockdevice\n");

      nub = static_cast<net_lundman_zfs_zvol_device*>(zv->zv_iokitdev);

      zv->zv_iokitdev = NULL;
      zv = NULL;

		if (nub)
			nub->terminate(kIOServiceRequired|
			    kIOServiceSynchronous);
    }

    return result;
}

bool net_lundman_zfs_zvol::updateVolSize(zvol_state_t *zv)
{
    net_lundman_zfs_zvol_device *nub = NULL;
    //bool            result = true;

    // Is it ok to keep a pointer reference to the nub like this?
    if (zv->zv_iokitdev) {
      nub = static_cast<net_lundman_zfs_zvol_device*>(zv->zv_iokitdev);

      if (!nub)
          return false;

      //IOLog("Attempting to update volsize\n");
      nub->retain();
      nub->registerService(kIOServiceSynchronous);
      nub->release();
    }
    return true;
}

/*
 * C language interfaces
 */

int zvolCreateNewDevice(zvol_state_t *zv)
{
    static_cast<net_lundman_zfs_zvol*>(global_c_interface)->createBlockStorageDevice(zv);
    return 0;
}

int zvolRemoveDevice(zvol_state_t *zv)
{
    static_cast<net_lundman_zfs_zvol*>(global_c_interface)->destroyBlockStorageDevice(zv);
    return 0;
}

int zvolSetVolsize(zvol_state_t *zv)
{
    static_cast<net_lundman_zfs_zvol*>(global_c_interface)->updateVolSize(zv);
    return 0;
}

uint64_t zvolIO_kit_read(void *iomem, uint64_t offset, char *address, uint64_t len)
{
  IOByteCount done;
  //IOLog("zvolIO_kit_read offset %p count %llx to offset %llx\n",
  //    address, len, offset);
  done=static_cast<IOMemoryDescriptor*>(iomem)->writeBytes(offset,
                                                           (void *)address,
                                                           len);
  return done;
}

uint64_t zvolIO_kit_write(void *iomem, uint64_t offset, char *address, uint64_t len)
{
  IOByteCount done;
  //IOLog("zvolIO_kit_write offset %p count %llx to offset %llx\n",
  //    address, len, offset);
  done=static_cast<IOMemoryDescriptor*>(iomem)->readBytes(offset,
                                                          (void *)address,
                                                          len);
  return done;
}

#include <sys/vdev_impl.h>
#include <sys/spa_impl.h>
#include <sys/vdev_disk.h>


static vdev_t *
vdev_lookup_by_path(vdev_t *vd, const char *name)
{
	vdev_t *mvd;
	int c;
	char *lookup_name;
	vdev_disk_t *dvd = NULL;

	if (!vd) return NULL;

	dvd = (vdev_disk_t *)vd->vdev_tsd;

	// Check both strings are valid
	if (name && *name && dvd &&
		vd->vdev_path && vd->vdev_path[0]) {
		int off;

		// Try normal path "vdev_path" or the readlink resolved

		lookup_name = vd->vdev_path;

		// Skip /dev/ or not?
		strncmp("/dev/", lookup_name, 5) == 0 ? off=5 : off=0;

		dprintf("ZFS: vdev '%s' == '%s' ?\n", name,
				&lookup_name[off]);

		if (!strcmp(name, &lookup_name[off])) return vd;


		lookup_name = dvd->vd_readlinkname;

		// Skip /dev/ or not?
		strncmp("/dev/", lookup_name, 5) == 0 ? off=5 : off=0;

		dprintf("ZFS: vdev '%s' == '%s' ?\n", name,
				&lookup_name[off]);

		if (!strcmp(name, &lookup_name[off])) return vd;
	}

	for (c = 0; c < vd->vdev_children; c++)
		if ((mvd = vdev_lookup_by_path(vd->vdev_child[c], name)) !=
			NULL)
			return (mvd);

	return (NULL);
}


extern "C" {

  /*
   * Unfortunately the notify thread that posts the termination event to us
   * is inside IOkit locked loop, so we have to issue the vnode_close()
   * async, or vn_close()/dkclose() will wait on notify to release the lock
   */
  static void vdev_close_thread(void *arg)
  {
	vdev_t *vd = (vdev_t *)arg;
	vdev_disk_t *dvd = (vdev_disk_t *)vd->vdev_tsd;

	if (dvd) dvd->vd_offline = B_TRUE;
	vdev_disk_close(vd);
	thread_exit();
  }
}

/*
 * Callback for device termination events, ie, disks removed.
 */
bool IOkit_disk_removed_callback(void* target,
								 void* refCon,
								 IOService* newService,
								 IONotifier* notifier)
{
	OSObject *prop = 0;
	OSString* bsdnameosstr = 0;

	prop = newService->getProperty(kIOBSDNameKey, gIOServicePlane,
								   kIORegistryIterateRecursively);
	if (prop) {
		spa_t *spa = NULL;

		bsdnameosstr = OSDynamicCast(OSString, prop);
		printf("ZFS: Device removal detected: '%s'\n",
			   bsdnameosstr->getCStringNoCopy());

		for (spa = spa_next(NULL);
			 spa != NULL; spa = spa_next(spa)) {
		  vdev_t *vd;

		  dprintf("ZFS: Scanning pool '%s'\n", spa_name(spa));

		  vd = vdev_lookup_by_path(spa->spa_root_vdev,
								   bsdnameosstr->getCStringNoCopy());

		  if (vd && vd->vdev_path) {

			  printf("ZFS: Device '%s' removal requested\n",
					 vd->vdev_path);
			  (void) thread_create(NULL, 0, vdev_close_thread,
								   vd, 0, &p0,
								   TS_RUN, minclsyspri);

			  vd->vdev_remove_wanted = B_TRUE;
			  spa_async_request(spa, SPA_ASYNC_REMOVE);

			  break;
		  }

		} // for all spa

	} // if has BSDname

	return true;
}
