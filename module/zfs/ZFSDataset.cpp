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
 * Copyright (c) 2016, Evan Susarret.  All rights reserved.
 * Copyright (c) 2017, Jorgen Lundman  All rights reserved.
 */

//extern "C" {
//}

#include <sys/ZFSDataset.h>
#include <sys/spa_impl.h>
#include <sys/ZFSPool.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>

#define	DLOGFUNC()	do {			\
	IOLog("ZFSDataset %s\n", __func__);	\
} while (0);

#ifdef dprintf
#undef dprintf
#endif
#define	dprintf		IOLog


//
// This function broke in the move to IOBlockStorageDevice, fixme
//
int
zfs_dataset_proxy_get_osname(const char *in, char *out, int len)
{
	ZFSDataset *dataset;
	IOService *service;
	OSDictionary *matching;
	OSString *osstr;
	const char *osname;
	const char *bsdname;
	bool ret;

	/* Validate arguments */
	if (!in || !out || len == 0) {
		dprintf("%s invalid argument\n", __func__);
		return (EINVAL);
	}
	if (strncmp(in, "/dev/", 5) == 0) {
		bsdname = in + 5;
	} else {
		bsdname = in;
	}
	if (strncmp(bsdname, "disk", 4) != 0) {
		dprintf("%s invalid bsdname %s from %s\n", __func__, bsdname, in);
		return (EINVAL);
	}
	if ((osstr = OSString::withCString(bsdname)) == NULL) {
		dprintf("%s couldn't alloc string\n", __func__);
		return (ENOMEM);
	}

	/* Get matching dictionary for ZFSDataset class */
	if ((matching = IOService::serviceMatching("ZFSDataset")) == NULL) {
		dprintf("%s couldn't get match dictionary\n", __func__);
		osstr->release();
		return (ENOMEM);
	}

	/* Add match key for BSD disk name from in argument */
	ret = matching->setObject(kIOBSDNameKey, osstr);
	osstr->release();
	osstr = 0;
	if (ret == false) {
		dprintf("%s couldn't match on bsdname\n", __func__);
		matching->release();
		return (ENOMEM);
	}

	/* Get matching service, should only be one */
	service = IOService::copyMatchingService(matching);
	matching->release();
	matching = 0;
	if (service == NULL) {
		dprintf("%s no matching service\n", __func__);
		return (ENOENT);
	}
	if ((dataset = OSDynamicCast(ZFSDataset, service)) == NULL) {
		dprintf("%s match couldn't be cast\n", __func__);
		service->release();
		return (ENOENT);
	}

	/* Grab and retain the ZFS Dataset property string */
	osstr = OSDynamicCast(OSString,
	    dataset->getProperty(kZFSDatasetNameKey));
	if (osstr) osstr->retain();
	dataset->release();

	if (!osstr) {
		dprintf("%s couldn't get datset name from proxy\n", __func__);
		return (ENXIO);
	}

	/* Get pointer to C string */
	osname = osstr->getCStringNoCopy();
	if (!osname) {
		dprintf("%s invalid OSString\n", __func__);
		return (ENXIO);
	}

	/* Finally, zero the out buffer and copyout the osname */
	bzero(out, len);
	snprintf(out, len, "%s", osname);
	osstr->release();

	dprintf("%s copied out %s\n", __func__, osname);
	return (0);
}

/*
 * Input:
 * osname: dataset name e.g. pool/dataset
 * Return:
 * 0 if exists, positive int on error or missing.
 */
int
spa_iokit_dataset_proxy_exists(const char *osname, IOService **found)
{
	IOService *service;
	OSDictionary *matching;
	const OSSymbol *nameSymbol, *classSymbol;

	if (found) *found = NULL;

	if (!osname || osname[0] == '\0' ||
	    (nameSymbol = OSSymbol::withCString(osname)) == NULL) {
		dprintf("%s invalid osname\n", __func__);
		return (EINVAL);
	}

	classSymbol = OSSymbol::withCString("ZFSDataset");
	if (!classSymbol) {
		dprintf("%s missing class name\n", __func__);
		nameSymbol->release();
		return (EINVAL);
	}

	matching = IOService::serviceMatching(classSymbol);
	if (!matching || matching->setObject(kZFSDatasetNameKey,
	    nameSymbol) == false) {
		dprintf("%s couldn't setup matching\n", __func__);
		nameSymbol->release();
		classSymbol->release();
		return (ENOMEM);
	}
	nameSymbol->release();
	nameSymbol = 0;
	classSymbol->release();
	classSymbol = 0;

	service = IOService::copyMatchingService(matching);
	matching->release();
	matching = 0;
	if (!service) {
		dprintf("%s no matching service\n", __func__);
		return (ENOENT);
	}

	/* Verify we can cast matching service */
	if (OSDynamicCast(ZFSDataset, service) != NULL) {
		service->release();
		if (found) *found = service;
		return (0);
	}

	service->release();
	return (ENOENT);
}

//spa_iokit_dataset_proxy_create(nvlist_t *config)
int
spa_iokit_dataset_proxy_create(const char *osname, char *diskname, int len)
{
	spa_t *spa;
	ZFSPool *pool = 0;
	ZFSDataset *dataset;

	if (!osname || osname[0] == '\0') {
		dprintf("%s missing dataset argument\n", __func__);
		return (EINVAL);
	}

	mutex_enter(&spa_namespace_lock);
	spa = spa_lookup(osname);
	if (spa && spa->spa_iokit_proxy) {
		pool = spa->spa_iokit_proxy->proxy;
		if (pool) pool->retain();
	}
	mutex_exit(&spa_namespace_lock);

	/* Need a pool proxy to attach to */
	if (!pool) {
		dprintf("%s couldn't get pool proxy\n", __func__);
		return (EINVAL);
	}

	/* Returns 0 for existing */
	if (spa_iokit_dataset_proxy_exists(osname, NULL) == 0) {
		dprintf("%s %s already has a proxy device\n",
		    __func__, osname);
		pool->release();
		return (EBUSY);
	}

	/* Create new proxy object */
	dataset = ZFSDataset::withDatasetName(osname);
	if (!dataset) {
		pool->release();
		return (ENOMEM);
	}

	pool->lockForArbitration();
	if (dataset->attach(pool) == false) {
		dprintf("%s attach failed\n", __func__);
		dataset->release();
		pool->unlockForArbitration();
		pool->release();
		return (ENXIO);
	}
	pool->unlockForArbitration();

	if (dataset->start(pool) == false) {
		dprintf("%s start failed\n", __func__);
		dataset->detach(pool);
		dataset->release();
		pool->release();
		return (ENXIO);
	}
	pool->release();
	pool = 0;

	dataset->registerService(kIOServiceSynchronous);
	/* XXX Check dataset list for existing */
	  /* XXX lock list
	   * walk, break on match
	   * unlock
	   */
	/* XXX Make new dataset proxy if no match*/
	/* XXX Add to list, or drop if race lost */
	  /* XXX lock list
	   * walk, break on match
	   * insert if no match
	   * unlock
	   * if match, release created proxy
	   */
	/* XXX registerService on matched or new proxy */

	dprintf("Trying to return BSD name\n");
	if (diskname && len > 0) {
		OSString *ospath = NULL;
		ospath = OSDynamicCast(OSString, dataset->getProperty(
				kIOBSDNameKey, gIOServicePlane,
				kIORegistryIterateRecursively));
		if (ospath && ospath->getLength() > 0) {
			snprintf(diskname, len, "/dev/%s", ospath->getCStringNoCopy());
			dprintf("  BSD name '%s'\n", diskname);
		}
	}

	return (0);
}

int
spa_iokit_dataset_proxy_destroy(char *osname)
{
	/* XXX Find dataset proxy and terminate
	 * lock list
	 * walk, break on match
	 * unlock list
	 * terminate if match
	 * return status
	 */
	IOService *service = NULL;

	if (spa_iokit_dataset_proxy_exists(osname, &service) == 0) {
		if (service != NULL) {
			printf("%s: destroying proxy for '%s'\n", __func__, osname);
			service->terminate();
		}
	}
	return (0);
}

#define super IOBlockStorageDevice
//OSDefineMetaClassAndStructors(ZFSDataset, IOMedia);
OSDefineMetaClassAndStructors(ZFSDataset, IOBlockStorageDevice);

#if 0
/* XXX Only for debug tracing */
bool
ZFSDataset::open(IOService *client,
	    IOOptionBits options, IOStorageAccess access)
{
	bool ret;
	DLOGFUNC();

	ret = IOMedia::open(client, options, access);

	dprintf("ZFSDataset %s ret %d\n", __func__, ret);
	return (ret);
}

bool
ZFSDataset::isOpen(const IOService *forClient) const
{
	IOLog("ZFSDataset %s\n", __func__);
	return (false);
}

void
ZFSDataset::close(IOService *client,
	    IOOptionBits options)
{
	DLOGFUNC();
	IOMedia::close(client, options);
}

bool
ZFSDataset::handleOpen(IOService *client,
	    IOOptionBits options, void *access)
{
	bool ret;
	DLOGFUNC();

	ret = IOMedia::handleOpen(client, options, access);

	dprintf("ZFSDataset %s ret %d\n", __func__, ret);
	return (ret);
}

bool
ZFSDataset::handleIsOpen(const IOService *client) const
{
	bool ret;
	DLOGFUNC();

	ret = IOMedia::handleIsOpen(client);

	dprintf("ZFSDataset %s ret %d\n", __func__, ret);
	return (ret);
}

void
ZFSDataset::handleClose(IOService *client,
    IOOptionBits options)
{
	DLOGFUNC();
	IOMedia::handleClose(client, options);
}
#endif

bool
ZFSDataset::attach(IOService *provider)
{
	DLOGFUNC();
	return (super::attach(provider));
}

void
ZFSDataset::detach(IOService *provider)
{
	DLOGFUNC();
	super::detach(provider);
}

bool
ZFSDataset::start(IOService *provider)
{
	DLOGFUNC();
	return (super::start(provider));
}

void
ZFSDataset::stop(IOService *provider)
{
	DLOGFUNC();
	super::stop(provider);
}

bool
ZFSDataset::init(OSDictionary *properties)
{
	dprintf("%s\n", __func__);
	if (super::init(properties) == false)
        return (false);

	super::setProperty(kIOMediaContentHintKey, "zfs_dataset_proxy");
	return true;
}

void
ZFSDataset::free()
{
	DLOGFUNC();
	super::free();
}

ZFSDataset *
ZFSDataset::withDatasetName(const char *name)
{
	ZFSDataset *dataset;
	size_t size;
	bool isWritable;

	DLOGFUNC();

	if (!name || name[0] == '\0') {
		dprintf("%s missing name\n", __func__);
		return (NULL);
	}

	dataset = new ZFSDataset;
	if (!dataset) {
		dprintf("%s allocation failed\n", __func__);
		return (NULL);
	}

	/* XXX Make up a size and read/write for now XXX */
	size = (1<<30);
	isWritable = true;
#if 0
ZFSDataset::init(UInt64 base, UInt64 size,
    UInt64 preferredBlockSize,
    IOMediaAttributeMask attributes,
    bool isWhole, bool isWritable,
    const char *contentHint,
    OSDictionary *properties)
#endif
	if (dataset->init(NULL) == false) {
		dprintf("%s init failed\n", __func__);
		dataset->release();
		return (NULL);
	}

	if (dataset->setDatasetName(name) == false) {
		dprintf("%s invalid name\n", __func__);
		dataset->release();
		return (NULL);
	}

	return (dataset);
}

#if 0
void
ZFSDataset::read(IOService *client,
    UInt64 byteStart, IOMemoryDescriptor *buffer,
    IOStorageAttributes *attributes,
    IOStorageCompletion *completion)
{
	IOByteCount total, cur_len, done = 0;
	addr64_t cur;

	DLOGFUNC();
	if (!buffer) {
		if (completion) complete(completion, kIOReturnInvalid, 0);
		return;
	}

	total = buffer->getLength();

	/* XXX Get each physical segment of the buffer and zero it */
	while (done < total) {
		cur_len = 0;
		cur = buffer->getPhysicalSegment(done, &cur_len);
		if (cur == 0) break;
		if (cur_len != 0) bzero_phys(cur, cur_len);
		done += cur_len;
		ASSERT3U(done, <=, total);
	}
	ASSERT3U(done, ==, total);

	//if (!completion || !completion->action) {
	if (!completion) {
		dprintf("ZFSDataset %s invalid completion\n", __func__);
		return;
	}

//	(completion->action)(completion->target, completion->parameter,
//	    kIOReturnSuccess, total);
	complete(completion, kIOReturnSuccess, total);
}

void
ZFSDataset::write(IOService *client,
    UInt64 byteStart, IOMemoryDescriptor *buffer,
    IOStorageAttributes *attributes,
    IOStorageCompletion *completion)
{
	IOByteCount total;
	DLOGFUNC();

	if (!buffer) {
		if (completion) complete(completion, kIOReturnInvalid);
		return;
	}

	total = buffer->getLength();

	//if (!completion || !completion->action) {
	if (!completion) {
		dprintf("ZFSDataset %s invalid completion\n", __func__);
		return;
	}

	/* XXX No-op, just return success */
//	(completion->action)(completion->target, completion->parameter,
//	    kIOReturnSuccess, total);
	complete(completion, kIOReturnSuccess, total);
}

volatile SInt64 num_sync = 0;

IOReturn
ZFSDataset::synchronize(IOService *client,
    UInt64 byteStart, UInt64 byteCount,
    IOStorageSynchronizeOptions options)
{
	SInt64 cur_sync = 0;
	DLOGFUNC();
	cur_sync = OSIncrementAtomic64(&num_sync);
	dprintf("sync called %lld times\n", cur_sync);

	/* XXX Needs to report success for mount_common() */
	return (kIOReturnSuccess);
	//return (kIOReturnUnsupported);
	//return (super::synchronize(client, byteStart, byteCount, options));
}

IOReturn
ZFSDataset::unmap(IOService *client,
    IOStorageExtent *extents, UInt32 extentsCount,
    IOStorageUnmapOptions options)
{
	DLOGFUNC();
	return (kIOReturnUnsupported);
	//return (super::unmap(client, extents, extentsCount, options));
}

IOStorage *
ZFSDataset::copyPhysicalExtent(IOService *client,
    UInt64 *byteStart, UInt64 *byteCount)
{
	DLOGFUNC();
	return (0);
	//return (super::copyPhysicalExtent(client, byteStart, byteCount));
}

void
ZFSDataset::unlockPhysicalExtents(IOService *client)
{
	DLOGFUNC();
	//super::unlockPhysicalExtents(client);
}

IOReturn
ZFSDataset::setPriority(IOService *client,
    IOStorageExtent *extents, UInt32 extentsCount,
    IOStoragePriority priority)
{
	DLOGFUNC();
	return (kIOReturnUnsupported);
	//return (super::setPriority(client, extents, extentsCount, priority));
}

UInt64
ZFSDataset::getPreferredBlockSize() const
{
	DLOGFUNC();
	//return (DEV_BSIZE);
	return (super::getPreferredBlockSize());
}

UInt64
ZFSDataset::getSize() const
{
	DLOGFUNC();
	return (super::getSize());
}

UInt64
ZFSDataset::getBase() const
{
	DLOGFUNC();
	return (super::getBase());
}

bool
ZFSDataset::isEjectable() const
{
	DLOGFUNC();
	return (super::isEjectable());
}

bool
ZFSDataset::isFormatted() const
{
	DLOGFUNC();
	return (super::isFormatted());
}

bool
ZFSDataset::isWhole() const
{
	DLOGFUNC();
	return (super::isWhole());
}

bool
ZFSDataset::isWritable() const
{
	DLOGFUNC();
	return (super::isWritable());
}

const char *
ZFSDataset::getContent() const
{
	DLOGFUNC();
	return (super::getContent());
}

const char *
ZFSDataset::getContentHint() const
{
	DLOGFUNC();
	return (super::getContentHint());
}

IOMediaAttributeMask
ZFSDataset::getAttributes() const
{
	DLOGFUNC();
	return (super::getAttributes());
}
#endif


bool
ZFSDataset::setDatasetName(const char *name)
{
	char *newname;
	size_t len;

	if (!name || name[0] == '\0') {
		dprintf("%s missing name\n", __func__);
		return (false);
	}

	/* Length of IOMedia name plus null terminator */
	len = (strlen(kZFSIOMediaPrefix) + strlen(name) +
	    strlen(kZFSIOMediaSuffix) + 1);
	//len = strlen("ZFS ") + strlen(name) + strlen(" Media") + 1;

	newname = (char *)kmem_alloc(len, KM_SLEEP);
	if (!newname) {
		dprintf("%s alloc failed\n", __func__);
		return (false);
	}

	bzero(newname, len);
	snprintf(newname, len, "%s%s%s", kZFSIOMediaPrefix,
	    name, kZFSIOMediaSuffix);
	if (strlen(newname) < 1) {
		dprintf("%s invalid newname for %s\n", __func__, name);
		IOSleep(1000);
		kmem_free(newname, len);
		return (false);
	}
	setName(newname);

	setProperty(kZFSDatasetNameKey, name);

	kmem_free(newname, len);

	return (true);
}







IOReturn
ZFSDataset::doAsyncReadWrite(
    IOMemoryDescriptor *buffer, UInt64 block, UInt64 nblks,
    IOStorageAttributes *attributes, IOStorageCompletion *completion)
{
	IODirection direction;
	IOByteCount actualByteCount = block * nblks;

	// Return errors for incoming I/O if we have been terminated.
	if (isInactive() == true) {
		dprintf("asyncReadWrite notActive fail\n");
		return (kIOReturnNotAttached);
	}

#if 0
	// These variables are set in zvol_first_open(), which should have been
	// called already.
	if (!zv->zv_objset || !zv->zv_dbuf) {
		dprintf("asyncReadWrite no objset nor dbuf\n");
		return (kIOReturnNotAttached);
	}

	// Ensure the start block is within the disk capacity.
	if ((block)*(ZVOL_BSIZE) >= zv->zv_volsize) {
		dprintf("asyncReadWrite start block outside volume\n");
		return (kIOReturnBadArgument);
	}

	// Shorten the read, if beyond the end
	if (((block + nblks)*(ZVOL_BSIZE)) > zv->zv_volsize) {
		dprintf("asyncReadWrite block shortening needed\n");
		return (kIOReturnBadArgument);
	}
#endif

	// Get the buffer direction, whether this is a read or a write.
	direction = buffer->getDirection();
	if ((direction != kIODirectionIn) && (direction != kIODirectionOut)) {
		dprintf("asyncReadWrite kooky direction\n");
		return (kIOReturnBadArgument);
	}

	retain();

	if (direction == kIODirectionIn) {

//		if (zvol_read_iokit(zv, (block*(ZVOL_BSIZE)),
//		    actualByteCount, &iomem)) {
//
//			actualByteCount = 0;
//		}

	} else {

//		if (zvol_write_iokit(zv, (block*(ZVOL_BSIZE)),
//		    actualByteCount, &iomem)) {
//			actualByteCount = 0;
//		}

	}

	release();


	// Call the completion function.
	(completion->action)(completion->target, completion->parameter,
	    kIOReturnSuccess, actualByteCount);
	return (kIOReturnSuccess);
}

UInt32
ZFSDataset::doGetFormatCapacities(UInt64* capacities,
    UInt32 capacitiesMaxCount) const
{
	dprintf("formatCap\n");

	/*
	 * Ensure that the array is sufficient to hold all our formats
	 * (we require one element).
	 */
	if ((capacities != NULL) && (capacitiesMaxCount < 1))
		return (0);
		/* Error, return an array size of 0. */

	/*
	 * The caller may provide a NULL array if it wishes to query the number
	 * of formats that we support.
	 */
//	if (capacities != NULL)
//		capacities[0] = zv->zv_volsize;

//	dprintf("returning capacity[0] size %llu\n", zv->zv_volsize);

	return (1);
}

char *
ZFSDataset::getProductString(void)
{
	//dprintf("getProduct %p\n", zv);

	//if (zv) return (zv->zv_name);

	return ((char *)"ZFSDataset");
}

IOReturn
ZFSDataset::reportBlockSize(UInt64 *blockSize)
{
	dprintf("reportBlockSize %llu\n", *blockSize);

	if (blockSize) *blockSize = 512;

	return (kIOReturnSuccess);
}

IOReturn
ZFSDataset::reportMaxValidBlock(UInt64 *maxBlock)
{
	dprintf("reportMaxValidBlock %llu\n", *maxBlock);

//if (maxBlock) *maxBlock = ((zv->zv_volsize / (ZVOL_BSIZE)) - 1);

	return (kIOReturnSuccess);
}

IOReturn
ZFSDataset::reportMediaState(bool *mediaPresent,
    bool *changedState)
{
	dprintf("reportMediaState\n");
	if (mediaPresent) *mediaPresent = true;
	if (changedState) *changedState = false;
	return (kIOReturnSuccess);
}

IOReturn
ZFSDataset::reportPollRequirements(bool *pollRequired,
    bool *pollIsExpensive)
{
	dprintf("reportPollReq\n");
	if (pollRequired) *pollRequired = false;
	if (pollIsExpensive) *pollIsExpensive = false;
	return (kIOReturnSuccess);
}

IOReturn
ZFSDataset::reportRemovability(bool *isRemovable)
{
	dprintf("reportRemova\n");
	if (isRemovable) *isRemovable = false;
	return (kIOReturnSuccess);
}

IOReturn
ZFSDataset::doEjectMedia(void)
{
	dprintf("ejectMedia\n");
	// this->m_provider->doEjectMedia(this);
	//this->m_provider->doEjectMedia(zv);
/* XXX */
	// Only 10.6 needs special work to eject
	//if ((version_major == 10) && (version_minor == 8))
	//	destroyBlockStorageDevice(zvol);
	//}

	return (kIOReturnSuccess);
}

IOReturn
ZFSDataset::doFormatMedia(UInt64 byteCapacity)
{
	dprintf("doFormat\n");
	return (kIOReturnSuccess);
}

IOReturn
ZFSDataset::doLockUnlockMedia(bool doLock)
{
	dprintf("doLockUnlock\n");
	return (kIOReturnSuccess);
}

IOReturn
ZFSDataset::doSynchronizeCache(void)
{
	dprintf("doSync\n");
	return (kIOReturnSuccess);
}

char *
ZFSDataset::getVendorString(void)
{
	dprintf("getVendor\n");
	return ((char *)"ZFS Dataset");
}

char *
ZFSDataset::getRevisionString(void)
{
	dprintf("getRevision\n");
	return ((char *)ZFS_META_VERSION);
}

char *
ZFSDataset::getAdditionalDeviceInfoString(void)
{
	dprintf("getAdditional\n");
	return ((char *)"ZFS dataset");
}

IOReturn
ZFSDataset::reportEjectability(bool *isEjectable)
{
	dprintf("reportEjecta\n");
	/*
	 * Which do we prefer? If you eject it, you can't get volume back until
	 * you import it again.
	 */

	if (isEjectable) *isEjectable = false;
	return (kIOReturnSuccess);
}

/* XXX deprecated function */
IOReturn
ZFSDataset::reportLockability(bool *isLockable)
{
	dprintf("reportLocka\n");
	if (isLockable) *isLockable = true;
	return (kIOReturnSuccess);
}

IOReturn
ZFSDataset::reportWriteProtection(bool *isWriteProtected)
{
	dprintf("reportWritePro: %d\n", *isWriteProtected);

	if (!isWriteProtected) return (kIOReturnSuccess);

	*isWriteProtected = false;

	return (kIOReturnSuccess);
}

IOReturn
ZFSDataset::getWriteCacheState(bool *enabled)
{
	dprintf("getCacheState\n");
	if (enabled) *enabled = true;
	return (kIOReturnSuccess);
}

IOReturn
ZFSDataset::setWriteCacheState(bool enabled)
{
	dprintf("setWriteCache\n");
	return (kIOReturnSuccess);
}
