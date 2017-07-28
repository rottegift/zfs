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
 */

#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOService.h>
//#include <IOKit/IODeviceTreeSupport.h>
//#include <IOKit/IOPlatformExpert.h>
//#include <IOKit/storage/IOMedia.h>
#include <IOKit/IOMemoryDescriptor.h>

extern "C" {
#include <sys/spa_impl.h>
#include <sys/spa_boot.h>
#include <sys/spa.h>
} /* extern "C" */

#include <sys/ZFSPool.h>

#ifndef	dprintf
#if defined(DEBUG) || defined(ZFS_DEBUG)
#define	dprintf(fmt, ...) do {					\
	printf("%s " fmt, __func__, __VA_ARGS__);		\
_NOTE(CONSTCOND) } while (0)
#else
#define	dprintf(fmt, ...)	do { } while (0);
#endif /* if DEBUG or ZFS_DEBUG */
#endif /* ifndef dprintf */

/*
 * Returns handle to ZFS IOService, with a retain count.
 */
static IOService *
copy_zfs_handle()
{
	/* Get the ZFS service handle the 'hard way' */
	OSDictionary *matching;
	IOService *service = 0;

	matching = IOService::serviceMatching("net_lundman_zfs_zvol");
	if (matching) {
		service = IOService::copyMatchingService(matching);
		matching->release();
		matching = 0;
	}

	if (!service) {
		dprintf("%s couldn't get zfs IOService\n", __func__);
		return (NULL);
	}

	return (service);
#if 0
	/* Got service, make sure it casts */
	zfs_hl = OSDynamicCast(net_lundman_zfs_zvol, service);
	if (zfs_hl == NULL) {
		dprintf("%s couldn't get zfs_hl\n", __func__);
		/* Drop retain from copyMatchingService */
		service->release();
		return (NULL);
	}

	return (zfs_hl);
#endif
}

OSDefineMetaClassAndStructors(ZFSPool, IOStorage);

#if 0
bool
ZFSPool::open(IOService *client, IOOptionBits options, void *arg)
{
	bool ret;

	IOLog("ZFSPool %s\n", __func__);

	ret = IOService::open(client, options, arg);

	IOLog("ZFSPool %s ret %d\n", __func__, ret);

	return (ret);
}

bool
ZFSPool::isOpen(const IOService *forClient) const
{
	IOLog("ZFSPool %s\n", __func__);
	return (false);
}

void
ZFSPool::close(IOService *client, IOOptionBits options)
{
	IOLog("ZFSPool %s\n", __func__);
	IOService::close(client, options);
	return;
}
#endif

bool
ZFSPool::handleOpen(IOService *client,
    IOOptionBits options, void *access)
{
	bool ret = true;

	IOLog("ZFSPool %s\n", __func__);

	/* XXX IOService open() locks for arbitration around handleOpen */
	//lockForArbitration();
	if (_openClients->containsObject(client)) {
		dprintf("ZFSPool %s already open\n", __func__);
		ret = false;
	}
	if (_openClients->setObject(client) == false) {
		dprintf("ZFSPool %s already open\n", __func__);
		ret = false;
	}
	//unlockForArbitration();

	return (ret);
//	return (IOService::handleOpen(client, options, NULL));
}

bool
ZFSPool::handleIsOpen(const IOService *client) const
{
	bool ret;

	IOLog("ZFSPool %s\n", __func__);

	/* XXX IOService isOpen() locks for arbitration around handleIsOpen */
	//lockForArbitration();
	ret = _openClients->containsObject(client);
	//unlockForArbitration();

	return (ret);
//	return (IOService::handleIsOpen(client));
}

void
ZFSPool::handleClose(IOService *client,
    IOOptionBits options)
{
	IOLog("ZFSPool %s\n", __func__);

	/* XXX IOService close() locks for arbitration around handleClose */
	//lockForArbitration();
	if (_openClients->containsObject(client) == false) {
		dprintf("ZFSPool %s not open\n", __func__);
	}
	/* Remove client from set */
	_openClients->removeObject(client);
	//unlockForArbitration();

//	IOService::handleClose(client, options);
}

void
ZFSPool::read(IOService *client, UInt64 byteStart,
    IOMemoryDescriptor *buffer, IOStorageAttributes *attr,
    IOStorageCompletion *completion)
{
	IOLog("ZFSPool %s\n", __func__);
	complete(completion, kIOReturnError, 0);
}

void
ZFSPool::write(IOService *client, UInt64 byteStart,
    IOMemoryDescriptor *buffer, IOStorageAttributes *attr,
    IOStorageCompletion *completion)
{
	IOLog("ZFSPool %s\n", __func__);
	complete(completion, kIOReturnError, 0);
}

bool
ZFSPool::init(OSDictionary *options, spa_t *spa)
{
	/* Call superclass init */
	if (IOService::init(options) == false) {
		printf("ZFSPool IOService::init failed\n");
		return (false);
	}

	/* Need an OSSet for open clients */
	_openClients = OSSet::withCapacity(1);
	if (_openClients == NULL) {
		dprintf("ZFSPool init client OSSet failed\n");
		return (false);
	}

	/* Set spa pointer and this Pool object's name to match */
	_spa = spa;
	setName(spa_name(spa));

	return (true);
}

void
ZFSPool::free()
{
	OSSet *oldSet;

	if (_openClients) {
		oldSet = _openClients;
		_openClients = 0;
		oldSet->release();
		oldSet = 0;
	}
	_spa = 0;

	IOService::free();
}

extern "C" {

void
spa_iokit_pool_proxy_destroy(spa_t *spa)
{
	ZFSPool *proxy;
	IOService *provider;
	spa_iokit_t *wrapper;

	if (!spa) {
		printf("%s missing spa\n", __func__);
		return;
	}

	/* Get pool proxy */
	wrapper = spa->spa_iokit_proxy;
	spa->spa_iokit_proxy = NULL;

	if (wrapper == NULL) {
		printf("%s missing spa_iokit_proxy\n", __func__);
		return;
	}

	proxy = wrapper->proxy;

	/* Free the struct */
	kmem_free(wrapper, sizeof(spa_iokit_t));
	if (!proxy) {
		printf("%s missing proxy\n", __func__);
		return;
	}

	spa->spa_iokit_proxy = NULL;
	provider = proxy->getProvider();

	proxy->detach(provider);
	proxy->stop(provider);

	proxy->release();
}

int
spa_iokit_pool_proxy_create(spa_t *spa)
{
	IOService *zfs_hl;
	ZFSPool *proxy;
	spa_iokit_t *wrapper;

	if (!spa) {
		dprintf("%s missing spa\n", __func__);
		return (EINVAL);
	}

	/* Allocate C struct */
	if ((wrapper = (spa_iokit_t *)kmem_alloc(sizeof (spa_iokit_t),
	    KM_SLEEP)) == NULL) {
		dprintf("%s couldn't allocate wrapper\n", __func__);
		return (ENOMEM);
	}

	/* Get ZFS IOService */
	if ((zfs_hl = copy_zfs_handle()) == NULL) {
		dprintf("%s couldn't get ZFS handle\n", __func__);
		kmem_free(wrapper, sizeof (spa_iokit_t));
		return (ENODEV);
	}

	/* Allocate and init ZFS pool proxy */
	proxy = ZFSPool::withServiceAndPool(zfs_hl, spa);
	if (!proxy) {
		dprintf("%s Pool proxy creation failed\n", __func__);
		kmem_free(wrapper, sizeof (spa_iokit_t));
		zfs_hl->release();
		return (ENOMEM);
	}
	/* Drop retain from copy_zfs_handle */
	zfs_hl->release();

	/* Set pool proxy */
	wrapper->proxy = proxy;
	spa->spa_iokit_proxy = wrapper;

	return (0);
}

} /* extern "C" */

ZFSPool *
ZFSPool::withServiceAndPool(IOService *zfs_hl,
    spa_t *spa)
{
	ZFSPool *proxy = new ZFSPool;

	if (!proxy) {
		printf("%s allocation failed\n", __func__);
		return (0);
	}

	if (proxy->init(0, spa) == false ||
	    proxy->attach(zfs_hl) == false) {
		printf("%s init/attach failed\n", __func__);
		proxy->release();
		return (0);
	}

	if (proxy->start(zfs_hl) == false) {
		printf("%s start failed\n", __func__);
		proxy->detach(zfs_hl);
		proxy->release();
		return (0);
	}

	return (proxy);
}

#if defined (MAC_OS_X_VERSION_10_11) &&        \
	(MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_11)
#endif

IOReturn ZFSPool::synchronizeCache(IOService * client)
{
	return 0;
}
