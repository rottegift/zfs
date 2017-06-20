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

#ifndef ZFSDATASET_H_INCLUDED
#define	ZFSDATASET_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * inout buffer should be set to the bsd name when called, and
 * will be set to the osname on success
 */
int zfs_dataset_proxy_get_osname(const char *in, char *out, int len);

int spa_iokit_dataset_proxy_create(const char *osname, char *, int);
int spa_iokit_dataset_proxy_destroy(char *osname);


#ifdef __cplusplus
} /* extern "C" */

#include <IOKit/storage/IOMedia.h>
#include <IOKit/storage/IOBlockStorageDevice.h>

/* XXX Should be UUID */
#define	kZFSContentHint		"zfs_dataset_proxy"

#define	kZFSIOMediaPrefix	"ZFS "
#define	kZFSIOMediaSuffix	" Media"
#define	kZFSDatasetNameKey	"ZFS Dataset"

class ZFSDataset : public IOBlockStorageDevice
{
	OSDeclareDefaultStructors(ZFSDataset)
public:
#if 0
	/* XXX Only for debug tracing */
	virtual bool open(IOService *client,
	    IOOptionBits options, IOStorageAccess access = 0);
	virtual bool isOpen(const IOService *forClient = 0) const;
	virtual void close(IOService *client,
	    IOOptionBits options);

	virtual bool handleOpen(IOService *client,
	    IOOptionBits options, void *access);
	virtual bool handleIsOpen(const IOService *client) const;
	virtual void handleClose(IOService *client,
	    IOOptionBits options);
#endif

	virtual bool attach(IOService *provider);
	virtual void detach(IOService *provider);

	virtual bool start(IOService *provider);
	virtual void stop(IOService *provider);

	virtual bool init(OSDictionary *properties);
	virtual void free();

	static ZFSDataset * withDatasetName(const char *name);

	virtual IOReturn doEjectMedia(void);
	virtual IOReturn doFormatMedia(UInt64 byteCapacity);
	virtual UInt32 doGetFormatCapacities(UInt64 * capacities,
		UInt32 capacitiesMaxCount) const;
	virtual char *getVendorString(void);
	virtual char *getProductString(void);
	virtual char *getRevisionString(void);
	virtual char *getAdditionalDeviceInfoString(void);
	virtual IOReturn reportBlockSize(UInt64 *blockSize);
	virtual IOReturn reportEjectability(bool *isEjectable);
	virtual IOReturn reportLockability(bool *isLockable);
	virtual IOReturn reportMaxValidBlock(UInt64 *maxBlock);
	virtual IOReturn reportMediaState(bool *mediaPresent,
		bool *changedState);
	virtual IOReturn reportRemovability(bool *isRemovable);
	virtual IOReturn reportWriteProtection(bool *isWriteProtected);
	virtual IOReturn doAsyncReadWrite(IOMemoryDescriptor *buffer,
		UInt64 block, UInt64 nblks,
		IOStorageAttributes *attributes,
		IOStorageCompletion *completion);
	virtual IOReturn reportPollRequirements(bool *pollRequired,
		bool *pollIsExpensive);
	virtual IOReturn doLockUnlockMedia(bool doLock);
	virtual IOReturn doSynchronizeCache(void);
	virtual IOReturn getWriteCacheState(bool *enabled);
	virtual IOReturn setWriteCacheState(bool enabled);

protected:
private:
	bool setDatasetName(const char *);


};

#endif /* __cplusplus */

#endif /* ZFSDATASET_H_INCLUDED */
