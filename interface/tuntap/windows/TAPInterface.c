/* vim: set expandtab ts=4 sw=4: */
/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// TODO(cjd): this is nasty, we need a wrapper.
#include "util/events/libuv/UvWrapper.h"
#include "util/events/libuv/EventBase_pvt.h"

#include "exception/Except.h"
#include "exception/WinFail.h"
#include "memory/Allocator.h"
#include "interface/tuntap/windows/TAPInterface.h"
#include "interface/tuntap/windows/TAPDevice.h"
#include "util/events/EventBase.h"
#include "util/platform/netdev/NetDev.h"
#include "wire/Error.h"
#include "wire/Message.h"

#include <stdio.h>
#include <assert.h>
#include <windows.h>
#include <winternl.h>
#include <io.h>
#include <fcntl.h>

#define TAP_CONTROL_CODE(request,method) \
  CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE (8, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE (9, METHOD_BUFFERED)



struct TAPInterface_Version_pvt {
    unsigned long major;
    unsigned long minor;
    unsigned long debug;
};

static void getVersion(HANDLE tap, struct TAPInterface_Version_pvt* version, struct Except* eh)
{
    ULONG version_len;
    BOOL bret = DeviceIoControl(tap,
                                TAP_IOCTL_GET_VERSION,
                                version,
                                sizeof(struct TAPInterface_Version_pvt),
                                version,
                                sizeof(struct TAPInterface_Version_pvt),
                                &version_len,
                                NULL);
    if (!bret) {
        DWORD err = GetLastError();
        CloseHandle(tap);
        WinFail_fail(eh, "DeviceIoControl(TAP_IOCTL_GET_VERSION)", err);
    }
    if (version_len != sizeof(struct TAPInterface_Version_pvt)) {
        CloseHandle(tap);
        Except_throw(eh, "DeviceIoControl(TAP_IOCTL_GET_VERSION) out size [%d] expected [%d]",
                     (int)version_len, (int)sizeof(struct TAPInterface_Version_pvt));
    }
}

static void setEnabled(HANDLE tap, int status, struct Except* eh)
{
    unsigned long len = 0;

    BOOL bret = DeviceIoControl(tap, TAP_IOCTL_SET_MEDIA_STATUS,
                                &status, sizeof (status),
                                &status, sizeof (status), &len, NULL);
    if (!bret) {
        DWORD err = GetLastError();
        CloseHandle(tap);
        WinFail_fail(eh, "DeviceIoControl(TAP_IOCTL_SET_MEDIA_STATUS)", err);
    }
}

#define WRITE_MESSAGE_SLOTS 20
struct TAPInterface_pvt
{
    struct TAPInterface pub;

    //uv_iocp_t readIocp;
    struct Message* readMsg;
	uv_device_t device;
	OVERLAPPED read_overlapped;

    //uv_iocp_t writeIocp;
	uv_write_t* req;
    struct Message* writeMsgs[WRITE_MESSAGE_SLOTS];
    /** This allocator holds messages pending write in memory until they are complete. */
    struct Allocator* pendingWritesAlloc;
    int writeMessageCount;
	OVERLAPPED write_overlapped;

    int isPendingWrite;

    //HANDLE handle;

    struct Log* log;
    struct Allocator* alloc;

    struct EventBase* base;
    Identity
};


static void readCallbackB(struct TAPInterface_pvt* tap);

static void postRead(struct TAPInterface_pvt* tap)
{
	printf("postRead!!!!!!!!!!!!!!!!!\n");
    struct Allocator* alloc = Allocator_child(tap->alloc);
    // Choose odd numbers so that the message will be aligned despite the weird header size.
    struct Message* msg = tap->readMsg = Message_new(1534, 514, alloc);
    OVERLAPPED* readol = &tap->read_overlapped;
    if (!ReadFile(tap->device.handle, msg->bytes, 1534, NULL, readol)) {
        switch (GetLastError()) {
            case ERROR_IO_PENDING:
            case ERROR_IO_INCOMPLETE: break;
            default: Assert_failure("ReadFile(tap): %s\n", WinFail_strerror(GetLastError()));
        }
    } else {
        // It doesn't matter if it returns immediately, it will also return async.
        //Log_debug(tap->log, "Read returned immediately");
    }
    Log_debug(tap->log, "Posted read");
}

static void readCallbackB(struct TAPInterface_pvt* tap)
{
	printf("readCallbackB!!!!!!!!!!!!!!!!!\n");
    struct Message* msg = tap->readMsg;
    tap->readMsg = NULL;
    DWORD bytesRead;
    OVERLAPPED* readol = &tap->read_overlapped;
    if (!GetOverlappedResult(tap->device.handle, readol, &bytesRead, FALSE)) {
        Assert_failure("GetOverlappedResult(read, tap): %s\n", WinFail_strerror(GetLastError()));
    }
	printf("bytesRead: %d\n", bytesRead);
    msg->length = bytesRead;
    Log_debug(tap->log, "Read [%d] bytes", msg->length);
    Iface_send(&tap->pub.generic, msg);
    Allocator_free(msg->alloc);
    postRead(tap);
}

static void readCallback(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf)
{
	printf("readCallback!!!!!!!!!!!!!!!!!\n");
	struct TAPInterface_pvt* tap =
		Identity_check((struct TAPInterface_pvt*)
			(((char*)handle) - offsetof(struct TAPInterface_pvt, device)));
	readCallbackB(tap);
}

static void writeCallbackB(struct TAPInterface_pvt* tap);

static void postWrite(struct TAPInterface_pvt* tap)
{
	//write_req_t wr;
	//uv_write(&wr->req); // TODO
    Assert_true(!tap->isPendingWrite);
    tap->isPendingWrite = 1;
    struct Message* msg = tap->writeMsgs[0];
    OVERLAPPED* writeol = &tap->write_overlapped;
    if (!WriteFile(tap->device.handle, msg->bytes, msg->length, NULL, writeol)) {
        switch (GetLastError()) {
            case ERROR_IO_PENDING:
            case ERROR_IO_INCOMPLETE: break;
            default: Assert_failure("WriteFile(tap): %s\n", WinFail_strerror(GetLastError()));
        }
    } else {
        // It doesn't matter if it returns immediately, it will also return async.
        //Log_debug(tap->log, "Write returned immediately");
    }
    Log_debug(tap->log, "Posted write [%d] bytes", msg->length);
}

static void writeCallbackB(struct TAPInterface_pvt* tap)
{
    DWORD bytesWritten;
    OVERLAPPED* writeol = &tap->write_overlapped;
    if (!GetOverlappedResult(tap->device.handle, writeol, &bytesWritten, FALSE)) {
        Assert_failure("GetOverlappedResult(write, tap): %s\n", WinFail_strerror(GetLastError()));
    }

    Assert_true(tap->isPendingWrite);
    tap->isPendingWrite = 0;
    Assert_true(tap->writeMessageCount--);

    struct Message* msg = tap->writeMsgs[0];
    if (msg->length != (int)bytesWritten) {
        Log_info(tap->log, "Message of length [%d] truncated to [%d]",
                 msg->length, (int)bytesWritten);
        Assert_true(msg->length > (int)bytesWritten);
    }

    if (tap->writeMessageCount) {
        for (int i = 0; i < tap->writeMessageCount; i++) {
            tap->writeMsgs[i] = tap->writeMsgs[i+1];
        }
        postWrite(tap);
    } else {
        Log_debug(tap->log, "All pending writes are complete");
        Allocator_free(tap->pendingWritesAlloc);
        tap->pendingWritesAlloc = NULL;
    }
}

static void writeCallback(uv_write_t* req, int status)
{
    struct TAPInterface_pvt* tap =
        Identity_check((struct TAPInterface_pvt*)
            (((char*)req->handle) - offsetof(struct TAPInterface_pvt, device)));
    writeCallbackB(tap);
}

// TODO
static void alloc_cb(uv_handle_t* handle,
                       size_t suggested_size,
                       uv_buf_t* buf) {
  //printf("echo_alloc\n");
  buf->base = (char*) malloc(suggested_size);
  buf->len = suggested_size;
}

static Iface_DEFUN sendMessage(struct Message* msg, struct Iface* iface)
{
    struct TAPInterface_pvt* tap = Identity_check((struct TAPInterface_pvt*) iface);
    if (tap->writeMessageCount >= WRITE_MESSAGE_SLOTS) {
        Log_info(tap->log, "DROP message because the tap is lagging");
        return 0;
    }
    if (!tap->pendingWritesAlloc) {
        tap->pendingWritesAlloc = Allocator_child(tap->alloc);
    }
    tap->writeMsgs[tap->writeMessageCount++] = msg;
    Allocator_adopt(tap->pendingWritesAlloc, msg->alloc);
    if (tap->writeMessageCount == 1) {
        postWrite(tap);
    }
    return 0;
}

//static int init_overlapped(uv_loop_t* loop, HANDLE fd, uv_read_cb cb) {
//	NTSTATUS nt_status;
//	IO_STATUS_BLOCK io_status;
//	FILE_MODE_INFORMATION mode_information;
//	
//  /* Check if the handle was created with FILE_FLAG_OVERLAPPED. */
//	nt_status = pNtQueryInformationFile(fd,
//		&io_status,
//		&mode_info,
//		sizeof(mode_info),
//		FileModeInformation);
//		
//	 if (nt_status != STATUS_SUCCESS) {
//		return uv_translate_sys_error(GetLastError());
//	}
//	if (mode_info.Mode & FILE_SYNCHRONOUS_IO_ALERT ||
//		mode_info.Mode & FILE_SYNCHRONOUS_IO_NONALERT) {
//		/* Not overlapped. */
//		return UV_EINVAL;
//	} else {
//	/* Try to associate with IOCP. */
//		if (!CreateIoCompletionPort(fd, loop->iocp, (ULONG_PTR)handle, 0)) {
//			if (ERROR_INVALID_PARAMETER == GetLastError()) {
//			// Already associated.
//			} else {
//				return uv_translate_sys_error(GetLastError());
//			}
//		}
//	}
//}

struct TAPInterface* TAPInterface_new(const char* preferredName,
                                      struct Except* eh,
                                      struct Log* logger,
                                      struct EventBase* base,
                                      struct Allocator* alloc)
{
    Log_debug(logger, "Getting TAP-Windows device name");

    struct TAPDevice* dev = TAPDevice_find(preferredName, eh, alloc);

    NetDev_flushAddresses(dev->name, eh);

    Log_debug(logger, "Opening TAP-Windows device [%s] at location [%s]", dev->name, dev->path);

	int r;
	
    struct TAPInterface_pvt* tap = Allocator_calloc(alloc, sizeof(struct TAPInterface_pvt), 1);
    Identity_set(tap);
    tap->base = base;
    tap->alloc = alloc;
    tap->log = logger;
    tap->pub.assignedName = dev->name;
    tap->pub.generic.send = sendMessage;
	memset(&tap->read_overlapped, 0, sizeof(tap->read_overlapped));
	memset(&tap->write_overlapped, 0, sizeof(tap->write_overlapped));
	

    /*tap->handle = CreateFile(dev->path,
                             GENERIC_READ | GENERIC_WRITE,
                             0,
                             0,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                             0);
*/

    struct EventBase_pvt* ebp = EventBase_privatize(tap->base);
    /*int ret;
	
    if ((ret = uv_iocp_start(ebp->loop, &tap->readIocp, tap->handle, readCallback))) {
        Except_throw(eh, "uv_iocp_start(readIocp): %s", uv_strerror(ret));
    }
    if ((ret = uv_iocp_start(ebp->loop, &tap->writeIocp, tap->handle, writeCallback))) {
        Except_throw(eh, "uv_iocp_start(writeIocp): %s", uv_strerror(ret));
    }*/
	
	printf("tap_device name: %s\n", dev->name);
	printf("tap_device path: %s\n", dev->path);
	//SetLastError(0);
	r = uv_device_init(ebp->loop, &tap->device, dev->path, O_RDWR);
	printf("GetLastError: %d\n", GetLastError());
	//ASSERT(r == 0);
	printf("r = %d\n", r);
	assert(r == 0);
	
	printf("tap->device.handle: %d\n", tap->device.handle);
	if (tap->device.handle == INVALID_HANDLE_VALUE) {
        WinFail_fail(eh, "CreateFile(tapDevice)", GetLastError());
		printf("INVALID_HANDLE_VALUE!!\n");
		
    }
	
	struct TAPInterface_Version_pvt ver = { .major = 0 };
	printf("getVersion\n");
    getVersion(tap->device.handle, &ver, eh);

	printf("setEnabled\n");
    setEnabled(tap->device.handle, 1, eh);

    Log_info(logger, "Opened TAP-Windows device [%s] version [%lu.%lu.%lu] at location [%s]",
             dev->name, ver.major, ver.minor, ver.debug, dev->path);

	printf("uv_read_start\n");
	r = uv_read_start((uv_stream_t *)&tap->device, alloc_cb, readCallback);
    assert(r == 0);
    // begin listening.
    postRead(tap);

    return &tap->pub;
}



