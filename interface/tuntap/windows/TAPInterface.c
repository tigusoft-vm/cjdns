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
#include <windows.h>
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

    uv_device_t device;

    struct Message* readMsg;
    uv_write_t write_req;
    struct Message* writeMsgs[WRITE_MESSAGE_SLOTS];
    /** This allocator holds messages pending write in memory until they are complete. */
    struct Allocator* pendingWritesAlloc;
    int writeMessageCount;
    OVERLAPPED write_overlapped;

    int isPendingWrite;

    HANDLE handle;

    struct Log* log;
    struct Allocator* alloc;

    struct EventBase* base;
    Identity
};

static void alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    buf->base = (char*) malloc(suggested_size);
    buf->len = suggested_size;
}


static void readCallbackB(struct TAPInterface_pvt* tap);

static void postRead(struct TAPInterface_pvt* tap)
{
    uv_device_t* handle = &tap->device;
    uv_read_t* req = &handle->read_req;
    memset(&req->u.io.overlapped, 0, sizeof(req->u.io.overlapped));
    struct Allocator* alloc = Allocator_child(tap->alloc);
    // Choose odd numbers so that the message will be aligned despite the weird header size.
    struct Message* msg = tap->readMsg = Message_new(1534, 514, alloc);
    handle->alloc_cb((uv_handle_t*) handle, 1534, &handle->read_buffer); // XXX
    if (handle->read_buffer.len == 0) { // XXX
        handle->read_cb((uv_stream_t*) handle, UV_ENOBUFS, &handle->read_buffer);
        return;
    }

    if (!ReadFile(handle->handle, msg->bytes, 1534, NULL,  &req->u.io.overlapped)) {
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
    uv_device_t* handle = &tap->device;
    uv_read_t* req = &handle->read_req;
    struct Message* msg = tap->readMsg;
    tap->readMsg = NULL;
    DWORD bytesRead;
    OVERLAPPED* readol = (OVERLAPPED*) &req->u.io.overlapped;
    if (!GetOverlappedResult(tap->handle, readol, &bytesRead, FALSE)) {
        Assert_failure("GetOverlappedResult(read, tap): %s\n", WinFail_strerror(GetLastError()));
    }
    msg->length = bytesRead;
    Log_debug(tap->log, "Read [%d] bytes", msg->length);
    Iface_send(&tap->pub.generic, msg);
    Allocator_free(msg->alloc);
    postRead(tap);
}

static void readCallback(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf)
{
    struct TAPInterface_pvt* tap =
        Identity_check((struct TAPInterface_pvt*)
            (((char*)handle) - offsetof(struct TAPInterface_pvt, device)));
    readCallbackB(tap);
}

static void writeCallbackB(struct TAPInterface_pvt* tap);
static void writeCallback(uv_write_t* req, int status);

static void postWrite(struct TAPInterface_pvt* tap)
{
    Assert_true(!tap->isPendingWrite);
    tap->isPendingWrite = 1;
    struct Message* msg = tap->writeMsgs[0];
    uv_buf_t msg_buff = uv_buf_init(msg->bytes, msg->length);
    uv_write((uv_write_t*)&tap->write_req, (uv_stream_t*)&tap->device, &msg_buff, 1, writeCallback);
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

    struct TAPInterface_pvt* tap = Allocator_calloc(alloc, sizeof(struct TAPInterface_pvt), 1);
    Identity_set(tap);
    tap->base = base;
    tap->alloc = alloc;
    tap->log = logger;
    tap->pub.assignedName = dev->name;
    tap->pub.generic.send = sendMessage;
    tap->writeMessageCount = 0;
    memset(&tap->write_overlapped, 0, sizeof(tap->write_overlapped));

    struct EventBase_pvt* ebp = EventBase_privatize(tap->base);

    int ret = uv_device_init(ebp->loop, &tap->device, dev->path, O_RDWR);
    if (tap->handle == INVALID_HANDLE_VALUE) { // ???
        WinFail_fail(eh, "CreateFile(tapDevice)", GetLastError());
    }
    Assert_true(ret == 0);

    struct TAPInterface_Version_pvt ver = { .major = 0 };
    getVersion(tap->device.handle, &ver, eh);

    setEnabled(tap->device.handle, 1, eh);

    Log_info(logger, "Opened TAP-Windows device [%s] version [%lu.%lu.%lu] at location [%s]",
             dev->name, ver.major, ver.minor, ver.debug, dev->path);

    ret = uv_read_start((uv_stream_t *)&tap->device, alloc_cb, readCallback);
    Assert_true(ret == 0);
    // begin listening.
    postRead(tap);

    return &tap->pub;
}


