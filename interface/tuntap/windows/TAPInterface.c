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
	uv_write_t write_req;
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

// TODO
static void alloc_cb(uv_handle_t* handle,
                       size_t suggested_size,
                       uv_buf_t* buf) {
  //printf("echo_alloc\n");
  buf->base = (char*) malloc(suggested_size);
  buf->len = suggested_size;
}

// new postRead()
static void uv_device_queue_read(struct TAPInterface_pvt* tap) {
  printf("*** %s START\n" , __FUNCTION__);
  
  uv_read_t* req;
  BOOL r;
  DWORD err;
  uv_device_t* handle = &tap->device;
  struct Allocator* alloc = Allocator_child(tap->alloc);
  struct Message* msg = tap->readMsg = Message_new(1534, 514, alloc);

  // XXXXXX assert?
  printf("Handle flags: ");
  int i;
  int flag_tmp = handle->flags;
  for (i=0; i<8*sizeof(handle->flags); ++i) { printf("%d", flag_tmp%2); flag_tmp /= 2; }
  printf("\n");
  
  /*assert(handle->flags & UV_HANDLE_READING);
  assert(!(handle->flags & UV_HANDLE_READ_PENDING));
  assert(handle->handle && handle->handle != INVALID_HANDLE_VALUE);*/

  req = &handle->read_req;
  memset(&req->u.io.overlapped, 0, sizeof(req->u.io.overlapped));
  handle->alloc_cb((uv_handle_t*) handle, 1534, &handle->read_buffer);
  assert( ! (handle->read_buffer.len == 0) );
  /*if (handle->read_buffer.len == 0) {
    printf("*** %s XXX !!! read_buffer.len == 0 *** \n" , __FUNCTION__);
    handle->read_cb((uv_stream_t*) handle, UV_ENOBUFS, &handle->read_buffer);
    return;
  }*/
  	//printf("uv devicequeue read ReadFile\n");
	//printf("handle: %lu  ", (unsigned long)handle->handle);
	//printf("bytes: %d  ", handle->read_buffer.base);
	//printf("msg len: %d\n", handle->read_buffer.len);
	
//memset(handle->read_buffer.base, 0, handle->read_buffer.len);
  /*r = ReadFile(handle->handle,
               handle->read_buffer.base,
               handle->read_buffer.len,
               NULL,
               &req->u.io.overlapped);*/
			   
	DWORD bytes_read = 0;
    r =  ReadFile(handle->handle, msg->bytes, 1534, &bytes_read,  &req->u.io.overlapped);
	printf("%s uv_device_queue_read ReadFile() r = %d ; read_buffer.len = %d ; bytes_read = %d \n", 
	  __FUNCTION__ , 
	  r , handle->read_buffer.len , (bytes_read) ); // TODO(rfree) check %d here
	
	//printf("uv_device_queue_read read_buffer.len = %d\n", handle->read_buffer.len);
	if (!r) {
		switch (GetLastError()) {
            case ERROR_IO_PENDING:
            case ERROR_IO_INCOMPLETE: break;
            default: Assert_failure("ReadFile(uv_device_queue_read): %s\n", WinFail_strerror(GetLastError()));
        }
	}
	
//  if (r) {
    //handle->flags |= UV_HANDLE_READ_PENDING;
//    handle->reqs_pending++;
    //uv_insert_pending_req(tap->device.loop, (uv_req_t*) req);
//  } else {
//    err = GetLastError();
//    if (r == 0 && err == ERROR_IO_PENDING) {
      /* The req will be processed with IOCP. */
      //handle->flags |= UV_HANDLE_READ_PENDING;
//      handle->reqs_pending++;
//    } else {
      /* Make this req pending reporting an error. */
      //SET_REQ_ERROR(req, err);
      //uv_insert_pending_req(tap->device.loop, (uv_req_t*) req);
//      handle->reqs_pending++;
//    }
//  }
	//printf("uv_device_queue_read buff\n");
	//for (int i = 0; i < 100; ++i)
		////printf("%c", handle->read_buffer.base[i]);
	//printf("\n");
	
}

static void readCallbackB(struct TAPInterface_pvt* tap, ssize_t nread);
static void readCallback(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf);



static void postRead(struct TAPInterface_pvt* tap)
{
	printf("** postRead\n");
    struct Allocator* alloc = Allocator_child(tap->alloc);
    // Choose odd numbers so that the message will be aligned despite the weird header size.
    //struct Message* msg = tap->readMsg = Message_new(1534, 514, alloc);
    OVERLAPPED* readol = &tap->read_overlapped;
	memset(readol, 0, sizeof(OVERLAPPED));
	
	printf("post read read file, handle: %lu\n", (unsigned long)tap->device.handle);
	//printf("bytes: %d  ", msg->bytes);
	//printf("msg len: %d  \n", 1534);
	
    /*if (!ReadFile(tap->device.handle, msg->bytes, 1534, NULL, readol)) {
        switch (GetLastError()) {
            case ERROR_IO_PENDING:
            case ERROR_IO_INCOMPLETE: break;
            default: Assert_failure("ReadFile(tap): %s\n", WinFail_strerror(GetLastError()));
        }
    } else {
        // It doesn't matter if it returns immediately, it will also return async.
        //Log_debug(tap->log, "Read returned immediately");
    }*/
    
	Log_debug(tap->log, "Posted read");
	uv_device_queue_read(tap);
	
    //tap->readMsg->bytes = tap->device.read_buffer.base;
    //tap->readMsg->length = tap->device.read_buffer.len;
	/*memcpy(tap->device.read_buffer.base, msg->bytes, 1534);
	tap->device.read_buffer.len = 1534;*/
}

static void writeCallbackB(struct TAPInterface_pvt* tap);
static void writeCallback(uv_write_t* req, int status);
static Iface_DEFUN sendMessage(struct Message* msg, struct Iface* iface);
static void postWrite(struct TAPInterface_pvt* tap);

static void readCallbackB(struct TAPInterface_pvt* tap, ssize_t nread)
{
	printf("*** %s\n", __FUNCTION__);
	assert(tap);
	assert(tap->readMsg);
    struct Message* msg = tap->readMsg;
    tap->readMsg = NULL;
    DWORD bytesRead = nread; // TODO rm bytesRead
    OVERLAPPED* readol = &tap->read_overlapped;

	//printf("bytesRead: %d\n", bytesRead);
	//printf("write_queue_size = %d\n", tap->device.write_queue_size);
    msg->length = bytesRead;
    printf("%s Read [%d] bytes\n", __FUNCTION__, msg->length);
	//printf("writeMessageCount = %d\n", tap->writeMessageCount);
	//printf("send message to iface %s\n", tap->pub.assignedName);
	
	
    Iface_send(&tap->pub.generic, msg); // call sendMessage()
	/*int uv_device_write(uv_loop_t* loop,
                    uv_write_t* req,
                    uv_device_t* handle,
                    const uv_buf_t bufs[],
                    unsigned int nbufs,
                    uv_write_cb cb)*/
	//uv_buf_t buff = uv_buf_init(msg->bytes, msg->length);
	//printf("uv_device_write\n");
	//uv_device_write(tap->device.loop, tap->write_req, (uv_stream_t*)&tap->device, &buff, 1, writeCallback); // TODO post write?
    Allocator_free(msg->alloc);
	//printf("readCallbackB: uv_read_start\n");
	postRead(tap);
	//printf("end of readCallbackB\n");
}

static void readCallback(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf)
{
	//printf("readCallback\n");
	struct TAPInterface_pvt* tap =
		Identity_check((struct TAPInterface_pvt*)
			(((char*)handle) - offsetof(struct TAPInterface_pvt, device)));
	readCallbackB(tap, nread);
}
/*int uv_device_write(uv_loop_t* loop,
                    uv_write_t* req,
                    uv_device_t* handle,
                    const uv_buf_t bufs[],
                    unsigned int nbufs,
                    uv_write_cb cb);*/
					
static void postWrite(struct TAPInterface_pvt* tap)
{
	//printf("post postWrite\n");
	//printf("writeMessageCount = %d\n", tap->writeMessageCount);
    Assert_true(!tap->isPendingWrite);
	//printf("uv_loop_alive: %d\n", uv_loop_alive(tap->device.loop));
    tap->isPendingWrite = 1;
    struct Message* msg = tap->writeMsgs[0];
	uv_buf_t msg_buff = uv_buf_init(msg->bytes, msg->length);
	//printf("write msg len = %d\n", msg_buff.len);
	//for (int i = 0; i < msg_buff.len; ++i)
	//	//printf("%c", msg_buff.base[i]);
	//printf("\n");
	//uv_write(&tap->write_req, &tap->device, &msg_buff, 1, writeCallback);
	OVERLAPPED* writeol = &tap->write_overlapped;
	//uv_device_write(tap->device.loop, tap->write_req, (uv_stream_t*)&tap->device, &msg_buff, 1, writeCallback);
	uv_device_write(tap->device.loop, (uv_write_t*)&tap->write_req, &tap->device, &msg_buff, 1, writeCallback);
	//uv_write((uv_write_t*)&tap->write_req, &tap->device, &msg_buff, 1, writeCallback);
    /*OVERLAPPED* writeol = &tap->write_overlapped;*/
	//printf("write %d bytes\n", msg->bytes);
	//printf("write %d bytes\n", msg->bytes);
	//printf("write %d bytes\n", msg->bytes);
    /*if (!WriteFile(tap->device.handle, msg->bytes, msg->length, NULL, writeol)) {
        switch (GetLastError()) {
            case ERROR_IO_PENDING:
            case ERROR_IO_INCOMPLETE: break;
            default: Assert_failure("WriteFile(tap): %s\n", WinFail_strerror(GetLastError()));
        }
    } else {
        // It doesn't matter if it returns immediately, it will also return async.
        //Log_debug(tap->log, "Write returned immediately");
    }*/
    Log_debug(tap->log, "Posted write [%d] bytes", msg->length);
	//printf("end of post write\n");
}

static void writeCallbackB(struct TAPInterface_pvt* tap)
{
	//printf("writeCallbackB\n");
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
        //Log_info(tap->log, "Message of length [%d] truncated to [%d]",
        //         msg->length, (int)bytesWritten);
		//printf("Message of length [%d] truncated to [%d]",
        //         msg->length, (int)bytesWritten);
        Assert_true(msg->length > (int)bytesWritten);
    }

    //printf("tap->writeMessageCount: %d\n", tap->writeMessageCount);
    if (tap->writeMessageCount) {
        //printf("rotate write messages!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        for (int i = 0; i < tap->writeMessageCount; i++) {
            tap->writeMsgs[i] = tap->writeMsgs[i+1];
        }
		//printf("writeCallbackB: postWrite\n");
        postWrite(tap);
    } else {
        Log_debug(tap->log, "All pending writes are complete");
        Allocator_free(tap->pendingWritesAlloc);
        tap->pendingWritesAlloc = NULL;
    }

	//printf("writeCallbackB end\n");
}

static void writeCallback(uv_write_t* req, int status)
{
	//printf("writeCallback\n");
	//assert(0);
    struct TAPInterface_pvt* tap =
        Identity_check((struct TAPInterface_pvt*)
            (((char*)req->handle) - offsetof(struct TAPInterface_pvt, device)));
    writeCallbackB(tap);
}

static Iface_DEFUN sendMessage(struct Message* msg, struct Iface* iface)
{
	//printf("!!!!!!send sendMessage\n");
    struct TAPInterface_pvt* tap = Identity_check((struct TAPInterface_pvt*) iface);
	//printf("tap->writeMessageCount: %d\n", tap->writeMessageCount);
    if (tap->writeMessageCount >= WRITE_MESSAGE_SLOTS) {
        Log_info(tap->log, "DROP message because the tap is lagging");
		//printf("DROP message because the tap is lagging\n");
        return 0;
    }
    if (!tap->pendingWritesAlloc) {
        tap->pendingWritesAlloc = Allocator_child(tap->alloc);
    }
    tap->writeMsgs[tap->writeMessageCount++] = msg;
    Allocator_adopt(tap->pendingWritesAlloc, msg->alloc);
    if (tap->writeMessageCount == 1) {
		//printf("send sendMessage: postWrite\n");
        postWrite(tap);
    }
    else if (tap->writeMessageCount > 1)
    {
        //printf("tap->writeMessageCount\n");
        //postWrite(tap);
    }
    return 0;
}

static int init_overlapped(uv_loop_t* loop, HANDLE fd) {
	NTSTATUS nt_status;
	IO_STATUS_BLOCK io_status;
	FILE_MODE_INFORMATION mode_info;
	//printf("Check if the handle was created with FILE_FLAG_OVERLAPPED.\n");
  /* Check if the handle was created with FILE_FLAG_OVERLAPPED. */
  //printf("pNtQueryInformationFile\n");
	/*nt_status = pNtQueryInformationFile(fd,
		&io_status,
		&mode_info,
		sizeof(mode_info),
		FileModeInformation);*/
	//printf("nt_status: %d\n", nt_status);
	 //if (nt_status != STATUS_SUCCESS) {
	 if (nt_status != 0) {
		return uv_translate_sys_error(GetLastError());
	}
	if (mode_info.Mode & FILE_SYNCHRONOUS_IO_ALERT ||
		mode_info.Mode & FILE_SYNCHRONOUS_IO_NONALERT) {
		/* Not overlapped. */
		return UV_EINVAL;
	} else {
	/* Try to associate with IOCP. */
		//printf("CreateIoCompletionPort\n");
		//if (!CreateIoCompletionPort(fd, loop->iocp, (ULONG_PTR)handle, 0)) {
		if (!CreateIoCompletionPort(fd, loop->iocp, (ULONG_PTR)fd, 2)) {
			if (ERROR_INVALID_PARAMETER == GetLastError()) {
			// Already associated.
			} else {
				return uv_translate_sys_error(GetLastError());
			}
		}
	}
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

	int r;
	
	
	
    struct TAPInterface_pvt* tap = Allocator_calloc(alloc, sizeof(struct TAPInterface_pvt), 1);
	// tap->device uv_device_t
	
    Identity_set(tap);
    tap->base = base;
    tap->alloc = alloc;
    tap->log = logger;
    tap->pub.assignedName = dev->name;
    tap->pub.generic.send = sendMessage;
	tap->writeMessageCount = 0;
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
	
	//printf("init_overlapped\n");
	//r = init_overlapped(ebp->loop, tap->device.handle);
	//printf("r = %d\n", r);
	
	printf("TAP-START: tap_device name: %s\n", dev->name);
	printf("TAP-START: tap_device path: %s\n", dev->path);
	//SetLastError(0);
	r = uv_device_init(ebp->loop, &tap->device, dev->path, O_RDWR);
	printf("TAP-START: GetLastError: %d\n", GetLastError());
	//ASSERT(r == 0);
	printf("r = %d\n", r);
	assert(r == 0);
	
	printf("TAP-START: tap->device.handle: %d\n", tap->device.handle);
	if (tap->device.handle == INVALID_HANDLE_VALUE) {
        WinFail_fail(eh, "CreateFile(tapDevice)", GetLastError());
		printf("INVALID_HANDLE_VALUE!!\n");
		
    }
	
	struct TAPInterface_Version_pvt ver = { .major = 0 };
    getVersion(tap->device.handle, &ver, eh);

	printf("TAP-START: setEnabled\n");
    setEnabled(tap->device.handle, 1, eh);

    printf("TAP-START: Opened TAP-Windows device [%s] version [%lu.%lu.%lu] at location [%s]\n",
             dev->name, ver.major, ver.minor, ver.debug, dev->path);

	printf("TAP-START: uv_read_start\n");
	r = uv_read_start((uv_stream_t *)&tap->device, alloc_cb, readCallback); // ZZZ
    assert(r == 0);

	printf("TAP-START: Do postRead once\n");
	// postRead(tap); // XXXXXX	
	{	
		printf("** postRead replacement \n");
		
		struct Allocator* alloc = Allocator_child(tap->alloc);    
		OVERLAPPED* readol = &tap->read_overlapped;
		memset(readol, 0, sizeof(OVERLAPPED));	
		printf("%s (REPLACEMENT) post read read file, handle: %lu\n", __FUNCTION__, (unsigned long)tap->device.handle);	
		uv_device_queue_read(tap); // <--- FIX THIS 
	}
		
	printf("TAP-START: ALL DONE in %s\n\n\n" , __FUNCTION__);
    return &tap->pub;
}



