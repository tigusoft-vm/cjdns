/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "uv.h"
#include "task.h"

#include "Sockaddr.h" // ../../util/platform/Sockaddr.h" // TODO(rfree)


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <unistd.h> // for fork()
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h> 
#include <assert.h>

#if defined (_WIN32) || defined (__CYGWIN__)
#define NETWORK_ADAPTER_GUID "{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define ADAPTER_KEY \
    "SYSTEM\\CurrentControlSet\\Control\\Class\\" NETWORK_ADAPTER_GUID

#define NETWORK_CONNECTIONS_KEY \
    "SYSTEM\\CurrentControlSet\\Control\\Network\\" NETWORK_ADAPTER_GUID

#define USERMODEDEVICEDIR "\\\\.\\Global\\"
#define TAPSUFFIX         ".tap"

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


#endif









// #include "util/platform/netdev/NetPlatform.h" // XXX ?
// #include "util/platform/Sockaddr.h" // XXX ?

#include <string.h>
#include <errno.h>
#include <stdio.h>

#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <stdlib.h>
#include <stddef.h>

#if !defined(__CYGWIN__) && !defined(_WIN32)
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if.h>
#endif

char mybuff[10];
//uv_buf_t rbuf = uv_buf_init(mybuff, sizeof(mybuff));
uv_device_t device, device_tap2;

int Sockaddr_AF_INET=2; // TODO(rfree) XXX work around for includes problems
int Sockaddr_AF_INET6=10; // TODO(rfree) XXX work around for includes problems
// from: build_linux/util_platform_Sockaddr_c.o.i TODO(rfree)


struct Except { int x; };
struct Log { int x; };

struct Log *logger;

void Except_throw(struct Except *eh, const char *msg, ...) {
	va_list args;
	va_start(args, msg);
	printf("Error: ");
	printf(msg, args);
	printf("\n");
	va_end(args);
}

void Log_info(struct Log *eh, const char *msg, ...) {
	va_list args;
	va_start(args, msg);
	printf(msg, args);
	printf("\n");
	va_end(args);
}



/**
 * This hack exists because linux/in.h and linux/in6.h define
 * the same structures, leading to redefinition errors.
 * For the second operand, we're grateful to android/bionic, platform level 21.
 */
#if !defined(_LINUX_IN6_H) && !defined(_UAPI_LINUX_IN6_H)
    struct in6_ifreq
    {
        struct in6_addr ifr6_addr;
        uint32_t ifr6_prefixlen;
        int ifr6_ifindex;
    };
#endif

/**
 * Get a socket and ifRequest for a given interface by name.
 *
 * @param interfaceName the name of the interface, eg: tun0
 * @param af either AF_INET or AF_INET6
 * @param eg an exception handler in case something goes wrong.
 *           this will send a -1 for all errors.
 * @param ifRequestOut an ifreq which will be populated with the interface index of the interface.
 * @return a socket for interacting with this interface.
 */
 
void uv_device_queue_read(uv_loop_t* loop, uv_device_t* handle);
 

void uv_device_queue_read(uv_loop_t* loop, uv_device_t* handle) {
	printf("uv_device_queue_read\n");
  uv_read_t* req;
  BOOL r;
  DWORD err;

  //assert(handle->flags & UV_HANDLE_READING);
  //assert(!(handle->flags & UV_HANDLE_READ_PENDING));
  //assert(handle->handle && handle->handle != INVALID_HANDLE_VALUE);

  req = &handle->read_req;
  memset(&req->u.io.overlapped, 0, sizeof(req->u.io.overlapped));
  handle->alloc_cb((uv_handle_t*) handle, 65536, &handle->read_buffer);
  if (handle->read_buffer.len == 0) {
    handle->read_cb((uv_stream_t*) handle, UV_ENOBUFS, &handle->read_buffer);
    return;
  }
//memset(handle->read_buffer.base, 0, handle->read_buffer.len);
  r = ReadFile(handle->handle,
               handle->read_buffer.base,
               handle->read_buffer.len,
               NULL,
               &req->u.io.overlapped);
	printf("uv_device_queue_read r = %d\n", r);
//  if (r) {
    //handle->flags |= UV_HANDLE_READ_PENDING;
//    handle->reqs_pending++;
    //uv_insert_pending_req(loop, (uv_req_t*) req);
//  } else {
//    err = GetLastError();
//    if (r == 0 && err == ERROR_IO_PENDING) {
      /* The req will be processed with IOCP. */
      //handle->flags |= UV_HANDLE_READ_PENDING;
//      handle->reqs_pending++;
//    } else {
      /* Make this req pending reporting an error. */
      //SET_REQ_ERROR(req, err);
      //uv_insert_pending_req(loop, (uv_req_t*) req);
//      handle->reqs_pending++;
//    }
//  }
	printf("uv_device_queue_read buff\n");
	//for (int i = 0; i < 100; ++i)
		//printf("%c", handle->read_buffer.base[i]);
	printf("\n");
	
}
#if defined __linux__ && !defined __CYGWIN__

static int socketForIfName(const char* interfaceName,
                           int af,
                           struct Except* eh,
                           struct ifreq* ifRequestOut)
{
    int s;
    printf("function %s for [%s] with af=%d \n", __FUNCTION__, interfaceName, af);

    if ((s = socket(af, SOCK_DGRAM, 0)) < 0) {
        Except_throw(eh, "socket() [%s]", strerror(errno));
    }

    memset(ifRequestOut, 0, sizeof(struct ifreq));
    strncpy(ifRequestOut->ifr_name, interfaceName, IFNAMSIZ);
    printf("Getting name of [%s] on socket s=%d\n", ifRequestOut->ifr_name, s);

    if (ioctl(s, SIOCGIFINDEX, ifRequestOut) < 0) {
        int err = errno;
        Except_throw(eh, "ioctl(SIOCGIFINDEX) [%s] %d", strerror(err), err);
        close(s);
    }
    return s;
}

static void checkInterfaceUp(int socket,
                             struct ifreq* ifRequest,
                             struct Log* logger,
                             struct Except* eh)
{
    if (ioctl(socket, SIOCGIFFLAGS, ifRequest) < 0) {
        int err = errno;
        close(socket);
        Except_throw(eh, "ioctl(SIOCGIFFLAGS) [%s]", strerror(err));
    }

    if (ifRequest->ifr_flags & IFF_UP & IFF_RUNNING) {
        // already up.
        return;
    }

    Log_info(logger, "Bringing up interface [%s]", ifRequest->ifr_name);

    ifRequest->ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(socket, SIOCSIFFLAGS, ifRequest) < 0) {
        int err = errno;
        close(socket);
        Except_throw(eh, "ioctl(SIOCSIFFLAGS) [%s]", strerror(err));
    }
}



void NetPlatform_addAddress(const char* interfaceName,
                            const uint8_t* address,
                            int prefixLen,
                            int addrFam,
                            struct Log* logger,
                            struct Except* eh)
{
    printf("\nFunction to add the address\n\n");

    struct ifreq ifRequest;
    int s = socketForIfName(interfaceName, addrFam, eh, &ifRequest);
    int ifIndex = ifRequest.ifr_ifindex;
    printf("ifIndex=%d after socketForIfName, s=%d\n" , ifIndex, s);

    // checkInterfaceUp() clobbers the ifindex.
    checkInterfaceUp(s, &ifRequest, logger, eh);
    printf("ifIndex=%d\n" , ifIndex);

    if (addrFam == Sockaddr_AF_INET6) {
        struct in6_ifreq ifr6 = {
            .ifr6_ifindex = ifIndex,
            .ifr6_prefixlen = prefixLen
        };
        memcpy(&ifr6.ifr6_addr, address, 16);

        if (ioctl(s, SIOCSIFADDR, &ifr6) < 0) {
            int err = errno;
            close(s);
            Except_throw(eh, "ioctl(SIOCSIFADDR) [%s]", strerror(err));
        }


    } else if (addrFam == Sockaddr_AF_INET) {
        struct sockaddr_in sin = { .sin_family = AF_INET, .sin_port = 0 };
        memcpy(&sin.sin_addr.s_addr, address, 4);
        memcpy(&ifRequest.ifr_addr, &sin, sizeof(struct sockaddr));

        if (ioctl(s, SIOCSIFADDR, &ifRequest) < 0) {
            int err = errno;
            close(s);
            Except_throw(eh, "ioctl(SIOCSIFADDR) failed: [%s]", strerror(err));
        }

        uint32_t x = ~0 << (32 - prefixLen);
//        x = Endian_hostToBigEndian32(x); // TODO(rfree)
        memcpy(&sin.sin_addr, &x, 4);
        memcpy(&ifRequest.ifr_addr, &sin, sizeof(struct sockaddr_in));

        if (ioctl(s, SIOCSIFNETMASK, &ifRequest) < 0) {
            int err = errno;
            close(s);
            Except_throw(eh, "ioctl(SIOCSIFNETMASK) failed: [%s]", strerror(err));
        }
    } else {

            Except_throw(eh, "Unknown socket type");
 //       Assert_true(0);
    }

    close(s);
}

void NetPlatform_setMTU(const char* interfaceName,
                        uint32_t mtu,
                        struct Log* logger,
                        struct Except* eh)
{
    struct ifreq ifRequest;
    int s = socketForIfName(interfaceName, AF_INET6, eh, &ifRequest);

    Log_info(logger, "Setting MTU for device [%s] to [%u] bytes.", interfaceName, mtu);

    ifRequest.ifr_mtu = mtu;
    if (ioctl(s, SIOCSIFMTU, &ifRequest) < 0) {
        int err = errno;
        close(s);
        Except_throw(eh, "ioctl(SIOCSIFMTU) [%s]", strerror(err));
    }

    close(s);
}
#endif 

#if 0

    struct ifreq ifRequest;

		// int s = socketForIfName(interfaceName, addrFam, eh, &ifRequest);

    checkInterfaceUp(fd, &ifRequest); // logger, eh);

    int ifIndex = ifRequest.ifr_ifindex; // XXX TODO bad - find the index

    // checkInterfaceUp() clobbers the ifindex.

    //if (addrFam == /*Sockaddr_*/AF_INET6) 
    
    {

//			in6_ifreq test_var; // test TODO(rfree) remove later
				in6_ifreq ifr6;
				ifr6.ifr6_ifindex = ifIndex; 
				ifr6.ifr6_prefixlen = prefixLen; 

 /*       struct in6_ifreq ifr6 = {
            .ifr6_ifindex = ifIndex,
            .ifr6_prefixlen = prefixLen
        };*/

				uint8_t address[16];
				for (int i=0; i<16; ++i) address[i] = i+100;
				address[0] = 0xFC;

        memcpy(&ifr6.ifr6_addr, address, 16);

        if (ioctl(fd, SIOCSIFADDR, &ifr6) < 0) { // ***
            int err = errno;
            printf("Error ioctl %d: [%s] in %d in %s\n", err, strerror(err), __LINE__, __FUNCTION__);
            return -1;
        }
        else printf("Ok - address\n");


    } 
    
    #if 0
    ipv4

    else if (addrFam == /*Sockaddr_*/AF_INET) {
        struct sockaddr_in sin = { .sin_family = AF_INET, .sin_port = 0 };
        memcpy(&sin.sin_addr.s_addr, address, 4);
        memcpy(&ifRequest.ifr_addr, &sin, sizeof(struct sockaddr));

        if (ioctl(fd, SIOCSIFADDR, &ifRequest) < 0) { // ***
            int err = errno;
            return -1;
            //Except_throw(eh, "ioctl(SIOCSIFADDR) failed: [%s]", strerror(err));
        }

        uint32_t x = ~0 << (32 - prefixLen);

        printf("NOT IMPLEMENTED in %d !!!\n", __LINE__);
//        x = Endian_hostToBigEndian32(x);  /// TODO(rfree)

        memcpy(&sin.sin_addr, &x, 4);
        memcpy(&ifRequest.ifr_addr, &sin, sizeof(struct sockaddr_in));

        if (ioctl(fd, SIOCSIFNETMASK, &ifRequest) < 0) { // ***
            int err = errno;
            return -1;
            //Except_throw(eh, "ioctl(SIOCSIFNETMASK) failed: [%s]", strerror(err));
        }
    } else {
    	printf("Error (unknwon network type) in line %lu \n", (unsigned long)__LINE__);
    }
    #endif

   //  close(fd);

   return 0; // ok
}


#endif










#if defined (_WIN32) || defined (__CYGWIN__)


static int is_tap_win32_dev(const char *guid) {
  HKEY netcard_key;
  LONG status;
  DWORD len;
  int i = 0;

  status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        ADAPTER_KEY,
                        0,
                        KEY_READ,
                        &netcard_key);

  if (status != ERROR_SUCCESS) 
    return FALSE;

  for (;;) {
    char enum_name[256];
    char unit_string[256];
    HKEY unit_key;
    char component_id_string[] = "ComponentId";
    char component_id[256];
    char net_cfg_instance_id_string[] = "NetCfgInstanceId";
    char net_cfg_instance_id[256];
    DWORD data_type;

    len = sizeof (enum_name);
    status = RegEnumKeyEx(netcard_key,
                          i,
                          enum_name,
                          &len,
                          NULL,
                          NULL,
                          NULL,
                          NULL);

    if (status == ERROR_NO_MORE_ITEMS) 
      break;
    else if (status != ERROR_SUCCESS) 
      return FALSE;

    _snprintf (unit_string, 
               sizeof(unit_string), 
               "%s\\%s",
                ADAPTER_KEY,
                enum_name);

    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                          unit_string,
                          0,
                          KEY_READ,
                          &unit_key);
	//printf("KEY_READ: %d\n", KEY_READ);
    if (status != ERROR_SUCCESS) 
      return FALSE;
    else {
      len = sizeof (component_id);
      status = RegQueryValueEx(unit_key,
                               component_id_string,
                               NULL,
                               &data_type,
                               (uint8_t*) component_id,
                               &len);
		//printf("component_id_string: %s\n", component_id_string);
      if (!(status != ERROR_SUCCESS || data_type != REG_SZ)) {
        len = sizeof (net_cfg_instance_id);
        status = RegQueryValueEx(unit_key,
                                 net_cfg_instance_id_string,
                                 NULL,
                                 &data_type,
                                 (uint8_t*) net_cfg_instance_id,
                                 &len);

        if (status == ERROR_SUCCESS && data_type == REG_SZ) {
          if (!memcmp(component_id, "tap", strlen("tap")) &&
              !strcmp (net_cfg_instance_id, guid)) {
              RegCloseKey (unit_key);
              RegCloseKey (netcard_key);
              return TRUE;
          }
        }
      }
      RegCloseKey (unit_key);
    }
    ++i;
  }

  RegCloseKey (netcard_key);
  return FALSE;
}

static int get_device_guid(char *name,
                           int name_size,
                           char *actual_name,
                           int actual_name_size) {
  LONG status;
  HKEY control_net_key;
  DWORD len;
  int stop = 0;
  int i;

  status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
                        NETWORK_CONNECTIONS_KEY, 
                        0, 
                        KEY_READ, 
                        &control_net_key);

  if (status != ERROR_SUCCESS)
    return status;

  for (i = 0; !stop; i++) {
    char enum_name[256];
    char connection_string[256];
    HKEY connKey;
    char name_data[256];
    DWORD name_type;
    const char name_string[] = "Name";

    len = sizeof (enum_name);
    status = RegEnumKeyEx(control_net_key, 
                          i, 
                          enum_name, 
                          &len, 
                          NULL, 
                          NULL, 
                          NULL, 
                          NULL);

    if (status == ERROR_NO_MORE_ITEMS) 
      break;
    else if (status != ERROR_SUCCESS) 
      break;

    if (len != strlen(NETWORK_ADAPTER_GUID))
      continue;

    _snprintf(connection_string,
              sizeof(connection_string),
              "%s\\%s\\Connection",
              NETWORK_CONNECTIONS_KEY,
              enum_name);
	
	printf("connection_string: %s\n", connection_string);
	
    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
                          connection_string,
                          0,
                          KEY_READ,
                          &connKey);

    if (status != ERROR_SUCCESS) 
      break;

	printf("name_string %s\n", name_string);
    len = sizeof (name_data);
    status = RegQueryValueEx(connKey,
                             name_string,
                             NULL,
                             &name_type,
                             (uint8_t*) name_data,
                             &len);

    if (status == ERROR_FILE_NOT_FOUND)
      continue;
    if (status != ERROR_SUCCESS)
      break;

    if (name_type != REG_SZ) {
      status = !ERROR_SUCCESS;
      return status;
    }
	printf("enum_name: %s\n", enum_name);
    if (is_tap_win32_dev(enum_name)) {
      _snprintf(name, name_size, "%s", enum_name);
      if (actual_name) {
        if (strcmp(actual_name, "") != 0) {
          if (strcmp(name_data, actual_name) != 0) {
            RegCloseKey (connKey);
            ++i;
            continue;
          }
        }
        else {
          _snprintf(actual_name, actual_name_size, "%s", name_data);
        }
      }

      stop = 1;
    }

    RegCloseKey(connKey);
  }

  RegCloseKey (control_net_key);

  if (stop == 0)
    return -1;

  return 0;
}

void evevnt_cb(uv_fs_event_t *handle, const char *filename, int events, int status) {
	printf("evevnt_cb\n");
}

const char* TAPDevice_find(char* preferredName,
                           int nlen,
                           char* buffguid,
                           int len) {
  if (get_device_guid(buffguid, len, preferredName, nlen)) {
    return NULL;
  }
  return buffguid;
}

#endif



typedef struct {
  uv_write_t req;
  uv_buf_t buf;
} write_req_t;

static uv_loop_t* loop;

static void after_write(uv_write_t* req, int status);
static void after_read(uv_stream_t*, ssize_t nread, const uv_buf_t* buf);
static void on_close(uv_handle_t* peer);

static int step = 0;
static void after_write(uv_write_t* req, int status) {
	printf("after_write!!!!!!!!!!!!!!\n");
  write_req_t* wr;

  if (step > 100) {
    uv_stream_t *s = (uv_stream_t*) req->handle;
	printf("uv_read_stop\n");
    uv_read_stop(s);
  }
  /* Free the read/write buffer and the request */
  wr = (write_req_t*) req;
  free(wr->buf.base);
  free(wr);

  step += 1;

  if (status == 0)
    return;

  fprintf(stderr,
          "uv_write error: %s - %s\n",
          uv_err_name(status),
          uv_strerror(status));
}

static void after_shutdown(uv_shutdown_t* req, int status) {
  uv_close((uv_handle_t*) req->handle, on_close);
  free(req);
}

static void echo_alloc(uv_handle_t* handle,
                       size_t suggested_size,
                       uv_buf_t* buf);

static void after_read(uv_stream_t* handle,
                       ssize_t nread,
                       const uv_buf_t* buf) {
  printf("after_read!!!!!!!!!!!!!!!\n");
  printf("nread = %d\n", nread);
  printf("buf->len: %d\n", buf->len);
  if(nread > 100) {
	  for(int i = 0; i < nread; ++i)
		  printf("%c", buf->base[i]);
	  printf("\n");
  }
  write_req_t *wr;
    
  //printf("buff: \n");
  //for(int i = 0; i < buf->len; ++i) printf("%c", device_tap2.read_buffer.base[i]);
  //printf("\nbuff size: %d\n", device_tap2.read_buffer.len);
  if (nread < 0) {
    /* Error or EOF */
	printf("error or eof\n");
    ASSERT(nread == UV_EOF);

    free(buf->base);
    uv_close((uv_handle_t*) handle, on_close);
    return;
  }

  if (nread == 0) {
    /* Everything OK, but nothing read. */
	printf("Everything OK, but nothing read.\n");
    free(buf->base);
    return;
  }

  /*
   * Scan for the letter Q which signals that we should quit the server.
   * If we get QS it means close the stream.
   */
  ASSERT(nread>20);
  if (nread > 20 && buf->len > 20) {
    uint8_t ip[4];
    memcpy(ip,buf->base+12,4);
    memcpy(buf->base+12,buf->base+16,4);
    memcpy(buf->base+16,ip,4);
  } else {
    printf("data %p len:%d\n", buf->base,buf->len);
  }

  wr = (write_req_t*) malloc(sizeof *wr);
  ASSERT(wr != NULL);
  printf("create write packet\n");
  wr->buf = uv_buf_init(buf->base, nread);

  /*if (uv_write(&wr->req, handle, &wr->buf, 1, after_write)) {
    printf("uv_write failed\n");
    abort();
  }*/
  printf("uv_read_start\n");
  //uv_read_start((uv_stream_t*) &device_tap2, echo_alloc, after_read);
  uv_read_start((uv_stream_t*) &device, echo_alloc, after_read);
  printf("end uv_read_start\n");
  //uv_device_queue_read(loop, &device_tap2);
  uv_device_queue_read(loop, &device);
}

static void on_close(uv_handle_t* peer) {
  printf("close %p\n", (void*) peer);
}

static void echo_alloc(uv_handle_t* handle,
                       size_t suggested_size,
                       uv_buf_t* buf) {
  printf("echo_alloc\n");
  buf->base = (char*) malloc(suggested_size);
  buf->len = suggested_size;
}

void at_exit(uv_process_t *req, int64_t exit_status, int term_signal) {
  fprintf(stderr, 
          "Process exited with status %d, signal %d\n", 
          exit_status, 
          term_signal);
  uv_close((uv_handle_t*) req, NULL);
}





int main() {
  #define BUF_SZ 1024
  //uv_device_t device;
  char buff[BUF_SZ] = {0};
#if defined (_WIN32) || defined (__CYGWIN__)
  char guid[BUF_SZ] = "DC79795F-2F54-408B-A913-512C04BBE1D1";
  char tmp[MAX_PATH];
#endif
  int r;

#ifdef __linux__
  strcpy(buff,"/dev/net/tun");
#else
#if defined (_WIN32) || defined (__CYGWIN__)

  if (!TAPDevice_find(buff, sizeof(buff), guid, sizeof(guid)))
  {
    printf("You need install tap-windows "             \
           "(https://github.com/OpenVPN/tap-windows) " \
            "to do this test\n");
    return 0;
  }
  char buff_tap2[BUF_SZ] = "TAP2";
  printf("buff!!!!!!!!!!!!!: %s\n", buff);
  snprintf(tmp, 
           sizeof(tmp),
           "netsh interface ip set address \"%s\"" \
           " static 10.3.0.2 255.255.255.0",
           buff_tap2);
  printf("tmp: %s\n", tmp);
  system(tmp);

  snprintf(buff,sizeof(buff), "%s%s%s",USERMODEDEVICEDIR,guid,TAPSUFFIX);
#else
  printf("We not have test for uv_device_t on you platform, please wait\n");
  return 0;
#endif
#endif
  char tap2_filename[] = "\\\\.\\Global\\{DC79795F-2F54-408B-A913-512C04BBE1D1}.tap";
  loop = uv_default_loop();

  //r = uv_device_init(loop, &device_tap2, tap2_filename, O_RDWR); // XXX
  r = uv_device_init(loop, &device, buff, O_RDWR);
  printf("%d\n", r);
  ASSERT(r == 0);

#ifdef __linux__
  {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN; // |IFF_NO_PI; // we use TUN for now
    strncpy(ifr.ifr_name, "tuntest", 10); // TODO(rfree) limit length here when that is a variable
    printf("ioctl: Will create the interface\n");

    uv_os_fd_t fd = 0;
    if ( uv_fileno( (uv_handle_t*) &device , &fd ) != 0 ) { // TODO(rfree) is this castig correct use for uv_fileno?
      printf("Can not convert fd!\n");
      return 0;
		}
		printf("tuntap fileno fd=%d\n", fd);
		// r = uv_device_ioctl(&device, TUNSETIFF, &args);
    r = ioctl( fd , TUNSETIFF , &ifr ); // ***
    ASSERT(r >= 0);

    printf("After creation of tuntap: ifr_ifindex=%d\n", ifr.ifr_ifindex);

		printf("ioctl: Will set ip address\n");
		uint8_t address[16];
		for (int i=0; i<16; ++i) address[i] = i+100;
		address[0] = 0xFC;

		struct Log* logger = NULL;
		struct Except* eh = NULL;

	//	close(fd);

		NetPlatform_addAddress("tuntest", address, 8,  Sockaddr_AF_INET6,  logger,eh);
	  //  ASSERT(r >= 0);

		printf("Ok, tuntap configuration is done\n");
	//	return 0;
	}
#endif
#if defined (_WIN32) || defined (__CYGWIN__)
  {
    uv_process_t child_req = {0};
    uv_process_options_t options = {0};
    uv_stdio_container_t child_stdio[3];
    char* args[5];

    uv_ioargs_t ioarg = {0};
    uint32_t version[3];
    uint32_t p2p[2];
    uint32_t enable = 1;

    ioarg.input_len = sizeof(version);
    ioarg.input = (void*) version;
    ioarg.output_len = sizeof(version);
    ioarg.output = (void*) version;

    r = uv_device_ioctl(&device, TAP_IOCTL_GET_VERSION, &ioarg);
    //r = uv_device_ioctl(&device_tap2, TAP_IOCTL_GET_VERSION, &ioarg);
    ASSERT(r >= 0);
    printf("version: %d.%d.%d\n",version[0],version[1],version[2]);

    p2p[0] = inet_addr("10.3.0.2");
    p2p[1] = inet_addr("10.3.0.1");

    ioarg.input_len = sizeof(p2p);
    ioarg.input = (void*) &p2p;
    ioarg.output_len = sizeof(p2p);
    ioarg.output = (void*) &p2p;

    r = uv_device_ioctl(&device, TAP_IOCTL_CONFIG_POINT_TO_POINT, &ioarg);
    //r = uv_device_ioctl(&device_tap2, TAP_IOCTL_CONFIG_POINT_TO_POINT, &ioarg);
    ASSERT(r >= 0);

    ioarg.input_len = sizeof(enable);
    ioarg.input = (void*) &enable;
    ioarg.output_len = sizeof(enable);
    ioarg.output = (void*) &enable;

    r = uv_device_ioctl(&device, TAP_IOCTL_SET_MEDIA_STATUS, &ioarg);
    //r = uv_device_ioctl(&device_tap2, TAP_IOCTL_SET_MEDIA_STATUS, &ioarg);
    ASSERT(r >= 0);

    args[0] = "ping";
    args[1] = "10.3.0.1";
    args[2] = "-n";
    args[3] = "10";
    args[4] = NULL;

    options.exit_cb = NULL;
    options.file = "ping";
    options.args = args;
    options.stdio_count = 3;

    child_stdio[0].flags = UV_IGNORE;
    child_stdio[1].flags = UV_INHERIT_FD;
    child_stdio[1].data.fd = fileno(stdout);
    child_stdio[2].flags = UV_INHERIT_FD;
    child_stdio[2].data.fd = fileno(stderr);
    options.stdio = child_stdio;

    /*if (uv_spawn(loop, &child_req, &options)) {
      fprintf(stderr, "uv_spawn ping fail\n");
      return 1;
    }*/
    fprintf(stderr, "Launched ping with PID %d\n", child_req.pid);
    uv_unref((uv_handle_t*) &child_req);
  }
#endif

	//uv_fs_event_t ereq;
	//uv_fs_event_init(loop, &ereq);
	//uv_fs_event_start(&ereq, evevnt_cb, tap2_filename, UV_FS_EVENT_RECURSIVE);
	printf("uv_read_start\n");
  r = uv_read_start((uv_stream_t*) &device, echo_alloc, after_read);
  //r = uv_read_start((uv_stream_t*) &device_tap2, echo_alloc, after_read);
  ASSERT(r == 0);
  #if defined (_WIN32) || defined (__CYGWIN__)
  //for (int i = 0; i < 5; ++i) {
	//uv_device_queue_read(loop, &device_tap2);
  //}
  #endif
  printf("uv_run\n");
  uv_run(loop, UV_RUN_DEFAULT);
  printf("end main\n");
  return 0;
}

