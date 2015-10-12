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
#ifndef Sockaddr_H
#define Sockaddr_H

// #include "memory/Allocator.h"

// #include "util/Endian.h"

// #include "util/Linker.h"
// Linker_require("util/platform/Sockaddr.c")

#include <stdint.h>

struct Sockaddr
{
    /** the length of this sockaddr, this field is included in the length. */
    uint16_t addrLen;
    #define Sockaddr_flags_BCAST 1
    uint16_t flags;
    uint32_t pad;
};

/** The number of bytes of space taken for representing the addrLen at the beginning. */
#define Sockaddr_OVERHEAD 8

/** The maximum possible size for the native sockaddr (not including Sockaddr_OVERHEAD) */
#define Sockaddr_MAXSIZE 128
struct Sockaddr_storage
{
    struct Sockaddr addr;
    uint64_t nativeAddr[Sockaddr_MAXSIZE / 8];
};

/** 127.0.0.1 and ::1 addresses for building from. */

//const struct Sockaddr* const Sockaddr_LOOPBACK_be; // x
//const struct Sockaddr* const Sockaddr_LOOPBACK_le; // x

#define Sockaddr_LOOPBACK (Endian_isBigEndian() ? Sockaddr_LOOPBACK_be : Sockaddr_LOOPBACK_le)

// const struct Sockaddr* const Sockaddr_LOOPBACK6; // x

/**
 * Get the address family for the address.
 *
 * @param a sockaddr.
 * @return the AF number for this sockaddr.
 */

// extern const int Sockaddr_AF_INET;
// extern const int Sockaddr_AF_INET6;

// int Sockaddr_getFamily(struct Sockaddr* sa);


/**
 * Output the native form of a sockaddr.
 */
static inline void* Sockaddr_asNative(struct Sockaddr* sa)
{
    return (void*)(&sa[1]);
}
static inline const void* Sockaddr_asNativeConst(const struct Sockaddr* sa)
{
    return (const void*)(&sa[1]);
}


#endif
