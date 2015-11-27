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
#ifndef CircularBuff_H
#define CircularBuff_H

#include "memory/Allocator.h"
#include "util/Linker.h"
Linker_require("util/CircularBuff.c")

#include <assert.h>
#include <stdlib.h>
#include <uv.h>

/**
 * single element in circular buffer
 */
typedef struct send_buffer
{
    uv_buf_t *buffer;
    uv_udp_send_t* req;
    uv_udp_t* handle;
    const struct sockaddr* addr;
    uv_udp_send_cb send_cb;
} send_buffer;

typedef struct uv_buff_circular
{
    send_buffer *buffs; // array of buffers
    size_t max_size; // number of elements in buffs
    size_t size; // current size
    // private
    send_buffer *current_element; // last element
    struct Allocator* alloc;
} uv_buff_circular;

void CircularBuffInit(uv_buff_circular *circular_buff, size_t nbufs, struct Allocator* alloc);
int CircularBuffPush(uv_buff_circular * const circular_buff, send_buffer * const buff);
int CircularBuffPop(uv_buff_circular *circular_buff, send_buffer * const buff);
void CircularBuffDeinit(uv_buff_circular * const circular_buff);




#endif