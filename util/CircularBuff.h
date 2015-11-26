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

#include "util/Linker.h"
Linker_require("util/CircularBuff.c")

#include <uv.h>

typedef struct uv_buff_circular {
    uv_buf_t *buffs; // array of buffers
    size_t max_size; // number of elements in buffs
    int size; // current size
    // private
    uv_buf_t *current_element; // last element
} uv_buff_circular;

void CircularBuffInit(uv_buff_circular *circular_buff, size_t nbufs);
int CircularBuffPush(uv_buff_circular * const circular_buff, uv_buf_t * const buff);
int CircularBuffPop(uv_buff_circular *circular_buff, uv_buf_t * const buff);
void CircularBuffDeinit(uv_buff_circular * const circular_buff);

#endif