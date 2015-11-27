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
#include "util/CircularBuff.h"

#include <assert.h>
#include <stdlib.h>

static void free_buff(send_buffer *buff)
{
    assert(buff != NULL);
    free(buff->buffer->base);
    buff->buffer->base = NULL;
    buff->buffer->len = 0;
}

/**
 * Move current_element pointer to next element
 */
static void move_internal_pointer(uv_buff_circular * const circular_buff)
{
    assert(circular_buff != NULL);
    // Move 'current_element' pointer
    // check if current_element == last element
    if (circular_buff->current_element == &circular_buff->buffs[circular_buff->max_size -1])
    {
        circular_buff->current_element = &circular_buff->buffs[0];
    }
    else
    {
        circular_buff->current_element++;
    }
}

// public functions

/**
 * @param circular_buff Must be allocated in caller.
 * @param nbufs Number of buffers
 */
void CircularBuffInit(uv_buff_circular *circular_buff, size_t nbufs, struct Allocator* alloc)
{
    printf("CircularBuffInit\n");
    assert(circular_buff != NULL);
    circular_buff->buffs = Allocator_malloc(alloc, sizeof(send_buffer) * nbufs);
    for (size_t i = 0; i < nbufs; ++i)
    {
        circular_buff->buffs[i].buffer = Allocator_malloc(alloc, sizeof(uv_buf_t));
        circular_buff->buffs[i].buffer->base = NULL;
        circular_buff->buffs[i].buffer->len = 0;
    }
    circular_buff->max_size = nbufs;
    circular_buff->current_element = &circular_buff->buffs[nbufs -1];
    circular_buff->size = 0;
    circular_buff->alloc = alloc;
    printf("buffer size: %d\n", circular_buff->size);
    printf("buffer max size: %d\n", circular_buff->max_size);
    printf("CircularBuffInit end\n");
}

/**
 * Move data from @param buff to @param circular_buff
 * @param circular_buff Initialized by caller (buff_circular_init).
 * @param buff Initialized by caller. Clean in this function (.base = NULL, .len=0).
 * @return 0 if success
 */
int CircularBuffPush(uv_buff_circular * const circular_buff, send_buffer * const buff)
{
    printf("[%d] CircularBuffPush\n", __LINE__);
    if (circular_buff == NULL)
    {
        printf("[%d] CircularBuffPush RETURN 1\n", __LINE__);
        return 1;
    }
    if (buff == NULL)
    {
        printf("[%d] CircularBuffPush RETURN 2\n", __LINE__);
        return 2;
    }

    assert(circular_buff->size <= circular_buff->max_size);
    if (circular_buff->size == circular_buff->max_size)  // buffer if full
    {
        printf("[%d] CircularBuffPush RETURN 3\n", __LINE__);
        printf("size: %d\n", circular_buff->size);
        printf("max_size: %d\n", circular_buff->max_size);
        return 3;
    }

    // move 'current_element' pointer to next slot
    move_internal_pointer(circular_buff);

    printf("[%d] CircularBuffPush move\n", __LINE__);


    // move element
    circular_buff->current_element->buffer->len = buff->buffer->len;
    buff->buffer->len = 0;
    circular_buff->current_element->buffer->base = buff->buffer->base;
    buff->buffer->base = NULL;
    circular_buff->current_element->req = buff->req;
    buff->req = NULL;
    circular_buff->current_element->handle = buff->handle;
    buff->handle = NULL;
    circular_buff->current_element->addr = buff->addr;
    buff->addr = NULL;
    circular_buff->current_element->send_cb = buff->send_cb;
    buff->send_cb = NULL;

    // increment size
    if (circular_buff->size < circular_buff->max_size)
    {
        circular_buff->size++;
    }

    printf("[%d] CircularBuffPush END\n", __LINE__);

    return 0;
}

/**
 * Move data from @param circular_buff to @param buff
 * @param circular_buff Initialized by caller (buff_circular_init).
 * @param buff Out pointer. Must be empty (.base = NULL, .len=0).
 * @return 0 if success
 */
int CircularBuffPop(uv_buff_circular *circular_buff, send_buffer * const buff)
{
    printf("CircularBuffPop\n");
    if (circular_buff == NULL)
    {
        printf("[%d] CircularBuffPop RETURN 1\n", __LINE__);
        return 1;
    }
    if (buff == NULL)
    {
        printf("[%d] CircularBuffPop RETURN 2\n", __LINE__);
        return 2;
    }
    if (circular_buff->size == 0)
    {
        printf("[%d] CircularBuffPop RETURN 3\n", __LINE__);
        return 3;
    }

    assert(buff->buffer->base == NULL);
    assert(buff->buffer->len == 0);

    size_t pop_element_index = circular_buff->max_size;

    send_buffer *pop_ptr = circular_buff->current_element;
    for (size_t i = 0; i < circular_buff->size - 1; ++i)
    {
        //printf("[%d] size: %d\n", __LINE__, circular_buff->size);
        //printf("i = %d\n", i);
        //printf("size = %d\n", circular_buff->size);
        if (pop_ptr == &circular_buff->buffs[0])
        {
            pop_ptr += circular_buff->max_size - 1; // last element in array
        }
        else {
            pop_ptr--;
        }
    }

    assert(pop_element_index <= circular_buff->max_size);

    // move buffer
    buff->buffer->base = pop_ptr->buffer->base;
    pop_ptr->buffer->base = NULL;
    buff->buffer->len = pop_ptr->buffer->len;
    pop_ptr->buffer->len = 0;
    buff->req = pop_ptr->req;
    pop_ptr->req = NULL;
    buff->handle = pop_ptr->handle;
    pop_ptr->handle = NULL;
    buff->addr = pop_ptr->addr;
    pop_ptr->addr = NULL;
    buff->send_cb = pop_ptr->send_cb;
    pop_ptr->send_cb = NULL;

    circular_buff->size--;
    printf("CircularBuffPop end\n");
    return 0;
}

/**
 * Call free() for evry element.
 * Deallocate internal array.
 * Instance of struct 'circular_buff' will be not deallocate.
 */
void CircularBuffDeinit(uv_buff_circular * const circular_buff)
{
    if (circular_buff == NULL)
    {
        return;
    }

    for (size_t i = 0; i < circular_buff->max_size; ++i)
    {
        if (circular_buff->buffs[i].buffer->base != NULL)
        {
            free_buff(&circular_buff->buffs[i]);
        }
    }
    free(circular_buff->buffs);
    circular_buff->current_element = NULL;
    circular_buff->buffs = NULL;
    circular_buff->max_size = 0;
    circular_buff->size = 0;
}