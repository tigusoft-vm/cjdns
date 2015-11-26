#include "util/CircularBuff.h"

#include <stdlib.h>

typedef struct uv_buff_circular {
	uv_buf_t *buffs; // array of buffers
	size_t max_size; // number of elements in buffs
	int size; // current size
	// private
	uv_buf_t *current_element; // last element
} uv_buff_circular;


//private functions

/**
 * Call free for single uv_buf_t
 */
static void free_buff(uv_buf_t *buff) {
	assert(buff != NULL);
	free(buff->base);
	buff->base = NULL;
	buff->len = 0;
}

/**
 * Move current_element pointer to next element
 */
static void move_internal_pointer(uv_buff_circular * const circular_buff) {
	assert(circular_buff != NULL);
	// Move 'current_element' pointer
	// check if current_element == last element
	if (circular_buff->current_element == &circular_buff->buffs[circular_buff->max_size -1]) {
		circular_buff->current_element = &circular_buff->buffs[0];
	}
	else {
		circular_buff->current_element++;
	}
}

// public functions

/**
 * @param circular_buff Must be allocated in caller.
 * @param nbufs Number of buffers
 */
void buff_circular_init(uv_buff_circular *circular_buff, size_t nbufs) {
	assert(circular_buff != NULL);
	circular_buff->buffs = (uv_buf_t *)malloc(sizeof(uv_buf_t) * nbufs);
	for (int i = 0; i < nbufs; ++i) {
		circular_buff->buffs[i].base = NULL;
		circular_buff->buffs[i].len = 0;
	}
	circular_buff->max_size = nbufs;
	circular_buff->current_element = &circular_buff->buffs[nbufs -1];
	circular_buff->size = 0;
}

/**
 * Move data from @param buff to @param circular_buff
 * @param circular_buff Initialized by caller (buff_circular_init).
 * @param buff Initialized by caller. Clean in this function (.base = NULL, .len=0).
 * @return 0 if success
 */
int buff_circular_push(uv_buff_circular * const circular_buff, uv_buf_t * const buff) {
	if (circular_buff == NULL) {
		return 1;
	}
	if (buff == NULL) {
		return 2;
	}

	assert(circular_buff->size <= circular_buff->max_size);
	if (circular_buff->size == circular_buff->max_size) { // buffer if full
		return 3;
	}

	// move 'current_element' pointer to next slot
	move_internal_pointer(circular_buff);

	// move element
	circular_buff->current_element->len = buff->len;
	buff->len = 0;
	circular_buff->current_element->base = buff->base;
	buff->base = NULL;

	// increment size
	if (circular_buff->size < circular_buff->max_size) {
		circular_buff->size++;
	}
	return 0;
}

/**
 * Move data from @param circular_buff to @param buff
 * @param circular_buff Initialized by caller (buff_circular_init).
 * @param buff Out pointer. Must be empty (.base = NULL, .len=0).
 * @return 0 if success
 */
int buff_circular_pop(uv_buff_circular *circular_buff, uv_buf_t * const buff) {
	if (circular_buff == NULL) {
		return 1;
	}
	if (buff == NULL) {
		return 2;
	}

	assert(buff->base == NULL);
	assert(buff->len == 0);

	size_t pop_element_index = circular_buff->max_size;
	size_t last_element_index = circular_buff->current_element - circular_buff->buffs;

	uv_buf_t *pop_ptr = circular_buff->current_element;
	for (int i = 0; i < circular_buff->size - 1; ++i) {
		if (pop_ptr == &circular_buff->buffs[0]) {
			pop_ptr += circular_buff->max_size - 1; // last element in array
		}
		else {
			pop_ptr--;
		}
	}

	assert(pop_element_index <= circular_buff->max_size);

	// move buffer
	buff->base = pop_ptr->base;
	pop_ptr->base = NULL;
	buff->len = pop_ptr->len;
	pop_ptr->len = 0;

	circular_buff->size--;

	return 0;
}

/**
 * Call free() for evry element.
 * Deallocate internal array.
 * Instance of struct 'circular_buff' will be not deallocate.
 */
void buff_circular_deinit(uv_buff_circular * const circular_buff) {
	if (circular_buff == NULL) {
		return;
	}

	for (int i = 0; i < circular_buff->max_size; ++i) {
		if (circular_buff->buffs[i].base != NULL)
			free_buff(&circular_buff->buffs[i]);
	}
	free(circular_buff->buffs);
	circular_buff->current_element = NULL;
	circular_buff->buffs = NULL;
	circular_buff->max_size = 0;
	circular_buff->size = 0;
}