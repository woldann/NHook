/**
 * MIT License
 *
 * Copyright (c) 2025 Serkan Aksoy
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __MANAGER_H__
#define __MANAGER_H__

#include "hook.h"

#include "nmutex.h"
#include "nthread.h"

/**
 * @brief Manages all hooks and thread states for a specific process
 * 
 * Keeps track of process ID, synchronization mutex, thread handles and IDs,
 * counts of threads and hooks, and suspension counts.
 */
struct nhook_manager {
	DWORD pid; /**< Process ID */

	NMUTEX mutex; /**< Mutex for thread-safe operations */

	ntid_t *o_thread_ids; /**< Original thread IDs before hooking */
	ntid_t *n_thread_ids; /**< New thread IDs after hooking */
	size_t thread_ids_size; /**< Size of thread ID arrays */

	HANDLE *threads; /**< Handles to the threads */
	uint16_t thread_count; /**< Number of threads */
	uint16_t suspend_count; /**< Number of suspended threads */

	uint16_t max_hook_count; /**< Maximum number of hooks allowed */
};

/**
 * @brief Helper macro to get a hook by index from the hook manager
 */
#define NHOOK_MANAGER_GET_HOOK(nhook_manager, index) \
	(((nhook_t *)(((nhook_manager) + 1))) + i)

typedef struct nhook_manager nhook_manager_t;

#endif // !__MANAGER_H__
