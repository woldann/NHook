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

#ifndef __NHOOK_H__
#define __NHOOK_H__

#ifndef NHOOK_API
#define NHOOK_API NTHREAD_API
#endif // NHOOK_API

#ifdef NHOOK_EXPORTS

#ifndef NTHREAD_API
#define NTHREAD_API __declspec(dllexport)
#endif // !NTHREAD_API

#ifndef LOG_API
#define LOG_API __declspec(dllexport)
#endif // !LOG_API

#else // !NHOOK_EXPORTS

#define NTHREAD_API __declspec(dllimport)
#define LOG_API __declspec(dllimport)

#endif // !NHOOK_EXPORTS

#include "ntosutils.h"

#define NHOOK_ERROR 0x4500
#define NHOOK_FIND_ERROR 0x4501
#define NHOOK_REALLOC_ERROR 0x4502
#define NHOOK_MAX_HOOK_ERROR 0x4503
#define NHOOK_NTU_READ_MEMORY_ERROR 0x4505
#define NHOOK_CS_OPEN_ERROR 0x4506
#define NHOOK_GET_KERNEL32_BASE_ERROR 0x4507
#define NHOOK_GET_PROC_ADDRESS_ERROR 0x4508
#define NHOOK_NTU_MALLOC_ERROR 0x4509
#define NHOOK_NOSU_UPGRADE_ERROR 0x450A
#define NHOOK_NOSU_ATTACH_ERROR 0x450B
#define NHOOK_NH_UPDATE_THREAD_ERROR 0x450C
#define NHOOK_NH_SUSPEND_THREADS_ERROR 0x450D
#define NHOOK_NH_RESUME_THREADS_ERROR 0x450E
#define NHOOK_NH_TOGGLE_INIT_ERROR 0x450F
#define NHOOK_CS_DETAIL_ERROR 0x4510
#define NHOOK_TRAMPOLINE_INIT_ERROR 0x4511

#define NHOOK_FLAG_ENABLED 0x01
#define NHOOK_FLAG_SECOND_INSN 0x02

struct trampoline;

struct nhook {
	void *function;
	void *hook_function;

#ifndef NTU_GLOBAL_CC
	ntucc_t cc;
#endif // !NTU_GLOBAL_CC

	int8_t flags;
	uint8_t arg_count;

	uint8_t affected_length;
	uint8_t mem[16];

	void *tramp;
};

typedef struct nhook nhook_t;

#define NHOOK_SET_INVALID(nhook) ((nhook)->function = NULL)
#define NHOOK_IS_VALID(nhook) ((nhook)->function != NULL)

struct nhook_manager {
	DWORD pid;
	NMUTEX mutex;

	ntid_t *o_thread_ids;
	ntid_t *n_thread_ids;
	size_t thread_ids_size;

	HANDLE *threads;
	uint16_t thread_count;
	uint16_t suspend_count;

	uint16_t max_hook_count;
};

typedef struct nhook_manager nhook_manager_t;

#define NHOOK_MANAGER_GET_HOOK(nhook_manager, index) \
	(((nhook_t *)(((nhook_manager) + 1))) + i)

void *NHOOK_API nh_get_kernel32_base();

nerror_t NHOOK_API nh_global_init();

BOOL NHOOK_API nh_virtual_protect(LPVOID lpAddress, SIZE_T dwSize,
				  DWORD flNewProtect, PDWORD lpflOldProtect);

// SIZE_T NHOOK_API nh_virtual_query(LPVOID lpAddress,
// 				  PMEMORY_BASIC_INFORMATION lpBuffer,
// 				  SIZE_T dwLength);

bool NHOOK_API nh_is_enabled_ex(nhook_t *nhook);

bool NHOOK_API nh_is_enabled(nhook_manager_t *nhook_manager,
			     void *hook_function);

nhook_t *NHOOK_API nh_find_with_function(nhook_manager_t *nhook_manager,
					 void *function);

nhook_t *NHOOK_API nh_find(nhook_manager_t *nhook_manager, void *hook_function);

nhook_manager_t *NHOOK_API nh_create_manager(DWORD pid,
					     uint16_t max_hook_count);

uint16_t NHOOK_API nh_manager_get_enabled_count(nhook_manager_t *nhook_manager);

uint16_t NHOOK_API nh_manager_get_count(nhook_manager_t *nhook_manager);

nerror_t NHOOK_API nh_create(nhook_manager_t *nhook_manager, void *function,
			     void *hook_function, uint8_t arg_count);

nerror_t NHOOK_API nh_enable_ex(nhook_manager_t *nhook_manager, nhook_t *nhook);

nerror_t NHOOK_API nh_enable(nhook_manager_t *nhook_manager,
			     void *hook_function);

nerror_t NHOOK_API nh_enable_all(nhook_manager_t *nhook_manager);

nerror_t NHOOK_API nh_disable_ex(nhook_manager_t *nhook_manager,
				 nhook_t *nhook);

nerror_t NHOOK_API nh_disable(nhook_manager_t *nhook_manager,
			      void *hook_function);

nerror_t NHOOK_API nh_disable_all(nhook_manager_t *nhook_manager);

void NHOOK_API nh_destroy_ex(nhook_manager_t *nhook_manager, nhook_t *nhook);

void NHOOK_API nh_destroy(nhook_manager_t *nhook_manager, void *hook_function);

void NHOOK_API nh_destroy_all(nhook_manager_t *nhook_manager);

nerror_t NHOOK_API nh_resume_threads(nhook_manager_t *nhook_manager);

nerror_t NHOOK_API nh_suspend_threads(nhook_manager_t *nhook_manager);

void *NHOOK_API nh_trampoline_ex_v(nhook_manager_t *nhook_manager,
				   nhook_t *nhook, va_list args);

void *NHOOK_API nh_trampoline_ex(nhook_manager_t *nhook_manager, nhook_t *nhook,
				 ...);

void *NHOOK_API nh_trampoline_v(nhook_manager_t *nhook_manager,
				void *hook_function, va_list args);

void *NHOOK_API nh_trampoline(nhook_manager_t *nhook_manager,
			      void *hook_function, ...);

nerror_t NHOOK_API nh_update(nhook_manager_t *nhook_manager);

void NHOOK_API nh_destroy_manager(nhook_manager_t *nhook_manager);

#endif // !__NHOOK_H__
