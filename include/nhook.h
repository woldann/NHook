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

#include "ntosutils.h"

#define NHOOK_ERROR 0x4500
#define NHOOK_FIND_ERROR 0x4501
#define NHOOK_REALLOC_ERROR 0x4502
#define NHOOK_MAX_HOOK_ERROR 0x4503
#define NHOOK_NOSU_FIND_THREAD_AND_UPGRADE_ERROR 0x4504
#define NHOOK_NTU_READ_MEMORY_ERROR 0x4505
#define NHOOK_CS_OPEN_ERROR 0x4506
#define NHOOK_GET_KERNEL32_BASE_ERROR 0x4507
#define NHOOK_GET_PROC_ADDRESS_ERROR 0x4508
#define NHOOK_NTU_MALLOC_ERROR 0x4509
#define NHOOK_NOSU_UPGRADE_ERROR 0x450A
#define NHOOK_NOSU_ATTACH_ERROR 0x450A

struct nhook {
	void *function;
	void *hook_function;

#ifndef NTU_GLOBAL_CC
	ntucc_t cc;
#endif // !NTU_GLOBAL_CC
	uint8_t arg_count;

	uint8_t affected_length;
	uint8_t mem[16];
};

typedef struct nhook nhook_t;

#define NHOOK_SET_INVALID(nhook) ((nhook)->function = NULL)
#define NHOOK_IS_VALID(nhook) ((nhook)->function != NULL)

#define NHOOK_MANAGER_MAX_HOOK_COUNT 16

struct nhook_manager {
	DWORD pid;

	NMUTEX mutex;

	uint16_t thread_count;
	HANDLE *threads;

	uint16_t max_hook_count;
};

typedef struct nhook_manager nhook_manager_t;

#define NHOOK_MANAGER_GET_HOOK(nhook_manager, index) \
	(((nhook_t *)(((nhook_manager) + 1))) + i)

void *NHOOK_API nh_get_kernel32_base();

nerror_t NHOOK_API nh_global_init();

BOOL NHOOK_API nh_virtual_protect(LPVOID lpAddress, SIZE_T dwSize,
				  DWORD flNewProtect, PDWORD lpflOldProtect);

SIZE_T NHOOK_API nh_virtual_query(LPVOID lpAddress,
				  PMEMORY_BASIC_INFORMATION lpBuffer,
				  SIZE_T dwLength);

nerror_t NHOOK_API nh_register_threads(nhook_manager_t *nhook_manager,
				       HANDLE *thread, uint16_t thread_count);

nerror_t NHOOK_API nh_register_thread(nhook_manager_t *nhook_manager,
				      HANDLE thread);

nerror_t NHOOK_API nh_register_working_threads(nhook_manager_t *nhook_manager);

nhook_t *NHOOK_API nh_find_with_function(nhook_manager_t *nhook_manager,
					 void *function);

nhook_t *NHOOK_API nh_find(nhook_manager_t *nhook_manager, void *hook_function);

nhook_manager_t *NHOOK_API nh_create_manager(DWORD pid,
					     uint16_t max_hook_count);

nerror_t NHOOK_API nh_install(nhook_manager_t *nhook_manager, void *function,
			      void *hook_function, uint8_t arg_count);

nerror_t NHOOK_API nh_uninstall_ex(nhook_manager_t *nhook_manager,
				   nhook_t *nhook);

nerror_t NHOOK_API nh_uninstall(nhook_manager_t *nhook_manager,
				void *hook_function);

nerror_t NHOOK_API nh_trampoline_ex(nhook_manager_t *nhook_manager,
				    nhook_t *nhook);

nerror_t NHOOK_API nh_trampoline(nhook_manager_t *nhook_manager,
				 void *hook_function);

void NHOOK_API nh_destroy(nhook_manager_t *nhook_manager);

void NHOOK_API test();

#endif // !__NHOOK_H__
