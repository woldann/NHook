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

#include "nhook.h"
#include "log.h"
#include "nmem.h"

#include <capstone/capstone.h>

nerror_t NHOOK_API nh_register_threads(nhook_manager_t *nhook_manager,
				       HANDLE *threads, uint16_t thread_count)
{
	void *old_threads = nhook_manager->threads;
	uint16_t old_count = nhook_manager->thread_count;
	uint16_t new_count = old_count + thread_count;

	size_t new_size = sizeof(HANDLE) * new_count;
	void *new_threads = N_REALLOC(old_threads, new_size);
	if (new_threads == NULL)
		return GET_ERR(NHOOK_REALLOC_ERROR);

	memcpy(new_threads + old_count, threads, thread_count * sizeof(HANDLE));

	if (new_threads != old_threads)
		N_FREE(old_threads);

	nhook_manager->threads = new_threads;
	nhook_manager->thread_count = new_count;

	return N_OK;
}

nerror_t NHOOK_API nh_register_thread(nhook_manager_t *nhook_manager,
				      HANDLE thread)
{
	return nh_register_threads(nhook_manager, &thread, 1);
}

nerror_t NHOOK_API nh_register_working_threads(nhook_manager_t *nhook_manager)
{
	ntid_t thread_ids[MAX_THREAD_COUNT];
	uint16_t thread_id_count =
		nosu_get_process_threads(thread_ids, nhook_manager->pid);

	HANDLE *threads = N_ALLOC(thread_id_count * sizeof(HANDLE));
	uint16_t thread_count = 0;

	for (uint16_t i = 0; i < thread_id_count; i++) {
		HANDLE thread =
			OpenThread(NTHREAD_ACCESS, false, thread_ids[i]);
		if (thread != NULL) {
			threads[thread_count] = thread;
			thread_count++;
		}
	}

	nerror_t ret =
		nh_register_threads(nhook_manager, threads, thread_count);

	N_FREE(threads);
	return ret;
}

nhook_t *NHOOK_API nh_find(nhook_manager_t *nhook_manager, void *hook_function)
{
	for (uint16_t i = 0; i < nhook_manager->max_hook_count; i++) {
		nhook_t *nhook = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		if (!NHOOK_IS_VALID(nhook))
			continue;

		if (nhook->hook_function == hook_function)
			return nhook;
	}

	return NULL;
}

nhook_manager_t *NHOOK_API nh_create_manager(DWORD pid, uint16_t max_hook_count)
{
	size_t mem_len =
		sizeof(nhook_manager_t) + sizeof(nhook_t) * max_hook_count;
	nhook_manager_t *manager = N_ALLOC(mem_len);
	if (manager == NULL)
		return NULL;

	manager->max_hook_count = max_hook_count;
	manager->pid = pid;

	manager->thread_count = 0;
	manager->threads = N_ALLOC(0);
	if (manager->threads == NULL) {
		nh_destroy(manager);
		return NULL;
	}

	for (uint16_t i = 0; i < max_hook_count; i++) {
		nhook_t *hook = NHOOK_MANAGER_GET_HOOK(manager, i);
		NHOOK_SET_INVALID(hook);
	}

	return manager;
}

nerror_t NHOOK_API nh_install(nhook_manager_t *nhook_manager, void *function,
			      void *hook_function, uint16_t arg_count)
{
	nhook_t *nhook = NULL;

	for (uint16_t i = 0; i < nhook_manager->max_hook_count; i++) {
		nhook_t *nh = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		if (!NHOOK_IS_VALID(nh)) {
			nhook = nh;
			break;
		}
	}

	if (nhook == NULL)
		return GET_ERR(NHOOK_MAX_HOOK_ERROR);

	csh handle;
	cs_insn *insn;

	cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	if (err != CS_ERR_OK) {
		LOG_INFO("Failed on cs_open(): %s", cs_strerror(err));
		return 0;
	}

	nhook->function = function;
	nhook->hook_function = hook_function;

	if (HAS_ERR(nosu_find_thread_and_upgrade(nhook_manager->pid)))
		return GET_ERR(NHOOK_NOSU_FIND_THREAD_AND_UPGRADE_ERROR);

	void *mem = nhook->mem;
	if (HAS_ERR(ntu_read_memory(function, mem, 2)))
		return GET_ERR(NHOOK_NTU_READ_MEMORY_ERROR);

	LOG_INFO("function=%p", function);
	LOG_INFO("%02X %02X", ((uint8_t *)mem)[0], ((uint8_t *)mem)[1]);
	int8_t count = cs_disasm(handle, mem, 2, (uint64_t)mem, 2, &insn);
	LOG_INFO("count=%d", count);

	if (count == 1 && insn[0].size == 1) {
		int8_t i;
		for (i = 2; i < 15; i++) {
			if (HAS_ERR(ntu_read_memory(function + i, mem + i, 1)))
				return GET_ERR(NHOOK_NTU_READ_MEMORY_ERROR);

			count = cs_disasm(handle, mem + 1, i, (uint64_t)mem + 1,
					  1, &insn);
			if (count > 0)
				break;
		}

		nhook->affected_length = i + 1;
	} else if (count == 0) {
		int8_t i;
		for (i = 2; i < 15; i++) {
			if (HAS_ERR(ntu_read_memory(function + i, mem + i, 1)))
				return GET_ERR(NHOOK_NTU_READ_MEMORY_ERROR);

			count = cs_disasm(handle, mem, i + 1, (uint64_t)mem, 1,
					  &insn);
			if (count > 0)
				break;
		}

		nhook->affected_length = i + 1;
	} else
		nhook->affected_length = 2;

	LOG_INFO("Affected Length(%d)", nhook->affected_length);

	cs_close(&handle);

	ntu_destroy();
	return N_OK;
}

nerror_t NHOOK_API nh_uninstall_ex(nhook_manager_t *nhook_manager,
				   nhook_t *nhook)
{
	NHOOK_SET_INVALID(nhook);
	return N_OK;
}

nerror_t NHOOK_API nh_uninstall(nhook_manager_t *nhook_manager,
				void *hook_function)
{
	nhook_t *nhook = nh_find(nhook_manager, hook_function);
	if (nhook == NULL)
		return GET_ERR(NHOOK_FIND_ERROR);

	return nh_uninstall_ex(nhook_manager, hook_function);
}

nerror_t NHOOK_API nh_trampoline_ex(nhook_manager_t *nhook_manager,
				    nhook_t *nhook)
{
	return N_OK;
}

nerror_t NHOOK_API nh_trampoline(nhook_manager_t *nhook_manager,
				 void *hook_function)
{
	nhook_t *nhook = nh_find(nhook_manager, hook_function);
	if (nhook == NULL)
		return GET_ERR(NHOOK_FIND_ERROR);

	return nh_trampoline_ex(nhook_manager, hook_function);
}

void NHOOK_API nh_destroy(nhook_manager_t *nhook_manager)
{
	if (nhook_manager == NULL)
		return;

	for (uint16_t i = 0; i < nhook_manager->max_hook_count; i++) {
		nhook_t *nhook = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		nh_uninstall(nhook_manager, nhook);
	}

	if (nhook_manager->threads != NULL) {
		N_FREE(nhook_manager->threads);
		nhook_manager->threads = NULL;
	}

	N_FREE(nhook_manager);
}

void my_memcpy(void *addr1, void *addr2, size_t len)
{
	LOG_INFO("addr1=%p", addr1);
	LOG_INFO("addr2=%p", addr2);
	LOG_INFO("len=%p", len);
}

void NHOOK_API test()
{
	LOG_INFO("Creating manager");
	ntid_t tid = nosu_dummy_thread();

	HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
	if (thread == NULL) {
		LOG_INFO("OpenThread failed");
		return;
	}

	DWORD pid = GetProcessIdOfThread(thread);

	nhook_manager_t *man = nh_create_manager(pid, 8);
	nh_register_working_threads(man);
	if (man == NULL) {
		LOG_ERROR("Manager is NULL!");
		return;
	}

	void *libc = ntu_get_libc_base();
	void *memcpy = GetProcAddress(libc, "memcpy");

	LOG_INFO("error=%d", nh_install(man, memcpy, (void *)my_memcpy, 3));
}
