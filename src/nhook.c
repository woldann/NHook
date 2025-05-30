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
#include "ntmem.h"

#include <capstone/capstone.h>

struct nhook_tfunctions {
	void *VirtualProtect;
	// void *VirtualQuery;
} nh_funcs;

void *NHOOK_API nh_get_kernel32_base()
{
	return (void *)GetModuleHandleA("kernel32");
}

nerror_t NHOOK_API nh_global_init()
{
	void *kernel32_base = nh_get_kernel32_base();
	if (kernel32_base == NULL)
		return GET_ERR(NHOOK_GET_KERNEL32_BASE_ERROR);

	nh_funcs.VirtualProtect =
		GetProcAddress(kernel32_base, "VirtualProtect");
	// nh_funcs.VirtualQuery = GetProcAddress(libc_base, "VirtualQuery");

	if (nh_funcs.VirtualProtect ==
	    NULL /* || nh_funcs.VirtualQuery == NULL */)
		return GET_ERR(NHOOK_GET_PROC_ADDRESS_ERROR);

	return N_OK;
}

BOOL NHOOK_API nh_virtual_protect(LPVOID lpAddress, SIZE_T dwSize,
				  DWORD flNewProtect, PDWORD lpflOldProtect)
{
	ntu_set_default_cc();
	return (BOOL)(int64_t)ntu_ucall(nh_funcs.VirtualProtect, lpAddress,
					dwSize, flNewProtect, lpflOldProtect);
}
//
// SIZE_T NHOOK_API nh_virtual_query(LPVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
// {
// 	ntu_set_default_cc();
// 	return (BOOL) (int64_t)ntu_ucall(nh_funcs.VirtualQuery, lpAddress, lpBuffer, dwLength);
// }

nerror_t NHOOK_API nh_register_threads(nhook_manager_t *nhook_manager,
				       HANDLE *threads, uint16_t thread_count)
{
	void *old_threads = nhook_manager->threads;
	uint16_t old_count = nhook_manager->thread_count;
	uint16_t new_count = old_count + thread_count;

	size_t new_size = sizeof(HANDLE) * new_count;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	void *new_threads = N_REALLOC(old_threads, new_size);
	if (new_threads == NULL) {
		NMUTEX_UNLOCK(mutex);
		return GET_ERR(NHOOK_REALLOC_ERROR);
	}

	memcpy(new_threads + old_count, threads, thread_count * sizeof(HANDLE));

	if (new_threads != old_threads)
		N_FREE(old_threads);

	nhook_manager->threads = new_threads;
	nhook_manager->thread_count = new_count;

	NMUTEX_UNLOCK(mutex);
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

nhook_t *NHOOK_API nh_find_with_function(nhook_manager_t *nhook_manager,
					 void *function)
{
	for (uint16_t i = 0; i < nhook_manager->max_hook_count; i++) {
		nhook_t *nhook = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		if (!NHOOK_IS_VALID(nhook))
			continue;

		if (nhook->function == function)
			return nhook;
	}

	return NULL;
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

	NMUTEX_INIT(manager->mutex);
	if (manager->mutex == NULL)
		goto nh_create_manager_return_error;

	manager->max_hook_count = max_hook_count;
	manager->pid = pid;

	manager->thread_count = 0;
	manager->threads = N_ALLOC(0);
	if (manager->threads == NULL) {
nh_create_manager_return_error:
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
			      void *hook_function, uint8_t arg_count)
{
	nerror_t ret;
	nhook_t *nhook = NULL;
	NMUTEX mutex = nhook_manager->mutex;

	NMUTEX_LOCK(mutex);

	for (uint16_t i = 0; i < nhook_manager->max_hook_count; i++) {
		nhook_t *nh = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		if (!NHOOK_IS_VALID(nh)) {
			nhook = nh;
			break;
		}
	}

	if (nhook == NULL) {
		ret = GET_ERR(NHOOK_MAX_HOOK_ERROR);
		goto nh_install_return_without_ntu_destroy;
	}

	csh handle;
	cs_insn *insn;

	cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	if (err != CS_ERR_OK) {
		ret = GET_ERR(NHOOK_CS_OPEN_ERROR);
		goto nh_install_return_without_ntu_destroy;
	}

	nhook->function = function;
	nhook->hook_function = hook_function;
	nhook->arg_count = arg_count;

#ifndef NTU_GLOBAL_CC
	nhook->cc = NTUCC_DEFAULT_CC;
#endif /* ifndef NTU_GLOBAL_CC */

	if (HAS_ERR(nosu_find_thread_and_upgrade(nhook_manager->pid)))
		return GET_ERR(NHOOK_NOSU_FIND_THREAD_AND_UPGRADE_ERROR);

	DWORD old_protect;
	void *old_protect_addr = ntu_malloc(sizeof(old_protect));
	if (old_protect_addr == NULL) {
		ret = GET_ERR(NHOOK_NTU_MALLOC_ERROR);
		goto nh_install_return;
	}

	void *mem = nhook->mem;
	uint16_t sleep_gadget = SLEEP_OPCODE;

	ret = ntu_read_memory(function, mem, 2);
	if (HAS_ERR(ret))
		goto nh_install_return;

	int8_t count = cs_disasm(handle, mem, 2, (uint64_t)mem, 2, &insn);

	uint8_t affected_length;
	if (count == 1 && insn[0].size == 1) {
		int8_t i;
		for (i = 2; i < 15; i++) {
			ret = ntu_read_memory(function + i, mem + i, 1);
			if (HAS_ERR(ret))
				goto nh_install_return;

			count = cs_disasm(handle, mem + 1, i, (uint64_t)mem + 1,
					  1, &insn);
			if (count > 0)
				break;
		}

		affected_length = i + 1;
	} else if (count == 0) {
		int8_t i;
		for (i = 2; i < 15; i++) {
			ret = ntu_read_memory(function + i, mem + i, 1);
			if (HAS_ERR(ret))
				goto nh_install_return;

			count = cs_disasm(handle, mem, i + 1, (uint64_t)mem, 1,
					  &insn);

			if (count > 0)
				break;
		}

		affected_length = i + 1;
	} else
		affected_length = 2;

	cs_close(&handle);

	nh_virtual_protect(function, affected_length, PAGE_EXECUTE_READWRITE,
			   old_protect_addr);

	ret = ntu_read_memory(old_protect_addr, &old_protect,
			      sizeof(old_protect));
	if (HAS_ERR(ret))
		goto nh_install_return;

	ret = ntu_write_with_memset_dest(function, &sleep_gadget,
					 sizeof(sleep_gadget), mem);
	if (HAS_ERR(ret))
		goto nh_install_return;

	nh_virtual_protect(function, affected_length, old_protect,
			   old_protect_addr);
	ntu_free(old_protect_addr);

	nhook->affected_length = affected_length;

nh_install_return:
	ntu_destroy();
nh_install_return_without_ntu_destroy:
	NMUTEX_UNLOCK(mutex);
	return ret;
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

void NTHREAD_API nh_get_reg_args(uint8_t arg_count, void **args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

#ifdef NTU_GLOBAL_CC
	ntucc_t sel_cc = NTU_GLOBAL_CC;
#else /* ifdnef NTU_GLOBAL_CC */
	ntucc_t sel_cc = ntutils->sel_cc;
#endif /* ifndef NTU_GLOBAL_CC */

	for (int8_t i = 0; i < 8 && i < arg_count; i++) {
		int8_t reg_index = NTUCC_GET_ARG(sel_cc, i);
		if (reg_index == 0)
			continue;

		nthread_reg_offset_t off =
			NTHREAD_REG_INDEX_TO_OFFSET(reg_index);

		args[i] = NTHREAD_GET_OREG(nthread, off);
	}
}

nerror_t NTHREAD_API nh_get_args(uint8_t arg_count, void **args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	RET_ERR(nthread_get_regs(nthread));

#ifdef NTU_GLOBAL_CC
	ntucc_t sel_cc = NTU_GLOBAL_CC;
#else /* ifdnef NTU_GLOBAL_CC */
	ntucc_t sel_cc = ntutils->sel_cc;
#endif /* ifndef NTU_GLOBAL_CC */

#ifdef LOG_LEVEL_3
	LOG_INFO("ntu_get_args(cc=%p, nthread_id=%ld, arg_count=%d, args=%p)",
		 sel_cc, NTHREAD_GET_ID(nthread), arg_count, args);
#endif /* ifdef LOG_LEVEL_3 */

	int8_t reg_arg_count = 0;
	for (int8_t i = 0; i < 8; i++) {
		int8_t reg_index = NTUCC_GET_ARG(sel_cc, i);
		if (reg_index != 0)
			reg_arg_count++;
	}

	if (reg_arg_count > arg_count)
		reg_arg_count = arg_count;

	nh_get_reg_args(reg_arg_count, args);

	uint8_t push_arg_count = arg_count - reg_arg_count;
	if (push_arg_count > 0) {
		void *rsp = NTHREAD_GET_OREG(nthread, NTHREAD_RSP);
		void *wpos = rsp + NTUCC_GET_STACK_ADD(sel_cc);

		ntmem_t *ntmem = ntutils->stack_helper;
		NTM_SET_REMOTE(ntmem, wpos);

		nttunnel_t *nttunnel = ntu_nttunnel();
		void **push_args = (void *)ntm_pull_with_tunnel_ex(
			ntmem, nttunnel, sizeof(void *) * push_arg_count);

		uint8_t i;

		bool reverse = (sel_cc & NTUCC_REVERSE_OP) != 0;
		if (reverse) {
			for (uint8_t i = 0; i < push_arg_count; i++)
				args[reg_arg_count + i] =
					push_args[push_arg_count - i - 1];
		} else
			memcpy(args + reg_arg_count, push_args,
			       push_arg_count * sizeof(void *));
	}

	return N_OK;
}

static void nh_remove_thread(nhook_manager_t *nhook_manager, uint16_t index)
{
	void *pos = nhook_manager->threads + index;
	memcpy(pos, pos + 1, nhook_manager->thread_count - index - 1);
	CloseHandle(nhook_manager->threads[index]);
	nhook_manager->thread_count--;
}

void nh_call_dynamic_func(void *func, uint8_t arg_count, void **args);

nerror_t NHOOK_API nh_update(nhook_manager_t *nhook_manager)
{
	nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;

	uint16_t i = 0;
	while (i < nhook_manager->thread_count) {
		HANDLE thread = nhook_manager->threads[i];
		if (!GetThreadContext(thread, &ctx)) {
nh_update_remove_thread:
			nh_remove_thread(nhook_manager, i);
		} else {
			void *rip = (void *)ctx.Rip;

			nhook_t *nhook =
				nh_find_with_function(nhook_manager, rip);

			if (nhook == NULL)
				goto nh_update_loop_end;

			ntid_t tid = GetThreadId(thread);

			if (HAS_ERR(nosu_attach(tid)))
				goto nh_update_remove_thread;

#ifdef NTU_GLOBAL_CC
			ntu_set_cc();
#endif /* ifdef NTU_GLOBAL_CC */

			uint8_t arg_count = nhook->arg_count;
			void **args = N_ALLOC(sizeof(void *) * arg_count);
			if (HAS_ERR(nh_get_args(arg_count, args)))
				goto nh_update_remove_thread;

			void *func = nhook->hook_function;

			nh_call_dynamic_func(func, arg_count, args);

			ntu_destroy();

			void *ret_addr = nosu_push_addr + 1;
			ctx.Rip = (DWORD64)ret_addr;
			if (!SetThreadContext(thread, &ctx))
				goto nh_update_remove_thread;

nh_update_loop_end:
			i++;
		}
	}

	NMUTEX_UNLOCK(mutex);
	return N_OK;
}

void NHOOK_API nh_destroy(nhook_manager_t *nhook_manager)
{
	if (nhook_manager == NULL)
		return;

	for (uint16_t i = 0; i < nhook_manager->max_hook_count; i++) {
		nhook_t *nhook = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		nh_uninstall(nhook_manager, nhook);
	}

	if (nhook_manager->mutex != NULL) {
		NMUTEX_DESTROY(nhook_manager->mutex);
		nhook_manager->mutex = NULL;
	}

	if (nhook_manager->threads != NULL) {
		N_FREE(nhook_manager->threads);
		nhook_manager->threads = NULL;
	}

	N_FREE(nhook_manager);
}

void my_wait_for_single_object(void *addr1, void *addr2)
{
	LOG_INFO("addr1=%p", addr1);
	LOG_INFO("addr2=%p", addr2);
}

void NHOOK_API test()
{
	ntid_t tid = nosu_dummy_thread();

	HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
	if (thread == NULL) {
		LOG_INFO("OpenThread failed");
		nosu_kill_dummy(tid);
		return;
	}

	DWORD pid = GetProcessIdOfThread(thread);

	nhook_manager_t *man = nh_create_manager(pid, 8);
	if (man == NULL) {
		LOG_ERROR("nh_create_manager failed");
		nosu_kill_dummy(tid);
		return;
	}

	if (HAS_ERR(nh_register_working_threads(man))) {
		LOG_INFO("nh_register_working_threads failed");
		nosu_kill_dummy(tid);
		return;
	}

	void *mod = nh_get_kernel32_base();
	void *func = GetProcAddress(mod, "WaitForSingleObject");

	LOG_INFO("error=%d",
		 nh_install(man, func, (void *)my_wait_for_single_object, 2));
	while (true) {
		nh_update(man);
		Sleep(10);
	}
}
