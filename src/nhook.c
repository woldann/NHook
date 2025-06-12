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
#include "nthread.h"
#include "ntmem.h"

#include "ntutils.h"
#include <capstone/capstone.h>

#include "trampoline.h"

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

bool NHOOK_API nh_is_enabled_ex(nhook_t *nhook)
{
	return (nhook->flags & NHOOK_FLAG_ENABLED) != 0;
}

bool NHOOK_API nh_is_enabled(nhook_manager_t *nhook_manager,
			     void *hook_function)
{
	nhook_t *nhook = nh_find(nhook_manager, hook_function);
	if (nhook == NULL)
		return false;

	return nh_is_enabled_ex(nhook);
}

nhook_t *NHOOK_API nh_find_with_function(nhook_manager_t *nhook_manager,
					 void *function)
{
	uint16_t i;
	for (i = 0; i < nhook_manager->max_hook_count; i++) {
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
	uint16_t i;
	for (i = 0; i < nhook_manager->max_hook_count; i++) {
		nhook_t *nhook = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		if (!NHOOK_IS_VALID(nhook))
			continue;

		if (nhook->hook_function == hook_function)
			return nhook;
	}

	return NULL;
}

static void nh_reset_threads(nhook_manager_t *nhook_manager,
			     bool free_addresses)
{
	if (free_addresses) {
		ntid_t *o_thread_ids = nhook_manager->o_thread_ids;
		if (o_thread_ids != NULL)
			N_FREE(o_thread_ids);

		ntid_t *n_thread_ids = nhook_manager->n_thread_ids;
		if (n_thread_ids != NULL)
			N_FREE(n_thread_ids);

		HANDLE *threads = nhook_manager->threads;
		if (threads != NULL) {
			uint16_t count = nhook_manager->thread_count;
			uint16_t i;
			for (i = 0; i < count; i++)
				CloseHandle(threads[i]);

			N_FREE(threads);
		}
	}

	nhook_manager->o_thread_ids = NULL;
	nhook_manager->n_thread_ids = NULL;
	nhook_manager->threads = NULL;

	nhook_manager->thread_ids_size = 0;
	nhook_manager->thread_count = 0;
}

nhook_manager_t *NHOOK_API nh_create_manager(DWORD pid, uint16_t max_hook_count)
{
	size_t mem_len =
		sizeof(nhook_manager_t) + sizeof(nhook_t) * max_hook_count;

	NMUTEX mutex;
	NMUTEX_INIT(mutex);
	if (mutex == NULL)
		return NULL;

	nhook_manager_t *manager = N_ALLOC(mem_len);
	if (manager == NULL) {
		NMUTEX_DESTROY(mutex);
		return NULL;
	}

	manager->max_hook_count = max_hook_count;
	manager->pid = pid;
	manager->mutex = mutex;
	manager->suspend_count = 0;

	nh_reset_threads(manager, false);

	uint16_t i;
	for (i = 0; i < max_hook_count; i++) {
		nhook_t *hook = NHOOK_MANAGER_GET_HOOK(manager, i);
		NHOOK_SET_INVALID(hook);
	}

	return manager;
}

nerror_t NHOOK_API nh_create(nhook_manager_t *nhook_manager, void *function,
			     void *hook_function, uint8_t arg_count)
{
	nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	nhook_t *nhook = NULL;

	uint16_t i;
	for (i = 0; i < nhook_manager->max_hook_count; i++) {
		nhook_t *nh = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		if (!NHOOK_IS_VALID(nh)) {
			nhook = nh;
			break;
		}
	}

	if (nhook == NULL) {
		ret = GET_ERR(NHOOK_MAX_HOOK_ERROR);
		goto nh_install_return;
	}

	nhook->function = function;
	nhook->hook_function = hook_function;
	nhook->arg_count = arg_count;
	nhook->affected_length = 0;
	nhook->flags = 0;
	ret = N_OK;

#ifndef NTU_GLOBAL_CC
	nhook->cc = NTUCC_DEFAULT_CC;
#endif /* ifndef NTU_GLOBAL_CC */

nh_install_return:
	NMUTEX_UNLOCK(mutex);
	return ret;
}

uint16_t NHOOK_API nh_manager_get_enabled_count(nhook_manager_t *nhook_manager)
{
	uint16_t count = 0;

	uint16_t max_count = nhook_manager->max_hook_count;
	uint16_t i;
	for (i = 0; i < max_count; i++) {
		nhook_t *nhook = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		if (!NHOOK_IS_VALID(nhook))
			continue;

		if (nh_is_enabled_ex(nhook))
			count++;
	}

	return count;
}

uint16_t NHOOK_API nh_manager_get_count(nhook_manager_t *nhook_manager)
{
	uint16_t count = 0;

	uint16_t max_count = nhook_manager->max_hook_count;
	uint16_t i;
	for (i = 0; i < max_count; i++) {
		nhook_t *nhook = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		if (!NHOOK_IS_VALID(nhook))
			continue;

		count++;
	}

	return count;
}

static nerror_t nh_transfer_threads(nhook_manager_t *nhook_manager,
				    nhook_t *nhook)
{
	HANDLE *threads = nhook_manager->threads;
	HANDLE thread;

	CONTEXT ctx;
	void *rip;

	void *pos = nhook->function + 1;

	uint16_t count = nhook_manager->thread_count;
	uint16_t i;
	for (i = 0; i < count; i++) {
		thread = threads[i];
		if (thread == NULL)
			continue;

		if (!GetThreadContext(thread, &ctx))
			goto nh_transfer_threads_remove_thread;

		rip = (void *)ctx.Rip;
		if (rip != pos)
			continue;

		// TODO

		ctx.Rip = (DWORD64)(pos - 1);
		if (SetThreadContext(thread, &ctx)) {
nh_transfer_threads_remove_thread:
			threads[i] = NULL;
		}
	}

	return N_OK;
}

#define FORCE_NTUTILS_FAIL 0
#define FORCE_NTUTILS_OK 1
#define FORCE_NTUTILS_NEW 2

static int8_t nh_force_ntutils(nhook_manager_t *nhook_manager)
{
	int8_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	if (ntu_get() != NULL)
		ret = FORCE_NTUTILS_OK;
	else {
		DWORD pid = nhook_manager->pid;
		if (HAS_ERR(nosu_find_thread_and_upgrade(pid)))
			ret = FORCE_NTUTILS_FAIL;
		else
			ret = FORCE_NTUTILS_NEW;
	}

	NMUTEX_UNLOCK(mutex);
	return ret;
}

static int8_t nh_toggle_init(nhook_manager_t *nhook_manager)
{
	int8_t ret = nh_force_ntutils(nhook_manager);
	if (ret != FORCE_NTUTILS_FAIL) {
		if (HAS_ERR(nh_suspend_threads(nhook_manager))) {
			if (ret == FORCE_NTUTILS_NEW)
				ntu_destroy();

			return FORCE_NTUTILS_FAIL;
		}
	}

	return ret;
}

static void nh_toggle_destroy(nhook_manager_t *nhook_manager, int8_t fu)
{
	if (fu == FORCE_NTUTILS_FAIL)
		return;

	nh_resume_threads(nhook_manager);

	if (fu == FORCE_NTUTILS_NEW)
		ntu_destroy();
}

nerror_t NHOOK_API nh_enable_ex(nhook_manager_t *nhook_manager, nhook_t *nhook)
{
	nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	if (nh_is_enabled_ex(nhook)) {
		ret = N_OK;
		goto nh_enable_ex_return_without_fc;
	}

	int8_t fu = nh_toggle_init(nhook_manager);
	if (fu == FORCE_NTUTILS_FAIL) {
		ret = GET_ERR(NHOOK_NH_TOGGLE_INIT_ERROR);
		goto nh_enable_ex_return_without_free;
	}

	DWORD old_protect;
	void *old_protect_addr = ntu_malloc(sizeof(old_protect));
	if (old_protect_addr == NULL) {
		ret = GET_ERR(NHOOK_NTU_MALLOC_ERROR);
		goto nh_enable_ex_return;
	}

	void *func = nhook->function;
	uint8_t len = nhook->affected_length;
	void *mem = nhook->mem;

	ret = nh_suspend_threads(nhook_manager);
	if (HAS_ERR(ret))
		goto nh_enable_ex_return;

	if (len != 0)
		goto nh_enable_ex_read_mem_end;

	csh handle;
	cs_insn *insn;

	cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	if (err != CS_ERR_OK) {
		ret = GET_ERR(NHOOK_CS_OPEN_ERROR);
		goto nh_enable_ex_resume_return;
	}

	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
		ret = GET_ERR(NHOOK_CS_DETAIL_ERROR);
		goto nh_enable_ex_cs_close_and_return;
	}

	ret = ntu_read_memory(func, mem, 2);
	if (HAS_ERR(ret)) {
nh_enable_ex_cs_close_and_return:
		cs_close(&handle);
		goto nh_enable_ex_resume_return;
	}

	nhook->tramp = trampoline_init();
	if (nhook->tramp == NULL) {
		ret = GET_ERR(NHOOK_TRAMPOLINE_INIT_ERROR);
		goto nh_enable_ex_cs_close_and_return;
	}

	int8_t count = cs_disasm(handle, mem, 2, (uint64_t)mem, 2, &insn);
	if (count == 1) {
		if (!add_insn(nhook->tramp, insn))
			goto nh_enable_ex_cs_close_and_return;

		if (insn[0].size == 1) {
			int8_t i;
			for (i = 2; i < 15; i++) {
				ret = ntu_read_memory(func + i, mem + i, 1);
				if (HAS_ERR(ret))
					goto nh_enable_ex_cs_close_and_return;

				count = cs_disasm(handle, mem + 1, i,
						  (uint64_t)mem + 1, 1, &insn);

				if (count > 0) {
					if (!add_insn(nhook->tramp, insn))
						goto nh_enable_ex_cs_close_and_return;

					break;
				}
			}
			len = i + 1;
		} else
			len = 2;
	} else if (count == 0) {
		int8_t i;
		for (i = 2; i < 15; i++) {
			ret = ntu_read_memory(func + i, mem + i, 1);
			if (HAS_ERR(ret))
				goto nh_enable_ex_cs_close_and_return;

			count = cs_disasm(handle, mem, i + 1, (uint64_t)mem, 1,
					  &insn);

			if (count > 0) {
				if (!add_insn(nhook->tramp, insn))
					goto nh_enable_ex_cs_close_and_return;

				break;
			}
		}

		len = i + 1;
	} else {
		if (!add_insn(nhook->tramp, insn))
			goto nh_enable_ex_cs_close_and_return;

		if (!add_insn(nhook->tramp, insn + 1))
			goto nh_enable_ex_cs_close_and_return;
		len = 2;
	}

	cs_close(&handle);
	nhook->affected_length = len;

	nh_transfer_threads(nhook_manager, nhook);

nh_enable_ex_read_mem_end:
	nh_virtual_protect(func, len, PAGE_EXECUTE_READWRITE, old_protect_addr);

	ret = ntu_read_memory(old_protect_addr, &old_protect,
			      sizeof(old_protect));

	if (HAS_ERR(ret))
		goto nh_enable_ex_resume_return;

	uint16_t sleep_gadget = SLEEP_OPCODE;
	ret = ntu_write_with_memset_dest(func, &sleep_gadget,
					 sizeof(sleep_gadget), mem);

	if (HAS_ERR(ret))
		goto nh_enable_ex_resume_return;

	nh_virtual_protect(func, len, old_protect, old_protect_addr);

	nhook->flags |= NHOOK_FLAG_ENABLED;

nh_enable_ex_resume_return:
	nh_resume_threads(nhook_manager);

nh_enable_ex_return:
	ntu_free(old_protect_addr);

nh_enable_ex_return_without_free:
	nh_toggle_destroy(nhook_manager, fu);

nh_enable_ex_return_without_fc:
	NMUTEX_UNLOCK(mutex);
	return ret;
}

nerror_t NHOOK_API nh_enable(nhook_manager_t *nhook_manager,
			     void *hook_function)
{
	nhook_t *nhook = nh_find(nhook_manager, hook_function);
	if (nhook == NULL)
		return GET_ERR(NHOOK_FIND_ERROR);

	return nh_enable_ex(nhook_manager, nhook);
}

nerror_t NHOOK_API nh_enable_all(nhook_manager_t *nhook_manager)
{
	nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	int8_t fu = FORCE_NTUTILS_FAIL;

	uint16_t count = nhook_manager->max_hook_count;
	uint16_t i;
	for (i = 0; i < count; i++) {
		nhook_t *nhook = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		if (!NHOOK_IS_VALID(nhook))
			continue;

		if (fu == FORCE_NTUTILS_FAIL && !nh_is_enabled_ex(nhook)) {
			fu = nh_toggle_init(nhook_manager);
			if (fu == FORCE_NTUTILS_FAIL) {
				ret = GET_ERR(NHOOK_NH_TOGGLE_INIT_ERROR);
				break;
			}
		}

		nerror_t ret = nh_enable_ex(nhook_manager, nhook);
		if (HAS_ERR(ret))
			break;
	}

	nh_toggle_destroy(nhook_manager, fu);
	NMUTEX_UNLOCK(mutex);
	return ret;
}

nerror_t NHOOK_API nh_disable_ex(nhook_manager_t *nhook_manager, nhook_t *nhook)
{
	nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	if (!nh_is_enabled_ex(nhook)) {
		ret = N_OK;
		goto nh_disable_ex_return_without_fc;
	}

	int8_t fu = nh_toggle_init(nhook_manager);
	if (fu == FORCE_NTUTILS_FAIL) {
		ret = GET_ERR(NHOOK_NH_TOGGLE_INIT_ERROR);
		goto nh_disable_ex_return_without_free;
	}

	DWORD old_protect;
	void *old_protect_addr = ntu_malloc(sizeof(old_protect));
	if (old_protect_addr == NULL) {
		ret = GET_ERR(NHOOK_NTU_MALLOC_ERROR);
		goto nh_disable_ex_return;
	}

	ret = nh_suspend_threads(nhook_manager);
	if (HAS_ERR(ret))
		goto nh_disable_ex_return;

	void *func = nhook->function;
	size_t len = 2;

	nh_virtual_protect(func, len, PAGE_EXECUTE_READWRITE, old_protect_addr);

	ret = ntu_read_memory(old_protect_addr, &old_protect,
			      sizeof(old_protect));

	if (HAS_ERR(ret))
		goto nh_disable_ex_resume_return;

	uint16_t sleep_gadget = SLEEP_OPCODE;
	ret = ntu_write_with_memset_dest(func, nhook->mem, len, &sleep_gadget);
	if (HAS_ERR(ret))
		goto nh_disable_ex_resume_return;

	nh_virtual_protect(func, len, old_protect, old_protect_addr);

	nhook->flags &= ~(NHOOK_FLAG_ENABLED);

nh_disable_ex_resume_return:
	nh_resume_threads(nhook_manager);
nh_disable_ex_return:
	ntu_free(old_protect_addr);

nh_disable_ex_return_without_free:
	nh_toggle_destroy(nhook_manager, fu);

nh_disable_ex_return_without_fc:
	NMUTEX_UNLOCK(mutex);
	return ret;
}

nerror_t NHOOK_API nh_disable(nhook_manager_t *nhook_manager,
			      void *hook_function)
{
	nhook_t *nhook = nh_find(nhook_manager, hook_function);
	if (nhook == NULL)
		return GET_ERR(NHOOK_FIND_ERROR);

	return nh_disable_ex(nhook_manager, nhook);
}

nerror_t NHOOK_API nh_disable_all(nhook_manager_t *nhook_manager)
{
	nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	int8_t fu = FORCE_NTUTILS_FAIL;

	uint16_t count = nhook_manager->max_hook_count;
	uint16_t i;

	for (i = 0; i < count; i++) {
		nhook_t *nhook = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		if (!NHOOK_IS_VALID(nhook))
			continue;

		if (fu == FORCE_NTUTILS_FAIL && nh_is_enabled_ex(nhook)) {
			fu = nh_toggle_init(nhook_manager);
			if (fu == FORCE_NTUTILS_FAIL) {
				ret = GET_ERR(NHOOK_NH_TOGGLE_INIT_ERROR);
				break;
			}
		}

		nerror_t ret = nh_disable_ex(nhook_manager, nhook);
		if (HAS_ERR(ret))
			break;
	}

	nh_toggle_destroy(nhook_manager, fu);
	NMUTEX_UNLOCK(mutex);
	return ret;
}

void NHOOK_API nh_destroy_ex(nhook_manager_t *nhook_manager, nhook_t *nhook)
{
	nh_disable_ex(nhook_manager, nhook);
	trampoline_destroy(nhook->tramp);
	NHOOK_SET_INVALID(nhook);
}

void NHOOK_API nh_destroy(nhook_manager_t *nhook_manager, void *hook_function)
{
	nhook_t *nhook = nh_find(nhook_manager, hook_function);
	if (nhook != NULL)
		return nh_destroy_ex(nhook_manager, hook_function);
}

void NHOOK_API nh_destroy_all(nhook_manager_t *nhook_manager)
{
	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	nh_disable_all(nhook_manager);

	uint16_t count = nhook_manager->max_hook_count;
	uint16_t i;
	for (i = 0; i < count; i++) {
		nhook_t *nhook = NHOOK_MANAGER_GET_HOOK(nhook_manager, i);
		if (!NHOOK_IS_VALID(nhook))
			continue;

		nh_destroy_ex(nhook_manager, nhook);
	}

	NMUTEX_UNLOCK(mutex);
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

	int8_t i;
	for (i = 0; i < 8 && i < arg_count; i++) {
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

	int8_t i;
	for (i = 0; i < 8; i++) {
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
			for (i = 0; i < push_arg_count; i++)
				args[reg_arg_count + i] =
					push_args[push_arg_count - i - 1];
		} else
			memcpy(args + reg_arg_count, push_args,
			       push_arg_count * sizeof(void *));
	}

	return N_OK;
}

void *NHOOK_API nh_trampoline_ex_v(nhook_manager_t *nhook_manager,
				   nhook_t *nhook, va_list args)
{
	uint8_t arg_count = nhook->arg_count;

	va_list copy;
	va_copy(copy, args);
	if (HAS_ERR(ntu_set_args_v(arg_count, copy))) {
		va_end(copy);
		return NULL;
	}
	va_end(copy);

	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	void *func = nhook->function;

	void *rsp = nthread_stack_begin(nthread);
	NTHREAD_SET_REG(nthread, NTHREAD_RSP, rsp - sizeof(func));
	NTHREAD_SET_REG(nthread, NTHREAD_RIP, func);
	trampoline_simulate_insns(nhook->tramp);

	void *rip = NTHREAD_GET_REG(nthread, NTHREAD_RIP);
	uint8_t len = nhook->affected_length;

	void *call = func + len;

	if (HAS_ERR(ntu_set_args_v(arg_count, args)))
		return NULL;

	if (rip >= func && rip < call)
		NTHREAD_SET_REG(nthread, NTHREAD_RIP, call);

	if (HAS_ERR(nthread_set_regs(nthread)))
		return NULL;
	if (HAS_ERR(nthread_wait(nthread)))
		return NULL;

	return NTHREAD_GET_REG(nthread, NTHREAD_RAX);
}

void *NHOOK_API nh_trampoline_ex(nhook_manager_t *nhook_manager, nhook_t *nhook,
				 ...)
{
	va_list args;
	va_start(args, nhook);

	void *ret = nh_trampoline_ex_v(nhook_manager, nhook, args);

	va_end(args);
	return ret;
}

void *NHOOK_API nh_trampoline_v(nhook_manager_t *nhook_manager,
				void *hook_function, va_list args)
{
	nhook_t *nhook = nh_find(nhook_manager, hook_function);
	if (nhook == NULL)
		return NULL;

	return nh_trampoline_ex_v(nhook_manager, nhook, args);
}

void *NHOOK_API nh_trampoline(nhook_manager_t *nhook_manager,
			      void *hook_function, ...)
{
	va_list args;
	va_start(args, hook_function);

	void *ret = nh_trampoline_v(nhook_manager, hook_function, args);

	va_end(args);
	return ret;
}

static nerror_t nh_update_threads(nhook_manager_t *nhook_manager)
{
	nerror_t ret = N_OK;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	DWORD pid = nhook_manager->pid;

	ntid_t *o_ids = nhook_manager->o_thread_ids;
	ntid_t *n_ids = nhook_manager->n_thread_ids;

	size_t n_ids_size = nhook_manager->thread_ids_size;
	size_t o_ids_size = n_ids_size;

	uint16_t o_id_count = nhook_manager->thread_count;
	size_t o_real_size = o_id_count * sizeof(ntid_t);

	int8_t scale = (sizeof(HANDLE) / sizeof(ntid_t));
	size_t o_threads_size = o_ids_size * scale;

	memcpy(o_ids, n_ids, o_real_size);

	uint16_t n_id_count = nosu_get_threads_ex(pid, &n_ids, &n_ids_size);
	if (n_id_count == 0) {
		nh_reset_threads(nhook_manager, true);
		goto nh_update_threads_return;
	}

	size_t n_real_size = n_id_count * sizeof(ntid_t);

	HANDLE *threads = nhook_manager->threads;
	size_t n_threads_size = n_ids_size * scale;

	if (n_threads_size > o_threads_size) {
		o_ids = N_REALLOC(o_ids, n_ids_size);
		threads = N_REALLOC(threads, n_threads_size);

		if (o_ids == NULL || threads == NULL)
			goto nh_update_threads_realloc_error;

		size_t s = n_threads_size - o_threads_size;
		memset(((void *)threads) + o_threads_size, 0, s);
	}

	uint16_t i;
	for (i = 0; i < o_id_count; i++) {
		ntid_t id = o_ids[i];

		void *addr = memmem_n(n_ids, n_real_size, &id, sizeof(id));
		HANDLE thread = threads[i];
		if (addr == NULL) {
			threads[i] = NULL;
			CloseHandle(thread);
			continue;
		}

		uint16_t j = ((size_t)addr - (size_t)n_ids) / sizeof(ntid_t);
		ntid_t n_id = n_ids[i];
		n_ids[j] = n_id;
		n_ids[i] = id;
	}

	size_t n_real_threads_size = n_real_size * scale;

	if (n_ids_size >= n_real_size + 8192) {
		n_ids = N_REALLOC(n_ids, n_real_threads_size);
		threads = N_REALLOC(threads, n_real_threads_size);

		if (n_ids == NULL || threads == NULL) {
nh_update_threads_realloc_error:
			ret = GET_ERR(NHOOK_REALLOC_ERROR);
			goto nh_update_threads_return;
		}
	}

	for (i = o_id_count; i < n_id_count; i++)
		threads[i] = OpenThread(NTHREAD_ACCESS, false, n_ids[i]);

	nhook_manager->thread_count = n_id_count;
	nhook_manager->thread_ids_size = n_ids_size;
	nhook_manager->threads = threads;
	nhook_manager->n_thread_ids = n_ids;
	nhook_manager->o_thread_ids = o_ids;

nh_update_threads_return:
	NMUTEX_UNLOCK(mutex);
	return ret;
}

#define NHOOK_MAX_IGNORED_ID_COUNT 2

static uint16_t nh_get_ignored_ids(ntid_t *ignored_ids)
{
	uint16_t count = 0;
	register ntid_t id;

	id = GetCurrentThreadId();
	ignored_ids[count++] = id;

	ntutils_t *ntutils = ntu_get();
	if (ntutils != NULL) {
		id = NTHREAD_GET_ID(&ntutils->nthread);
		if (id != 0)
			ignored_ids[count++] = id;
	}

	return count;
}

nerror_t NHOOK_API nh_resume_threads(nhook_manager_t *nhook_manager)
{
	nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	if (nhook_manager->suspend_count == 0) {
		ret = N_OK;
		goto nh_resume_threads_return_without_check;
	}

	uint16_t n_id_count = nhook_manager->thread_count;

	HANDLE *threads = nhook_manager->threads;
	HANDLE thread;

	ntid_t *n_ids = nhook_manager->n_thread_ids;

	ntid_t ignored_ids[NHOOK_MAX_IGNORED_ID_COUNT];
	size_t ignored_ids_size =
		nh_get_ignored_ids(ignored_ids) * sizeof(ntid_t);

	uint16_t i;
	for (i = 0; i < n_id_count; i++) {
		ntid_t id = n_ids[i];
		if (memmem_n(ignored_ids, ignored_ids_size, &id, sizeof(id)) !=
		    NULL)
			continue;

		thread = threads[i];
		if (thread == NULL)
			continue;

		if (ResumeThread(thread) == (DWORD)(-1)) {
			CloseHandle(thread);
			threads[i] = NULL;
		}
	}

nh_resume_threads_return:

	if (!HAS_ERR(ret))
		nhook_manager->suspend_count--;

nh_resume_threads_return_without_check:

	NMUTEX_UNLOCK(mutex);
	return ret;
}

nerror_t NHOOK_API nh_suspend_threads(nhook_manager_t *nhook_manager)
{
	nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	if (nhook_manager->suspend_count > 0) {
		ret = N_OK;
		goto nh_suspend_threads_return;
	}

	ret = nh_update_threads(nhook_manager);
	if (HAS_ERR(ret))
		goto nh_suspend_threads_return;

	uint16_t o_id_count;
	uint16_t n_id_count = nhook_manager->thread_count;

	HANDLE *threads = nhook_manager->threads;
	HANDLE thread;

	ntid_t ignored_ids[NHOOK_MAX_IGNORED_ID_COUNT];
	size_t ignored_ids_size =
		nh_get_ignored_ids(ignored_ids) * sizeof(ntid_t);

	ntid_t *n_ids = nhook_manager->n_thread_ids;

	uint16_t i;
	for (i = 0; i < n_id_count; i++) {
		ntid_t id = n_ids[i];
		if (memmem_n(ignored_ids, ignored_ids_size, &id, sizeof(id)) !=
		    NULL)
			continue;

		thread = threads[i];
		if (thread == NULL)
			continue;

		if (SuspendThread(thread) == (DWORD)(-1)) {
			CloseHandle(thread);
			threads[i] = NULL;
		}
	}

	bool end;

	do {
		end = true;
		o_id_count = nhook_manager->thread_count;
		ret = nh_update_threads(nhook_manager);
		if (HAS_ERR(ret)) {
			nh_resume_threads(nhook_manager);
			goto nh_suspend_threads_return;
		}

		n_ids = nhook_manager->n_thread_ids;
		n_id_count = nhook_manager->thread_count;
		threads = nhook_manager->threads;

		size_t o_ids_size = sizeof(ntid_t) * o_id_count;

		uint16_t i;
		for (i = 0; i < n_id_count; i++) {
			ntid_t id = n_ids[i];

			void *addr = memmem_n(nhook_manager->o_thread_ids,
					      o_ids_size, &id, sizeof(id));

			if (addr != NULL)
				continue;
			thread = threads[i];
			if (thread == NULL)
				continue;

			if (SuspendThread(thread) == (DWORD)(-1)) {
				CloseHandle(thread);
				threads[i] = NULL;
			}

			end = false;
		}
	} while (!end);

nh_suspend_threads_return:

	if (!HAS_ERR(ret))
		nhook_manager->suspend_count++;

	NMUTEX_UNLOCK(mutex);
	return ret;
}

void *nh_call_dynamic_func(void *func, uint8_t arg_count, void **args);

nerror_t NHOOK_API nh_update(nhook_manager_t *nhook_manager)
{
	nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;

	ret = nh_update_threads(nhook_manager);
	if (HAS_ERR(ret))
		return ret;

	uint16_t count = nhook_manager->thread_count;
	HANDLE *threads = nhook_manager->threads;

	uint16_t i = 0;
	while (i < count) {
		HANDLE thread = threads[i];
		if (thread == NULL)
			goto nh_update_loop_end;

		if (!GetThreadContext(thread, &ctx)) {
nh_update_remove_thread:
			CloseHandle(thread);
			threads[i] = NULL;
		} else {
			void *rip = (void *)ctx.Rip;

			nhook_t *nhook =
				nh_find_with_function(nhook_manager, rip);

			if (nhook == NULL)
				goto nh_update_loop_end;

			ntid_t tid = (ntid_t)GetThreadId(thread);
			if (HAS_ERR(nosu_attach(tid)))
				goto nh_update_remove_thread;

			ntutils_t *ntutils = ntu_get();
			nthread_t *nthread = &ntutils->nthread;

#ifdef NTU_GLOBAL_CC
			ntu_set_cc();
#endif /* ifdef NTU_GLOBAL_CC */

			uint8_t arg_count = nhook->arg_count;
			void **args = N_ALLOC(sizeof(void *) * arg_count);
			if (HAS_ERR(nh_get_args(arg_count, args)))
				goto nh_update_remove_thread;

			void *func = nhook->hook_function;

			void *ret_value =
				nh_call_dynamic_func(func, arg_count, args);

			void *ret_addr = nosu_push_addr + 1;

			NTHREAD_SET_OREG(nthread, NTHREAD_RIP, ret_addr);
			NTHREAD_SET_OREG(nthread, NTHREAD_RAX, ret_value);

			ntu_destroy();

nh_update_loop_end:
			i++;
		}
	}

nh_update_return:
	NMUTEX_UNLOCK(mutex);
	return ret;
}

void NHOOK_API nh_destroy_manager(nhook_manager_t *nhook_manager)
{
	if (nhook_manager == NULL)
		return;

	nh_destroy_all(nhook_manager);

	if (nhook_manager->mutex != NULL) {
		NMUTEX_DESTROY(nhook_manager->mutex);
		nhook_manager->mutex = NULL;
	}

	nh_reset_threads(nhook_manager, true);
	N_FREE(nhook_manager);
}
