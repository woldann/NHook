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

#include "hook.h"
#include "nerror.h"
#include "trampoline.h"
#include "thread.h"
#include "manager.h"

#include "ntosutils.h"

#include <capstone/capstone.h>

bool NHOOK_API nh_is_enabled_ex(nhook_t *nhook)
{
	return (nhook->flags & NHOOK_FLAG_ENABLED) != 0;
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

	nhook->affected_length = 0;
	nhook->flags = 0;

	nhook->tramp = nh_trampoline_init();
	if (nhook->tramp == NULL) {
		ret = GET_ERR(NHOOK_TRAMPOLINE_INIT_ERROR);
		nh_destroy_ex(nhook_manager, nhook);
		goto nh_install_return;
	}

	nhook->function = function;
	nhook->hook_function = hook_function;
	nhook->arg_count = arg_count;
	ret = N_OK;

#ifndef NTU_GLOBAL_CC
	nhook->cc = NTUCC_DEFAULT_CC;
#endif /* ifndef NTU_GLOBAL_CC */

nh_install_return:
	NMUTEX_UNLOCK(mutex);
	return ret;
}

nerror_t NHOOK_API nh_create_with_mem(nhook_manager_t *nhook_manager,
				      void *function, void *hook_function,
				      uint8_t arg_count, void *mem)
{
	nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	ret = nh_create(nhook_manager, function, hook_function, arg_count);
	if (!HAS_ERR(ret)) {
		nhook_t *nhook = nh_find(nhook_manager, hook_function);

		csh handle;
		cs_insn *insn;

		cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
		if (err != CS_ERR_OK) {
			ret = GET_ERR(NHOOK_CS_OPEN_ERROR);
			goto nh_create_with_mem_return;
		}

		err = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		if (err != CS_ERR_OK) {
			ret = GET_ERR(NHOOK_CS_OPTION_ERROR);
			goto nh_enable_ex_cs_close_and_return;
		}

		int8_t i;
		int8_t count =
			cs_disasm(handle, mem, 16, (uint64_t)mem, 2, &insn);

		size_t affected_length = 0;
		for (i = 0; i < count; i++) {
			if (!nh_trampoline_add_insn(nhook->tramp, insn + i)) {
				ret = GET_ERR(NHOOK_ADD_INSN_ERROR);
				goto nh_enable_ex_cs_close_and_return;
			}

			affected_length += insn[i].size;
		}

		nhook->affected_length = affected_length;
		memcpy(nhook->mem, mem, affected_length);

		nhook->flags |= NHOOK_FLAG_ENABLED;

nh_enable_ex_cs_close_and_return:
		cs_close(&handle);
	}

nh_create_with_mem_return:
	NMUTEX_UNLOCK(mutex);
	return ret;
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
		if (HAS_ERR(suspend_threads(nhook_manager))) {
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

	resume_threads(nhook_manager);

	if (fu == FORCE_NTUTILS_NEW)
		ntu_destroy();
}

BOOL nh_virtual_protect(LPVOID lpAddress, SIZE_T dwSize,
				  DWORD flNewProtect, PDWORD lpflOldProtect);

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

	ret = suspend_threads(nhook_manager);
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

	err = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	if (err != CS_ERR_OK) {
		ret = GET_ERR(NHOOK_CS_OPTION_ERROR);

nh_enable_ex_cs_close_and_return:
		cs_close(&handle);
		goto nh_enable_ex_resume_return;
	}

	ret = ntu_read_memory(func, mem, 2);
	if (HAS_ERR(ret))
		goto nh_enable_ex_cs_close_and_return;

	int8_t count = cs_disasm(handle, mem, 2, (uint64_t)mem, 2, &insn);
	if (count == 1) {
		if (!nh_trampoline_add_insn(nhook->tramp, insn))
			goto nh_enable_ex_add_insn_error;

		if (insn[0].size == 1) {
			int8_t i;
			for (i = 2; i < 15; i++) {
				ret = ntu_read_memory(func + i, mem + i, 1);
				if (HAS_ERR(ret))
					goto nh_enable_ex_cs_close_and_return;

				count = cs_disasm(handle, mem + 1, i,
						  (uint64_t)mem + 1, 1, &insn);

				if (count > 0) {
					if (!nh_trampoline_add_insn(nhook->tramp, insn))
						goto nh_enable_ex_add_insn_error;

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
				if (!nh_trampoline_add_insn(nhook->tramp, insn)) {
nh_enable_ex_add_insn_error:
					ret = GET_ERR(NHOOK_ADD_INSN_ERROR);
					goto nh_enable_ex_cs_close_and_return;
				}

				break;
			}
		}

		len = i + 1;
	} else {
		if (!nh_trampoline_add_insn(nhook->tramp, insn))
			goto nh_enable_ex_add_insn_error;

		if (!nh_trampoline_add_insn(nhook->tramp, insn + 1))
			goto nh_enable_ex_add_insn_error;
		len = 2;
	}

	cs_close(&handle);
	nhook->affected_length = len;

nh_enable_ex_read_mem_end:
	transfer_threads(nhook_manager, nhook);

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
	resume_threads(nhook_manager);

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
	nerror_t ret = N_OK;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	int8_t fu = FORCE_NTUTILS_FAIL;

	uint16_t i;
	uint16_t count = nhook_manager->max_hook_count;
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

		ret = nh_enable_ex(nhook_manager, nhook);
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

	ret = suspend_threads(nhook_manager);
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
	resume_threads(nhook_manager);
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
	nerror_t ret = N_OK;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	int8_t fu = FORCE_NTUTILS_FAIL;

	uint16_t i;
	uint16_t count = nhook_manager->max_hook_count;
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

		ret = nh_disable_ex(nhook_manager, nhook);
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
	nh_trampoline_destroy(nhook->tramp);
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
