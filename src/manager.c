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

#include "core.h"
#include "thread.h"
#include "trampoline.h"

#include "nmem.h"
#include "ntosutils.h"

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

	reset_threads(manager, false);

	uint16_t i;
	for (i = 0; i < max_hook_count; i++) {
		nhook_t *hook = NHOOK_MANAGER_GET_HOOK(manager, i);
		NHOOK_SET_INVALID(hook);
	}

	return manager;
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

	reset_threads(nhook_manager, true);
	N_FREE(nhook_manager);
}

void *call_dynamic_func(void *func, uint8_t arg_count, void **args);

nh_nerror_t NHOOK_API nh_update(nhook_manager_t *nhook_manager)
{
	nh_nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;

	ret = update_threads(nhook_manager);
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
			if (HAS_ERR(ntu_get_args(arg_count, args)))
				goto nh_update_remove_thread;

			void *func = nhook->hook_function;

			void *ret_value =
				call_dynamic_func(func, arg_count, args);

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

void *nh_trampoline_v(nhook_manager_t *nhook_manager, void *hook_function,
		      va_list args)
{
	nhook_t *nhook = nh_find(nhook_manager, hook_function);
	if (nhook == NULL)
		return NULL;

	return nh_trampoline_ex(nhook_manager, nhook, nhook->tramp, args);
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