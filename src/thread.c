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

#include "ntosutils.h"
#include "nmem.h"

static uint16_t get_ignored_ids(ntid_t *ignored_ids)
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

nerror_t transfer_threads(nhook_manager_t *nhook_manager, nhook_t *nhook)
{
	HANDLE *threads = nhook_manager->threads;
	HANDLE thread;

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;

	void *pos = (void *)((uint64_t)nhook->function + 1);
	void *rip;

	uint16_t i;
	uint16_t count = nhook_manager->thread_count;
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

		ctx.Rip = (DWORD64)((uint64_t)pos - 1);
		if (SetThreadContext(thread, &ctx)) {
nh_transfer_threads_remove_thread:
			threads[i] = NULL;
		}
	}

	return N_OK;
}

void reset_threads(nhook_manager_t *nhook_manager, bool free_addresses)
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

nerror_t resume_threads(nhook_manager_t *nhook_manager)
{
	nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	if (nhook_manager->suspend_count == 0) {
		ret = N_OK;
		goto resume_threads_return_without_check;
	}

	uint16_t n_id_count = nhook_manager->thread_count;

	HANDLE *threads = nhook_manager->threads;
	HANDLE thread;

	ntid_t *n_ids = nhook_manager->n_thread_ids;

	ntid_t ignored_ids[NHOOK_MAX_IGNORED_ID_COUNT];
	size_t ignored_ids_size = get_ignored_ids(ignored_ids) * sizeof(ntid_t);

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

	if (!HAS_ERR(ret))
		nhook_manager->suspend_count--;

resume_threads_return_without_check:

	NMUTEX_UNLOCK(mutex);
	return ret;
}

nerror_t suspend_threads(nhook_manager_t *nhook_manager)
{
	nerror_t ret;

	NMUTEX mutex = nhook_manager->mutex;
	NMUTEX_LOCK(mutex);

	if (nhook_manager->suspend_count > 0) {
		ret = N_OK;
		goto suspend_threads_return;
	}

	ret = update_threads(nhook_manager);
	if (HAS_ERR(ret))
		goto suspend_threads_return;

	uint16_t o_id_count;
	uint16_t n_id_count = nhook_manager->thread_count;

	HANDLE *threads = nhook_manager->threads;
	HANDLE thread;

	ntid_t ignored_ids[NHOOK_MAX_IGNORED_ID_COUNT];
	size_t ignored_ids_size = get_ignored_ids(ignored_ids) * sizeof(ntid_t);

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
		ret = update_threads(nhook_manager);
		if (HAS_ERR(ret)) {
			resume_threads(nhook_manager);
			goto suspend_threads_return;
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

suspend_threads_return:

	if (!HAS_ERR(ret))
		nhook_manager->suspend_count++;

	NMUTEX_UNLOCK(mutex);
	return ret;
}

nerror_t update_threads(nhook_manager_t *nhook_manager)
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
		reset_threads(nhook_manager, true);
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
		memset(((uint8_t *)threads) + o_threads_size, 0, s);
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

		uint16_t j = ((uint64_t)addr - (uint64_t)n_ids) / sizeof(ntid_t);
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
