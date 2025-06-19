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

#include <stdio.h>

#define STR "test str"

nhook_manager_t *man;

typedef size_t (*strlen_fn)(const char *str);
strlen_fn strlen_func;
size_t strlen_counter = 0;

size_t my_strlen(const char *str)
{
	size_t ret = (size_t)nh_trampoline(man, my_strlen, str);

	size_t len = sizeof(STR) - 1;
	if (len != ret) {
		perror("Trampoline Failed!");
		nh_disable_all(man);
	}

	printf("my_strlen(%p)=%ld\n", str, ret);

	if (strlen_counter >= 10)
		nh_disable_all(man);

	strlen_counter++;
	return ret;
}

void thread_loop()
{
	char str1[128] = STR;

	while (true) {
		size_t ret = strlen_func(str1);
		printf("strlen(%p)=%ld\n", str1, ret);
		for (uint8_t i = 0; i < 100; i++)
			Sleep(1);
	}
}

#include <capstone/capstone.h>

int main(int argc, char *argv[])
{
	void *mod = GetModuleHandleA("msvcrt.dll");
	char func_name[] = "strlen";

	strlen_func = (void *)GetProcAddress((HANDLE)mod, func_name);
	if (strlen_func == NULL) {
		printf("Error: GetProcAddress failed - Could not find %s in module %p\n",
		       func_name, mod);
		return 0x01;
	}

	DWORD pid = GetCurrentProcessId();
	man = nh_create_manager(pid, 2);
	if (man == NULL) {
		printf("Error: nh_create_manager failed - Could not create hook manager for PID %lu\n",
		       pid);
		return 0x03;
	}

	if (NH_HAS_ERR(nh_create(man, strlen_func, (void *)my_strlen, 1))) {
		printf("Error: nh_create failed - Could not create hook for function %p with hook %p\n",
		       strlen_func, (void *)my_strlen);
		return 0x04;
	}

	HANDLE cr_thread =
		CreateThread(NULL, 0, (void *)thread_loop, NULL, 0, NULL);
	if (cr_thread == NULL) {
		printf("Error: CreateThread failed - Could not create test thread\n");
		return 0x02;
	}

	if (NH_HAS_ERR(nh_enable_all(man))) {
		printf("Error: nh_enable_all failed - Could not enable hooks in manager %p\n",
		       man);
		return 0x05;
	}

	while (nh_manager_get_enabled_count(man) > 0) {
		nh_update(man);
		Sleep(10);
	}

	nh_destroy_manager(man);
	return EXIT_SUCCESS;
}
