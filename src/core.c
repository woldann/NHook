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

struct nh_tfunctions nh_tfuncs;

HMODULE nh_get_kernel32_module(void)
{
	return GetModuleHandleA("kernel32");
}

nerror_t nh_global_init(void)
{
	HMODULE kernel32 = nh_get_kernel32_module();
	if (kernel32 == NULL)
		return GET_ERR(NHOOK_GET_KERNEL32_BASE_ERROR);

	nh_tfuncs.VirtualProtect = GetProcAddress(kernel32, "VirtualProtect");
	// nh_tfuncs.VirtualQuery = GetProcAddress(libc_base, "VirtualQuery");

	if (nh_tfuncs.VirtualProtect ==
	    NULL /* || nh_tfuncs.VirtualQuery == NULL */)
		return GET_ERR(NHOOK_GET_PROC_ADDRESS_ERROR);

	return N_OK;
}
