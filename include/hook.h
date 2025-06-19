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

#ifndef __HOOK_H__
#define __HOOK_H__

#include "ntucc.h"

#define NHOOK_FLAG_ENABLED 0x01
#define NHOOK_FLAG_SECOND_INSN 0x02

struct nh_trampoline;

/**
 * @brief Represents an inline hook instance
 * 
 * Contains the original function address, hook function address, calling convention,
 * flags, argument count, overwritten instruction bytes, and trampoline address.
 */
struct nhook {
	void *function; /**< Address of the original function */
	void *hook_function; /**< Address of the hook function */

#ifndef NTU_GLOBAL_CC
	ntucc_t cc; /**< Calling convention */
#endif // !NTU_GLOBAL_CC

	int8_t flags; /**< Hook flags (e.g. enabled) */
	uint8_t arg_count; /**< Number of arguments the function accepts */

	uint8_t affected_length; /**< Number of bytes overwritten in original function */
	uint8_t mem[16]; /**< Backup of overwritten instruction bytes */

	struct nh_trampoline *tramp; /**< Trampoline struct */
};

/**
 * @brief Marks a hook as invalid (clears its function pointer)
 * @param nhook Pointer to hook instance
 */
#define NHOOK_SET_INVALID(nhook) ((nhook)->function = NULL)

/**
 * @brief Checks whether a hook is valid (has a non-null function pointer)
 * @param nhook Pointer to hook instance
 * @return true if valid, false otherwise
 */
#define NHOOK_IS_VALID(nhook) ((nhook)->function != NULL)

typedef struct nhook nhook_t;

#endif // !__HOOK_H__