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

#ifndef __TRAMPOLINE_H__
#define __TRAMPOLINE_H__

#include "nhook.h"
#include <stdarg.h>

struct mem_args {
	int base;
	int index;
	int8_t scale;
	int32_t disp;
};

union op_value {
	int reg;
	void *imm;
	struct mem_args mem;
};

struct lea_args {
	int reg;
	union op_value op_value;

	int8_t size;
};

struct jmp_args {
	union op_value op_value;
	int8_t size;
	int8_t jmp_add;
};

struct call_args {
	union op_value op_value;
	int8_t size;
};

struct add_args {
	union op_value f_op_value;
	union op_value s_op_value;

	int8_t size;
};

struct sub_args {
	union op_value f_op_value;
	union op_value s_op_value;

	int8_t size;
};

struct xor_args {
	union op_value f_op_value;
	union op_value s_op_value;

	int8_t size;
};

struct cmp_args {
	union op_value f_op_value;
	union op_value s_op_value;

	int8_t size;
};

struct test_args {
	union op_value f_op_value;
	union op_value s_op_value;

	int8_t size;
};

struct push_args {
	union op_value op_value;
	int8_t size;
};

struct mov_args {
	union op_value f_op_value;
	union op_value s_op_value;

	int8_t size;
};

struct movzx_args {
	int reg;
	union op_value op_value;

	int8_t size;
};

#define INSN_UNION                       \
	union {                          \
		struct lea_args lea;     \
		struct jmp_args jmp;     \
		struct call_args call;   \
		struct add_args add;     \
		struct sub_args sub;     \
		struct xor_args xor ;    \
		struct cmp_args cmp;     \
		struct test_args test;   \
		struct push_args push;   \
		struct mov_args mov;     \
		struct movzx_args movzx; \
	}

struct insn_args_rw;
typedef void (*proc_insn_fn)(struct insn_args_rw *args);

struct insn_args {
	INSN_UNION;

	proc_insn_fn func;
};

struct insn_args_w {
	void *write;
	void *write_val;
	uint8_t write_size;

	INSN_UNION;

	proc_insn_fn func;
};

struct insn_args_r {
	INSN_UNION;

	proc_insn_fn func;

	void *read;
	void *read_val;
	uint8_t read_size;
};

struct insn_args_rw {
	void *write;
	void *write_val;
	uint8_t write_size;

	INSN_UNION;

	proc_insn_fn func;

	void *read;
	void *read_val;
	uint8_t read_size;
};

typedef struct insn_args insn_args_t;
typedef struct insn_args_w insn_args_w_t;
typedef struct insn_args_r insn_args_r_t;
typedef struct insn_args_rw insn_args_rw_t;

#define INSN_ARGS_READ_DIFF (sizeof(insn_args_rw_t) - sizeof(insn_args_w_t))
#define INSN_ARGS_WRITE_DIFF (sizeof(insn_args_rw_t) - sizeof(insn_args_r_t))
#define INSN_ARGS_READWRITE_DIFF (INSN_ARGS_READ_DIFF + INSN_ARGS_WRITE_DIFF)

#define INSN_FLAG_WRITE 0x01
#define INSN_FLAG_READ 0x02
#define INSN_FLAG_READWRITE (INSN_FLAG_INSN_READ | INSN_FLAG_INSN_WRITE)

typedef void (*proc_insns_fn)(insn_args_rw_t *args);

struct trampoline {
	proc_insns_fn func;
	union {
		insn_args_rw_t args[2];
		struct {
			insn_args_rw_t f_args;
			insn_args_rw_t s_args;
		};
	};
};

#include <capstone/capstone.h>

typedef struct trampoline trampoline_t;

void trampoline_simulate_insns(trampoline_t *tramp);

bool add_insn(trampoline_t *tramp, cs_insn *insn);

trampoline_t *trampoline_init();

void trampoline_destroy(trampoline_t *tramp);

#endif // !__TRAMPOLINE_H__
