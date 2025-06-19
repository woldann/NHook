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

#include "trampoline.h"

#include "nmem.h"

#include <capstone/capstone.h>

static int8_t reg_id_to_index(int reg_id)
{
	switch (reg_id) {
	case X86_REG_RAX:
	case X86_REG_EAX:
	case X86_REG_AX:
	case X86_REG_AL:
	case X86_REG_AH:
		return NTHREAD_RAX_INDEX;

	case X86_REG_RCX:
	case X86_REG_ECX:
	case X86_REG_CX:
	case X86_REG_CL:
	case X86_REG_CH:
		return NTHREAD_RCX_INDEX;

	case X86_REG_RDX:
	case X86_REG_EDX:
	case X86_REG_DX:
	case X86_REG_DL:
	case X86_REG_DH:
		return NTHREAD_RDX_INDEX;

	case X86_REG_RBX:
	case X86_REG_EBX:
	case X86_REG_BX:
	case X86_REG_BL:
	case X86_REG_BH:
		return NTHREAD_RBX_INDEX;

	case X86_REG_RSP:
	case X86_REG_ESP:
	case X86_REG_SP:
	case X86_REG_SPL:
		return NTHREAD_RSP_INDEX;

	case X86_REG_RBP:
	case X86_REG_EBP:
	case X86_REG_BP:
	case X86_REG_BPL:
		return NTHREAD_RBP_INDEX;

	case X86_REG_RSI:
	case X86_REG_ESI:
	case X86_REG_SI:
	case X86_REG_SIL:
		return NTHREAD_RSI_INDEX;

	case X86_REG_RDI:
	case X86_REG_EDI:
	case X86_REG_DI:
	case X86_REG_DIL:
		return NTHREAD_RDI_INDEX;

	case X86_REG_R8:
	case X86_REG_R8D:
	case X86_REG_R8W:
	case X86_REG_R8B:
		return NTHREAD_R8_INDEX;

	case X86_REG_R9:
	case X86_REG_R9D:
	case X86_REG_R9W:
	case X86_REG_R9B:
		return NTHREAD_R9_INDEX;

	case X86_REG_R10:
	case X86_REG_R10D:
	case X86_REG_R10W:
	case X86_REG_R10B:
		return NTHREAD_R10_INDEX;

	case X86_REG_R11:
	case X86_REG_R11D:
	case X86_REG_R11W:
	case X86_REG_R11B:
		return NTHREAD_R11_INDEX;

	case X86_REG_R12:
	case X86_REG_R12D:
	case X86_REG_R12W:
	case X86_REG_R12B:
		return NTHREAD_R12_INDEX;

	case X86_REG_R13:
	case X86_REG_R13D:
	case X86_REG_R13W:
	case X86_REG_R13B:
		return NTHREAD_R13_INDEX;

	case X86_REG_R14:
	case X86_REG_R14D:
	case X86_REG_R14W:
	case X86_REG_R14B:
		return NTHREAD_R14_INDEX;

	case X86_REG_R15:
	case X86_REG_R15D:
	case X86_REG_R15W:
	case X86_REG_R15B:
		return NTHREAD_R15_INDEX;

	case X86_REG_RIP:
	case X86_REG_EIP:
	case X86_REG_EIZ:
		return NTHREAD_RIP_INDEX;

	default:
		return (int8_t)((NTHREAD_RAX / sizeof(DWORD64)) * (-1));
	}
}

static void *calc_effective_addr_with_indexes(int8_t base_index,
					      int8_t index_index, int8_t scale,
					      int32_t displacement)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	nthread_reg_offset_t base_off = NTHREAD_REG_INDEX_TO_OFFSET(base_index);
	nthread_reg_offset_t index_off =
		NTHREAD_REG_INDEX_TO_OFFSET(index_index);

	void *base_val, *index_val;

	if (base_off == 0)
		base_val = 0;
	else
		base_val = NTHREAD_GET_REG(nthread, base_off);

	if (index_off == 0)
		index_val = 0;
	else
		index_val = NTHREAD_GET_REG(nthread, index_off);

	return (void *)(((uint64_t)base_val) + (((uint64_t)index_val) * scale) +
			displacement);
}

static void *calc_effective_addr(int base, int index, int8_t scale,
				 int32_t displacement)
{
	int8_t base_index = reg_id_to_index(base);
	int8_t index_index = reg_id_to_index(index);

	return calc_effective_addr_with_indexes(base_index, index_index, scale,
						displacement);
}

#include <arch/X86/X86Mapping.h>

static void *get_reg_value(int reg)
{
	nthread_reg_offset_t index = reg_id_to_index(reg);
	nthread_reg_offset_t off = NTHREAD_REG_INDEX_TO_OFFSET(index);
	if (off == 0)
		return 0;

	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	int8_t reg_size = regsize_map_64[reg];
	if (reg_size != sizeof(void *)) {
		int8_t bits = reg_size * 8;
		uint64_t mask = (1ULL << bits) - 1;
		return (void *)((int64_t)NTHREAD_GET_REG(nthread, off) & mask);
	}

	return NTHREAD_GET_REG(nthread, off);
}

static void set_reg_value(int reg, void *val)
{
	nthread_reg_offset_t index = reg_id_to_index(reg);
	nthread_reg_offset_t off = NTHREAD_REG_INDEX_TO_OFFSET(index);
	if (off == 0)
		return;

	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	int8_t reg_size = regsize_map_64[reg];
	if (reg_size != sizeof(void *)) {
		int8_t bits = reg_size * 8;
		uint64_t low_mask = (1ULL << bits) - 1;
		uint64_t high_mask = ~low_mask;

		uint64_t reg_value = (uint64_t)NTHREAD_GET_REG(nthread, off) &
				     high_mask;
		uint64_t val_int = (uint64_t)val & low_mask;

		NTHREAD_SET_REG(nthread, off, reg_value | val_int);
	} else
		NTHREAD_SET_REG(nthread, off, val);
}

static void set_mem_args(struct mem_args *mem_args, cs_x86_op *op)
{
	x86_op_mem *mem = &op->mem;

	mem_args->base = mem->base;
	mem_args->index = mem->index;
	mem_args->scale = mem->scale;
	mem_args->disp = mem->disp;
}

static void *calc_mem_args(struct mem_args *mem_args)
{
	void *base_val = get_reg_value(mem_args->base);
	void *index_val = get_reg_value(mem_args->index);
	return (void *)(((uint64_t)base_val) +
			(((uint64_t)index_val) * mem_args->scale) +
			mem_args->disp);
}

static void *get_op_value(union op_value *op_value)
{
	int8_t scale = op_value->mem.scale;
	if (scale == 0)
		return get_reg_value(op_value->reg);

	if (scale > 0)
		return calc_mem_args(&op_value->mem);

	return op_value->imm;
}

static int8_t set_op_value_args(union op_value *op_value, cs_x86_op *op)
{
	uint8_t type = op->type;
	if (type == X86_OP_REG) {
		op_value->reg = op->reg;
		op_value->mem.scale = 0;
	} else if (type == X86_OP_MEM) {
		set_mem_args(&op_value->mem, op);
	} else if (type == X86_OP_IMM) {
		op_value->imm = (void *)op->imm;
		op_value->mem.scale = -1;
	} else
		return 0;

	return op->size;
}

static bool is_op_value_mem(union op_value *op_value)
{
	return op_value->mem.scale > 0;
}

static int8_t set_two_op_value_from_insn(union op_value *f_op_value,
					 union op_value *s_op_value,
					 cs_insn *insn)
{
	cs_x86 *x86 = &insn->detail->x86;
	if (x86->op_count != 2)
		return false;

	cs_x86_op *f_op = &x86->operands[0];
	cs_x86_op *s_op = &x86->operands[1];

	if (f_op->type == X86_OP_MEM && s_op->type == X86_OP_MEM)
		return 0;

	size_t f_size = set_op_value_args(f_op_value, f_op);
	size_t s_size = set_op_value_args(s_op_value, s_op);
	if (f_size != s_size || f_size == 0 || s_size == 0)
		return 0;

	return f_size;
}

static int8_t set_reg_n_op_value_from_insn(int *reg, union op_value *op_value,
					   cs_insn *insn)
{
	cs_x86 *x86 = &insn->detail->x86;
	if (x86->op_count != 2)
		return 0;

	cs_x86_op *f_op = &x86->operands[0];
	cs_x86_op *s_op = &x86->operands[1];

	int8_t size = set_op_value_args(op_value, s_op);
	if (size == 0)
		return 0;

	*reg = f_op->reg;
	return size;
}

static void proc_lea(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	void *set = get_op_value(&args->lea.op_value);
	set_reg_value(args->lea.reg, set);
}

static bool set_lea_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_LEA)
		return false;

	int8_t size = set_reg_n_op_value_from_insn(&args->lea.reg,
						   &args->lea.op_value, insn);
	if (size == 0)
		return false;

	args->lea.size = size;
	args->func = proc_lea;
	return true;
}

static void proc_jmp(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	union op_value *op_value = &args->jmp.op_value;
	void *val = get_op_value(op_value);
	val += args->jmp.jmp_add;

	int8_t size = args->jmp.size;
	if (is_op_value_mem(op_value)) {
		int8_t read_size = args->read_size;
		if (read_size == 0) {
			args->read = val;
			args->read_size = size;
			return;
		}

		val = args->read_val;
	}

	NTHREAD_SET_REG(nthread, NTHREAD_RIP, val);
	NTHREAD_SET_REG(nthread, NTHREAD_RSP, NULL);
}

static bool set_jmp_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_JMP)
		return false;

	cs_x86 *x86 = &insn->detail->x86;
	if (x86->op_count != 1)
		return false;

	cs_x86_op *op = &x86->operands[0];

	if (!set_op_value_args(&args->jmp.op_value, op))
		return false;

	args->jmp.size = op->size;
	args->jmp.jmp_add = insn->size;
	args->func = proc_jmp;
	return true;
}

static void proc_call(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	union op_value *op_value = &args->call.op_value;
	void *val = get_op_value(op_value);
	int8_t size = args->call.size;

	void *rsp = NTHREAD_GET_REG(nthread, NTHREAD_RSP);
	void *new_rsp = rsp - size;
	NTHREAD_SET_REG(nthread, NTHREAD_RSP, new_rsp);

	if (is_op_value_mem(op_value)) {
		int8_t read_size = args->read_size;
		if (read_size == 0) {
			args->read = val;
			args->read_size = size;
			return;
		}

		val = args->read_val;
	}

	args->write = new_rsp;
	args->write_val = val;
	args->write_size = size;
	NTHREAD_SET_REG(nthread, NTHREAD_RIP, val);
}

static bool set_call_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_CALL)
		return false;

	cs_x86 *x86 = &insn->detail->x86;
	if (x86->op_count != 1)
		return false;

	cs_x86_op *op = &x86->operands[0];

	if (!set_op_value_args(&args->call.op_value, op))
		return false;

	args->call.size = op->size;
	args->func = proc_call;
	return true;
}

DWORD simulate_add(void *first_value, void *second_value, int8_t size,
		   void **calc);

#define ADD_FLAGS_MASK 0x08D5 // 0000 1000 1101 0101 = CF, PF, AF, ZF, SF, OF

static void proc_add(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	union op_value *f_op_value = &args->add.f_op_value;
	union op_value *s_op_value = &args->add.s_op_value;

	void *address;
	void *f_val = get_op_value(f_op_value);
	void *s_val = get_op_value(s_op_value);

	bool is_f_type_mem = is_op_value_mem(f_op_value);
	bool is_s_type_mem = is_op_value_mem(s_op_value);

	int8_t size = args->add.size;

	if (is_f_type_mem || is_s_type_mem) {
		int8_t read_size = args->read_size;
		if (read_size == 0) {
			if (is_f_type_mem)
				address = f_val;
			else
				address = s_val;

			args->read = address;
			args->read_size = size;
			return;
		}

		void *val = args->read_val;
		if (is_f_type_mem)
			f_val = val;
		else
			s_val = val;
	}

	void *add;
	DWORD sim = simulate_add(f_val, s_val, size, &add);
	if (is_f_type_mem) {
		args->write = address;
		args->write_val = add;
		args->write_size = size;
	} else
		set_reg_value(f_op_value->reg, add);

	CONTEXT *ctx = &nthread->n_ctx;
	ctx->EFlags &= ~(ADD_FLAGS_MASK);
	ctx->EFlags |= (sim & ADD_FLAGS_MASK);
}

static bool set_add_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_ADD)
		return false;

	int8_t size = set_two_op_value_from_insn(&args->add.f_op_value,
						 &args->add.s_op_value, insn);

	if (size == 0)
		return false;

	args->add.size = size;
	args->func = proc_add;
	return true;
}

DWORD simulate_sub(void *first_value, void *second_value, int8_t size,
		   void **calc);

#define SUB_FLAGS_MASK 0x08D5 // 0000 1000 1101 0101 = CF, PF, AF, ZF, SF, OF

static void proc_sub(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	union op_value *f_op_value = &args->sub.f_op_value;
	union op_value *s_op_value = &args->sub.s_op_value;

	void *address;
	void *f_val = get_op_value(f_op_value);
	void *s_val = get_op_value(s_op_value);

	bool is_f_type_mem = is_op_value_mem(f_op_value);
	bool is_s_type_mem = is_op_value_mem(s_op_value);

	int8_t size = args->sub.size;

	if (is_f_type_mem || is_s_type_mem) {
		int8_t read_size = args->read_size;
		if (read_size == 0) {
			if (is_f_type_mem)
				address = f_val;
			else
				address = s_val;

			args->read = address;
			args->read_size = size;
			return;
		}

		void *val = args->read_val;
		if (is_f_type_mem)
			f_val = val;
		else
			s_val = val;
	}

	void *sub;
	DWORD sim = simulate_sub(f_val, s_val, size, &sub);
	if (is_f_type_mem) {
		args->write = address;
		args->write_val = sub;
		args->write_size = size;
	} else
		set_reg_value(f_op_value->reg, sub);

	CONTEXT *ctx = &nthread->n_ctx;
	ctx->EFlags &= ~(SUB_FLAGS_MASK);
	ctx->EFlags |= (sim & SUB_FLAGS_MASK);
}

static bool set_sub_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_SUB)
		return false;

	int8_t size = set_two_op_value_from_insn(&args->sub.f_op_value,
						 &args->sub.s_op_value, insn);

	if (size == 0)
		return false;

	args->sub.size = size;
	args->func = proc_sub;
	return true;
}

DWORD simulate_inc(void *value, int8_t size, void **calc);

#define INC_FLAGS_MASK 0x08D4 // 0000 1000 1101 0101 = CF, PF, AF, ZF, SF, OF

static void proc_inc(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	union op_value *op_value = &args->inc.op_value;

	void *address;
	void *val = get_op_value(op_value);
	bool is_type_mem = is_op_value_mem(op_value);
	int8_t size = args->inc.size;

	if (is_type_mem) {
		int8_t read_size = args->read_size;
		address = val;

		if (read_size == 0) {
			args->read = address;
			args->read_size = size;
			return;
		}

		val = args->read_val;
	}

	void *inc;
	DWORD sim = simulate_inc(val, size, &inc);
	if (is_type_mem) {
		args->write = address;
		args->write_val = inc;
		args->write_size = size;
	} else
		set_reg_value(op_value->reg, inc);

	CONTEXT *ctx = &nthread->n_ctx;
	ctx->EFlags &= ~(INC_FLAGS_MASK);
	ctx->EFlags |= (sim & INC_FLAGS_MASK);
}

static bool set_inc_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_INC)
		return false;

	cs_x86 *x86 = &insn->detail->x86;
	if (x86->op_count != 1)
		return false;

	cs_x86_op *op = &x86->operands[0];
	int8_t size = set_op_value_args(&args->inc.op_value, op);
	if (size == 0)
		return false;

	args->inc.size = size;
	args->func = proc_inc;
	return true;
}

DWORD simulate_dec(void *value, int8_t size, void **calc);

#define DEC_FLAGS_MASK 0x08D4 // 0000 1000 1101 0101 = CF, PF, AF, ZF, SF, OF

static void proc_dec(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	union op_value *op_value = &args->dec.op_value;

	void *address;
	void *val = get_op_value(op_value);
	bool is_type_mem = is_op_value_mem(op_value);
	int8_t size = args->dec.size;

	if (is_type_mem) {
		int8_t read_size = args->read_size;
		address = val;

		if (read_size == 0) {
			args->read = address;
			args->read_size = size;
			return;
		}

		val = args->read_val;
	}

	void *dec;
	DWORD sim = simulate_dec(val, size, &dec);
	if (is_type_mem) {
		args->write = address;
		args->write_val = dec;
		args->write_size = size;
	} else
		set_reg_value(op_value->reg, dec);

	CONTEXT *ctx = &nthread->n_ctx;
	ctx->EFlags &= ~(DEC_FLAGS_MASK);
	ctx->EFlags |= (sim & DEC_FLAGS_MASK);
}

static bool set_dec_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_DEC)
		return false;

	cs_x86 *x86 = &insn->detail->x86;
	if (x86->op_count != 1)
		return false;

	cs_x86_op *op = &x86->operands[0];
	int8_t size = set_op_value_args(&args->dec.op_value, op);
	if (size == 0)
		return false;

	args->dec.size = size;
	args->func = proc_dec;
	return true;
}

DWORD simulate_xor(void *first_value, void *second_value, int8_t size,
		   void **calc);

#define XOR_FLAGS_MASK 0x08D5 // 0000 1000 1101 0101 = CF, PF, AF, ZF, SF, OF

static void proc_xor(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	union op_value *f_op_value = &args->xor.f_op_value;
	union op_value *s_op_value = &args->xor.s_op_value;

	void *address;
	void *f_val = get_op_value(f_op_value);
	void *s_val = get_op_value(s_op_value);

	bool is_f_type_mem = is_op_value_mem(f_op_value);
	bool is_s_type_mem = is_op_value_mem(s_op_value);

	int8_t size = args->xor.size;

	if (is_f_type_mem || is_s_type_mem) {
		int8_t read_size = args->read_size;

		if (is_f_type_mem)
			address = f_val;
		else
			address = s_val;

		if (read_size == 0) {
			args->read = address;
			args->read_size = size;
			return;
		}

		void *val = args->read_val;
		if (is_f_type_mem)
			f_val = val;
		else
			s_val = val;
	}

	void *xor;
	DWORD sim = simulate_xor(f_val, s_val, size, &xor);
	if (is_f_type_mem) {
		args->write = address;
		args->write_val = xor;
		args->write_size = size;
	} else
		set_reg_value(f_op_value->reg, xor);

	CONTEXT *ctx = &nthread->n_ctx;
	ctx->EFlags &= ~(XOR_FLAGS_MASK);
	ctx->EFlags |= (sim & XOR_FLAGS_MASK);
}

static bool set_xor_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_XOR)
		return false;

	int8_t size = set_two_op_value_from_insn(&args->add.f_op_value,
						 &args->add.s_op_value, insn);

	if (size == 0)
		return false;

	args->add.size = size;
	args->func = proc_xor;
	return true;
}

DWORD simulate_cmp(void *first_value, void *second_value, int8_t size);

#define CMP_FLAGS_MASK 0x08D5 // 0000 1000 1101 0101 = CF, PF, AF, ZF, SF, OF

static void proc_cmp(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	union op_value *f_op_value = &args->cmp.f_op_value;
	union op_value *s_op_value = &args->cmp.s_op_value;

	void *f_val = get_op_value(f_op_value);
	void *s_val = get_op_value(s_op_value);

	bool is_f_type_mem = is_op_value_mem(f_op_value);
	bool is_s_type_mem = is_op_value_mem(s_op_value);

	int8_t size = args->cmp.size;

	if (is_f_type_mem || is_s_type_mem) {
		void *val;

		int8_t read_size = args->read_size;
		if (read_size == 0) {
			if (is_f_type_mem)
				val = f_val;
			else
				val = s_val;

			args->read = val;
			args->read_size = size;
			return;
		}

		val = args->read_val;
		if (is_f_type_mem)
			f_val = val;
		else
			s_val = val;
	}

	DWORD sim = simulate_cmp(f_val, s_val, size);
	CONTEXT *ctx = &nthread->n_ctx;
	ctx->EFlags &= ~(CMP_FLAGS_MASK);
	ctx->EFlags |= (sim & CMP_FLAGS_MASK);
}

static bool set_cmp_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_CMP)
		return false;

	int8_t size = set_two_op_value_from_insn(&args->cmp.f_op_value,
						 &args->cmp.s_op_value, insn);

	if (size == 0)
		return false;

	args->cmp.size = size;
	args->func = proc_cmp;
	return true;
}

DWORD simulate_test(void *first_value, void *second_value, int8_t size);

#define TEST_FLAGS_MASK 0x08D5 // 0000 1000 1101 0101 = CF, PF, AF, ZF, SF, OF

static void proc_test(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	union op_value *f_op_value = &args->test.f_op_value;
	union op_value *s_op_value = &args->test.s_op_value;

	void *f_val = get_op_value(f_op_value);
	void *s_val = get_op_value(s_op_value);

	bool is_f_type_mem = is_op_value_mem(f_op_value);
	bool is_s_type_mem = is_op_value_mem(s_op_value);

	int8_t size = args->test.size;

	if (is_f_type_mem || is_s_type_mem) {
		void *val;

		int8_t read_size = args->read_size;
		if (read_size == 0) {
			if (is_f_type_mem)
				val = f_val;
			else
				val = s_val;

			args->read = val;
			args->read_size = size;
			return;
		}

		val = args->read_val;
		if (is_f_type_mem)
			f_val = val;
		else
			s_val = val;
	}

	DWORD sim = simulate_test(f_val, s_val, size);
	CONTEXT *ctx = &nthread->n_ctx;
	ctx->EFlags &= ~(TEST_FLAGS_MASK);
	ctx->EFlags |= (sim & TEST_FLAGS_MASK);
}

static bool set_test_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_TEST)
		return false;

	int8_t size = set_two_op_value_from_insn(&args->test.f_op_value,
						 &args->test.s_op_value, insn);

	if (size == 0)
		return false;

	args->test.size = size;
	args->func = proc_test;
	return true;
}

static void proc_push(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	union op_value *op_value = &args->push.op_value;
	void *val = get_op_value(op_value);
	int8_t size = args->push.size;

	void *rsp = NTHREAD_GET_REG(nthread, NTHREAD_RSP);
	void *new_rsp = rsp - size;
	NTHREAD_SET_REG(nthread, NTHREAD_RSP, new_rsp);

	if (is_op_value_mem(op_value)) {
		int8_t read_size = args->read_size;
		if (read_size == 0) {
			args->read = val;
			args->read_size = size;
			return;
		}

		val = args->read_val;
	}

	args->write = new_rsp;
	args->write_val = val;
	args->write_size = size;
}

static bool set_push_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_PUSH)
		return false;

	cs_x86 *x86 = &insn->detail->x86;
	if (x86->op_count != 1)
		return false;

	cs_x86_op *op = &x86->operands[0];

	if (!set_op_value_args(&args->push.op_value, op))
		return false;

	args->push.size = op->size;
	args->func = proc_push;
	return true;
}

static void proc_mov(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	union op_value *f_op_value = &args->mov.f_op_value;
	union op_value *s_op_value = &args->mov.s_op_value;

	void *val = get_op_value(s_op_value);

	bool is_f_type_mem = is_op_value_mem(f_op_value);
	bool is_s_type_mem = is_op_value_mem(s_op_value);

	int8_t size = args->mov.size;

	if (is_s_type_mem) {
		int8_t read_size = args->read_size;
		if (read_size == 0) {
			args->read = val;
			args->read_size = size;
			return;
		}

		val = args->read_val;
	}

	if (is_f_type_mem) {
		args->write = get_op_value(f_op_value);
		args->write_val = val;
		args->write_size = size;
	} else
		set_reg_value(f_op_value->reg, val);
}

static bool set_mov_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_MOV)
		return false;

	int8_t size = set_two_op_value_from_insn(&args->mov.f_op_value,
						 &args->mov.s_op_value, insn);

	if (size == 0)
		return false;

	args->mov.size = size;
	args->func = proc_mov;
	return true;
}

static void proc_movzx(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	union op_value *op_value = &args->movzx.op_value;

	void *val = get_op_value(op_value);

	bool is_type_mem = is_op_value_mem(op_value);

	int8_t size = args->mov.size;

	if (is_type_mem) {
		int8_t read_size = args->read_size;
		if (read_size == 0) {
			args->read = val;
			args->read_size = size;
			return;
		}

		val = args->read_val;
	}

	set_reg_value(op_value->reg, val);
}

static bool set_movzx_args(insn_args_rw_t *args, cs_insn *insn)
{
	if (insn->id != X86_INS_MOVZX)
		return false;

	int8_t size = set_reg_n_op_value_from_insn(&args->movzx.reg,
						   &args->movzx.op_value, insn);

	if (size == 0)
		return false;

	args->movzx.size = size;
	args->func = proc_movzx;
	return true;
}

typedef bool (*set_insn_args_fn)(insn_args_rw_t *insn_args, cs_insn *insn);
set_insn_args_fn set_insn_args_funcs[] = {
	set_lea_args,  set_jmp_args, set_sub_args,  set_inc_args,
	set_sub_args,  set_xor_args, set_cmp_args,  set_test_args,
	set_push_args, set_mov_args, set_movzx_args
};

static void *set_insn_args(insn_args_rw_t *insn_args, cs_insn *insn)
{
	int8_t count =
		sizeof(set_insn_args_funcs) / sizeof(*set_insn_args_funcs);

	int8_t i;
	for (i = 0; i < count; i++) {
		set_insn_args_fn func = set_insn_args_funcs[i];
		if (func(insn_args, insn))
			return func;
	}

	return NULL;
}

static void *insns_args_read(insn_args_rw_t *args)
{
	int8_t size = args->read_size;
	ntu_read_memory(args->read, &args->read_val, size);

	int8_t bits = size * 8;

	return (void *)(((int64_t)args->read_val
			 << ((8 * sizeof(void *)) - bits)) >>
			bits);
}

static void proc_insns_f(insn_args_rw_t *args)
{
	insn_args_rw_t *f_args = (void *)args - INSN_ARGS_WRITE_DIFF;
	f_args->func(f_args);
}

static void proc_insns_f_s(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *f_args = (void *)args - INSN_ARGS_WRITE_DIFF;
	insn_args_rw_t *s_args =
		((void *)(f_args + 1)) - INSN_ARGS_READWRITE_DIFF;

	f_args->func(f_args);
	nthread->n_ctx.Rip++;
	s_args->func(s_args);
}

static void proc_insns_f_sw(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *f_args = (void *)args - INSN_ARGS_WRITE_DIFF;
	insn_args_rw_t *s_args = ((void *)(f_args + 1)) - INSN_ARGS_READ_DIFF;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	s_args->write_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	ntu_write_memory(s_args->write, &s_args->write_val, s_args->write_size);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_f_sr(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *f_args = (void *)args - INSN_ARGS_WRITE_DIFF;
	insn_args_rw_t *s_args =
		((void *)(f_args + 1)) - INSN_ARGS_READWRITE_DIFF;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	s_args->read_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	insns_args_read(s_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_f_srw(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *f_args = (void *)args - INSN_ARGS_WRITE_DIFF;
	insn_args_rw_t *s_args = ((void *)(f_args + 1)) - INSN_ARGS_READ_DIFF;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	s_args->read_size = 0;
	s_args->write_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	insns_args_read(s_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	ntu_write_memory(s_args->write, &s_args->write_val, s_args->write_size);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_fw(insn_args_rw_t *f_args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->write_size = 0;

	proc_insn_fn f_func = f_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);
	ntu_write_memory(f_args->write, &f_args->write_val, f_args->write_size);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
}

static void proc_insns_fw_s(insn_args_rw_t *f_args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *s_args =
		((void *)(f_args + 1)) - INSN_ARGS_READWRITE_DIFF;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->write_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);

	ntu_write_memory(f_args->write, &f_args->write_val, f_args->write_size);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_fw_sw(insn_args_rw_t *f_args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *s_args = ((void *)(f_args + 1)) - INSN_ARGS_READ_DIFF;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->write_size = 0;
	s_args->write_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	void *stack_begin = nthread_stack_begin(nthread);
	void *stack_end = stack_begin + NTHREAD_STACK_ADD;

	int8_t f_write_size = f_args->write_size;
	int8_t s_write_size = s_args->write_size;

	void *f_write = f_args->write;
	void *f_write_end = f_write + f_write_size;

	void *s_write = s_args->write;
	void *s_write_end = s_write + s_write_size;

	bool f_in_stack = f_write_end > stack_begin && f_write < stack_end;
	bool s_in_stack = s_write_end > stack_begin && s_write < stack_end;
	if (f_in_stack && s_in_stack) {
		void *stack_write_start;
		void *stack_write_end;

		if (f_write > s_write)
			stack_write_start = s_write;
		else
			stack_write_start = f_write;

		if (f_write_end > s_write_end)
			stack_write_end = f_write;
		else
			stack_write_end = s_write;

		size_t stack_write_len =
			(size_t)stack_write_end - (size_t)stack_write_start;
		void *stack_write = N_ALLOC(stack_write_len);
		if (stack_write == NULL)
			return;

		uint64_t pos =
			(uint64_t)stack_write + (uint64_t)stack_write_start;
		void *f_pos = (void *)(pos - (uint64_t)f_write);
		void *s_pos = (void *)(pos - (uint64_t)s_write);

		memcpy(f_pos, &f_args->write_val, f_write_size);
		memcpy(s_pos, &s_args->write_val, s_write_size);

		ntu_write_memory(stack_write_start, stack_write,
				 stack_write_len);

		N_FREE(stack_write);
	} else if (f_in_stack) {
		ntu_write_memory(s_write, &s_args->write_val, s_write_size);
		ntu_write_memory(f_write, &f_args->write_val, f_write_size);
	} else {
		ntu_write_memory(f_write, &f_args->write_val, f_write_size);
		ntu_write_memory(s_write, &s_args->write_val, s_write_size);
	}

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_fw_sr(insn_args_rw_t *f_args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *s_args = ((void *)(f_args + 1)) - INSN_ARGS_WRITE_DIFF;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->write_size = 0;
	s_args->read_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	insns_args_read(s_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);

	ntu_write_memory(f_args->write, &f_args->write_val, f_args->write_size);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_fw_srw(insn_args_rw_t *f_args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *s_args = ((void *)(f_args + 1)) - INSN_ARGS_READ_DIFF;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->write_size = 0;
	s_args->read_size = 0;
	s_args->write_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	insns_args_read(s_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	void *stack_begin = nthread_stack_begin(nthread);
	void *stack_end = stack_begin + NTHREAD_STACK_ADD;

	int8_t f_write_size = f_args->write_size;
	int8_t s_write_size = s_args->write_size;

	void *f_write = f_args->write;
	void *f_write_end = f_write + f_write_size;

	void *s_write = s_args->write;
	void *s_write_end = s_write + s_write_size;

	bool f_in_stack = f_write_end > stack_begin && f_write < stack_end;
	bool s_in_stack = s_write_end > stack_begin && s_write < stack_end;
	if (f_in_stack && s_in_stack) {
		void *stack_write_start;
		void *stack_write_end;

		if (f_write > s_write)
			stack_write_start = s_write;
		else
			stack_write_start = f_write;

		if (f_write_end > s_write_end)
			stack_write_end = f_write;
		else
			stack_write_end = s_write;

		size_t stack_write_len =
			(size_t)stack_write_end - (size_t)stack_write_start;
		void *stack_write = N_ALLOC(stack_write_len);
		if (stack_write == NULL)
			return;

		uint64_t pos =
			(uint64_t)stack_write + (uint64_t)stack_write_start;
		void *f_pos = (void *)(pos - (uint64_t)f_write);
		void *s_pos = (void *)(pos - (uint64_t)s_write);

		memcpy(f_pos, &f_args->write_val, f_write_size);
		memcpy(s_pos, &s_args->write_val, s_write_size);

		ntu_write_memory(stack_write_start, stack_write,
				 stack_write_len);

		N_FREE(stack_write);
	} else if (f_in_stack) {
		ntu_write_memory(s_write, &s_args->write_val, s_write_size);
		ntu_write_memory(f_write, &f_args->write_val, f_write_size);
	} else {
		ntu_write_memory(f_write, &f_args->write_val, f_write_size);
		ntu_write_memory(s_write, &s_args->write_val, s_write_size);
	}

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_fr(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *f_args = (void *)args - INSN_ARGS_WRITE_DIFF;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->read_size = 0;

	proc_insn_fn f_func = f_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);

	insns_args_read(f_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
}

static void proc_insns_fr_s(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *f_args = (void *)args - INSN_ARGS_WRITE_DIFF;
	insn_args_rw_t *s_args = ((void *)(f_args + 1)) - INSN_ARGS_WRITE_DIFF;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->read_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);

	insns_args_read(f_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_fr_sw(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *f_args = (void *)args - INSN_ARGS_WRITE_DIFF;
	insn_args_rw_t *s_args = f_args + 1;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->read_size = 0;
	s_args->write_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);

	insns_args_read(f_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	ntu_write_memory(s_args->write, &s_args->write_val, s_args->write_size);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_fr_sr(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *f_args = (void *)args - INSN_ARGS_WRITE_DIFF;
	insn_args_rw_t *s_args = ((void *)(f_args + 1)) - INSN_ARGS_WRITE_DIFF;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->read_size = 0;
	s_args->read_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	insns_args_read(f_args);
	insns_args_read(s_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_fr_srw(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *f_args = (void *)args - INSN_ARGS_WRITE_DIFF;
	insn_args_rw_t *s_args = f_args + 1;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->read_size = 0;
	s_args->read_size = 0;
	s_args->write_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	insns_args_read(f_args);
	insns_args_read(s_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	ntu_write_memory(s_args->write, &s_args->write_val, s_args->write_size);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_frw(insn_args_rw_t *f_args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->read_size = 0;
	f_args->write_size = 0;

	proc_insn_fn f_func = f_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);

	insns_args_read(f_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);

	ntu_write_memory(f_args->write, &f_args->write_val, f_args->write_size);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
}

static void proc_insns_frw_s(insn_args_rw_t *f_args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *s_args = ((void *)(f_args + 1)) - INSN_ARGS_WRITE_DIFF;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->read_size = 0;
	f_args->write_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);

	insns_args_read(f_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);

	ntu_write_memory(f_args->write, &f_args->write_val, f_args->write_size);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_frw_sw(insn_args_rw_t *f_args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *s_args = f_args + 1;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->read_size = 0;
	f_args->write_size = 0;
	s_args->write_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);

	insns_args_read(f_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	void *stack_begin = nthread_stack_begin(nthread);
	void *stack_end = stack_begin + NTHREAD_STACK_ADD;

	int8_t f_write_size = f_args->write_size;
	int8_t s_write_size = s_args->write_size;

	void *f_write = f_args->write;
	void *f_write_end = f_write + f_write_size;

	void *s_write = s_args->write;
	void *s_write_end = s_write + s_write_size;

	bool f_in_stack = f_write_end > stack_begin && f_write < stack_end;
	bool s_in_stack = s_write_end > stack_begin && s_write < stack_end;
	if (f_in_stack && s_in_stack) {
		void *stack_write_start;
		void *stack_write_end;

		if (f_write > s_write)
			stack_write_start = s_write;
		else
			stack_write_start = f_write;

		if (f_write_end > s_write_end)
			stack_write_end = f_write;
		else
			stack_write_end = s_write;

		size_t stack_write_len =
			(size_t)stack_write_end - (size_t)stack_write_start;
		void *stack_write = N_ALLOC(stack_write_len);
		if (stack_write == NULL)
			return;

		uint64_t pos =
			(uint64_t)stack_write + (uint64_t)stack_write_start;
		void *f_pos = (void *)(pos - (uint64_t)f_write);
		void *s_pos = (void *)(pos - (uint64_t)s_write);

		memcpy(f_pos, &f_args->write_val, f_write_size);
		memcpy(s_pos, &s_args->write_val, s_write_size);

		ntu_write_memory(stack_write_start, stack_write,
				 stack_write_len);

		N_FREE(stack_write);
	} else if (f_in_stack) {
		ntu_write_memory(s_write, &s_args->write_val, s_write_size);
		ntu_write_memory(f_write, &f_args->write_val, f_write_size);
	} else {
		ntu_write_memory(f_write, &f_args->write_val, f_write_size);
		ntu_write_memory(s_write, &s_args->write_val, s_write_size);
	}

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_frw_sr(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *f_args = args;
	insn_args_rw_t *s_args = ((void *)(f_args + 1)) - INSN_ARGS_WRITE_DIFF;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->read_size = 0;
	f_args->write_size = 0;
	s_args->read_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	insns_args_read(f_args);
	insns_args_read(s_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);

	ntu_write_memory(f_args->write, &f_args->write_val, f_args->write_size);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

static void proc_insns_frw_srw(insn_args_rw_t *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	insn_args_rw_t *f_args = args;
	insn_args_rw_t *s_args = f_args + 1;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;

	f_args->read_size = 0;
	f_args->write_size = 0;
	s_args->read_size = 0;
	s_args->write_size = 0;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	memcpy(&ctx, n_ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	insns_args_read(f_args);
	insns_args_read(s_args);

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);

	void *stack_begin = nthread_stack_begin(nthread);
	void *stack_end = stack_begin + NTHREAD_STACK_ADD;

	int8_t f_write_size = f_args->write_size;
	int8_t s_write_size = s_args->write_size;

	void *f_write = f_args->write;
	void *f_write_end = f_write + f_write_size;

	void *s_write = s_args->write;
	void *s_write_end = s_write + s_write_size;

	bool f_in_stack = f_write_end > stack_begin && f_write < stack_end;
	bool s_in_stack = s_write_end > stack_begin && s_write < stack_end;
	if (f_in_stack && s_in_stack) {
		void *stack_write_start;
		void *stack_write_end;

		if (f_write > s_write)
			stack_write_start = s_write;
		else
			stack_write_start = f_write;

		if (f_write_end > s_write_end)
			stack_write_end = f_write;
		else
			stack_write_end = s_write;

		size_t stack_write_len =
			(size_t)stack_write_end - (size_t)stack_write_start;
		void *stack_write = N_ALLOC(stack_write_len);
		if (stack_write == NULL)
			return;

		uint64_t pos =
			(uint64_t)stack_write + (uint64_t)stack_write_start;
		void *f_pos = (void *)(pos - (uint64_t)f_write);
		void *s_pos = (void *)(pos - (uint64_t)s_write);

		memcpy(f_pos, &f_args->write_val, f_write_size);
		memcpy(s_pos, &s_args->write_val, s_write_size);

		ntu_write_memory(stack_write_start, stack_write,
				 stack_write_len);

		N_FREE(stack_write);
	} else if (f_in_stack) {
		ntu_write_memory(s_write, &s_args->write_val, s_write_size);
		ntu_write_memory(f_write, &f_args->write_val, f_write_size);
	} else {
		ntu_write_memory(f_write, &f_args->write_val, f_write_size);
		ntu_write_memory(s_write, &s_args->write_val, s_write_size);
	}

	memcpy(n_ctx, &ctx, sizeof(ctx));
	f_func(f_args);
	nthread->n_ctx.Rip++;
	s_func(s_args);
}

proc_insns_fn proc_insns_funcs[4][5] = {
	{ proc_insns_f, proc_insns_f_s, proc_insns_f_sw, proc_insns_f_sr,
	  proc_insns_f_srw },
	{ proc_insns_fw, proc_insns_fw_s, proc_insns_fw_sw, proc_insns_fw_sr,
	  proc_insns_fw_srw },
	{ proc_insns_fr, proc_insns_fr_s, proc_insns_fr_sw, proc_insns_fr_sr,
	  proc_insns_fr_srw },
	{ proc_insns_frw, proc_insns_frw_s, proc_insns_frw_sw,
	  proc_insns_frw_sr, proc_insns_frw_srw }
};

static void proc_insns_select_f(void *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	nh_trampoline_t *tramp =
		(nh_trampoline_t *)(args - sizeof(proc_insns_fn));
	insn_args_rw_t *f_args = &tramp->f_args;
	proc_insn_fn f_func = f_args->func;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;
	memcpy(&ctx, n_ctx, sizeof(ctx));

	f_args->read_size = 0;
	f_args->write_size = 0;

	f_func(f_args);
	memcpy(n_ctx, &ctx, sizeof(ctx));

	int8_t flags = 0;
	size_t size = sizeof(nh_trampoline_t) - sizeof(insn_args_rw_t);

	if (f_args->read_size > 0)
		flags |= INSN_FLAG_READ;
	else
		size -= INSN_ARGS_READ_DIFF;

	f_func(f_args);
	memcpy(n_ctx, &ctx, sizeof(ctx));

	if (f_args->write_size > 0)
		flags |= INSN_FLAG_WRITE;
	else {
		memcpy(f_args, (void *)f_args + INSN_ARGS_WRITE_DIFF,
		       sizeof(insn_args_t));
		size -= INSN_ARGS_WRITE_DIFF;
	}

	if (N_REALLOC(tramp, size) != NULL) {
		proc_insns_fn func = proc_insns_funcs[flags][0];
		tramp->func = func;
		func(args);
	}
}

static void proc_insns_select_f_s(void *args)
{
	ntutils_t *ntutils = ntu_get();
	nthread_t *nthread = &ntutils->nthread;

	nh_trampoline_t *tramp =
		(nh_trampoline_t *)(args - sizeof(proc_insns_fn));
	insn_args_rw_t *f_args = &tramp->f_args;
	insn_args_rw_t *s_args = &tramp->s_args;

	proc_insn_fn f_func = f_args->func;
	proc_insn_fn s_func = s_args->func;

	CONTEXT ctx;
	CONTEXT *n_ctx = &nthread->n_ctx;
	memcpy(&ctx, n_ctx, sizeof(ctx));

	f_args->read_size = 0;
	f_args->write_size = 0;
	s_args->read_size = 0;
	s_args->write_size = 0;

	f_func(f_args);
	s_func(s_args);
	memcpy(n_ctx, &ctx, sizeof(ctx));

	int8_t f_flags = 0;
	int8_t s_flags = 0;

	int8_t f_diff = 0;
	int8_t s_diff = 0;

	if (f_args->read_size > 0)
		f_flags |= INSN_FLAG_READ;
	else
		f_diff += INSN_ARGS_READ_DIFF;

	if (s_args->read_size > 0)
		s_flags |= INSN_FLAG_READ;
	else
		s_diff += INSN_ARGS_READ_DIFF;

	f_func(f_args);
	s_func(s_args);
	memcpy(n_ctx, &ctx, sizeof(ctx));

	if (f_args->write_size > 0)
		f_flags |= INSN_FLAG_WRITE;
	else {
		memcpy(f_args, (void *)f_args + INSN_ARGS_WRITE_DIFF,
		       sizeof(insn_args_t));
		f_diff += INSN_ARGS_WRITE_DIFF;
	}

	void *pos = (void *)(f_args + 1) - f_diff;
	if (s_args->write_size > 0) {
		s_flags |= INSN_FLAG_WRITE;
		memcpy(pos, s_args, sizeof(insn_args_t));
	} else {
		s_diff += INSN_ARGS_WRITE_DIFF;
		memcpy(pos, (void *)s_args + INSN_ARGS_WRITE_DIFF,
		       sizeof(insn_args_t));
	}

	size_t size = sizeof(nh_trampoline_t) - f_diff - s_diff;
	if (N_REALLOC(tramp, size) != NULL) {
		proc_insns_fn func = proc_insns_funcs[f_flags][1 + s_flags];
		tramp->func = func;
		func(args);
	}
}

static void proc_insns_select(void *args)
{
	nh_trampoline_t *tramp =
		(nh_trampoline_t *)(args - sizeof(proc_insns_fn));
	insn_args_rw_t *f_args = &tramp->f_args;
	insn_args_rw_t *s_args = &tramp->s_args;

	if (f_args->func != NULL && s_args->func != NULL)
		proc_insns_select_f_s(args);
	else if (f_args->func != NULL)
		proc_insns_select_f(args);
}

bool nh_trampoline_add_insn(nh_trampoline_t *tramp, cs_insn *insn)
{
	bool ret;

	insn_args_rw_t *f_args = &tramp->f_args;
	insn_args_rw_t *args;

	// LOG_INFO("0x%" PRIx64 ":\t%s\t%s", insn->address, insn->mnemonic,
	// 	 insn->op_str);

	if (f_args->func == NULL) {
		args = f_args;
	} else {
		insn_args_rw_t *s_args = &tramp->s_args;
		if (s_args->func == NULL)
			args = s_args;
		else {
			ret = false;
			goto add_insn_return;
		}
	}

	ret = set_insn_args(args, insn) != NULL;

add_insn_return:
	cs_free(insn, 1);
	return ret;
}

nh_trampoline_t *nh_trampoline_init()
{
	nh_trampoline_t *tramp = N_ALLOC(sizeof(nh_trampoline_t));
	if (tramp == NULL)
		return NULL;

	tramp->f_args.func = NULL;
	tramp->s_args.func = NULL;
	tramp->func = (proc_insns_fn)proc_insns_select;
	return tramp;
}

void nh_trampoline_destroy(nh_trampoline_t *tramp)
{
	if (tramp == NULL)
		return;

	N_FREE(tramp);
}

void *nh_trampoline_ex(nhook_manager_t *nhook_manager, nhook_t *nhook,
		       nh_trampoline_t *tramp, va_list args)
{
#ifndef NTUTILS_GLOBAL_CC
	ntu_set_cc(nhook->cc);
#endif /* ifndef NTUTILS_GLOBAL_CC */

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

	tramp->func(tramp->args);

	void *rip = NTHREAD_GET_REG(nthread, NTHREAD_RIP);
	uint8_t len = nhook->affected_length;

	void *call = func + len;

	void *reg_args[8];
	ntu_get_reg_args(arg_count, reg_args);

	if (HAS_ERR(ntu_set_args_v(arg_count, args)))
		return NULL;

	ntu_set_reg_args(arg_count, reg_args);

	if (rip >= func && rip < call)
		NTHREAD_SET_REG(nthread, NTHREAD_RIP, call);

	if (HAS_ERR(nthread_set_regs(nthread)))
		return NULL;
	if (HAS_ERR(nthread_wait(nthread)))
		return NULL;

	return NTHREAD_GET_REG(nthread, NTHREAD_RAX);
}
