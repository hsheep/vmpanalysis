# -*- coding:utf-8 -*-
# code by @madfinger, 2020-3-2

import idaapi
import idc
from capstone import *


jmp_set = [
    idaapi.NN_jmp,
    idaapi.NN_jmpfi,
    idaapi.NN_jmpni,
    idaapi.NN_jmpshort
]


# EFlags
CF = 1
PF = 4
AF = 0x10
ZF = 0x40
SF = 0x80
TF = 0x100
IF = 0x200
DF = 0x400
OF = 0x800


jcc_set = {
    idaapi.NN_ja:   [CF&ZF, [0]],                           # CF=0 and ZF=0
    idaapi.NN_jae:  [CF, [0]],                              # CF=0
    idaapi.NN_jb:   [CF, [CF]],                             # CF=1
    idaapi.NN_jbe:  [CF&ZF, [CF, ZF, CF&ZF]],               # CF=1 or ZF=1
    idaapi.NN_jc:   [CF, [CF]],                             # CF=1
    idaapi.NN_je:   [ZF, [ZF]],                             # ZF=1
    idaapi.NN_jg:   [ZF&SF&OF, [SF&OF, 0]],                 # ZF=0 and SF=OF
    idaapi.NN_jge:  [SF&OF, [SF&OF, 0]],                    # SF=OF
    idaapi.NN_jl:   [SF&OF, [SF, OF]],                      # SF!=OF
    idaapi.NN_jle:  [ZF&SF&OF, [SF, OF, SF&ZF, OF&ZF, ZF, SF&ZF&OF]],     # ZF=1 or SF!=OF
    idaapi.NN_jna:  [CF&ZF, [CF, ZF, CF&ZF]],               # CF=1 or ZF=1
    idaapi.NN_jnae: [CF, [CF]],                             # CF=1
    idaapi.NN_jnb:  [CF, [0]],                              # CF=0
    idaapi.NN_jnbe: [CF&ZF, [0]],                           # CF=0 and ZF=0
    idaapi.NN_jnc:  [CF, [0]],                              # CF=0
    idaapi.NN_jne:  [ZF, [0]],                              # ZF=0
    idaapi.NN_jng:  [ZF&SF&OF, [SF, OF, SF&ZF, OF&ZF, ZF, SF&ZF&OF]],   # ZF=1 or SF!=OF
    idaapi.NN_jnge: [SF&OF, [SF, OF]],                      # SF!=OF
    idaapi.NN_jnl:  [SF&OF, [SF&OF, 0]],                    # SF=OF
    idaapi.NN_jnle: [ZF&SF&OF, [SF&OF, 0]],                 # ZF=0 and SF=OF
    idaapi.NN_jno:  [OF, [0]],                              # OF=0
    idaapi.NN_jnp:  [PF, [0]],                              # PF=0
    idaapi.NN_jns:  [SF, [0]],                              # SF=0
    idaapi.NN_jnz:  [ZF, [0]],                              # ZF=0
    idaapi.NN_jo:   [OF, [OF]],                             # OF=1
    idaapi.NN_jp:   [PF, [PF]],                             # PF=1
    idaapi.NN_jpe:  [PF, [PF]],                             # PF=1
    idaapi.NN_jpo:  [PF, [0]],                              # PF=0
    idaapi.NN_js:   [SF, [SF]],                             # SF=1
    idaapi.NN_jz:   [ZF, [0]],                              # ZF=0
}

data_transfer_condition = [
    idaapi.NN_cmovz,
    idaapi.NN_cmovnz,
    idaapi.NN_cmovbe,
    idaapi.NN_cmovnb,
    idaapi.NN_cmovb,
    idaapi.NN_cmovbe,
    idaapi.NN_cmovg,
    idaapi.NN_cmovge,
    idaapi.NN_cmovl,
    idaapi.NN_cmovle,
    idaapi.NN_cmovo,
    idaapi.NN_cmovno,
    idaapi.NN_cmovs,
    idaapi.NN_cmovns,
    idaapi.NN_cmovp,
    idaapi.NN_cmovnp,
    idaapi.NN_cmovs,
    idaapi.NN_cmovns,
    idaapi.NN_cmova,
    idaapi.NN_cmpxchg,
    idaapi.NN_cmpxchg8b,
]


data_transfer_x = [
    idaapi.NN_xadd,
    idaapi.NN_xchg,
]


data_transfer = [
    idaapi.NN_mov,
    idaapi.NN_movsx,
    idaapi.NN_movzx,
    idaapi.NN_pop,
    idaapi.NN_lea
    # idaapi.NN_bswap,
]


flag_control = [
    idaapi.NN_stc,
    idaapi.NN_clc,
    idaapi.NN_cmc,
    idaapi.NN_cld,
    idaapi.NN_std,
    # idaapi.NN_lahf,
    # idaapi.NN_sahf,
    idaapi.NN_sti,
    idaapi.NN_cli,
    idaapi.NN_cmp,
    idaapi.NN_test,
]


stack_operation = [
    idaapi.NN_push,
    idaapi.NN_pusha,
    idaapi.NN_pushad,
    idaapi.NN_pushf,
    idaapi.NN_pushfd,
    idaapi.NN_pop,
    idaapi.NN_popa,
    idaapi.NN_popad,
    idaapi.NN_popf,
    idaapi.NN_popfd,
]


bit_extend = [
    idaapi.NN_cbw,
    idaapi.NN_cwd,
    idaapi.NN_cdq,
    idaapi.NN_cwde,
    idaapi.NN_cdqe,
]


IDA_REG_EAX = 0
IDA_REG_AX = 0
IDA_REG_AL = 0
IDA_REG_AH = 0
IDA_REG_ECX = 1
IDA_REG_CX = 1
IDA_REG_CL = 1
IDA_REG_CH = 1
IDA_REG_EDX = 2
IDA_REG_DX = 2
IDA_REG_DL = 2
IDA_REG_DH = 2
IDA_REG_EBX = 3
IDA_REG_BX = 3
IDA_REG_BL = 3
IDA_REG_BH = 3
IDA_REG_ESP = 4
IDA_REG_SP = 4
IDA_REG_EBP = 5
IDA_REG_BP = 5
IDA_REG_ESI = 6
IDA_REG_SI = 6
IDA_REG_EDI = 7
IDA_REG_DI = 7


capstone_reg_map = {
    "eax": 0,
    "ax": 0,
    "al": 0,
    "ah": 0,
    "ecx": 1,
    "cx": 1,
    "cl": 1,
    "ch": 1,
    "edx": 2,
    "dx": 2,
    "dl": 2,
    "dh": 2,
    "ebx": 3,
    "bx": 3,
    "bl": 3,
    "bh": 3,
    "esp": 4,
    "sp": 4,
    "ebp": 5,
    "bp": 5,
    "esi": 6,
    "si": 6,
    "edi": 7,
    "di": 7,
}

# register map
idareg2unicorn = [
    19,  # UC_X86_REG_EAX
    22,  # UC_X86_REG_ECX
    24,  # UC_X86_REG_EDX
    21,  # UC_X86_REG_EBX
    30,  # UC_X86_REG_ESP
    20,  # UC_X86_REG_EBP
    29,  # UC_X86_REG_ESI
    23,  # UC_X86_REG_EDI
]


def reg_map(reg_value):
    """ remap AL/CL/DL/BL AH/CH/DH/BH """
    reg_index = reg_value % 0x10
    if reg_value > 0x10:
        reg_index %= 4
    return reg_index


# capstone init and set "detail" mode
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True


# capstone 解析指令, 获取phrase操作数引用的base&index寄存器
def get_displ_reg(arg_inst, opt_index):
    base_reg = -1
    index_reg = -1
    disp = 0

    # capstone 解码内存引用寄存器
    for cs_insn in md.disasm(idc.get_bytes(arg_inst.ea, arg_inst.size), arg_inst.size):
        cs_opt0 = cs_insn.operands[opt_index]

        # ps: mov eax, [edi+ecx+0x10]
        # 基地址寄存器
        if cs_opt0.value.mem.base:
            base_reg = capstone_reg_map[cs_insn.reg_name(cs_opt0.value.mem.base)]

        # 变地寄存器
        if cs_opt0.value.mem.index:
            index_reg = capstone_reg_map[cs_insn.reg_name(cs_opt0.value.mem.index)]

        # 偏移
        if cs_opt0.value.mem.disp:
            disp = cs_opt0.value.mem.disp
        break

    return base_reg, index_reg, disp


def DebugOutput(inst):
    print("%s %s" % (hex(int(inst.ea)), idc.GetDisasm(inst.ea)))
