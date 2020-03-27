# -*- coding:utf-8 -*-
# code by @madfinger, 2020-2-2
import time
from tools import *

# 指令清理器调试变量
DEBUG = False
DEBUG_BLOCK_INDEX = [683]
g_block_index = -1


# instruction recording
reg_reference = [{}, {}, {}, {}, {}, {}, {}, {}]
mem_reference = {}
stack_reference = []
trash_insts = {}

xchg_ref_map = [0, 1, 2, 3, 4, 5, 6, 7]


def dbgprint(dbg_str):
    if DEBUG or g_block_index in DEBUG_BLOCK_INDEX:
        print("  %s" % dbg_str)


def OutputInst(block_index=0):
    global stack_reference
    global mem_reference

    # sort instruction
    instructions = {}

    # 寄存器指令
    for reg_item in reg_reference:
        for inst_item in reg_item.values():
            if inst_item[0] not in trash_insts and (inst_item[0] >> 16) == block_index:
                instructions[inst_item[0]] = inst_item[1]

    # 栈指令
    for inst_item in stack_reference:
        if inst_item[0] not in trash_insts and (inst_item[0] >> 16) == block_index:
            instructions[inst_item[0]] = inst_item[1]
    stack_reference = []

    # 内存指令
    for icount, inst in mem_reference.items():
        if icount not in trash_insts and (icount >> 16) == block_index:
            instructions[icount] = inst
    mem_reference = {}

    dbgprint(">>>>>>> Optimized Instructions >>>>>>>")

    # DEBUG: show handle instruction
    if DEBUG or g_block_index in DEBUG_BLOCK_INDEX:
        for icount in sorted(instructions.keys()):
            inst = instructions[icount]
            print("%s\t%s %s" % (icount, hex(int(inst.ea)), idc.GetDisasm(inst.ea)))

    return instructions


# 优化1: 寄存器传播优化
def RegAnalysis(inst, icount=-1):
    """ instruction analysis"""

    dbgprint("%s %s" % (hex(int(inst.ea)), idc.GetDisasm(inst.ea)))

    # 基本指令类型过滤
    def _inst_filter(arg_inst):
        if arg_inst.Op1.type not in (idaapi.o_reg, idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ):
            # push / pop
            if arg_inst.itype in stack_operation:
                stack_reference.append([icount, arg_inst])
                dbgprint("[+] <push/pop> ignore.")
                return False

            # jcc / jmp
            elif arg_inst.itype in jcc_set or arg_inst.itype == idaapi.NN_jmp:
                dbgprint("trash inst: %s" % idc.GetDisasm(arg_inst.ea))
                return False

        # call
        if arg_inst.itype in (idaapi.NN_call, idaapi.NN_retn):
            stack_reference.append([icount, arg_inst])
            dbgprint("[+] <call> ignore.")
            return False

        # * cmovcc
        elif arg_inst.itype in data_transfer_condition:
            dbgprint("trash inst: %s" % idc.GetDisasm(arg_inst.ea))
            return False

        # * flags
        elif arg_inst.itype in flag_control:
            dbgprint("trash inst: %s" % idc.GetDisasm(arg_inst.ea))
            return False

        # * cbw/cwd/cdq
        elif arg_inst.itype in bit_extend:
            dbgprint("trash inst: %s" % idc.GetDisasm(arg_inst.ea))
            return False

        # * xadd
        elif arg_inst.itype == idaapi.NN_xadd:
            dbgprint("trash inst: %s" % idc.GetDisasm(arg_inst.ea))
            return False

        # * none operand
        elif arg_inst.Op1.type == idaapi.o_void:
            trash_insts[icount] = arg_inst
            dbgprint("[+] operands is None!")
            return False

        return True

    # 目标操作数类型为phrase处理
    def _assign_mem_handle(inst, src_index):
        """
            所有目标寄存器为内存的指令分析
                @icount: 指令顺序
                @inst: 指令结构
                @src_reg: 引用寄存器
        """
        global reg_reference
        # mov dword ptr:[eax + ecx + 4], esi
        # add dword ptr:[eax + ecx + 4], esi

        # 源寄存器列表转移
        dst_index = (src_index + 1) % 2

        if inst.Operands[dst_index].type == idaapi.o_reg:
            opt2_reg = reg_map(inst.Operands[dst_index].reg)
            reg_reference[opt2_reg][icount] = [icount, inst, -1]
            for inst_item in reg_reference[opt2_reg].values():
                if inst_item[0] not in trash_insts:
                    dbgprint("inst_item: %s, %s" % (inst_item, idc.GetDisasm(inst_item[1].ea)))
                    mem_reference[inst_item[0]] = inst_item[1]
            reg_reference[opt2_reg] = dict()

        if inst.Operands[src_index].type != idaapi.o_void:
            dbgprint("MEM_INST: %s, %s %s" % (icount >> 16, hex(int(inst.ea)), idc.GetDisasm(inst.ea)))
            # 目标内存指令列表转移
            base_reg, index_reg, _disp = get_displ_reg(inst, src_index)
            if base_reg != -1:
                reg_reference[base_reg][icount] = [icount, inst]
                for inst_item in reg_reference[base_reg].values():
                    if inst_item[0] not in trash_insts:
                        dbgprint("inst_item: %s, %s" % (inst_item, idc.GetDisasm(inst_item[1].ea)))
                        mem_reference[inst_item[0]] = inst_item[1]
                reg_reference[base_reg] = dict()

            if index_reg != -1:
                reg_reference[index_reg][icount] = [icount, inst]
                for inst_item in reg_reference[index_reg].values():
                    if inst_item[0] not in trash_insts:
                        dbgprint("inst_item: %s, %s" % (inst_item, idc.GetDisasm(inst_item[1].ea)))
                        mem_reference[inst_item[0]] = inst_item[1]
                reg_reference[index_reg] = dict()

    # 目标操作数类型为reg处理
    def _assign_reg_handle(arg_inst, src_index):
        """
            数据传输指令分析
                @icount: 指令顺序
                @inst: 指令结构
                @src_reg: 引用寄存器
        """
        global reg_reference

        # 排除源和目标寄存器存在交叉引用的情况: mov edi, dword ptr:[edi + ecx + 4]
        if arg_inst.Op2.type == idaapi.o_reg:
            if arg_inst.Op1.reg == arg_inst.Op2.reg:
                dbgprint("spread to self %s" % idc.GetDisasm(arg_inst.ea))
                return
        elif arg_inst.Op2.type in (idaapi.o_phrase, idaapi.o_mem, idaapi.o_displ):
            if arg_inst.Op1.reg in get_displ_reg(inst, 1)[:1]:
                dbgprint("spread to self %s" % idc.GetDisasm(arg_inst.ea))
                return

        # mov edi, dword ptr:[eax + ecx + 4]
        src_reg = reg_map(arg_inst.Operands[src_index].reg)
        opt1_reg_list = reg_reference[src_reg]

        # dbgprint("opt1_reg_list %s" %
        #          ([[hex(opt1_reg_list[item_k][1].ea), idc.GetDisasm(opt1_reg_list[item_k][1].ea), opt1_reg_list[item_k][2]] for item_k in reversed(opt1_reg_list.keys())]))

        # 逆向枚举最后一次引用指令
        for inst_count, inst_key in enumerate(reversed(sorted(opt1_reg_list.keys()))):
            inst_item = opt1_reg_list[inst_key]
            dbgprint("inst_item: %s, %s" % (inst_item, idc.GetDisasm(inst_item[1].ea)))

            # 取出被xchg映射寄存器
            ref_reg = -1
            if inst_item[2] != ref_reg:
                ref_reg = xchg_ref_map[inst_item[2]]
                dbgprint("inst_item[2]: %s -> %s" % (inst_item[2], ref_reg))
            # ref_reg = inst_item[2]

            # 发现非自身的指令引用(-1 自身指令, src_reg 可能为反复合并自身寄存器索引)
            if ref_reg not in (-1, src_reg) and inst_item[0] not in trash_insts:

                # 仍在寄存器引用列表中, 将当前寄存器指令表迁移到引用寄存器列表中
                if inst_item[0] not in mem_reference:
                    dbgprint("combine list %s to %s" % (src_reg, ref_reg))
                    reg_reference[ref_reg].update(sorted(opt1_reg_list.items(), reverse=True)[inst_count:])

                # 仍在寄存器引用列表中, 将当前寄存器指令表迁移到引用内存列表中
                else:
                    dbgprint("combine list %s to mem" % src_reg)
                    for key, value in sorted(opt1_reg_list.items(), reverse=True)[inst_count:]:
                        # dbgprint("move inst_item: %08x, %s" % (value[1].ea, idc.GetDisasm(value[1].ea)))
                        mem_reference[key] = value[1]
                break

            # 否则，记录到垃圾指令列表
            else:
                trash_insts[inst_item[0]] = inst_item[1]
                dbgprint("trash inst: %08x %s" % (inst_item[1].ea, idc.GetDisasm(inst_item[1].ea)))

        # 重置映射关系 [??]
        dbgprint("reset xchg_ref_map: %s" % src_reg)
        xchg_ref_map[xchg_ref_map[src_reg]] = xchg_ref_map[src_reg]
        # xchg_ref_map[src_reg] = src_reg

        # 清理寄存器列表
        opt1_reg_list.clear()

    # 源操作数类型处理
    def _refer_reg_handle(inst, src_index):
        """
            算术指令、逻辑指令、位运算指令分析
                @icount: 指令顺序
                @inst: 指令结构
                @src_reg: 引用寄存器
        """
        global reg_reference

        # 指令加入目标寄存器队列
        src_reg = reg_map(inst.Operands[src_index].reg)
        reg_reference[src_reg][icount] = [icount, inst, -1]

        # 第二/三操作数寄存器分析，并将引用指令加入其队列
        for opt_count, cur_opt in enumerate(inst.Operands):
            if opt_count == src_index:
                continue

            # * 排除源和目标寄存器存在交叉引用的情况
            if cur_opt.type == idaapi.o_reg:
                cur_reg = reg_map(cur_opt.reg)
                if src_reg != cur_reg:
                    reg_reference[cur_reg][icount] = [icount, inst, src_reg]

            elif cur_opt.type in (idaapi.o_phrase, idaapi.o_mem, idaapi.o_displ):
                dbgprint("MEM_INST: %s, %s %s" % (icount >> 16, hex(int(inst.ea)), idc.GetDisasm(inst.ea)))
                base_reg, index_reg, _disp = get_displ_reg(inst, 1)
                if base_reg not in (-1, src_reg):
                    reg_reference[base_reg][icount] = [icount, inst, src_reg]
                if index_reg not in (-1, src_reg):
                    reg_reference[index_reg][icount] = [icount, inst, src_reg]

    def xchg_inst_handler(inst):
        """ xchg 指令特殊处理，将其转为指令队列交换"""
        # xchg reg, reg (寄存器指令队列交换)
        if inst.Op1.type == idaapi.o_reg and inst.Op2.type == idaapi.o_reg:
            opt1_reg = reg_map(inst.Op1.reg)
            opt2_reg = reg_map(inst.Op2.reg)

            # xchg eax, eax / xchg dl, dh
            if opt1_reg != opt2_reg:
                reg_reference[opt1_reg][icount] = [icount, inst, -1]
                reg_reference[opt2_reg][icount] = [icount, inst, -1]
                tmp_refer = reg_reference[opt1_reg]
                reg_reference[opt1_reg] = reg_reference[opt2_reg]
                reg_reference[opt2_reg] = tmp_refer

                # 设置寄存器引用映射, 在赋值合并引用列表的时候引用此表
                xchg_ref_map[opt1_reg] = opt2_reg
                xchg_ref_map[opt2_reg] = opt1_reg

                dbgprint("[+] xchg reg:%s, reg:%s" % (opt1_reg, opt2_reg))

        # xchg reg/phrase, phrase/reg (相当于两条mov指令)
        else:
            for opt_count, cur_opt in enumerate(inst.Operands):
                # mov edi, dword ptr:[eax + ecx + 4]
                if cur_opt.type == idaapi.o_reg:
                    _assign_reg_handle(inst, opt_count)
                    _refer_reg_handle(inst, opt_count)

                # mov dword ptr:[eax + ecx + 4], edi
                elif cur_opt.type in (idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ):
                    _assign_mem_handle(inst, opt_count)
            dbgprint("[+] xchg reg/disp, disp/reg")

    # -------------------------------- 处理逻辑开始 --------------------------------
    # 过滤和保存非参与寄存器传播分析的指令
    if _inst_filter(inst):

        # xchg 指令处理
        if inst.itype in (idaapi.NN_xchg, idaapi.NN_xadd):
            xchg_inst_handler(inst)

        # push/jmp 指令处理(非立即数)
        elif (inst.itype == idaapi.NN_push or inst.itype in jmp_set) and \
                inst.Op1.type in (idaapi.o_reg, idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ):
            # [引用] 当前指令为内存操作，将该指令引用的所有寄存器列表转移到 mem_reference
            if inst.Op1.type == idaapi.o_reg:
                _assign_mem_handle(inst, 1)
            else:
                _assign_mem_handle(inst, 0)
            dbgprint("[+] push/jmp handler")

        # register assign （目标寄存器被赋值）
        elif inst.Op1.type == idaapi.o_reg:
            # [清理] 当前指令目标寄存器如果被重新赋值, pop也归类到赋值操作
            if inst.itype in data_transfer or inst.itype == idaapi.NN_pop:
                _assign_reg_handle(inst, 0)
                _refer_reg_handle(inst, 0)
                dbgprint("[+] data_transfer inst")

            # [引用] 当前指令为计算赋值，记录到寄存器引用列表
            else:
                _refer_reg_handle(inst, 0)
                dbgprint("[+] refer inst")

        # assign value to mem (内存赋值)
        elif inst.Op1.type in (idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ):
            # [引用] 当前指令为内存操作，以第二操作数（默认为寄存器）为主引用列表
            _assign_mem_handle(inst, 0)
            dbgprint("[+] mem inst")

        else:
            print("# >>>>>>>>>>>>> record error: %s %s <<<<<<<<<<<<<" %
                  (hex(int(inst.ea)), idc.GetDisasm(inst.ea)))


# Export
def InstructionCleaner(inst_series_all, block_index=0):
    global g_block_index
    global xchg_ref_map

    # 每个代码块重置映射表 [??]
    xchg_ref_map = [0, 1, 2, 3, 4, 5, 6, 7]

    # global debug
    g_block_index = block_index

    # block_index:16 | inst_index:16
    icount = block_index << 0x10

    for cur_inst in inst_series_all:
        # register spread
        RegAnalysis(cur_inst, icount)
        icount += 1

    return OutputInst(block_index)
