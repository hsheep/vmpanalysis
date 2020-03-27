# -*- coding:utf-8 -*-
# code by @madfinger, 2020-3-24

from __future__ import print_function
import idautils
import traceback
import time
import os

# IDAPython 重新加载该模块刷新字节码, 否则执行的字节码和代码不对应
import tools
import VMInstCleaner
import VMInstParser

reload(tools)
reload(VMInstCleaner)
reload(VMInstParser)

from tools import *
from VMInstCleaner import InstructionCleaner
from VMInstParser import ConvertCodeSequence

# 调试参数初始化
DEBUG = False                          # <-- 全局输出调试信息
DEBUG_BLOCK_INDEX = [683]             # <-- 输出特定指令到调试信息
OUTPUT_FILE = True                     # <-- 是否要输出到文件
g_block_index = -1


# 获取当前镜像基地址
cur_base_addr = idaapi.get_imagebase()
print("current baseaddr: %08x" % cur_base_addr)


def dbgprint(dbg_str):
    global g_block_index
    if DEBUG or g_block_index in DEBUG_BLOCK_INDEX:
        print("  %s" % dbg_str)


def GetBlockCode(trace_fd, base_addr, next_context=None):
    """ execute code by unicron """
    inst_series = list()
    icount = 0
    reg_dict = {}
    start_addr = None
    
    """
    # 首条指令分析
    if next_context:
        # 寄存器上下文
        reg_context = next_context[1:]
        reg_dict[icount] = [int(item) for item in reg_context]
        icount += 1
        # print("cur_addr %08x, reg: %s" % (cur_addr, reg_context))
    
        # decode instruction
        inst = idautils.DecodeInstruction(next_context[0])
        inst_series.append(inst)
    """
    
    # 继续读取文件分析
    for inst_context_line in trace_fd.xreadlines():
        # 寄存器上下文
        context = inst_context_line.split(",")
        cur_addr = cur_base_addr + (int(context[0]) - base_addr)
        reg_context = context[1:]
        reg_dict[icount] = [int(item) for item in reg_context]
        icount += 1
        # print("cur_addr %08x, reg: %s" % (cur_addr, reg_context))
        
        # decode instruction
        inst = idautils.DecodeInstruction(cur_addr)
        inst_series.append(inst)
        
        if not start_addr:
            start_addr = cur_addr

        # DebugOutput(inst)

        # "call"
        if inst.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
            if inst.Op1.type not in (idaapi.o_imm, idaapi.o_far, idaapi.o_near):
                print("CALL CalcNextAddr Error: %08x %s" % (inst.ea, idc.GetDisasm(inst.ea)))

        # "jmp" and "jcc"
        elif inst.itype in jmp_set or inst.itype in jcc_set:
            if inst.Op1.type == idaapi.o_reg:
                print("NN_jmp reg, Break!")
                break
            elif inst.Op1.type not in (idaapi.o_imm, idaapi.o_far, idaapi.o_near):
                print("JMP CalcNextAddr Error: %08x %s" % (inst.ea, idc.GetDisasm(inst.ea)))

        # "retn"
        elif inst.itype == idaapi.NN_retn:
            print("NN_retn, break")
            break
    
    """
    # 获取下一条指令地址
    for inst_context_line in trace_fd.xreadlines():
        next_context = inst_context_line.split(",")
        next_context[0] = cur_base_addr + (int(next_context[0]) - base_addr)
        print("# NextBlock, %08x" % int(next_context[0]))
        break
    """
    
    return start_addr, inst_series, reg_dict


def x86Inst2File(handler_list, file_name):
    """ output to file """
    # inst analysis cache
    output_fd = open(file_name, "w+")

    for icount, vm_handler in enumerate(handler_list):
        output_fd.write("\n>>>>>>> Handler: %s >>>>>>>\n" % icount)
        for icount in sorted(vm_handler.keys()):
            inst = vm_handler[icount]
            output_fd.write("%s %s\n" % (hex(int(inst.ea)), idc.GetDisasm(inst.ea)))

    output_fd.close()


def vCode2File(v_code_list, file_name):
    """ output to file"""
    # inst analysis cache
    output_fd = open(file_name, "w+")
    for addr, v_code_item in v_code_list:
        output_fd.write("%s  %s\n" % (hex(int(addr)), v_code_item))
    output_fd.close()


def StartAnalysis(trace_file, base_addr):
    global g_block_index
    block_index = 0

    # debug list
    DEBUG_BLOCK_INDEX.sort()

    # all handlers
    inst_blocks = []
    v_code_list = []
    v_code = ""
    cur_addr = None

    trace_fd = open(trace_file)

    # 开始分析
    while v_code != "VMLeave":
        try:
            print("<<<<<<<<<<<<<<<<<<<<<<<<<< [%s]Debug <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" % block_index)
            # 指令解析,获取一个代码块
            start0 = time.time()
            cur_addr, inst_series_all, reg_dict = GetBlockCode(trace_fd, base_addr, cur_addr)
            g_block_index = block_index

            # 消除花指令，输出结果
            start1 = time.time()
            inst_series_clean = InstructionCleaner(inst_series_all, block_index)

            # 记录去花后的所有指令, 用于分析
            inst_blocks.append(inst_series_clean)
            if not inst_series_clean:
                print("exception, inst_series_clean is empty!!")
                break

            # 解析并输出VM指令
            start2 = time.time()
            v_code = ConvertCodeSequence(inst_series_clean, reg_dict, block_index)
            v_code_list.append([cur_addr, v_code])
            print ("$ %08x  %s" % (cur_addr, v_code))

            start3 = time.time()

            # 执行时间分析
            print(" GetCodeBlock= %s\n ClearInstructions=%s\n ConvertVMCode=%s\n" %
                  (start1 - start0, start2 - start1, start3 - start2))

            block_index += 1

            # 调试执行到指定代码块
            if DEBUG_BLOCK_INDEX and block_index > DEBUG_BLOCK_INDEX[-1]:
                break

        except Exception as e:
            traceback.print_exc()
            break

    trace_fd.close()

    # 本次虚拟执行的所有指令缓存写入文件
    if OUTPUT_FILE:
        file_dir, file_name = os.path.split(trace_file)
        x86Inst2File(inst_blocks, "%s/insts.txt" % file_dir)
        vCode2File(v_code_list, "%s/vcodes.txt" % file_dir)

    return v_code_list


if __name__ == "__main__":
    # * 使用前请指定"映像基地址"
    base_addr = 0x00FC0000
    trace_file = "/Users/madfinger/Desktop/VMPAnalysis/test/result.trace.txt"
    if not os.path.exists(trace_file):
        print("trace file %s not found!!!" % trace_file)
        exit(0)
    StartAnalysis(trace_file, base_addr)
