# -*- coding:utf-8 -*-
# code by @madfinger, 2020-3-24

from __future__ import print_function
import idautils
import traceback
import time
import os
import logging

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

log = logging.getLogger("main.VMTraceParser")

# 调试参数初始化
DEBUG = False                          # <-- 全局输出调试信息
DEBUG_BLOCK_INDEX = []         # <-- 输出特定指令到调试信息
OUTPUT_FILE = True                     # <-- 是否要输出到文件
g_block_index = -1


# 获取当前镜像基地址
cur_base_addr = idaapi.get_imagebase()
print("current baseaddr: %08x" % cur_base_addr)


def dbgprint(dbg_str):
    if DEBUG or g_block_index in DEBUG_BLOCK_INDEX:
        print("  %s" % dbg_str)


def GetBlockCode(trace_fd, base_addr):
    """ execute code by unicron """
    inst_series = list()
    icount = 0
    reg_dict = {}
    start_addr = None
    fd_tell = 0

    dbgprint("=================== [%s] debug =================" % g_block_index)
    
    # 继续读取文件分析
    for inst_context_line in trace_fd.xreadlines():
        fd_tell += len(inst_context_line)
        # dbgprint("[%s] %s" % (fd_tell, inst_context_line))
        # 寄存器上下文
        context = inst_context_line.strip().split(",")
        cur_addr = cur_base_addr + (int(context[0]) - base_addr)
        reg_context = context[1:]
        reg_dict[icount] = [int(item) for item in reg_context]
        icount += 1
        
        # decode instruction
        inst = idautils.DecodeInstruction(cur_addr)
        inst_series.append(inst)
        
        dbgprint("%08x %s" % (inst.ea, idc.GetDisasm(inst.ea)))
        
        if not start_addr:
            start_addr = cur_addr

        # "call"
        if inst.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
            if inst.Op1.type not in (idaapi.o_imm, idaapi.o_far, idaapi.o_near):
                log.info("CALL CalcNextAddr Error: %08x %s" % (inst.ea, idc.GetDisasm(inst.ea)))

        # "jmp" and "jcc"
        elif inst.itype in jmp_set or inst.itype in jcc_set:
            if inst.Op1.type == idaapi.o_reg:
                log.info("NN_jmp reg, Break!")
                break
            elif inst.Op1.type not in (idaapi.o_imm, idaapi.o_far, idaapi.o_near):
                print("JMP CalcNextAddr Error: %08x %s" % (inst.ea, idc.GetDisasm(inst.ea)))

        # "retn"
        elif inst.itype == idaapi.NN_retn:
            log.info("NN_retn, break")
            break

    return start_addr, inst_series, reg_dict, fd_tell


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


def StartAnalysis(trace_file, base_addr, seek_off=0):
    """ @seek_off: vmentry对应的文件偏移，"""
    global g_block_index
    block_index = 0

    # debug list
    DEBUG_BLOCK_INDEX.sort()

    # all handlers
    inst_blocks = []
    v_code_list = []
    v_code = ""
    cur_addr = None
    trace_line = 0
    trace_fd = open(trace_file)
    if seek_off:
        trace_fd.seek(seek_off, 0)

    # 开始分析
    # while v_code != "VMLeave":
    while True:
        try:
            log.info("---- [%s]Debug, tell: %s ----" %
                  (block_index, trace_line))
            # 指令解析,获取一个代码块
            # start0 = time.time()
            g_block_index = block_index
            cur_addr, inst_series_all, reg_dict, fd_tell = GetBlockCode(trace_fd, base_addr)
            trace_line += fd_tell
            if not cur_addr:
                log.info("# end of trace, exit!")
                break
            
            # 消除花指令，输出结果
            # start1 = time.time()
            cleaner_init = False
            if v_code == "":
                cleaner_init = True
            inst_series_clean = InstructionCleaner(
                inst_series_all, block_index=block_index, init=cleaner_init)

            # 记录去花后的所有指令, 用于分析
            inst_blocks.append(inst_series_clean)
            if not inst_series_clean:
                log.error("exception %08x, inst_series_clean is empty!!" % cur_addr)
                break

            # 解析并输出VM指令
            # start2 = time.time()
            v_code = ConvertCodeSequence(inst_series_clean, reg_dict, block_index)
            if not v_code:
                log.info("%08x failed" % cur_addr)
                continue
            v_code_list.append([cur_addr, v_code])
            print ("$ %s %08x  %s" % (block_index, cur_addr, v_code))

            # 执行时间分析
            # start3 = time.time()
            # print(" GetCodeBlock= %s\n ClearInstructions=%s\n ConvertVMCode=%s\n" %
            #       (start1 - start0, start2 - start1, start3 - start2))

            block_index += 1

            # 调试执行到指定代码块
            if DEBUG_BLOCK_INDEX and block_index > DEBUG_BLOCK_INDEX[-1]:
                log.info("DEBUG Break!")
                break
                
        except KeyboardInterrupt as e:
            print("# suspend analysis.")
            break
        
        except Exception as e:
            log.error(traceback.format_exc())
            break

    trace_fd.close()

    # 本次虚拟执行的所有指令缓存写入文件
    if OUTPUT_FILE:
        log.info("output result...")
        file_dir, file_name = os.path.split(trace_file)
        # x86Inst2File(inst_blocks, "%s/insts.txt" % file_dir)
        vCode2File(v_code_list, "%s/vcodes.txt" % file_dir)
    
    print("done.")

    return v_code_list


# trace file format:
# "addr,eax,ecx,edx,ebx,esp,ebp,esi,edi\n"
# ...
if __name__ == "__main__":
    # * 使用前请指定"映像基地址"
    base_addr = 0x00FC0000
    trace_file = "/Users/madfinger/Desktop/VMPAnalysis/test/result.trace.txt"
    if not os.path.exists(trace_file):
        print("trace file %s not found!!!" % trace_file)
        exit(0)
    StartAnalysis(trace_file, base_addr)
