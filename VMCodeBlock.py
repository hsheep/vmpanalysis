# -*- coding:utf-8 -*-
# code by @madfinger, 2020-2-2
from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import idautils
import traceback
import struct
import time

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
DEBUG_BLOCK_INDEX = [97]             # <-- 输出特定指令到调试信息
OUTPUT_FILE = True                     # <-- 是否要输出到文件
g_block_index = -1

# memory address where emulation starts
BASE_ADDR = 0x400000                # <-- 当前分析PE到IDA加载基地址
SPACE_SIZE = 20 * 1024 * 1024       # <-- 内存映像大小

mu = Uc(UC_ARCH_X86, UC_MODE_32)
mu.mem_map(BASE_ADDR, SPACE_SIZE)
mu.mem_write(BASE_ADDR, idc.get_bytes(BASE_ADDR, SPACE_SIZE))

# init stack and register
STACK_ADDR = 0x10000
mu.mem_map(STACK_ADDR, 1 * 1024 * 1024)
mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + 0x90000)
mu.reg_write(UC_X86_REG_EBP, STACK_ADDR + 0x90000)


def dbgprint(dbg_str):
    global g_block_index
    if DEBUG or g_block_index in DEBUG_BLOCK_INDEX:
        print("  %s" % dbg_str)


def DebugRegContext(mu, inst):
    if DEBUG or g_block_index in DEBUG_BLOCK_INDEX:
        cur_esp = mu.reg_read(UC_X86_REG_ESP)

        print(">>> EAX = 0x%08x, \t[%s]: 0x%X" % (mu.reg_read(UC_X86_REG_EAX),
                                                  hex(cur_esp),
                                                  struct.unpack("<L", mu.mem_read(cur_esp, 4))[0]))
        print(">>> ECX = 0x%08x, \t[%s]: 0x%X" % (mu.reg_read(UC_X86_REG_ECX),
                                                  hex(cur_esp + 4),
                                                  struct.unpack("<L", mu.mem_read(cur_esp + 4, 4))[0]))
        print(">>> EDX = 0x%08x, \t[%s]: 0x%X" % (mu.reg_read(UC_X86_REG_EDX),
                                                  hex(cur_esp + 8),
                                                  struct.unpack("<L", mu.mem_read(cur_esp + 8, 4))[0]))
        print(">>> EBX = 0x%08x, \t[%s]: 0x%X" % (mu.reg_read(UC_X86_REG_EBX),
                                                  hex(cur_esp + 0xC),
                                                  struct.unpack("<L", mu.mem_read(cur_esp + 0xC, 4))[0]))
        print(">>> ESI = 0x%08x, \t[%s]: 0x%X" % (mu.reg_read(UC_X86_REG_ESI),
                                                  hex(cur_esp + 0x10),
                                                  struct.unpack("<L", mu.mem_read(cur_esp + 0x10, 4))[0]))
        print(">>> EDI = 0x%08x, \t[%s]: 0x%X" % (mu.reg_read(UC_X86_REG_EDI),
                                                  hex(cur_esp + 0x14),
                                                  struct.unpack("<L", mu.mem_read(cur_esp + 0x14, 4))[0]))
        print(">>> ESP = 0x%08x, \t[%s]: 0x%X" % (cur_esp,
                                                  hex(cur_esp + 0x18),
                                                  struct.unpack("<L", mu.mem_read(cur_esp + 0x18, 4))[0]))
        print(">>> EBP = 0x%08x, \t[%s]: 0x%X" % (mu.reg_read(UC_X86_REG_EBP),
                                                  hex(cur_esp + 0x1C),
                                                  struct.unpack("<L", mu.mem_read(cur_esp + 0x1C, 4))[0]))
        print("%s %s" % (hex(int(inst.ea)), idc.GetDisasm(inst.ea)))


# 注:
# 某地址在IDA中未被解析，所以会引出很多分析上的问题，
# 这里是通过该函数让IDA将指定地址上的内容分析为代码
def IDACode(cur_addr):
    """  set db to Code """
    # print("[IDC] make code %08x" % cur_addr)
    sec_chance = True

    while not idc.MakeCode(cur_addr) and sec_chance:
        print("[IDC] %08x make code failed!" % cur_addr)
        # time.sleep(0.5)
        # idc.del_items(cur_addr)
        idc.MakeUnkn(cur_addr, 1)
        idc.MakeByte(cur_addr)
        idc.MakeCode(cur_addr)
        sec_chance = False
        # time.sleep(0.5)

    if not sec_chance:
        time.sleep(0.5)
        DebugOutput(idautils.DecodeInstruction(cur_addr))


def GetBlockCode(cur_addr):
    """ execute code by unicron """
    next_addr = 0
    inst_series = list()
    inst = None
    icount = 0
    reg_dict = {}

    # EIP初始化
    mu.reg_write(UC_X86_REG_EIP, cur_addr)

    while True:
        try:
            # decode instruction
            inst = idautils.DecodeInstruction(cur_addr)
            inst_series.append(inst)

            # if inst.ea == 0x5F5C82:
            #     print("NN_retn %s" % idaapi.NN_retn)
            #     dbgprint("%08x %s, itype: %s" % (inst.ea, idc.GetDisasm(inst.ea), inst.itype))

            # execute code
            # "call"
            if inst.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
                if inst.Op1.type in (idaapi.o_imm, idaapi.o_far, idaapi.o_near):
                    cur_addr = int(inst.Op1.addr)
                    mu.emu_start(inst.ea, cur_addr)
                    icount += 1

                    # IDA分析下一段代码
                    idc.MakeCode(cur_addr)
                    continue

                else:
                    # raise UcError("CALL CalcNextAddr Error: %s" % idc.GetDisasm(inst.ea))
                    print("CALL CalcNextAddr Error: %08x %s" % (inst.ea, idc.GetDisasm(inst.ea)))
                    DebugRegContext(mu, inst)

            # "jmp" and "jcc"
            elif inst.itype in jmp_set or \
                    (inst.itype in jcc_set and (mu.reg_read(UC_X86_REG_EFLAGS) & jcc_set[inst.itype][0]) in jcc_set[inst.itype][1]):

                if inst.Op1.type == idaapi.o_reg:
                    next_addr = mu.reg_read(idareg2unicorn[inst.Op1.reg])
                    print("NN_jmp: 0x%x, Break!" % next_addr)
                    try:
                        mu.emu_start(inst.ea, next_addr)
                    except UcError as e:
                        print("ERROR: %s, %08x %s" % (e, inst.ea, idc.GetDisasm(inst.ea)))

                    # IDA分析下一段代码
                    idc.MakeCode(next_addr)
                    break

                elif inst.Op1.type in (idaapi.o_imm, idaapi.o_far, idaapi.o_near):
                    cur_addr = int(inst.Op1.addr)
                    mu.emu_start(inst.ea, cur_addr)
                    icount += 1

                    # IDA分析下一段代码
                    idc.MakeCode(cur_addr)
                    continue

                else:
                    # raise UcError("JMP CalcNextAddr Error: %s" % idc.GetDisasm(inst.ea))
                    print("JMP CalcNextAddr Error: %08x %s" % (inst.ea, idc.GetDisasm(inst.ea)))
                    DebugRegContext(mu, inst)

            # "retn"
            elif inst.itype == idaapi.NN_retn:
                cur_esp = mu.reg_read(UC_X86_REG_ESP)
                next_addr = struct.unpack("<L", mu.mem_read(cur_esp, 4))[0]
                print("NN_retn: 0x%x, cur_esp: %x, Break!" % (next_addr, cur_esp))
                try:
                    mu.emu_start(inst.ea, next_addr)
                except UcError as e:
                    print("ERROR: %s, %08x %s" % (e, inst.ea, idc.GetDisasm(inst.ea)))

                # IDA分析下一段代码
                idc.MakeCode(next_addr)
                break

            # "mov"
            elif inst.itype in data_transfer:
                # 如果有内存操作，获取所有寄存器的值存入映射表 "{ 指令ID, [寄存器列表] }"
                for opi in [0, 1]:
                    if inst.Operands[opi].type in [idaapi.o_displ, idaapi.o_mem, idaapi.o_phrase]:
                        reg_dict[icount] = [mu.reg_read(item) for item in idareg2unicorn]
                        # DebugRegContext(mu, inst)
                        break
                mu.emu_start(inst.ea, inst.ea + inst.size)

            else:
                mu.emu_start(inst.ea, inst.ea + inst.size)

        except UcError as e:
            # 暂时忽略掉未知的内存读写（有时是FS段寄存器读写导致）
            if e.errno not in (UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED, UC_ERR_FETCH_UNMAPPED):
                print("KNOWN ERROR: %s, %08x %s" % (e, inst.ea, idc.GetDisasm(inst.ea)))
                raise e
            else:
                print("ERROR: %s, %08x %s" % (e, inst.ea, idc.GetDisasm(inst.ea)))
                # break

        except Exception as e:
            traceback.print_exc()
            raise e

        # next info
        # cur_addr = idc.NextHead(cur_addr)     # <-- 获取IDA未分析的地址会返回错误的长度
        cur_addr += inst.size
        icount += 1

    # 指令末尾提取寄存器上下文
    reg_dict[icount] = [mu.reg_read(item) for item in idareg2unicorn]

    return next_addr, inst_series, reg_dict


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


def StartAnalysis(code_start_addr):
    global g_block_index
    block_index = 0

    # debug list
    DEBUG_BLOCK_INDEX.sort()

    # all handlers
    inst_blocks = []
    v_code_list = []
    v_code = ""
    block_addr = code_start_addr

    # 开始分析
    while v_code != "VMLeave":
        try:
            print("<<<<<<<<<<<<<<<<<<<<<<<<<< [%s]Debug: 0x%x <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" %
                  (block_index, block_addr))
            cur_addr = block_addr
            g_block_index = block_index

            # 指令解析,获取一个代码块
            start0 = time.time()
            block_addr, inst_series_all, reg_dict = GetBlockCode(block_addr)

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

    # 本次虚拟执行的所有指令缓存写入文件
    if OUTPUT_FILE:
        x86Inst2File(inst_blocks, "/Users/madfinger/Desktop/inst_code_%08X.txt" % code_start_addr)
        vCode2File(v_code_list, "/Users/madfinger/Desktop/vcode_%08X.txt" % code_start_addr)

    return v_code_list


if __name__ == "__main__":
    # * 使用前请指定"映像基地址"和"映像大小"
    # vmentry
    # 5ssc
    # vmcode_start_addr = 0x6257CF
    # vmcode_start_addr = 0x62f66A
    # vmcode_start_addr = 0x664C1A
    # vmcode_start_addr = 0x64FF86

    # msgbox.vmp.exe
    # vmcode_start_addr = 0x7D4897
    # msgbox.vmp0.exe
    # vmcode_start_addr = 0x881D7A
    vmcode_start_addr = 0x1781D7A
    StartAnalysis(vmcode_start_addr)
