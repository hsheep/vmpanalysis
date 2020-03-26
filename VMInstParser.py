# -*- coding:utf-8 -*-
# code by @madfinger, 2020-3-2
from __future__ import print_function
import traceback
from tools import *

# IDAPython 重新加载该模块刷新字节码, 否则执行的字节码和代码不对应
import VMInstructions
reload(VMInstructions)

from VMInstructions import VMEntry, vPopOptable, vInstList, vRegMap

# 中间代码解析器调试变量
DEBUG = False
DEBUG_BLOCK_INDEX = [96]
g_block_index = -1


# -----------------------------------------------------------------------------------
# current VM register
# 一、CPU类型
# 0～3 预定义寄存器变量
RegAny_0 = 0
RegAny_1 = 1
RegAny_2 = 2
RegAny_3 = 3

#  4～7 段表示VMCPU变量
vRegArray = 4
vOptable = 5
vEip = 6
vEsp = 7

# 虚拟寄存器，VMEntry初始化时: vVariable的VMCPU映射关系移动到vReg
vReg = {}

# 默认声明的寄存器变量，可以为任意寄存器
vVariable = {
    "RegAny:0": RegAny_0,
    "RegAny:1": RegAny_1,
    "RegAny:2": RegAny_2,
    "RegAny:3": RegAny_3,
    "vRegArray": vRegArray,
    "vOptable": vOptable,
    "vEip": vEip,
    "vEsp": vEsp,
}

vCPUMap = {
    vRegArray: 4  	    # 默认为esp，且不会变化
}


# 三、指令中间码的每条指令为一个DWORD，其中每个字节对应一个位
# * 第一字节固定为Opcode索引，中间两字节为操作数，最后一个字节表示为操作数类型（用于特征串匹配）
# *	00 ｜ 00 ｜ 00 ｜ 00

# (1) 最高位Opcode映射表
InterByte = {
    "mov": 0x7f,
    "movsx": 0x7f,
    "movzx": 0x7f,
    "xchg":  0,
    "bswap":  1,
    "xadd":  2,
    "cwd":  3,
    "cdq":  4,
    "cbw":  5,
    "cwde":  6,

    "add":  7,
    "adc":  7,
    "sub":  8,
    "sbb":  8,
    "imul":  9,
    "mul":  9,
    "idiv":  0xa,
    "div":  0xa,
    "inc":  0xb,
    "dec":  0xc,
    "neg":  0xd,
    "cmp":  0xe,

    "and":  0xf,
    "or":  0x10,
    "xor":  0x11,
    "not":  0x12,

    "sar":  0x13,
    "shr":  0x14,
    "sal":  0x15,
    "shl":  0x16,
    "shrd":  0x17,
    "shld":  0x18,
    "ror":  0x19,
    "rol":  0x1a,
    "rcr":  0x1b,
    "rcl":  0x1c,

    "push": 0x1d,
    "pop": 0x1e,
    "pushf": 0x1f,
    "popf": 0x20,
    "retn": 0x21,
    "call": 0x22,
    "jmp": 0x23,
    "lea": 0x24,
}

# (2) 第二、三位为操作数位（无IMM和Offset的表示），分2段表示如下：
# 0 0 0 0｜0 0 0 0
# ———————  ———————
# * 高4位表示基址寄存器和非内存寄存器.
# * 低4位表示变址寄存器.
# 映射关系同变量capstone_reg_map
RegMap = {
    "eax": 0,
    "ecx": 1,
    "edx": 2,
    "ebx": 3,
    "esp": 4,
    "ebp": 5,
    "esi": 6,
    "edi": 7,
}

# (3) 第四位指示出操作数类型，示意如下：
# 0 0 0 0｜0 0 0 0
# ———————  ———————
# 高四位表示第一操作数，低四位表示第二操作数
# 1:最高位表示是否为内存
# 2:次高位表示为[base+index]形式
# 3:表示立即数
# 4:表示变量（任意寄存器）, 用于模式匹配
OpTypeDispl = 0xC
OpTypeMem = 8
OpTypeImm = 4
OpTypeValue1 = 2
OpTypeValue0 = 1

# (4) 举例:
# 	mov eax, esp 		=> 	7f,10,40,00
# 	mov eax, [esp]		=> 	7f,10,40,08
# 	mov eax, [esp+4]	=> 	7f,10,40,08
# 	mov eax, [esp+edi] 	=> 	7f,10,47,0C


# 三、伪代码类型声明（作用仅仅为了方便阅读）:
InstBatIdent = {
    "MOV": InterByte["mov"],  # "lea"绝对地址解析为"mov"
    "ADD": InterByte["add"],  # "lea+"解析称"add"
    "SUB": InterByte["sub"],  # "lea-"解析成"sub"
    "JMP": InterByte["jmp"],  # "push&ret"解析成"jmp"
}

# 类型
TypeMap = {
    "IMM": 1
}

# DEBUG output
rRegMap = {
    0: "eax",
    1: "ecx",
    2: "edx",
    3: "ebx",
    4: "esp",
    5: "ebp",
    6: "esi",
    7: "edi",
}

rvVariable = {
    RegAny_0: "RegAny:0",
    RegAny_1: "RegAny:1",
    RegAny_2: "RegAny:2",
    RegAny_3: "RegAny:3",
    vRegArray: "vRegArray",
    vOptable: "vOptable",
    vEip: "vEip",
    vEsp: "vEsp",
}


# DEBUG
def dbgprint(dbg_str):
    if DEBUG or g_block_index in DEBUG_BLOCK_INDEX:
        print("  %s" % dbg_str)


def InitGlobalRegMap():
    global vVariable
    global vReg
    global vCPUMap

    vReg = {
        "vRegArray": vRegArray
    }
    vCPUMap = {
        4: vRegArray,
    }
    vVariable = {
        "RegAny:0": RegAny_0,
        "RegAny:1": RegAny_1,
        "RegAny:2": RegAny_2,
        "RegAny:3": RegAny_3,
        "vOptable": vOptable,
        "vEip": vEip,
        "vEsp": vEsp,
    }

# --------------------------------------------------------
# 特殊指令识别
# --------------------------------------------------------
def lea_proc(inst):
    """ lea => sub|add|mov """
    inst_dword = 0

    # 1) 解析为mov
    # lea	esi, loc_636A8C
    if inst.Operands[1].type in (idaapi.o_mem, idaapi.o_far, idaapi.o_imm, idaapi.o_near):
        # print("lea => mov")
        # Opcode位
        inst_dword |= InterByte["mov"] << 24
        # 操作数
        inst_dword |= inst.Operands[0].reg << 20
        # operand type
        inst_dword |= OpTypeImm

    # 2) 1、2操作数的寄存器相同，解析为add或sub，否则为mov
    else:
        base_reg, index_reg, _disp = get_displ_reg(inst, 1)
        # print ("lea OP1", base_reg, index_reg, _disp)
        if inst.Operands[0].reg == base_reg:
            # lea	ebp, [ebp+ecx]
            if index_reg != -1:
                # print("lea => add")
                inst_dword |= InterByte["add"] << 24
                # 操作数
                inst_dword |= index_reg << 12

            # lea	ebp, [ebp+4]
            elif _disp != 0:
                # print("lea => add/sub")
                # Opcode位
                if _disp > 0:
                    inst_dword |= InterByte["add"] << 24
                elif _disp < 0:
                    inst_dword |= InterByte["sub"] << 24
                # operand type
                inst_dword |= OpTypeImm

            # 操作数
            inst_dword |= inst.Operands[0].reg << 20

        # lea	eax, [ebp + 4]
        elif base_reg != -1:
            # print("lea => mov@")
            # Opcode位
            inst_dword |= InterByte["mov"] << 24
            # 操作数
            inst_dword |= inst.Operands[0].reg << 20
            inst_dword |= base_reg << 12

    return inst_dword


g_push_record = []


def retn_proc(inst):
    """push&ret => jmp """
    inst_dword = 0

    if g_push_record:
        # Opcode位
        inst_dword |= InterByte["jmp"] << 24
        # 操作数
        inst_dword |= g_push_record[-1].Operands[0].reg << 20
    else:
        # Opcode位
        inst_dword |= InterByte["retn"] << 24

    return inst_dword


def x86InstBuild(inst_serial):
    """ x86指令转译为中间码 """
    global g_push_record
    opcode_lsit = {}
    type_list = {}
    g_push_record = []

    for icount in sorted(inst_serial.keys()):
        try:
            inst = inst_serial[icount]
            inst_dword = 0
            inst_str = inst.get_canon_mnem()

            if inst_str not in InterByte:
                raise Exception("<%s> Unknown Inst!!" % inst_str)

            # 特殊指令处理
            if inst.itype == idaapi.NN_lea:
                inst_dword = lea_proc(inst)

            elif inst.itype == idaapi.NN_retn:
                inst_dword = retn_proc(inst)

            else:
                # 记录push寄存器,待retn时候进行转译
                if inst.itype == idaapi.NN_push and inst.Op1.type == idaapi.o_reg:
                    g_push_record.append(inst)

                # Opcode位
                inst_dword |= InterByte[inst_str] << 24

                # 第2、3位操作数分析
                for opi in [0, 1]:
                    cur_op = (opi + 1) % 2
                    if inst.Operands[opi].type == idaapi.o_void:
                        break

                    # 立即数,记录类,忽略内容
                    elif inst.Operands[opi].type == idaapi.o_imm:
                        # operand type
                        inst_dword |= OpTypeImm << (cur_op * 4)
                        break

                    # 寄存器
                    elif inst.Operands[opi].type == idaapi.o_reg:
                        # * 寄存器操作数类型为默认0，不需要置位
                        # operand data
                        inst_dword |= reg_map(inst.Operands[opi].reg) << (12 + cur_op * 8)
                        continue

                    # 目标内存指令列表转移
                    base_reg, index_reg, _disp = get_displ_reg(inst, opi)
                    # "[base]"
                    if base_reg != -1:
                        # operand type
                        inst_dword |= OpTypeMem << (cur_op * 4)
                        # operand data
                        inst_dword |= base_reg << (12 + cur_op * 8)

                    # "[base + index]"
                    if index_reg != -1:
                        # operand type
                        inst_dword |= OpTypeDispl << (cur_op * 4)
                        # operand data
                        inst_dword |= index_reg << (8 + cur_op * 8)

            # 加入类型列表
            indx_dword = inst_dword & 0xff0000ff
            if indx_dword not in type_list:
                type_list[indx_dword] = []
            type_list[indx_dword].append(inst_dword)

            # 加入opcode列表
            if inst_dword not in opcode_lsit:
                opcode_lsit[inst_dword] = []
            opcode_lsit[inst_dword].append(icount)

        except Exception as e:
            traceback.print_exc()

    return opcode_lsit, type_list


def interInstPre(v_inst_serial, result_list=None, index_map=None):
    """
        预解析，将伪代码"或"操作展开成多条描述
        @v_inst_serial: 声明的指令语法
        @result_list: 指令集合，初始化为"{ 0: [] }"
    """
    # 初始化结构和映射表
    if not result_list:
        result_list = [[]]
        index_map = {}

    # 开始描述代码串分析
    for v_inst in v_inst_serial:

        # 字符串，加入到每个或指令中
        if isinstance(v_inst, str):
            for item in result_list:
                item.append(v_inst)

        # 宏数组，进入继续分析
        elif isinstance(v_inst, list):
            interInstPre(v_inst, result_list, index_map)

        # "或"语法，指令均匀拆分
        elif isinstance(v_inst, dict):
            result_len = len(result_list)
            serial_len = len(v_inst)
            serial_keys = v_inst.keys()

            # 检查索引，该索引要么全部在index_map,要么都不在，否则语法错误
            index_true = 0
            for item in serial_keys:
                if item in index_map:
                    index_true += 1

            if index_true != 0 and index_true != serial_len:
                raise Exception("Or Index Error!!!")

            # 新建分支或指令
            if not index_true:
                for item in range(result_len * (serial_len-1)):
                    result_list.append(list(result_list[item % result_len]))

                # 将分支或指令分别加入到列表中
                v_inst_items = [[item, v_inst[item]] for item in sorted(v_inst.keys())]
                for i, item in enumerate(result_list):
                    cur_inst = v_inst_items[i / result_len]

                    # 加入到映射表
                    if cur_inst[0] not in index_map:
                        index_map[cur_inst[0]] = [i]
                    else:
                        index_map[cur_inst[0]].append(i)

                    # 指令加入到对应列表
                    item.extend(cur_inst[1])

            # 通过index_map找到和result_list对应关系，并添加到对应的指令列表下
            else:
                for or_id, insts in v_inst.items():
                    for index in index_map[or_id]:
                        result_list[index].extend(insts)

    return result_list


def interInstBuild(v_inst_serial, init=False):
    """ 描述伪代码转中间码 """
    opcode_lsit = []
    type_list = []

    def set_opbit(var, cur_op, optype):
        tmp_dword = 0
        # print("set_opbit var: %s" % var)

        # 真实寄存器
        if var in RegMap:
            # set operands
            tmp_dword |= RegMap[var] << (8 + optype * 4 + cur_op * 8)

        # 虚拟寄存器在已初始化状态下，对应真实寄存器
        elif not init and var in vReg:
            # set operands
            tmp_dword |= vReg[var] << (8 + optype * 4 + cur_op * 8)

        # 设置变量类型，对应任意寄存器，包括未初始化虚拟寄存器变量
        elif var in vVariable:
            # add variant type
            tmp_dword |= (optype + 1) << (cur_op * 4)
            # set operands
            tmp_dword |= vVariable[var] << (8 + optype * 4 + cur_op * 8)

        return tmp_dword

    # 开始描述代码串分析
    for v_inst in v_inst_serial:
        inst_dword = 0

        try:
            if isinstance(v_inst, str):
                sprt = v_inst.split(" ", 1)
                opcode, operands = sprt[0], sprt[-1]

                # Opcode位
                relop = opcode.split(":")
                if relop[0] == "i":
                    if relop[1] in InterByte:
                        inst_dword |= InterByte[relop[1]] << 24
                elif opcode in InstBatIdent:
                    inst_dword |= InstBatIdent[opcode] << 24

                if len(sprt) > 1:
                    # 第2、3位操作数分析
                    for opi, OpItem in enumerate(operands.split(",")):
                        cur_op = (opi + 1) % 2
                        OpItem = OpItem.strip()

                        # 内存操作数
                        if OpItem.startswith("["):
                            base, index, athr = "", "", ""
                            for item in ["+", "-"]:
                                if item in OpItem:
                                    athr = item
                                    base, index = OpItem[1:-1].split("+")
                                    break
                            # displ
                            if athr:
                                # set type
                                inst_dword |= OpTypeDispl << (cur_op * 4)
                                # set operands
                                inst_dword |= set_opbit(base.strip(), cur_op, 1)
                                inst_dword |= set_opbit(index.strip(), cur_op, 0)
                            # mem
                            else:
                                # set type
                                inst_dword |= OpTypeMem << (cur_op * 4)
                                # set operands
                                inst_dword |= set_opbit(OpItem[1:-1], cur_op, 1)

                        # IMM
                        elif OpItem in TypeMap:
                            inst_dword |= OpTypeImm << (cur_op * 4)

                        else:
                            inst_dword |= set_opbit(OpItem, cur_op, 1)

                        # else:
                        # 	raise Exception("%s Unknown Operand, opi: %s, OpItem: %s" % (v_inst, opi, OpItem))

                # 加入列表
                type_list.append(inst_dword & 0xff0000cc)
                opcode_lsit.append(inst_dword)

            elif isinstance(v_inst, list):
                r0, r1 = interInstBuild(v_inst, init)
                type_list.extend(r1)
                opcode_lsit.extend(r0)

            else:
                raise Exception("%s Unknown Instrucion!" % v_inst)

        except Exception as e:
            print("error inst: %s" % v_inst)
            traceback.print_exc()

    return opcode_lsit, type_list


def MakeInterCode(v_inst_serial, init=False):
    """ 虚拟指令声称中间描述码 """
    inter_codes = []
    for inst_item in interInstPre(v_inst_serial):
        inter_codes.append(interInstBuild(inst_item, init))
    return inter_codes


# --------------------------------------------------------
# 匹配逻辑
# --------------------------------------------------------
# 描述语言指令中间码, 默认初始化为VMEntry
g_entry_code = [MakeInterCode(VMEntry, True)]

# 初始化预定义的指令，指令特征转中间代码
g_inst_list = []

# 指令名称
g_inst_str = []


def DebugOpCode(code_list, code_type):
    if DEBUG or g_block_index in DEBUG_BLOCK_INDEX:
        print (">>> %s >>>" % code_type)
        if isinstance(code_list, list):
            for i, item in enumerate(code_list):
                print("%s: %08x" % (i, item))
        elif isinstance(code_list, dict):
            for i, item in enumerate(code_list.items()):
                print("%s: %08x: %s" % (i, item[0], item[1]))
        else:
            print("%s, %s" % (code_type, code_list))


def VMLeaveProcess(inst_name, vars):
    """ 离开虚拟机，重置所有寄存器相关值"""
    global g_vminit
    print("VMLeaveProcess callback")
    g_vminit = False

    # 重新初始化寄存器映射，为了下次VMInitEntry使用
    InitGlobalRegMap()


def VMTransRegProcess(inst_name, vars):
    """ VM入口点识别，并识别出上面四个关键寄存器 """
    global g_inst_list
    global g_inst_str

    print("VMTransRegProcess callback", inst_name, vars)

    # 1. 重新初始化寄存器映射
    vEspTmp = vCPUMap[vEsp]
    InitGlobalRegMap()

    # 2. 重新初始化VMTransReg指令，该指令需要重新提取所有虚拟寄存器值
    g_inst_list = list()
    g_inst_str = ["vPopOptable"]
    # vEsp可以作作为锚点
    if RegAny_1 in vars:
        vCPUMap[vEsp] = vars[RegAny_1]
    else:
        vCPUMap[vEsp] = vEspTmp
    vReg["vEsp"] = vCPUMap[vEsp]
    g_inst_list.append(MakeInterCode(vPopOptable))

    # 3.重新初始化vCPU和映射关系
    vCPUMap[vOptable] = vars[vOptable]
    vCPUMap[vEip] = vars[vEip]
    print("* vCPUMap: %s" % vCPUMap)

    vm_var = []
    for vrstr, vr in vVariable.items():
        if vr in vCPUMap:
            vReg[vrstr] = vCPUMap[vr]
            vm_var.append(vrstr)

    for item in vm_var:
        vVariable.pop(item)

    # 4. vCPU寄存器等映射关系等变化，重新生成中间代码（后面可以做成在匹配等时候进行实时映射）
    print("* Reinit VM instructions...")
    for v_str, v_inst in vInstList.items():
        print("* build %s" % v_str)
        g_inst_list.append(MakeInterCode(v_inst))
    g_inst_str.extend(vInstList.keys())
    print("* Reinit complete.")


# 指令回调函数
g_vcode_callback = {
    "VMLeave": VMLeaveProcess,
    "vPopOptable": VMTransRegProcess,
}


def vInterCodeMach(vCodes, vTypes):
    """ 匹配中间代码 """
    match_vop = "UNKNOWN"
    # 当前vCode中变量和对应的值
    variables = {}
    # 当前代码块的Opcode和操作数类型
    code_types = vTypes.keys()

    DebugOpCode(vCodes, "vCodes")

    def get_vins_var(inst_code):
        """
            获取变量标记位和偏移量
            * inst_code: 描述代码的变量和标记位
        """
        var_list = {}
        bit_var = {1: 8, 2: 12, 0x10: 16, 0x20: 20}
        for var_bit, var_off in bit_var.items():
            if inst_code & var_bit:
                var_list[var_off] = (inst_code >> var_off) & 0xF
        return var_list

    def get_opt_var(inst_code_list, bit_var):
        """
            获取变量对应的真实寄存器
            * inst_code_list: 类型对应的多个值
            * bit_var: 类型标记位和对应的寄存器标记
        """
        opt_vars = []
        all_ids = []
        for i, item_inst in enumerate(inst_code_list):
            var_list = {}

            # 要保证读取all_ids的顺序，否则会进行乱序匹配
            all_ids.extend(sorted(vCodes[item_inst]))
            dbgprint("all_ids: %s" % all_ids)

            for var_off, var_key in bit_var.items():
                var_list[var_key] = [(item_inst >> var_off) & 0xF, var_off, all_ids[i], item_inst]
            opt_vars.append(var_list)
        return opt_vars

    def var_substitute(op_list, vm_insts, vars, offs=0):
        """
            寄存器串联分析,示例:
                【虚拟指令】 {
                    【描述语句】变量组合，
                        => [{RegAny0: ecx, RegAny1: edx}, {RegAny0: edx, RegAny1: ecx}]
                    【描述语句】变量组合，
                        => [{RegAny2: eax}, {RegAny2: ebx}]
                    ...,
                }
            x 寄存器分配不唯一
            x 匹配地址序
            * 所有描述语句完全匹配
        """
        result = True
        dbgprint("\nvars: %s, len(op_list) = %s" % (vars, len(op_list)))

        # 【虚拟指令】所对应的多组变量组合
        for ic, var_item in enumerate(op_list[offs:]):
            iv = var_item[0]
            inst_code = vm_insts[iv]
            inst_vtypes = vTypes[inst_code & 0xff0000cc]
            group_match = False

            dbgprint("var_item: %s" % var_item[1])

            # 【描述语句】对应的变量组合
            for item in var_item[1]:
                test_code = inst_code
                has_var = True
                cur_addr = 0

                dbgprint("iv: %s, item: %s" % (iv, item))

                # 【当前变量】代入var = [real_reg, offset]
                for var_id, var in item.items():
                    # 匹配地址序列必须大于当前序列起始地址(向下匹配)
                    cur_addr = var[2]
                    if cur_addr < vars["addr"]:
                        dbgprint("False: %08x: cur_addr: %s <<<<< addr_serial: %s" % (inst_code, cur_addr,  vars["addr"]))
                        has_var = False
                        break

                    # 存在预设寄存器
                    elif var_id in vars:
                        cur_var = vars[var_id]
                        dbgprint("%08x: %s => %s" % (inst_code, var_id, vars[var_id]))

                    # 代入过程中发现新变量被引用（mov\xchg指令寄存器复用特例）
                    elif inst_code >> 24 in (InterByte["mov"], InterByte["xchg"]) or var[0] not in vars.values():
                        # 记录当前变量，判断失败后恢复
                        vars[var_id] = cur_var = var[0]
                        old_addr = vars["addr"]
                        offset = len(vars["match"])
                        dbgprint("* %08x: new var, cur_addr:%s, match: %s, %s" % (inst_code, cur_addr, offset, vars["match"]))

                        # 迭代判断新变量
                        if not var_substitute(op_list, vm_insts, vars, offs+ic):
                            vars.pop(var_id)
                            has_var = False
                            vars["addr"] = old_addr
                            vars["match"] = vars["match"][:offset]
                            dbgprint("* %08x: new var False, match: %s, %s" % (inst_code, offset, vars["match"]))

                    # 引用冲突，新变量的值其他寄存器也有引用
                    else:
                        dbgprint("%08x: vars.values() include %s" % (inst_code, var[0]))
                        has_var = False
                        break

                    test_code = ((test_code & ~(0xf << var[1])) | ((cur_var + 1) << var[1])) - (1 << var[1])
                    # dbgprint("%08x: testcode %08x" % (inst_code, test_code & 0xffffffcc))

                dbgprint("> %08x, %s,%s, %s, %s %s" % (inst_code, vars["addr"], cur_addr, has_var, [hex(item0) for item0 in inst_vtypes], item))
                # dbgprint("match_list: %s" % vars["match"])

                # 测试变量是匹配
                if has_var and test_code & 0xffffffcc in inst_vtypes and cur_addr not in vars["match"]:
                    old_addr = vars["addr"]
                    offset = len(vars["match"])

                    if vars["addr"] < cur_addr:
                        vars["addr"] = cur_addr
                    vars["match"].append(cur_addr)

                    dbgprint("%08x: testcode ok, addr_srial => %s" % (inst_code, vars["addr"]))
                    if var_substitute(op_list, vm_insts, vars, offs + ic + 1):
                        group_match = True
                        break

                    vars["addr"] = old_addr
                    vars["match"] = vars["match"][:offset]
                    dbgprint("* %08x: new var False, match: %s, %s" % (inst_code, offset, vars["match"]))

            dbgprint("> next vm, %s" % (offs+ic+1))

            # 已经分析遍历最后
            if group_match and offs+ic+1 == len(op_list):
                vars["addr"] = 0x7fffffff
                break
            elif vars["addr"] == 0x7fffffff:
                dbgprint("[*] match final.")
                break

            # 当前变量在一条描述语句中全部未命中
            elif not group_match:
                result = False
                dbgprint("%08x: mismatch!" % inst_code)
                break

        dbgprint("> return: %s" % result)
        return result

    # 取出一条虚拟指令
    for iv, vm_item in enumerate(g_inst_list):

        # 该指令包含了各种不同逻辑的分支
        for vm_inst, vm_types in vm_item:
            variables["addr"] = 0
            variables["match"] = []

            # 指令和操作数类型模糊匹配
            if len(set(code_types).intersection(vm_types)) == len(set(vm_types)):
                dbgprint("\n\n ============ %s ============" % g_inst_str[iv])
                DebugOpCode(vm_inst, "vm_inst")

                op_list = []
                match_stc = True

                for ic, inst_code in enumerate(vm_inst):
                    # 变量处理
                    if inst_code & 0x33:
                        # 获取每条描述代码中寄存器ID对应的真实寄存器列表组合
                        op_list.append([ic, get_opt_var(vTypes[vm_types[ic]], get_vins_var(inst_code))])

                    # 常量处理
                    elif inst_code not in vCodes:
                        dbgprint("* static <%08x> not in vCodes" % inst_code)
                        match_stc = False
                        break

                dbgprint("op_list: %s" % op_list)
                # 常量变量同时匹配
                if match_stc and var_substitute(op_list, vm_inst, variables):
                    match_vop = g_inst_str[iv]
                    dbgprint("* register match %s" % match_vop)
                    break

            # 清理变量
            variables.clear()

        # 匹配成功
        if match_vop != "UNKNOWN":
            break

    return match_vop, variables


# 是否初始化入口点
g_vminit = False


def VMEntryIdent(inst_serial):
    """ VM入口点识别，并识别出上面四个关键寄存器 """
    global g_inst_list
    global g_inst_str
    global g_vminit

    # 1.分析匹配是否为VMEntry
    g_inst_list = g_entry_code
    g_inst_str = ["VMEntry"]

    bmatch, var = vInterCodeMach(*x86InstBuild(inst_serial))
    if bmatch == "UNKNOWN":
        print("* VMEntry mismatch!!")
        return bmatch
    else:
        print("* VMEntry matched.")
    g_vminit = True

    # 2. 初始化VMTransReg指令，该指令需要重新提取所有虚拟寄存器值
    g_inst_list = list()
    g_inst_str = ["vPopOptable"]
    vCPUMap[vEsp] = var.pop(vEsp)
    vReg["vEsp"] = vCPUMap[vEsp]
    g_inst_list.append(MakeInterCode(vPopOptable))

    # 3.vCPU和变量初始化赋值
    for vr, rr in var.items():
        if isinstance(vr, int) and vr > 4:
            vCPUMap[vr] = rr
    print("* vCPUMap: %s" % vCPUMap)

    vm_var = []
    for vrstr, vr in vVariable.items():
        if vr in vCPUMap:
            vReg[vrstr] = vCPUMap[vr]
            vm_var.append(vrstr)

    for item in vm_var:
        vVariable.pop(item)

    # 4. vCPU寄存器有变化，重新生成中间代码
    print("* Init VM instructions...")
    for v_str, v_inst in vInstList.items():
        print("* build %s" % v_str)
        g_inst_list.append(MakeInterCode(v_inst))
    g_inst_str.extend(vInstList.keys())
    print("* Init complete.")

    return bmatch


def SetOperands(match_vop, vars, reg_dict):
    """ 设置VM指令操作数 """

    if match_vop in vRegMap:

        if DEBUG or g_block_index in DEBUG_BLOCK_INDEX:
            for item in sorted(set(vars["match"])):
                print("vars =>>> %s: %s" % (item, item & 0xffff))

            for item_icount, item_context in reg_dict.items():
                print("%s: %s, %s" % (item_icount | (g_block_index << 16), item_icount, item_context))

        op_info = vRegMap[match_vop]

        try:
            # 获取当前寄存器ID
            if op_info[2] in vVariable:
                reg_id = vVariable[op_info[2]]
            else:
                reg_id = vReg[op_info[2]]

            # 通过寄存器ID获取真实寄存器
            if reg_id in vCPUMap:
                reg = vCPUMap[reg_id]
            else:
                reg = vars[reg_id]

            # 获取该描述指令的寄存器上下文
            match_list = sorted(set(vars["match"]))
            if op_info[0] != -1:
                icount = match_list[op_info[0]] & 0xffff
                dbgprint("%s reg => icount: %s" % (match_vop, match_list[op_info[0]]))
                reg_context = reg_dict[icount]
            else:
                reg_context = reg_dict[sorted(reg_dict.keys())[op_info[0]]]

            # 设置虚拟操作数
            if op_info[1] == "reg":
                match_vop = "%s R%s" % (match_vop, reg_context[reg]/4)
            elif op_info[1] == "imm":
                match_vop = "%s %08x" % (match_vop, reg_context[reg])
            else:
                print("[warn] vRegMap operand type error, %s" % op_info[1])

        except Exception as e:
            print("[warn] set operands error:")
            traceback.print_exc()

    return match_vop


# Export
def ConvertCodeSequence(inst_serial_clean, reg_dict, block_index):
    """
        @inst_serial_clean: 所有指令的列表
        @reg_dict: 内存操作的寄存器映射表
        @block_index: 当前代码块的索引
    """
    global g_block_index
    g_block_index = block_index

    # 匹配
    if not g_vminit:
        match_vop = VMEntryIdent(inst_serial_clean)
    else:
        match_vop, vars = vInterCodeMach(*x86InstBuild(inst_serial_clean))

        # 特殊指令回调
        if match_vop in g_vcode_callback:
            g_vcode_callback[match_vop](match_vop, vars)

        # 操作数标记
        match_vop = SetOperands(match_vop, vars, reg_dict)

    return match_vop
