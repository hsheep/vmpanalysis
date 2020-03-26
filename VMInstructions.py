# -*- coding:utf-8 -*-
# code by @zhd, 2020-3-4
# ------------------------------------------------------------------------------------
# 宏定义
# ------------------------------------------------------------------------------------
# 抬高栈帧
_InStackvSubEsp_ = "SUB vEsp, IMM"
# 降低栈帧
_OutStackvIncEsp_ = "ADD vEsp, IMM"

# * Optable存在正向或反响向的寻址操作，所以都要兼顾
_OptableSeekAdd_ = "ADD vOptable, IMM"
_OptableSeekSub_ = "SUB vOptable, IMM"


# vEip跳转下一个代码块,Optable反向寻址
_StreamNextCodeAdd_ = [
    "MOV RegAny:3, [vOptable]",
    _OptableSeekAdd_,
    "ADD vEip, RegAny:3",
    "JMP vEip"
]

_StreamNextCodeSub_ = [
    _OptableSeekSub_,
    "MOV RegAny:3, [vOptable]",
    "ADD vEip, RegAny:3",
    "JMP vEip"
]

_StreamNextCode_ = {
    0: _StreamNextCodeAdd_,
    1: _StreamNextCodeSub_,
}

# 算术运算标记为（Add、Sub、Nor等）
_StreamSetFlags_ = [
    "i:pushf",
    "i:pop [vEsp]"
]

# ------------------------------------------------------------------------------------
# 指令特征描述：
#   0）汇编描述伪代码为一个DWORD值，仅描述寄存器之间的运算关系
#   1）不描述立即数(IMM)操作，只记录立即数(IMM)类型
#   2）有4个虚拟化寄存器映射到x86寄存器（分别为vRegArray、vOptable、vEip、vEsp）
#   3）有4个寄存器变量随意使用（RegAny:0～3），可表示任意寄存器运算
#   4）RegAny:3已被"_StreamNextCode_"宏所使用，所以只可用"RegAny:0～2"寄存器变量
#  *5）RegAny寄存器变量只可表示一次从内存取值，如若被从新赋值则需要使用新变量进行表示（这里后面会对重新复制进行支持）
#  *6）变量有序匹配，常量无序匹配
# ------------------------------------------------------------------------------------
VMEntry = [
    "i:push IMM",
    "i:call",
    "i:push eax",
    "i:push ecx",
    "i:push edx",
    "i:push ebx",
    "i:push ebp",
    "i:push esi",
    "i:push edi",
    "i:pushf",
    "MOV vOptable, [esp]",
    # "i:xor vOptable, IMM",
    "MOV vEsp, esp",
    "SUB esp, IMM",
    _StreamNextCode_,
]

VMLeave = [
    "MOV esp, vEsp",
    "i:pop eax",
    "i:pop ecx",
    "i:pop edx",
    "i:pop ebx",
    "i:pop ebp",
    "i:pop esi",
    "i:pop edi",
    "i:popf",
    "i:retn",
]

vPopOptable = [
    "MOV RegAny:0, [vEsp]",
    _OutStackvIncEsp_,
    {
        3: [
            "i:xchg vOptable, RegAny:0",
            "MOV RegAny:1, RegAny:0"],
        4: [
            "MOV vOptable, RegAny:0",
            "MOV RegAny:1, vEsp"],
        5:[
            "MOV vOptable, RegAny:0",
            ]
    },
    "MOV vEip, IMM",
    _StreamNextCode_
]

vPopReg = [
    "MOV RegAny:0, [vEsp]",
    _OutStackvIncEsp_,
    {
        0: ["MOV RegAny:1, [vOptable]", _OptableSeekAdd_],
        1: [_OptableSeekSub_, "MOV RegAny:1, [vOptable]"],
    },
    "MOV [vRegArray + RegAny:1], RegAny:0",
    _StreamNextCode_
]

vPushEsp = [
    "MOV RegAny:0, vEsp",
    _InStackvSubEsp_,
    "MOV [vEsp], RegAny:0",
    _StreamNextCode_
]

vPushImm = [
    {
        0: ["MOV RegAny:0, [vOptable]", _OptableSeekAdd_],
        1: [_OptableSeekSub_, "MOV RegAny:0, [vOptable]"],
    },
    _InStackvSubEsp_,
    "MOV [vEsp], RegAny:0",
    _StreamNextCode_
]

vResetEsp = [
    "MOV vEsp, [vEsp]",
    _StreamNextCode_
]

vPushReg = [
    {
        0: ["MOV RegAny:0, [vOptable]", _OptableSeekAdd_],
        1: [_OptableSeekSub_, "MOV RegAny:0, [vOptable]"],
    },
    "MOV RegAny:1, [vRegArray + RegAny:0]",
    _InStackvSubEsp_,
    "MOV [vEsp], RegAny:1",
    _StreamNextCode_
]

vPopMem = [
    "MOV RegAny:0, [vEsp]",
    "MOV RegAny:1, [vEsp]",
    _OutStackvIncEsp_,
    "MOV [RegAny:0], RegAny:1",
    _StreamNextCode_
]

vJmp = [
    "MOV vEip, IMM",
    _StreamNextCode_
]

vPoiEsp = [
    "MOV RegAny:0, [vEsp]",
    "MOV RegAny:1, [RegAny:0]",
    "MOV [vEsp], RegAny:1",
    _StreamNextCode_
]

vNand = [
    "MOV RegAny:0, [vEsp]",
    "MOV RegAny:1, [vEsp]",
    "i:not RegAny:0",
    "i:not RegAny:1",
    "i:and RegAny:0, RegAny:1",
    "MOV [vEsp], RegAny:0",
    _StreamSetFlags_,
    _StreamNextCode_
]

vNor = [
    "MOV RegAny:0, [vEsp]",
    "MOV RegAny:1, [vEsp]",
    "i:not RegAny:0",
    "i:not RegAny:1",
    "i:or RegAny:0, RegAny:1",
    "MOV [vEsp], RegAny:0",
    _StreamSetFlags_,
    _StreamNextCode_
]

vAdd = [
    "MOV RegAny:0, [vEsp]",
    "MOV RegAny:1, [vEsp]",
    "ADD RegAny:0, RegAny:1",
    "MOV [vEsp], RegAny:0",
    _StreamSetFlags_,
    _StreamNextCode_
]

vShr = [
    "MOV RegAny:0, [vEsp]",
    "MOV RegAny:1, [vEsp]",
    _InStackvSubEsp_,
    "i:shr RegAny:0, RegAny:1",
    "MOV [vEsp], RegAny:0",
    _StreamSetFlags_,
    _StreamNextCode_
]


# ------------------------------------------------------------------------------------
# 指令匹配列表,上面声明的指令要在这里加入到解析列表:
# ------------------------------------------------------------------------------------
vInstList = {
    "VMLeave": VMLeave,
    "vPopReg": vPopReg,
    "vPushReg": vPushReg,
    "vPushEsp": vPushEsp,
    "vPushImm": vPushImm,
    "vResetEsp": vResetEsp,
    "vJmp": vJmp,
    "vPoiEsp": vPoiEsp,
    "vAdd": vAdd,
    "vNand": vNand,
    "vNor": vNor,
    "vShr": vShr,
    "vPopMem": vPopMem
}

# ------------------------------------------------------------------------------------
# 指令描述代码和寄存器映射关系：
# ["命中的指令索引", "变量类型", "被提取的变量"]
# * 指令索引以该指令描述代码是否有变量累计
# ------------------------------------------------------------------------------------
vRegMap = {
    "vPopReg": [2, "reg", "RegAny:1"],
    "vPushReg": [1, "reg", "RegAny:0"],
    "vPushImm": [1, "imm", "RegAny:0"],
    "vJmp": [-1, "imm", "vEip"],
}
