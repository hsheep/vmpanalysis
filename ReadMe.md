# IDA VMProtect 3.4 Analysis Script

> 通过"Unicorn engine"模拟或"IDA Trace"分析每个指令块的地址和寄存器，再通过花指令消减和VM指令匹配，来静态分析提取虚拟化的指令

* 已经完成:
    1. x86寄存器传播分析，指令优化 [ok]
        * jcc指令分析处理 (待加入分析) [??]
        * xchg指令处理有问题 [ok]
        * x86指令化简

    2. VM代码识别
        * VM指令识别 [ok]
        * 伪代码模式匹配 [ok]
        * VM寄存器适配 [ok]
    
* VM指令示例：
```
    0x1341d7a  VMEntry
    0x1119383  vPopReg R1
    0x12ab1ef  vPopReg R2
    0x107559b  vPopReg R11
    0x129cf7c  vPopReg R9
    0x105322e  vPopReg R5
    0x129f8ac  vPopReg R4
    0x1069c6a  vPopReg R12
    0x10ea0a3  vPopReg R8
    0x109d9ba  vPopReg R15
    0x1054a12  vPopReg R7
    0x107c093  vPopReg R6
    0x12e067a  vPushReg R15
    0x12dfac4  vPushImm 00000020
    0x128e50e  vPushEsp
    0x1096a78  vPushImm 00000004
    0x13140d4  vAdd
    0x1119383  vPopReg R7
    0x106a04c  vPushEsp
    0x12bdf39  vPushImm 00000008
    0x10e4509  vAdd
    0x12ab1ef  vPopReg R0
    0x12af894  vNor
    0x107559b  vPopReg R6
    0x1296a98  vAdd
    0x129cf7c  vPopReg R3
    0x10eff0d  vPushEsp
    0x10c8e27  vPoiEsp
    0x10acfee  vNand
    ...
    0x12b457a  vPopReg R0
    0x10f22dd  vPushReg R8
    0x10cf09d  vPushReg R6
    0x1335635  vPushReg R15
    0x11197ec  vPushReg R2
    0x129f083  vPushReg R1
    0x10a063a  vPushReg R11
    0x10a1621  vPushReg R9
    0x130cf9c  vPushReg R14
    0x13610a5  VMLeave
```

---

* 待加入逻辑
    * 没有对段寄存器进行标注
    * 没有对操作数宽度进行标注
    * 推算寄存器索引的解密算法和vEip的解密算法

* 待修复问题：
    * 解决在提取指令流的时候，会出现与动态执行不一致导致的VM指令内存异常。 [done]

* 和接下来要做的事情：
    1. 将VM指令标注成可读性强的x86类指令，并解决寄存器分配问题。[doing]
    2. 寄存器轮转映射处理
    3. 通过capstone汇编引擎将虚拟指令转化为x86指令,去除虚拟机。