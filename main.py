# -*- coding:utf-8 -*-
# code by @madfinger, 2020-3-29
import os
import logging
import VMTraceParser
import VMCodeBlock

reload(VMTraceParser)
reload(VMCodeBlock)

# g_analyzer_type = "unicorn"
g_analyzer_type = "tracing"

log = logging.getLogger("main")


def init_log():
    log.setLevel(level=logging.INFO)
    handler = logging.FileHandler('output.log')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    # 仅使用我们自己的handler,否则重复记录
    for item_handler in log.handlers:
        log.removeHandler(item_handler)
    log.addHandler(handler)
    

if __name__ == "__main__":
    # 初始化全局日志
    init_log()
    log.info("=============== start analysis: ================")
    
    # 通过tracefile进行分析 (trace文件可根据IDATraceHook.py脚本抓取)
    if g_analyzer_type == "tracing":
        base_addr = 0x00FC0000
        trace_file = "/Users/madfinger/Desktop/VMPAnalysis/test/result.trace.txt"
        if not os.path.exists(trace_file):
            log.error("trace file %s not found!!!" % trace_file)
            exit(0)
        VMTraceParser.StartAnalysis(trace_file, base_addr)
    
    # 使用"unicorn engine"进行分析
    elif g_analyzer_type == "unicorn":
        # maybe scan vm_entry
        vmcode_start_addr = [0x13316ED]
        for item_addr in vmcode_start_addr:
            VMCodeBlock.StartAnalysis(item_addr)
