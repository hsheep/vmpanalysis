# ---------------------------------------------------------------------
# Debug notification hook test
#
# This script start the executable and steps through the first five
# instructions. Each instruction is disassembled after execution.
#
# Original Author: Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#
# Maintained By: IDAPython Team
#
# ---------------------------------------------------------------------
import idaapi
import idc
import idautils
from idaapi import *


g_inst_series = []


class TraceAnalysis(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """
    
    def __init__(self, file_name, *args):
        DBG_Hooks.__init__(self) 
        self.count = 0
        self.trace_limit = {}
        self.fd = open(file_name, "wb+")
       
    def __del__(self):
        self.fd.close()

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))

    def dbg_process_exit(self, pid, tid, ea, code):
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
    
    def dbg_bpt(self, tid, ea):
        print "Break point at 0x%x pid=%d" % (ea, tid)
        g_inst_series.append("%s,%s,%s,%s,%s,%s,%s,%s,%s\n" % (
            ea,
            idautils.cpu.eax,
            idautils.cpu.ecx,
            idautils.cpu.edx,
            idautils.cpu.ebx,
            idautils.cpu.esp,
            idautils.cpu.ebp,
            idautils.cpu.esi,
            idautils.cpu.edi)
        )
        self.count += 1
        print("%s, Break tid=%d ea=0x%x" % (self.count, tid, ea))
        
        # return values:
        #   -1 - to display a breakpoint warning dialog
        #        if the process is suspended.
        #    0 - to never display a breakpoint warning dialog.
        #    1 - to always display a breakpoint warning dialog.
        return 0

    def dbg_suspend_process(self):
        print "Process suspended"

    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        print("Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (
            pid, tid, ea, exc_code & idaapi.BADADDR, exc_can_cont, exc_ea, exc_info))
        # return values:
        #   -1 - to display an exception warning dialog
        #        if the process is suspended.
        #   0  - to never display an exception warning dialog.
        #   1  - to always display an exception warning dialog.
        return 0

    def dbg_trace(self, tid, ea):
        global g_inst_series
        # decode instruction
        # inst = idautils.DecodeInstruction(ea)
        g_inst_series.append("%s,%s,%s,%s,%s,%s,%s,%s,%s\n" % (
            ea,
            idautils.cpu.eax,
            idautils.cpu.ecx,
            idautils.cpu.edx,
            idautils.cpu.ebx,
            idautils.cpu.esp,
            idautils.cpu.ebp,
            idautils.cpu.esi,
            idautils.cpu.edi)
        )

        # print("%s, Trace tid=%d ea=0x%x" % (self.count, tid, ea))
        self.count += 1
            
        if ea == self.trace_limit["end"] or not self.count % 100:
            print("count: %s, %08x, end: %08x" % (self.count, ea, self.trace_limit["end"]))
            # idc.suspend_thread(tid)
            idc.suspend_process()

            for item_inst in g_inst_series:
                self.fd.write(item_inst)
            g_inst_series = []
            # time.sleep(3)

            if ea == self.trace_limit["end"]:
                print("trace end: %s, %s" % (ea, self.count))
                idc.exit_process()

            idc.resume_process()

        # return values:
        #   1  - do not log this trace event;
        #   0  - log it
        return 1

    def dbg_step_into(self):
        print("Step into")
        # self.dbg_step_over()

    def dbg_run_to(self, pid, tid=0, ea=0):
        print "Runto: tid=%d" % tid
        idaapi.continue_process()


# Remove an existing debug hook
try:
    if trace:
        print("Removing previous hook ...")
        trace.unhook()
except Exception as e:
    pass

if __name__ == "__main__":
    # *set hardware BP and trace
    # Install the debug hook
    trace = TraceAnalysis("C:\\Users\\zhang\\Desktop\\result.trace.txt")
    trace.hook()

    # Stop at the entry point
    ep = idc.get_inf_attr(idc.INF_START_IP)
    request_run_to(ep)
    
    # Start debugging
    run_requests()

    # Set trace limit
    trace.trace_limit["start"] = ep
    # trace.trace_limit["end"] = idaapi.get_dword(idautils.cpu.esp)
    trace.trace_limit["end"] = 0x75196359
    print("start: %08x ~ %08x" % (trace.trace_limit["start"], trace.trace_limit["end"]))

    # Enable tracing()
    idc.EnableTracing(idc.TRACE_STEP, 1)
