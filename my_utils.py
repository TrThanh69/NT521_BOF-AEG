#!/usr/bin/env python3
#https://github.com/matrix1001/welpwn
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0,'/home/trthanh/Desktop/DoAn-LTAT/bof_aeg/welpwn')
import PwnContext as pwn
from pwn import *
import IPython
import subprocess, os, sys
import binascii
import r2pipe
import json

def one_gadget(filename):
  return [int(i) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]
def killmyself():
    os.system('kill %d' % os.getpid())

def check_in_mapinfo(num, mapinfo):
    for i in mapinfo:
        if num >= i[0] and num <= i[1]:
            return True

    return False

def init_profile(filepath, libpath, inputpath, outputpath):
    """初始化profile.rr2文件
    """
    content = """#!/path/to/rarun2
program={filepath}
stdin={inputpath}
stdout={outputpath}
libpath={libpath}
preload={libpath}ld-linux-x86-64.so.2
aslr=no
""".format(filepath=filepath, libpath=libpath, inputpath=inputpath, outputpath=outputpath)
    
    with open('profile.rr2','w') as fp:
        fp.write(content)

def init_r2(filepath, input):
    """初始化调试模式的r2用于动态分析
    """
    with open('input.txt', 'wb') as f:
        f.write(input)

    if os.path.exists('output.txt'):
        os.remove('output.txt')

    r2 = r2pipe.open(filepath,flags=['-r','profile.rr2'])
    r2.cmd('doo')
    return r2

def set_concrete(state, addrs, concrete_byte=None, pad_byte=b'\x00'):
    """
    addrs: []
    将state的addrs具体化为concrete_str
    """
    if addrs == []:
        return
    if not concrete_byte:
        tmp = pwn.cyclic(len(addrs))
    else:
        if len(concrete_byte) > len(addrs):
            pwn.log.error("set_concrete: len(concrete_byte) > len(addrs).")
        tmp = concrete_byte
        tmp = tmp.ljust(len(addrs), pad_byte)

    if len(addrs) == 1:
        state.add_constraints(state.memory.load(addrs[0],1) == tmp[0])
    else:
        for i in range(len(addrs)-1):
            state.add_constraints(state.memory.load(addrs[i],1) == tmp[i])

        #最后一位有可能被gets函数设置成\n
        if state.solver.satisfiable( \
            extra_constraints = (state.memory.load(addrs[i+1],1) == tmp[i+1],)):
            state.add_constraints(state.memory.load(addrs[i+1],1) == tmp[i+1])

def check_r2_one(r2, stack_off=0):
    """判断当前程序的内存状态是否满足one_gadget
    """

    rsp = int(r2.cmd('dr rsp'),16)+stack_off
    rax = int(r2.cmd('dr rax'),16)

    if rax == 0:
        return 0x45206

    if not pwn.u64(bytes(json.loads(r2.cmd('xj 8 @'+hex(rsp+0x30))))):
        return 0x4525a

    if not pwn.u64(bytes(json.loads(r2.cmd('xj 8 @'+hex(rsp+0x50))))):
        return 0xef9f4
        
    if not pwn.u64(bytes(json.loads(r2.cmd('xj 8 @'+hex(rsp+0x70))))):
        return 0xf0897
