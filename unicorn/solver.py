# -*- coding: utf-8 -*-
from unicorn import *
from unicorn.x86_const import *



def read(name):
    with open(name, "rb") as f:
        return f.read()


mu = Uc(UC_ARCH_X86, UC_MODE_64)

#  0       1024*1024 = HEAP_BASE     HEAP_MAX
#   ----------------------------------
#  |     stack      |      heap       |
#   ----------------------------------
BASE = 0x0400000
STACK_ADDR = 0X0
STACK_SIZE = 1024 * 1024

HEAP_BASE = STACK_ADDR + STACK_SIZE
HEAP_MAX = HEAP_BASE
HEAP_POINTER = 0x0
HEAP_UNINT = 1024 * 1024

NEEDED_FIXED_0x400A13 = True

mu.mem_map(BASE, 1024 * 1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)

mu.mem_write(BASE, read("./re"))
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 1)




def mu_malloc(mu, size):
    global HEAP_MAX, HEAP_POINTER
    LastAddress = HEAP_BASE + HEAP_POINTER
    HEAP_POINTER += size
    while HEAP_POINTER > HEAP_MAX - HEAP_BASE:
        mu.mem_map(HEAP_MAX, HEAP_UNINT)
        HEAP_MAX += HEAP_UNINT

    return LastAddress


def get_mu_bytes(mu, addr):
    s = b''
    addr_tmp = addr
    cc = mu.mem_read(addr_tmp, 1)
    s += cc
    while ord(cc) != 0:
        addr_tmp += 1
        cc = mu.mem_read(addr_tmp, 1)
        s += cc
    return addr_tmp - addr, s


def hook_code(mu, address, size, user_data):
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

    # hook int puts(const char* s)
    if address == 0x400570:
        # read the first param
        rdi = mu.reg_read(UC_X86_REG_RDI)
        s_size, s = get_mu_bytes(mu, rdi)
        mu.reg_write(UC_X86_REG_RAX, rdi)  # set return value
        mu.reg_write(UC_X86_REG_RIP, 0x400BC4)  # borrow a retn op to return
        print(s)

    # hook char *gets(char *str)
    elif address == 0x4005c0:
        rdi = mu.reg_read(UC_X86_REG_RDI)
        input_str = b'flag{76sgf17gf9asydjhatd93e73gf9}'
        mu.mem_write(rdi, input_str)
        mu.reg_write(UC_X86_REG_RAX, rdi)  # set return value
        mu.reg_write(UC_X86_REG_RIP, 0x400BC4)  # borrow a retn op to return

    # hook size_t strlen(const char *s)
    elif address == 0x400580:
        rdi = mu.reg_read(UC_X86_REG_RDI)
        s_size, s = get_mu_bytes(mu, rdi)
        mu.reg_write(UC_X86_REG_RAX, s_size)  # set return value
        mu.reg_write(UC_X86_REG_RIP, 0x400BC4)  # borrow a retn op to return

    # hook char *strstr(const char *haystack, const char *needle)
    elif address == 0x4005E0:
        rdi = mu.reg_read(UC_X86_REG_RDI)  # get the first param s
        rsi = mu.reg_read(UC_X86_REG_RSI)  # get the second param c

        hl, haystack = get_mu_bytes(mu, rdi)
        nl, needle = get_mu_bytes(mu, rsi)

        ########################################
        # debug area                           #
        ########################################
        key_len, keys = get_mu_bytes(mu, 0x400BE8)
        needle_decipher = []
        for i in needle:
            if i != 0:
                needle_decipher.append(keys.index(i))

        # start decipher now
        sss = b''
        for i in range(len(needle_decipher)//4):
            a = (needle_decipher[4*i] << 2 & 0xFF) | ((needle_decipher[4*i+1]//16) & 3)
            b = (needle_decipher[4*i+1] << 4 & 0xFF)  | ((needle_decipher[4*i+2]//4) & 0xF)
            c = (needle_decipher[4*i+2] << 6 & 0xFF) | (needle_decipher[4*i+3])
            sss += a.to_bytes(1, "little")
            sss += b.to_bytes(1, "little")
            sss += c.to_bytes(1, "little")
        print(sss)

        print(haystack)
        print(needle)

        ########################################
        # debug area                           #
        ########################################
        rax = 0
        if needle in haystack:
            rax = rsi + haystack.find(needle)
        mu.reg_write(UC_X86_REG_RAX, rax)  # set return value
        mu.reg_write(UC_X86_REG_RIP, 0x400BC4)  # borrow a retn op to return

    # hook void *malloc(size_t size)
    elif address == 0x4005D0:
        rdi = mu.reg_read(UC_X86_REG_RDI)  # get the first param
        addr = mu_malloc(mu, rdi)  # malloc the size
        mu.reg_write(UC_X86_REG_RAX, addr)  # set return value
        mu.reg_write(UC_X86_REG_RIP, 0x400BC4)  # borrow a retn op to return

    # hook void *memset(void *s, int c, size_t n)
    elif address == 0x04005A0:
        rdi = mu.reg_read(UC_X86_REG_RDI)  # get the first param s
        rsi = mu.reg_read(UC_X86_REG_RSI)  # get the second param c
        rdx = mu.reg_read(UC_X86_REG_RDX)  # get the third param n
        for i in range(rdx):
            mu.mem_write(rdi + i, rsi.to_bytes(length=1,byteorder='little',signed=False))

        mu.reg_write(UC_X86_REG_RAX, rdi)  # set return value
        mu.reg_write(UC_X86_REG_RIP, 0x400BC4)  # borrow a retn op to return

    elif address == 0x400a13:  # fix segments
        global NEEDED_FIXED_0x400A13
        if NEEDED_FIXED_0x400A13:
            mu.mem_map(0x600000, 1024 * 1024)
            mu.mem_write(0x0000000000602068, b'\xe8\x0b\x40\x00\x00\x00\x00\x00')
            NEEDED_FIXED_0x400A13 = False



    elif address == 0x400590:
        mu.reg_write(UC_X86_REG_RIP, 0x400BC4)  # borrow a retn op to return


mu.hook_add(UC_HOOK_CODE, hook_code)
mu.emu_start(0x0000000000400A44, 0x400b51)