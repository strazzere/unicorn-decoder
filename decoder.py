#!/usr/bin/python
import sys
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from capstone import *
import argparse

class SimpleEngine:
	def __init__(self, arch, mode):
		if arch.lower() == 'x86':
			cur_arch = CS_ARCH_X86
		elif arch.lower() == 'arm':
			cur_arch = CS_ARCH_ARM
		else:
			cur_arch = CS_ARCH_ARM64

		if cur_arch is CS_ARCH_X86:
			if mode == '32':
				cur_mode = CS_MODE_32
			elif mode == '16':
				cur_mode = CS_MODE_16
			else:
				cur_mode = CS_MODE_64
		else:
			if mode.lower() == 'thumb':
				cur_mode = CS_MODE_THUMB
			else:
				cur_mode = CS_MODE_ARM

		self.capmd = Cs(cur_arch, cur_mode)

	def disas_single(self, data, addr):
		for i in self.capmd.disasm(data, addr):
			print("  0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
			break

	def disas_all(self, data, addr):
		for i in self.capmd.disasm(data, addr):
			print("  0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

# globals for the hooks
write_bounds = [None, None]

def mem_reader(uc, addr, size):
	tmp = uc.mem_read(addr, size)

	for i in tmp:
		print("   0x%x" % i),
	print("")

# bail out on INT 0x3 (0xCC)
def hook_intr(uc, intno, user_data):
	if intno == 0x3:
		return False;
	else:
		return True

def get_eip_reg(uc):
        eip_reg = UC_X86_REG_EIP

        if uc._arch is UC_ARCH_ARM:
                eip_reg = UC_ARM_REG_PC
        elif uc._arch is UC_ARCH_ARM64:
                eip_reg = UC_ARM64_REG_PC

        return eip_reg

def get_esp_reg(uc):
        esp_reg = UC_X86_REG_ESP

        if uc._arch is UC_ARCH_ARM:
                esp_reg = UC_ARM_REG_SP
        elif uc._arch is UC_ARCH_ARM64:
                esp_reg = UC_ARM64_REG_SP

        return esp_reg

def hook_mem_invalid(uc, access, address, size, value, user_data):
	eip = uc.reg_read(get_eip_reg(uc))

	if access == UC_MEM_WRITE:
		print("invalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" % (address, eip, size, value))
	if access == UC_MEM_READ:
		print("invalid READ of 0x%x at 0x%X, data size = %u" % (address, eip, size))

	return False

def hook_smc_check(uc, access, address, size, value, user_data):
	SMC_BOUND = 0x200
	eip = uc.reg_read(get_eip_reg(uc))

	# Just check if the write target addr is near EIP
	if abs(eip - address) < SMC_BOUND:
		if write_bounds[0] == None:
			write_bounds[0] = address
			write_bounds[1] = address
		elif address < write_bounds[0]:
			write_bounds[0] = address
		elif address > write_bounds[1]:
			write_bounds[1] = address

def hook_mem_read(uc, access, address, size, value, user_data):
	print("mem READ:  0x%x, data size = %u, data value = 0x%x" % (address, size, value))
	print("Printing near deref:")
	mem_reader(uc, address, 32)

	return True

def hook_code(uc, addr, size, user_data):
	mem = uc.mem_read(addr, size)
	uc.disasm.disas_single(str(mem), addr)
	return True

# Using new JIT blocks as a heuristic could really add to the simple SMC system if implemented correctly.
# TODO: attempt to make a new-block based heuristic, I am thinking repeated addresses / size of blocks, 
# maybe even disasm them and poke around.

def main():
	parser = argparse.ArgumentParser(description='Decode supplied x86 / x64 shellcode automatically with the unicorn engine')
	parser.add_argument('-f', dest='file', help='file to shellcode binary file', required=True, type=file)
	parser.add_argument('-a', dest='arch', help='architecture for the emulator (ARM|ARM64|X86)', required=False, default='X86')
	parser.add_argument('-m', dest='mode', help='mode of the emulator (16|32|64|THUMB)', required=False, default="32")
	parser.add_argument('-i', dest='max_instruction', help='max instructions to emulate', required=False)
	parser.add_argument('-d', dest='debug', help='Enable extra hooks for debugging of shellcode', required=False, default=False, action='store_true')

	args = parser.parse_args()

	bin_code = args.file.read()
	disas_engine = SimpleEngine(args.arch, args.mode)

	if args.arch.lower() == 'x86':
		cur_arch = UC_ARCH_X86
	elif args.arch.lower() == 'arm':
		cur_arch = UC_ARCH_ARM
	else:
		cur_arch = UC_ARCH_ARM64

	if cur_arch is UC_ARCH_X86:
		if args.mode == '32':
			cur_mode = UC_MODE_32
		elif args.mode == '16':
			cur_mode = UC_MODE_16
		else:
			cur_mode = UC_MODE_64
	else:
		if args.mode.lower() == 'thumb':
			cur_mode = UC_MODE_THUMB
		else:
			cur_mode = UC_MODE_ARM

	PAGE_SIZE = 2 * 1024 * 1024
	START_RIP = 0x0

	# setup engine and write the memory there.
	emu = Uc(cur_arch, cur_mode)
	emu.disasm = disas_engine # python is silly but it works.
	emu.mem_map(0, PAGE_SIZE)
	# write machine code to be emulated to memory
	emu.mem_write(START_RIP, bin_code)

	# write a INT 0x3 near the end of the code blob to make sure emulation ends
	emu.mem_write(len(bin_code) + 0xff, "\xcc\xcc\xcc\xcc")

	emu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
	emu.hook_add(UC_HOOK_MEM_WRITE, hook_smc_check)
	emu.hook_add(UC_HOOK_INTR, hook_intr)
	
	if args.debug:
		emu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
		emu.hook_add(UC_HOOK_CODE, hook_code)

	# arbitrary address for ESP.
	emu.reg_write(get_esp_reg(emu), 0x2000)

	if args.max_instruction:
		end_addr = -1
	else:
		args.max_instruction = 0x1000
		end_addr = len(bin_code)

	try: 
		emu.emu_start(START_RIP, end_addr, 0, int(args.max_instruction))
	except UcError as e:
		print("ERROR: %s" % e)

	if write_bounds[0] != None:
		print("Shellcode address ranges:")
		print("   low:  0x%X" % write_bounds[0])
		print("   high: 0x%X" % write_bounds[1])
		print("")
		print("Decoded shellcode:")
		mem = emu.mem_read(write_bounds[0], (write_bounds[1] - write_bounds[0]))
		emu.disasm.disas_all(str(mem), write_bounds[0])

	else:
		print("No SMC hits, no encoder detected")

if __name__ == '__main__':
	main()

