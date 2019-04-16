#!/usr/bin/env python3

from elftools.elf.elffile import ELFFile
from Gadget import *
import pydis
import argparse


def findall_ret(data):
    ret_list = []
    last_ret = 0
    while True:
        x = data.find(0xc3, last_ret+1)
        if x == -1:
            return ret_list
        ret_list.append(x)
        last_ret = x
    

def backward_disas(data, offset, n, section_offset):
    '''
    This function dissasemble a bytecode which ends at a specific @offset.
    The @n parameter gives how many bytes back must be taken at max.
    The @section_offset parameter is present to keep consistent addresses of the gadgets
    '''
    assert(data[offset] == 0xc3)
    gadgets = []
    for i in range(n,1, -1): 
        bytecode = data[offset-i:offset+1]
        instructions = []
        # --- with pydis
        try:

            address = (offset-i) + section_offset
            for inst in pydis.decode(bytecode, address=address):
                instructions.append(inst)
        except Exception:
            continue
        
        try: 
            gadgets.append(Gadget(instructions))
        except InvalidGadget:
            continue

    return gadgets

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Look for interesting gadgets inside a binary.')
    parser.add_argument('file', type=str, help='The binary file to inspect')
    parser.add_argument('-m', '--mnemonic', help='Search for a specific mnemonic')
    parser.add_argument('-r', '--register', help='What register you want to manipulate.')
    parser.add_argument('-l', '--max-len', type=int, help='Maximum lenght of gadgets found.', default=8)
    args = parser.parse_args()


    with open(args.file, 'rb') as f:
        elf = ELFFile(f)
        text_section = elf.get_section_by_name('.text')
        text_bytes = text_section.data()
    # look into the .text section to find all interesting ending-gadgets opcodes
    ret_offsets = findall_ret(text_bytes)
    
    gadgets = []
    for ret in ret_offsets:
        gadget = backward_disas(text_bytes, ret, args.max_len, \
                section_offset=text_section.header.sh_addr)
        gadgets.extend(gadget)

    
    for gadget in gadgets:
        if args.mnemonic:
            if not gadget.has_mnemonic(args.mnemonic):
                continue
        if args.register:
            if not gadget.has_register(args.register):
                continue
                
        print('{} : {}'.format(gadget.address, gadget.to_string()))
