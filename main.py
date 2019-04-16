#!/usr/bin/env python3
from elftools.elf.sections import SymbolTableSection
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
    

def backward_disas(data, offset, n, section_offset, maxlen=8, symtab=None):
    '''
    This function dissasemble a bytecode which ends at a specific @offset.
    The @n parameter gives how many bytes back must be taken at max.
    The @section_offset parameter is present to keep consistent addresses of the gadgets
    '''
    assert(data[offset] == 0xc3)
    gadgets = []
    for i in range(n,0, -1): 
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
            gadgets.append(Gadget(instructions, maxlen, symtab))
        except InvalidGadget:
            continue

    return gadgets

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Look for interesting gadgets inside a binary.')
    parser.add_argument('file', type=str, help='The binary file to inspect')
    parser.add_argument('-m', '--mnemonic', help='Search for a specific mnemonic')
    parser.add_argument('-r', '--register', help='What register you want to manipulate.')
    parser.add_argument('-l', '--max-len', type=int, help='Maximum lenght of gadgets found. (default to 8)', default=8)
    parser.add_argument('-b', '--bytes-backward', type=int, default=30, help='Number of bytes to browse backwards each time a ret instruction if found. (default to 30)')
    parser.add_argument('-s', '--symbols', action='store_true', default=False, help='Try to resolve symbols (prototypal only .symtab for now).')
    args = parser.parse_args()


    with open(args.file, 'rb') as f:
        elf = ELFFile(f)
        text_section = elf.get_section_by_name('.text')
        text_data = text_section.data()
        if args.symbols:
            symtab = {}
            for section in elf.iter_sections():
                # if we found multiple symboltablesections
                # we update our own local symtab dictionnary
                if isinstance(section, SymbolTableSection):
                    symtab.update({s.entry.st_value: s.name for s in section.iter_symbols() \
                            if len(s.name) > 0
                            })
        else:
            symtab = None
   
    # look into the .text section to find all interesting ending-gadgets opcodes
    ret_offsets = findall_ret(text_data)
    
    gadgets = []
    # for each 'ret' opcode we found in the binary
    # we proceed backwards to find new gadgets
    for ret in ret_offsets:
        gadget = backward_disas(text_data, ret, args.bytes_backward, \
                section_offset=text_section.header.sh_addr, \
                maxlen=args.max_len, symtab=symtab)
        gadgets.extend(gadget)

    # and after all of this we have a complete list of gadgets :-) 
    for gadget in gadgets:
        if args.mnemonic:
            if not gadget.has_mnemonic(args.mnemonic):
                continue
        if args.register:
            if not gadget.has_register(args.register):
                continue
                
        print('{} : {}'.format(gadget.address, gadget.to_string()))
