#!/usr/bin/env python3

import pydis
from Instruction import InstructionWrapper
import re
# this is the list of the invalid mnemonics which *SHALL NOT*
# be present in any gadget (otherwise dropped)
REJECTED_MNEMONICS = ['hlt']
# this is the list of valids mnemonics which *MUST*
# be present at the end of each gadget (otherwise dropped)
FINISHER_MNEMONICS = ['ret', 'call', 'jmp']



class InvalidGadget(Exception):
    def __init__(self, message):
        super().__init__(message)

class Gadget():
    
    def __init__(self, instructions=(), maxlen=8, symtab=None):
        '''
        This method creates a new gadget
        @list_of_instructions : a list of Instruction() objects
        @maxlen: the maximum number of instructions allowed for a unique gadget
        @symtab: a symbol table to try to resolve symbols in the gadgets (default to None, optional)
        '''
        self.symtab = symtab
        # proceed to some checks
        self.instructions = tuple(map(InstructionWrapper, self._check_and_load_instructions(instructions, maxlen)))

    
    def _check_and_load_instructions(self, instructions, maxlen):
        '''
        This method checks that the list of instructions provided are valid.
        '''
        if len(instructions) == 0:
            raise InvalidGadget('Gadget is empty')
        if len(instructions) > maxlen:
            raise InvalidGadget('Gadget is too long. maxlen is set to {}'.format(maxlen))

        # this regex gonna be used to extract addresses and try to resolve symbols
        n = 0
        for inst in instructions:
            # first instruction checks
            if n == 0:
                if inst.mnemonic == 'nop':
                    raise InvalidGadget('Gadget with first mnemonic "nop" is useless')
            # last instruction checks
            if n == (len(instructions)-1):
                if inst.mnemonic not in FINISHER_MNEMONICS:
                    raise InvalidGadget('Gadget must end with one of the following mnemonics : {}'\
                            .format(FINISHER_MNEMONICS))
            else:
                # if a ret instruction is found in the middle of the gadget, we cut it
                if inst.mnemonic in FINISHER_MNEMONICS:
                    return instructions[:n+1]
                # if a forbidden instruction is found, we drop the gadget
                if inst.mnemonic in REJECTED_MNEMONICS:
                    raise InvalidGadget('Gadget must not contains any of the following \
                            mnemonics before the end : {}'.format(REJECTED_MNEMONICS))
            
                                            
            n += 1
        
        return instructions

    @property
    def size(self):
        return len(self.instructions)
 
    @property
    def address(self):
        return '0x{:016x}'.format(self.instructions[0].address)
    
    def __getitem__(self, key):
        return self.instructions[key]

    def __repr__(self):
        return 'Gadget({})'.format(self.instructions)

    def to_string(self):
        '''
        Convert the gadget to a string representation of the instructions (inline)
        '''
        out = ''
        for inst in self.instructions:
            out += inst.to_string()
            out += ' ; '
        
        if self.symtab:
            for key in self.symtab.keys():
                txt_addr = '0x' + '{:016x}'.format(key).upper()
                out = out.replace(txt_addr, '<'+self.symtab[key]+'>') 
        return out[:-3]

    def has_mnemonic(self, query):
        '''
        Check if a specific mnemonic is present or not in the gadget
        '''
        assert(isinstance(query, str))
        if any(inst for inst in self.instructions if inst.mnemonic == query):
            return True
        else:
            return False

    def has_register(self, register):
        '''
        Check if a specific register is present or not in the gadget
        '''
        assert(isinstance(register, str))
        for inst in self.instructions:
            if inst.to_string().find(register) > 0:
                return True
        return False
    
    # We change the __hash__ method to compare gadgets with the str() representation
    # of the instructions they embed
    def __hash__(self):
        return sum(hash(inst) for inst in self.instructions)

    def __eq__(self, other):
        return self.__repr__() == other.__repr__() 

