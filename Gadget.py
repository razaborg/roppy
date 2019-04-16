#!/usr/bin/env python3

from pydis import Instruction

# this is the list of the invalid mnemonics which *SHALL NOT*
# be present in any gadget (otherwise dropped)
REJECTED_MNEMONICS = ['ret', 'call']
# this is the list of valids mnemonics which *MUST*
# be present at the end of each gadget (otherwise dropped)
FINISHER_MNEMONICS = ['ret', 'call']


class InvalidGadget(Exception):
    def __init__(self, message):
        super().__init__(message)

class Gadget():
    
    def __init__(self, list_of_instructions, maxlen=8):
        '''
        This method creates a new gadget
        '''
        # proceed to some checks
        self._check_instructions(list_of_instructions, maxlen)
        # officially create the gadget
        self.instructions = list_of_instructions

    @staticmethod
    def _check_instructions(instructions, maxlen):
        '''
        This method checks that the list of instructions provided are valid.
        '''
        if len(instructions) == 0:
            raise InvalidGadget('Gadget is empty')
        if len(instructions) > maxlen:
            raise InvalidGadget('Gadget is too long. maxlen is set to {}'.format(maxlen))

        n = 0
        for inst in instructions[0:-1]:
            # check for the type of the instructions
            if not isinstance(inst, Instruction):
                raise InvalidGadget('Invalid type of Instructions')
           
            # first instruction checks
            if n == 0:
                if inst.mnemonic == 'nop':
                    raise InvalidGadget('Gadget with first mnemonic "nop" is useless')
            # last instruction checks
            if n == (len(instructions)-1):
                if inst.mnemonic not in FINISHER_MNEMONICS:
                    raise Invalidgadget('Gadget must end with one of the following mnemonics : {}'\
                            .format(FINISHER_GADGETS))
            # check for the validity of instructions in the gadget
            if inst.mnemonic in REJECTED_MNEMONICS:
                raise InvalidGadget('Gadget must not contains any of the following mnemonics before\
                        the end : {}'.format(REJECTED_MNEMONICS))
            n += 1

    @property
    def size(self):
        return len(self.instructions)
 
    @property
    def address(self):
        return '0x{:08x}'.format(self.instructions[0].address)
    
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




if __name__ == '__main__':
    g = Gadget([Instruction(pop), Instruction(ret), Instruction(nop), Instruction(endbr64)])
    print(g)
