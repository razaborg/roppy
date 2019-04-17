#!/usr/bin/env python3

class InstructionWrapper():
    def __init__(self, InstructionObject):
        self._wrapped_inst = InstructionObject

    def __getattr__(self,attr):
        return self._wrapped_inst.__getattribute__(attr)
    
    def __repr__(self):
        return "Instruction('{}')".format(self._wrapped_inst.to_string())
    # We change the __hash__ method to compare the instruction using their str representations
    def __hash__(self):
        return hash(self._wrapped_inst.to_string())

    def __eq__(self, other):
        return self._wrapped_inst.to_string()  == other._wrapped_inst.to_string()

