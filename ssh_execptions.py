# exceptions.py
# description: some exceptions...
class UnknownHost(Exception):
    def __init__(self,err):
        self.err = err
    def __repr__(self):
        return str(self.err)
    def __str__(self):
        return str(elf.err)

class NotRoot(Exception):
    def __init__(self,err):
        self.err = err
    def __repr__(self):
        return str(self.err)
    def __str__(self):
        return str(elf.err)
