#!/usr/bin/python

# Copyright (c) 2012 Rebecca (bx) Shapiro

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import gdb

class ReadCurrentEntry(gdb.Command):
    """Read current entry on tape"""
    def __init__(self):
        gdb.Command.__init__(self,"elfbf", gdb.COMMAND_DATA)


    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)

        if args[0] == 'set_tape':
            self.tapehead = int(args[1],16)
            self.orig_head_addr = self.get_head_addr()
        elif args[0] == "print_current_entry":
            head = self.get_current_entry()
            self.print_entry(head)
        elif args[0] == "print_entry":
            if len(args) > 1:
                num = int(args[1])
            else:
                num = 0
            self.print_entry_at(num)
        elif args[0] == "get_tape_index":
            print self.get_head_index()
        elif args[0] == "print_tape_range":
            print self.get_tape_range(int(args[1]), int(args[2]))
        else:
            print "bad elfbf command"

    def get_tape_range(self,low,high):
        return gdb.execute("x/%dbx %x" %(high-low,int(self.orig_head_addr+low)), to_string=True)

    def get_head_index(self):
        loc = self.get_head_addr()
        return (loc - self.orig_head_addr)/8

    def get_head_addr(self):
        r = gdb.parse_and_eval('(Elf64_Sym *) %d' %self.tapehead)
        head =  r['st_value']
        return int(str(head),16)


    def get_entry(self,loc):
        return gdb.execute("x/bx %x" %int(loc), to_string=True)

    def get_current_entry(self):
        return self.get_entry_at(0)

    def get_entry_at(self, num=0):
        entry = self.get_head_addr() + 8*num
        return self.get_entry(entry)

    def print_entry_at(self, num=0):
        entry = self.get_entry_at(num)
        self.print_entry(entry)

    def print_entry(self,entry):
        print entry

ReadCurrentEntry()
