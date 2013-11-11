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

class RelaLoopDoneBreakpoint(gdb.Breakpoint):

    def stop(self):
        laddr = int(gdb.execute("print l->l_addr", to_string=True).split()[2])
        if 0 == laddr:
            print "(elfbfgdb) Branching..."
        return self._dostop and (0 == laddr)

class ReadCurrentEntry(gdb.Command):
    instructions = None

    """Read current entry on tape"""
    def __init__(self):
        gdb.Command.__init__(self,"elfbf", gdb.COMMAND_DATA)
        self.source = None
        self.rela_loop_break = gdb.Breakpoint("do-rel.h:117") #at the loop that processes relocation entries
        self.rela_loop_break.condition = "map->l_addr==0"
        self.rela_proc_break = gdb.Breakpoint("do-rel.h:120") #inside the loop that processes relocation entries
        self.rela_proc_break.enabled = False
        self.rela_proc_break.condition = "map->l_addr==0"
        self.rela_loop_exit = RelaLoopDoneBreakpoint("rtld.c:2262")
        self.rela_loop_exit._dostop = False

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)

        # fast forward to linker code that processes reloc entries
        # if needed
        if "elf_dynamic_do_rela" != gdb.selected_frame().name():
            self.rela_loop_break.enabled = True
            self.rela_proc_break.enabled = False
            gdb.execute("c")

        elif None == self.instructions:
            if args[0] == "setup":
                execfile(args[1])
                self.initialize()
            else:
                print "Must first call 'elfbf setup <debug config file>'"
        elif args[0] == "tape":
            self.print_tape_range()
        elif args[0] == "tape_range":
            low = int(args[1])
            high = int(args[2])
            self.print_tape_range(low,high)
        elif args[0] == "tape_value": #prints current tape value
            head = self.get_tape_head_ptr()
            print gdb.execute("x/bx 0x%x" %head, to_string=True)
        elif args[0] == "tape_value_relative": #argument index relative to current tape index
            if len(args) > 1:
                num = int(args[1])
            else:
                num = 0
            head = self.get_tape_head_ptr()
            head += num
            print gdb.execute("x/bx 0x%x" %head, to_string=True)
        elif args[0] == "tape_index": #returns current tape index
            print self.get_head_index()
        elif args[0] == "source": #prints brainfuck source
            print self.source
        elif args[0] == "current_ins": #prints info on current instruction being executed
            r = self.get_current_rel()
            i = self.get_ins(r)
            if (i < 0):
                if i == -1:
                    print "Initializing brainfuck environment"
                else:
                    print "Invalid instruction"
            else:
                print "Instruction %s at index %d" %(self.source[i],i)
        elif args[0] == "go_to_next_rel":
            self.rela_proc_break.enabled = True
            gdb.execute("c")
            self.rela_proc_break.enabled = False
        elif args[0] == "go_to_next_ins":
            index = self.get_ins(self.get_current_rel())
            print index
            if (index < len(self.source)) and ((index < 0) or (not 'X' == self.source[index])):
                # loop until get_ins != index
                self.rela_proc_break.enabled = True
                while index == self.get_ins(self.get_current_rel()):
                    print "continuing"
                    gdb.execute("c")
                self.rela_proc_break.enabled = False
            else:
                print "all instrutions have been executed"
                if ('X' == self.source[index]):
                    print "finishing cleanup"
                    self.rela_loop_exit.enabled = False
                    self.rela_proc_break.enabled = False
                    self.rela_loop_break.enabled = False
                    gdb.execute("c")
        elif args[0] == "rel_num": #prints current reloc index being processed
            print (self.get_current_rel() - self.rela_start)/self.relsz
        else:
            print "bad elfbf command"

    def initialize(self):
        self.set_source(self.bf_src_path, self.exec_path)
        relsz = gdb.execute("print sizeof(Elf64_Rela)", to_string=True)
        relsz = relsz.split()
        self.relsz = int(relsz[2])
        symsz = gdb.execute("print sizeof(Elf64_Sym)", to_string=True)
        symsz = symsz.split()
        self.symsz = int(symsz[2])
        self.tape_top = self.dynsym + ((self.numsym+1)*self.symsz)
        self.tape_len = self.tape_len * self.symsz

    def continue_to(self, insidx):
        #calculate first reloc entry of insids
        relcount = self.instructions["init"]
        for i in range(insidx):
            try:
                relcount += self.instructions[self.source[i]]
            except KeyError:
                print "key error"
        # calculate addr of relocatin entry
        lastrel = self.rela_start + (relcount * self.relsz)

        while self.get_current_rel() < lastrel:
            print "next"
            gdb.execute("n", to_string=True)

    def get_current_rel(self):
        creladdr = gdb.execute("print r", to_string=True)
        creladdr = creladdr.split()
        return int(creladdr[5], 16)

    def get_ins(self, reloc):
        relnum = (reloc - self.rela_start) / self.relsz
        if (relnum < self.instructions["I"]):
            return -1
        else:
            relidx = self.instructions["I"]
            for i in range(len(self.source)):
                inst = self.source[i]
                try:
                    relidx += self.instructions[inst]
                    if (relnum < relidx): #we are at next instr
                        #print "Instruction: %s at index %d\n" %(inst, i)
                        return i
                except KeyError:
                    print "skipping instruction '%s'" %inst.encode("hex")
            print "Instruction not found"
            return -2

    def set_source(self, source, elf):
        self.elf = elf
        # look up address of first relocation entry (DT_RELA)
        import os
        addr = os.popen("readelf -d %s | grep '(RELA)' | awk '{print $3}';" %self.elf)
        r = addr.read()
        addr.close()
        self.rela_start = int(r,16)
        addr = os.popen("readelf -d %s | grep '(SYMTAB)' | awk '{print $3}';" %self.elf)
        d = addr.read()
        addr.close()
        self.dynsym = int(d,16)
        # read in bf instructions
        f = open(source)
        if f:
            self.source = f.read()
            f.close()
        print self.source

    def print_tape_range(self,low=None, high=None):
        if (None == low):
            low = 0
            high = self.tape_len
        print gdb.execute("x/%dbx 0x%x" %(high-low,int(self.tape_top+low)), to_string=True)

    def get_head_index(self):
        return  self.get_tape_head_ptr() - self.tape_top

    def get_sym_value(self, symaddr):
        s = gdb.parse_and_eval('(Elf64_Sym *) %d' %symaddr)
        head =  s['st_value']
        return int(str(head))

    def get_tape_head_ptr(self):
        return self.get_sym_value(self.tape_ptr_addr)


ReadCurrentEntry()
