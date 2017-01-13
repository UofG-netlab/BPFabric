import struct
import StringIO
import sys
import networkx as nx
from networkx.drawing.nx_agraph import graphviz_layout
from matplotlib import pyplot as plt
from elftools.elf.elffile import ELFFile

Inst = struct.Struct("BBHI")

CLASSES = {
    0: "ld",
    1: "ldx",
    2: "st",
    3: "stx",
    4: "alu",
    5: "jmp",
    7: "alu64",
}

ALU_OPCODES = {
    0: 'add',
    1: 'sub',
    2: 'mul',
    3: 'div',
    4: 'or',
    5: 'and',
    6: 'lsh',
    7: 'rsh',
    8: 'neg',
    9: 'mod',
    10: 'xor',
    11: 'mov',
    12: 'arsh',
    13: '(endian)',
}

JMP_OPCODES = {
    0: 'ja',
    1: 'jeq',
    2: 'jgt',
    3: 'jge',
    4: 'jset',
    5: 'jne',
    6: 'jsgt',
    7: 'jsge',
    8: 'call',
    9: 'exit',
}

MODES = {
    0: 'imm',
    1: 'abs',
    2: 'ind',
    3: 'mem',
    6: 'xadd',
}

SIZES = {
    0: 'w',
    1: 'h',
    2: 'b',
    3: 'dw',
}

BPF_CLASS_LD = 0
BPF_CLASS_LDX = 1
BPF_CLASS_ST = 2
BPF_CLASS_STX = 3
BPF_CLASS_ALU = 4
BPF_CLASS_JMP = 5
BPF_CLASS_ALU64 = 7

BPF_ALU_NEG = 8
BPF_ALU_END = 13

def R(reg):
    return "r" + str(reg)

def I(imm):
    return "%#x" % imm

def M(base, off):
    if off != 0:
        return "[%s%s]" % (base, O(off))
    else:
        return "[%s]" % base

def O(off):
    if off <= 32767:
        return "+" + str(off)
    else:
        return "-" + str(65536-off)

def disassemble_one(data, offset):
    code, regs, off, imm = Inst.unpack_from(data, offset)
    dst_reg = regs & 0xf
    src_reg = (regs >> 4) & 0xf
    cls = code & 7

    class_name = CLASSES.get(cls)

    if cls == BPF_CLASS_ALU or cls == BPF_CLASS_ALU64:
        source = (code >> 3) & 1
        opcode = (code >> 4) & 0xf
        opcode_name = ALU_OPCODES.get(opcode)
        if cls == BPF_CLASS_ALU:
            opcode_name += "32"

        if opcode == BPF_ALU_END:
            opcode_name = source == 1 and "be" or "le"
            return ("%s%d %s" % (opcode_name, imm, R(dst_reg)), class_name)
        elif opcode == BPF_ALU_NEG:
            return ("%s %s" % (opcode_name, R(dst_reg)), class_name)
        elif source == 0:
            return ("%s %s, %s" % (opcode_name, R(dst_reg), I(imm)), class_name)
        else:
            return ("%s %s, %s" % (opcode_name, R(dst_reg), R(src_reg)), class_name)
    elif cls == BPF_CLASS_JMP:
        source = (code >> 3) & 1
        opcode = (code >> 4) & 0xf
        opcode_name = JMP_OPCODES.get(opcode)

        if opcode_name == "exit":
            return (opcode_name, class_name)
        elif opcode_name == "call":
            return ("%s %s" % (opcode_name, I(imm)), class_name)
        elif opcode_name == "ja":
            return ("%s %s" % (opcode_name, O(off)), class_name, O(off))
        elif source == 0:
            return ("%s %s, %s, %s" % (opcode_name, R(dst_reg), I(imm), O(off)), class_name, O(off))
        else:
            return ("%s %s, %s, %s" % (opcode_name, R(dst_reg), R(src_reg), O(off)), class_name, O(off))
    elif cls == BPF_CLASS_LD or cls == BPF_CLASS_LDX or cls == BPF_CLASS_ST or cls == BPF_CLASS_STX:
        size = (code >> 3) & 3
        mode = (code >> 5) & 7
        mode_name = MODES.get(mode, str(mode))
        # TODO use different syntax for non-MEM instructions
        size_name = SIZES.get(size, str(size))
        if code == 0x18: # lddw
            _, _, _, imm2 = Inst.unpack_from(data, offset+8)
            imm = (imm2 << 32) | imm
            return ("%s %s, %s" % (class_name + size_name, R(dst_reg), I(imm)), class_name)
        elif code == 0x00:
            # Second instruction of lddw
            return (None, class_name)
        elif cls == BPF_CLASS_LDX:
            return ("%s %s, %s" % (class_name + size_name, R(dst_reg), M(R(src_reg), off)), class_name)
        elif cls == BPF_CLASS_ST:
            return ("%s %s, %s" % (class_name + size_name, M(R(dst_reg), off), I(imm)), class_name)
        elif cls == BPF_CLASS_STX:
            return ("%s %s, %s" % (class_name + size_name, M(R(dst_reg), off), R(src_reg)), class_name)
        else:
            return ("unknown mem instruction %#x" % code, None)
    else:
        return ("unknown instruction %#x" % code, None)

def disassemble(data):
    output = StringIO.StringIO()
    offset = 0

    G=nx.DiGraph()
    G.add_node(offset, code=[])
    current_node=offset

    while offset < len(data):
        s = disassemble_one(data, offset)
        if s[0]:
            output.write(s[0] + "\n")

            #
            if offset != current_node and G.has_node(offset):
                print current_node, offset
                G.add_edge(current_node, offset)
                current_node = offset

            G.node[current_node]['code'].append(s[0])
            if s[1] == 'jmp' and s[0].split()[0] not in ['exit', 'call']:
                print 'jump', s

                G.add_node(offset+8, code=[])
                G.add_edge(current_node, offset+8)

                branch_offset = offset + 8 + int(s[2])*8
                G.add_node(branch_offset, code=[])
                G.add_edge(current_node, branch_offset)

                current_node=offset+8

        offset += 8

    print sum([ len(d['code']) for n,d in G.nodes(data=True) ])
    for path in nx.all_simple_paths(G, 0, current_node):
        print path, sum([ len(G.node[n]['code']) for n in path ])

    nx.draw_networkx(G, labels={ k: '\n'.join(n.get('code', '')) for k,n in G.nodes(data=True) })
    plt.show()

    A = nx.nx_agraph.to_agraph(G)
    A.layout('dot', args='-Nfontsize=10 -Nwidth=".2" -Nheight=".2" -Nmargin=0 -Gfontsize=8')
    A.draw('test.png')




    return output.getvalue()

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as f:
        elffile = ELFFile(f)

        for section in elffile.iter_sections():
            if section.name == '.text':
                disassemble(section.data())
