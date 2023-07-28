#!/usr/bin/env python
#Generates a C struct from the /sys/kernel/debug/tracing/events/*/*/format file
#Needs access to debugfs obviously

import re, sys


def size_to_type(size, signed):
    if(signed == 0):
        if(size == 1):
            return "uint8_t";
        if(size == 2):
            return "uint16_t";
        if(size == 4):
            return "uint32_t";
        if(size == 8):
            return "uint64_t";
        return "uint8_t[{}]".format(size)
    if(signed == 1):
        if(size == 1):
            return "int8_t";
        if(size == 2):
            return "int16_t";
        if(size == 4):
            return "int32_t";
        if(size == 8):
            return "int64_t";
    sys.exit("Unknown size: " + size)

if len(sys.argv) != 3:
    sys.exit("Too few arguments specified")

group = sys.argv[1]
tracepoint = sys.argv[2]


pattern = re.compile('\s+field:.*\s([a-zA-Z_]+).*;\s+offset:(\d+).*size:(\d+).*signed:(\d);')

f = open("/sys/kernel/debug/tracing/events/{}/{}/format".format(group, tracepoint));

print("struct __attribute((__packed__)) TracepointSampleType")
print("{")
print("    uint64_t time;")
print("    uint32_t tp_data_size;")
print("    uint16_t common_type;")
print("    uint8_t common_flags;")
print("    uint8_t common_preempt_count;")
print("    int32_t common_pid;")
print("};")
print("")
print("struct __attribute((__packed__)) {}_{}".format(group, tracepoint))
print("{")
print("    struct TracepointSampleType header;")

cur_offset = 8
padding_num = 0

for line in f:
    match = pattern.match(line)
    if match:
        name = match.group(1)
        if("common_" in name):
            continue
        next_offset = int(match.group(2))
        size = int(match.group(3))
        signed = int(match.group(4))

        if (next_offset > cur_offset):
            print("    char padding{} [{}];".format(padding_num, next_offset-cur_offset))
            cur_offset = next_offset
            padding_num = padding_num + 1
        if('[' in line):
            print("    char {}[{}];".format(name, size))
        else:
            print("    {} {};".format(size_to_type(size, signed), name))
        cur_offset = cur_offset + size;
print("};")
