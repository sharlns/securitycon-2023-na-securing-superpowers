#!/bin/bash

i=5000

for (( ; ; ))
do
        i=$((i+1))
        bpftool prog load seattle_bpf_prog.o /sys/fs/bpf/a85d48$i --legacy type kprobe
        sleep 30s
        bpftool map create /sys/fs/bpf/seattle_$i type hash key 4 value 20 entries 4 name tetragon_bpf_$i
        sleep 30s
done