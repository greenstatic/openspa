#!/usr/bin/env python3

import sys

def main():
    if len(sys.argv) != 3:
        print("./check_nic_irq_affinity.py <irq_start> <irq_end>")
        sys.exit(1)

    irq_start = sys.argv[1]
    irq_end = sys.argv[2]

    irq_to_cpu(int(irq_start), int(irq_end))


def irq_to_cpu(irq_start, irq_end):
    for i in range(irq_start, irq_end+1):
        raw = open("/proc/irq/{}/smp_affinity".format(i)).read()
        hexadecimal = raw.replace("\n", "")
        binary = bin(int(hexadecimal, 16))
        cpus = bin_mask_to_index(str(binary)[2:])

        cpus_str = map(str, cpus)
        cpus_str_h = ",".join(cpus_str)

        print("irq: {} - cpus: {}".format(i, cpus_str_h))

def bin_mask_to_index(mask):
    idx = []

    mask_rev = mask[::-1]
    count = 0

    for s in mask_rev:
        if s == "1":
            idx.append(count)

        count += 1

    return idx



if __name__ == "__main__":
    main()
