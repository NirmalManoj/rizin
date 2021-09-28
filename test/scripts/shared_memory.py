#!/usr/bin/env python3

from multiprocessing import shared_memory

import rzpipe

FILENAMES = ["bins/elf/_Exit (42)", "bins/pe/winver.exe", "bins/mach0/mach0_2-x86_64"]

for fname in FILENAMES:
    with open(fname, "rb") as f:
        data = f.read()
        shm = shared_memory.SharedMemory(create=True, size=len(data))
        print("Copying %s..." % fname)
        shm.buf[:] = data[:]
        print("Copied %s succesfully" % fname)
        print("-------------")
        print("Shared buffer size 0x{0:x}".format(shm.size))
        print("-------------")

        rzp = rzpipe.open("shm://{0:s}".format(shm.name))
        rzp.cmd("e scr.color=0")
        rzp.cmd("e scr.utf8=false")
        rzp.cmd("e scr.interactive=false")
        infoj = rzp.cmdj("ij")
        print(infoj["bin"])
        print(rzp.cmd("px 16"))
        rzp.cmd("aaa")
        print(rzp.cmd("afl"))
        print(rzp.cmd("pdf @ entry0"))
        rzp.quit()
        shm.close()
        shm.unlink()
