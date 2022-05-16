/*
 *  kernel.m
 *  kokeshidoll
 *
 *  Created by sakuRdev on 2022/05/17.
 *  Copyright (c) 2021 - 2022 sakuRdev. All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *
 */

#import <Foundation/Foundation.h>

#include "common.h"
#include "kernel.h"

extern mach_port_t tfp0;

void copyin(void* to, kaddr_t from, size_t size) {
    mach_vm_size_t outsize = size;
    size_t szt = size;
    if (size > 0x1000) {
        size = 0x1000;
    }
    size_t off = 0;
    while (1) {
        mach_vm_read_overwrite(tfp0, off+from, size, (mach_vm_offset_t)(off+to), &outsize);
        szt -= size;
        off += size;
        if (szt == 0) {
            break;
        }
        size = szt;
        if (size > 0x1000) {
            size = 0x1000;
        }
        
    }
}

void copyout(kaddr_t to, void* from, size_t size) {
    mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

#ifdef __LP64__
uint64_t rk64(uint64_t addr) {
    uint64_t val = 0;
    copyin(&val, addr, 8);
    return val;
}

uint64_t wk64(uint64_t addr, uint64_t val) {
    copyout(addr, &val, 8);
    return val;
}
#endif

uint32_t rk32(kaddr_t addr) {
    uint32_t val = 0;
    copyin(&val, addr, 4);
    return val;
}

kaddr_t wk32(kaddr_t addr, uint32_t val) {
    copyout(addr, &val, 4);
    return val;
}

__unused kaddr_t wk16(kaddr_t addr, uint16_t val) {
    copyout(addr, &val, 2);
    return val;
}

__unused kaddr_t wk8(kaddr_t addr, uint8_t val) {
    copyout(addr, &val, 1);
    return val;
}

kaddr_t rkptr(kaddr_t addr)
{
#ifdef __LP64__
    return rk64(addr);
#else
    return rk32(addr);
#endif
}

kaddr_t wkptr(kaddr_t addr, kaddr_t val)
{
#ifdef __LP64__
    return wk64(addr, val);
#else
    return wk32(addr, val);
#endif
}
