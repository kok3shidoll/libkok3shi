/*
 *  kernel.h
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

#ifndef kernel_h
#define kernel_h

#include <mach/mach.h>

#include "common.h"

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

void copyin(void* to, kaddr_t from, size_t size);
void copyout(kaddr_t to, void* from, size_t size);

#ifdef __LP64__
uint64_t rk64(uint64_t addr);
uint64_t wk64(uint64_t addr, uint64_t val);
#endif

uint32_t rk32(kaddr_t addr);
kaddr_t wk32(kaddr_t addr, uint32_t val);
__unused kaddr_t wk16(kaddr_t addr, uint16_t val);
__unused kaddr_t wk8(kaddr_t addr, uint8_t val);

kaddr_t rkptr(kaddr_t addr);
kaddr_t wkptr(kaddr_t addr, kaddr_t val);

#endif /* kernel_h */
