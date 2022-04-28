/*
 *  _unjail9.h
 *  kokeshidoll
 *
 *  Created by sakuRdev on 2021/12/02.
 *  Update by sakuRdev on 2022/04/29 for armv7
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


#ifndef unjail9_h
#define unjail9_h

#include <dlfcn.h>
#include <copyfile.h>
#include <stdio.h>
#include <spawn.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <Foundation/Foundation.h>

#ifdef __LP64__
#include "patchfinder64.h"
#define KERNEL_HEADER_SIZE (0x4000)
typedef uint64_t kaddr_t;
#else
#include "patchfinder32.h"
typedef uint32_t kaddr_t;
#define KERNEL_HEADER_SIZE (0x1000)
#endif

extern mach_port_t tfp0;

int unjail9(mach_port_t pt, kaddr_t region, int lwvm_type, int kpp);

#endif /* unjail9_h */
