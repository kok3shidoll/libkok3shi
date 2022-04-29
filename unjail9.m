/*
 *  _unjail9.m
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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

#include <mach/mach.h>
#include <mach-o/dyld.h>

#include <sys/mount.h>

#include "unjail9.h"

#include "mac.h"

#ifdef DEBUG
#define DEBUGLog(str, args...)\
do\
{\
NSLog(@str, ##args);\
} while(0)
#else
#define DEBUGLog(str, args...)
#endif

extern void (*printLog)(const char *text, ...);

mach_port_t tfp0 = 0;

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

static void copyin(void* to, kaddr_t from, size_t size) {
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

static void copyout(kaddr_t to, void* from, size_t size) {
    mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

#ifdef __LP64__
static uint64_t rk64(uint64_t addr) {
    uint64_t val = 0;
    copyin(&val, addr, 8);
    return val;
}

static uint64_t wk64(uint64_t addr, uint64_t val) {
    copyout(addr, &val, 8);
    return val;
}
#endif

static uint32_t rk32(kaddr_t addr) {
    uint32_t val = 0;
    copyin(&val, addr, 4);
    return val;
}

static kaddr_t wk32(kaddr_t addr, uint32_t val) {
    copyout(addr, &val, 4);
    return val;
}

static kaddr_t wk16(kaddr_t addr, uint16_t val) {
    copyout(addr, &val, 2);
    return val;
}

static kaddr_t wk8(kaddr_t addr, uint8_t val) {
    copyout(addr, &val, 1);
    return val;
}

static kaddr_t rkptr(kaddr_t addr)
{
#ifdef __LP64__
    return rk64(addr);
#else
    return rk32(addr);
#endif
}

static kaddr_t wkptr(kaddr_t addr, kaddr_t val)
{
#ifdef __LP64__
    return wk64(addr, val);
#else
    return wk32(addr, val);
#endif
}


static uint8_t *kdata = NULL;
static size_t ksize = 0;

static uint64_t kernel_entry = 0;
uint64_t kerndumpbase = -1;
static void *kernel_mh = 0;

#ifndef __LP64__
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

uint32_t tte_virt;
uint32_t tte_phys;

#define TTB_SIZE            4096
#define L1_SECT_S_BIT       (1 << 16)
#define L1_SECT_PROTO       (1 << 1)        /* 0b10 */
#define L1_SECT_AP_URW      (1 << 10) | (1 << 11)
#define L1_SECT_APX         (1 << 15)
#define L1_SECT_DEFPROT     (L1_SECT_AP_URW | L1_SECT_APX)
#define L1_SECT_SORDER      (0)            /* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_DEFCACHE    (L1_SECT_SORDER)
#define L1_PROTO_TTE(entry) (entry | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE)
#define L1_PAGE_PROTO       (1 << 0)
#define L1_COARSE_PT        (0xFFFFFC00)
#define PT_SIZE             256
#define L2_PAGE_APX         (1 << 9)

void patch_page_table(uint32_t tte_virt, uint32_t tte_phys, uint32_t page) {
    uint32_t i = page >> 20;
    uint32_t j = (page >> 12) & 0xFF;
    uint32_t addr = tte_virt+(i<<2);
    uint32_t entry = rk32(addr);
    if ((entry & L1_PAGE_PROTO) == L1_PAGE_PROTO) {
        uint32_t page_entry = ((entry & L1_COARSE_PT) - tte_phys) + tte_virt;
        uint32_t addr2 = page_entry+(j<<2);
        uint32_t entry2 = rk32(addr2);
        if (entry2) {
            uint32_t new_entry2 = (entry2 & (~L2_PAGE_APX));
            wk32(addr2, new_entry2);
        }
    } else if ((entry & L1_SECT_PROTO) == L1_SECT_PROTO) {
        uint32_t new_entry = L1_PROTO_TTE(entry);
        new_entry &= ~L1_SECT_APX;
        wk32(addr, new_entry);
    }
    
    usleep(10000);
    
}

static unsigned int
make_b_w(int pos, int tgt)
{
    int delta;
    unsigned int i;
    unsigned short pfx;
    unsigned short sfx;
    
    unsigned int omask_1k = 0xB800;
    unsigned int omask_2k = 0xB000;
    unsigned int omask_3k = 0x9800;
    unsigned int omask_4k = 0x9000;
    
    unsigned int amask = 0x7FF;
    int range;
    
    range = 0x400000;
    
    delta = tgt - pos - 4; /* range: 0x400000 */
    i = 0;
    if(tgt > pos) i = tgt - pos - 4;
    if(tgt < pos) i = pos - tgt - 4;
    
    if (i < range){
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_1k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range < i && i < range*2){
        delta -= range;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_2k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range*2 < i && i < range*3){
        delta -= range*2;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_3k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range*3 < i && i < range*4){
        delta -= range*3;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_4k | ((delta >>  1) & amask);
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    return -1;
}
#endif

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
/* pangu9 method */
static void sbWriteCode(uint64_t shc, uint64_t x30_reg, uint64_t equal, uint64_t next)
{
    /*
     * Replace _memset.stub with shellcode in the following policy hook functions,
     * set x0 register to 0, and jump to ret.
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
    
    DEBUGLog("%llx: %llx, next: %llx", x30_reg, equal, next);
    
                                  // _shellcode: check x30 register to branch which function it came from.
    wk32(shc + 0x00, 0x58000110); //     ldr        x16, _x30_reg
    wk32(shc + 0x04, 0xeb1003df); //     cmp        x30, x16
    wk32(shc + 0x08, 0x54000060); //     b.eq       _ret0
    wk32(shc + 0x0c, 0x58000128); //     ldr        x8, _next
    wk32(shc + 0x10, 0xd61f0100); //     br         x8
                                  //  _ret0: x0 to 0 and jump to ret of original functions.
    wk32(shc + 0x14, 0xd2800000); //     movz       x0, #0x0
    wk32(shc + 0x18, 0x58000088); //     ldr        x8, _equal
    wk32(shc + 0x1c, 0xd61f0100); //     br         x8
    
    wkptr(shc + 0x20, x30_reg);   // _x30_reg
    wkptr(shc + 0x28, equal);     // _equal
    wkptr(shc + 0x30, next);      // _next
}
#endif

static int kpatch9(kaddr_t region, kaddr_t lwvm_type)
{
    init_kernel(region);
    
    /*--- helper ---*/
    kaddr_t ret0_gadget;
    kaddr_t ret1_gadget;
    
    /*--- AMFI patchfinder ---*/
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
    // armv7
    kaddr_t amfi_execve_ret;
    kaddr_t cs_enforcement_disable;
#endif
    
    /*--- LwVM patchfinder ---*/
    // __got
    kaddr_t lwvm_krnl_conf_got;
    
    // jmp
    kaddr_t lwvm_jump;
    
    /*--- Sandbox patchfinder ---*/
    // policy_ops
    kaddr_t sbops;
    
#ifdef __LP64__
    // shellcode
    kaddr_t memset_stub;
    kaddr_t sbBase;
    
    /*-- MAC policy --*/
    kaddr_t proc_check_fork_ret;
    kaddr_t proc_check_fork_lr;
    
    kaddr_t iokit_check_open_ret;
    kaddr_t iokit_check_open_lr;
    
    kaddr_t mount_check_fsctl_ret;
    kaddr_t mount_check_fsctl_lr;
    
    kaddr_t vnode_check_rename_ret;
    kaddr_t vnode_check_rename_lr_1;
    kaddr_t vnode_check_rename_lr_2;
    kaddr_t vnode_check_rename_lr_3;
    kaddr_t vnode_check_rename_lr_4;
    
    kaddr_t vnode_check_access_ret;
    kaddr_t vnode_check_access_lr;
    
    kaddr_t vnode_check_chroot_ret;
    kaddr_t vnode_check_chroot_lr;
    
    kaddr_t vnode_check_create_ret;
    kaddr_t vnode_check_create_lr_1;
    kaddr_t vnode_check_create_lr_2;
    kaddr_t vnode_check_create_lr_3;
    
    kaddr_t vnode_check_deleteextattr_ret;
    kaddr_t vnode_check_deleteextattr_lr;
    
    kaddr_t vnode_check_exchangedata_ret;
    kaddr_t vnode_check_exchangedata_lr_1;
    kaddr_t vnode_check_exchangedata_lr_2;
    
    kaddr_t vnode_check_getattrlist_ret;
    kaddr_t vnode_check_getattrlist_lr;
    
    kaddr_t vnode_check_getextattr_ret;
    kaddr_t vnode_check_getextattr_lr;
    
    kaddr_t vnode_check_ioctl_ret;
    kaddr_t vnode_check_ioctl_lr;
    
    kaddr_t vnode_check_link_ret;
    kaddr_t vnode_check_link_lr_1;
    kaddr_t vnode_check_link_lr_2;
    kaddr_t vnode_check_link_lr_3;
    
    kaddr_t vnode_check_listextattr_ret;
    kaddr_t vnode_check_listextattr_lr;
    
    kaddr_t vnode_check_open_ret;
    kaddr_t vnode_check_open_lr;
    
    kaddr_t vnode_check_readlink_ret;
    kaddr_t vnode_check_readlink_lr;
    
    kaddr_t vnode_check_revoke_ret;
    kaddr_t vnode_check_revoke_lr;
    
    kaddr_t vnode_check_setattrlist_ret;
    kaddr_t vnode_check_setattrlist_lr;
    
    kaddr_t vnode_check_setextattr_ret;
    kaddr_t vnode_check_setextattr_lr;
    
    kaddr_t vnode_check_setflags_ret;
    kaddr_t vnode_check_setflags_lr;
    
    kaddr_t vnode_check_setmode_ret;
    kaddr_t vnode_check_setmode_lr;
    
    kaddr_t vnode_check_setowner_ret;
    kaddr_t vnode_check_setowner_lr;
    
    kaddr_t vnode_check_setutimes_ret;
    kaddr_t vnode_check_setutimes_lr;
    
    kaddr_t vnode_check_stat_ret;
    kaddr_t vnode_check_stat_lr;
    
    kaddr_t vnode_check_truncate_ret;
    kaddr_t vnode_check_truncate_lr;
    
    kaddr_t vnode_check_unlink_ret;
    kaddr_t vnode_check_unlink_lr_1;
    kaddr_t vnode_check_unlink_lr_2;
    
    kaddr_t file_check_mmap_ret;
    kaddr_t file_check_mmap_lr;
#endif
    
    // __got
    kaddr_t sb_PE_i_can_has_debugger_got;
#ifdef __LP64__
    kaddr_t sb_memset_got;
#endif
    kaddr_t sb_vfs_rootvnode_got;
    
    // fn
    kaddr_t vfs_rootvnode_fn;
    kaddr_t rootvnode;
    kaddr_t rootfs_vnode;
    
#ifndef __LP64__
    // legacy
    kaddr_t tfp0_patch;
    kaddr_t vm_fault_enter;
    kaddr_t vm_map_enter;
    kaddr_t vm_map_protect;
    kaddr_t csops;
    kaddr_t pmap_location;
#endif
    
    // MAC
    struct mac_policy_ops mpc_ops;
    memset(&mpc_ops, '\0', sizeof(mpc_ops));
    
    
    DEBUGLog("Searching koffsets..");
    
    {
        DEBUGLog("gadget");
        if(!(ret0_gadget = KOFFSET(region, find_ret0_gadget(region, kdata, ksize)))) goto fail;
        if(!(ret1_gadget = KOFFSET(region, find_ret1_gadget(region, kdata, ksize)))) goto fail;
    }
    
    {
        DEBUGLog("AMFI __got");
        if(!(amfi_PE_i_can_has_debugger_got = KOFFSET(region, find_amfi_PE_i_can_has_debugger_got(region, kdata, ksize)))) goto fail;
        if(!(amfi_cs_enforcement_got = KOFFSET(region, find_amfi_cs_enforcement_got(region, kdata, ksize)))) goto fail;
#ifdef __LP64__
        if(!(amfi_vnode_isreg_got = KOFFSET(region, find_vnode_isreg_in_amfi_execve_hook(region, kdata, ksize)))) goto fail;
#endif
    }
    
#ifdef __LP64__
    {
        DEBUGLog("AMFI shellcode");
        if(!(_amfi_execve_hook = KOFFSET(region, find_amfi_execve_hook(region, kdata, ksize)))) goto fail;
        
        _vnode_isreg = rkptr(amfi_vnode_isreg_got); // 9.3.3: 0xffffff800414e214
        if(!_vnode_isreg) {
            DEBUGLog("[ERROR] Failed to read offset!");
            goto fail;
        }
    }
#endif
    
#ifndef __LP64__
    {
        DEBUGLog("AMFI");
        if(!(amfi_execve_ret = KOFFSET(region, find_amfi_execve_ret(region, kdata, ksize)))) goto fail;
        if(!(cs_enforcement_disable = KOFFSET(region, find_cs_enforcement_disable_amfi(region, kdata, ksize)))) goto fail;
    }
#endif
    
    {
        DEBUGLog("LwVM __got");
        if(lwvm_type == 1){
            // 9.3.2, 9.3.3, 9.3.4, 9.3.5
            if(!(lwvm_krnl_conf_got = KOFFSET(region, find_PE_i_can_has_kernel_configuration_got(region, kdata, ksize)))) goto fail;
        } else {
            // For 9.3.1 and below, find _PE_i_can_has_debugger.stub and bypass isWriteProtected check.
#ifdef __LP64__
            // 9.2-9.3.1
            if(!(lwvm_krnl_conf_got = KOFFSET(region, find_LwVM_PE_i_can_has_debugger_got(region, kdata, ksize)))) goto fail;
#else
            // TODO
            goto fail;
#endif
        }
        if(!(lwvm_jump = KOFFSET(region, find_lwvm_jump(region, kdata, ksize)))) goto fail;
    }
    
    {
        DEBUGLog("Sandbox ops");
        if(!(sbops = KOFFSET(region, find_sandbox_mac_policy_ops(region, kdata, ksize)))) goto fail;
    }

#ifdef __LP64__
    {
        DEBUGLog("_memset.stub");
        if(!(memset_stub = KOFFSET(region, find_memset(region, kdata, ksize)))) goto fail;
    }
#endif
    
    {
        DEBUGLog("MAC");
        mpc_ops.mpo_mount_check_remount         = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_remount));
        mpc_ops.mpo_vnode_check_exec            = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exec));
        mpc_ops.mpo_proc_check_fork             = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_fork));
        mpc_ops.mpo_iokit_check_open            = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_iokit_check_open));
        mpc_ops.mpo_mount_check_fsctl           = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_fsctl));
        mpc_ops.mpo_vnode_check_rename          = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename));
        mpc_ops.mpo_vnode_check_access          = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_access));
        mpc_ops.mpo_vnode_check_chroot          = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_chroot));
        mpc_ops.mpo_vnode_check_create          = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_create));
        mpc_ops.mpo_vnode_check_deleteextattr   = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr));
        mpc_ops.mpo_vnode_check_exchangedata    = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata));
        mpc_ops.mpo_vnode_check_getattrlist     = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist));
        mpc_ops.mpo_vnode_check_getextattr      = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr));
        mpc_ops.mpo_vnode_check_ioctl           = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl));
        mpc_ops.mpo_vnode_check_link            = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_link));
        mpc_ops.mpo_vnode_check_listextattr     = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr));
        mpc_ops.mpo_vnode_check_open            = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_open));
        mpc_ops.mpo_vnode_check_readlink        = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_readlink));
        mpc_ops.mpo_vnode_check_revoke          = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_revoke));
        mpc_ops.mpo_vnode_check_setattrlist     = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist));
        mpc_ops.mpo_vnode_check_setextattr      = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr));
        mpc_ops.mpo_vnode_check_setflags        = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setflags));
        mpc_ops.mpo_vnode_check_setmode         = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setmode));
        mpc_ops.mpo_vnode_check_setowner        = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setowner));
        mpc_ops.mpo_vnode_check_setutimes       = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes));
        mpc_ops.mpo_vnode_check_stat            = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_stat));
        mpc_ops.mpo_vnode_check_truncate        = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_truncate));
        mpc_ops.mpo_vnode_check_unlink          = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_unlink));
        mpc_ops.mpo_file_check_mmap             = rkptr(sbops+offsetof(struct mac_policy_ops, mpo_file_check_mmap));
        
        if(!mpc_ops.mpo_mount_check_remount||
           !mpc_ops.mpo_vnode_check_exec||
           !mpc_ops.mpo_proc_check_fork||
           !mpc_ops.mpo_iokit_check_open||
           !mpc_ops.mpo_mount_check_fsctl||
           !mpc_ops.mpo_vnode_check_rename||
           !mpc_ops.mpo_vnode_check_access||
           !mpc_ops.mpo_vnode_check_chroot||
           !mpc_ops.mpo_vnode_check_create||
           !mpc_ops.mpo_vnode_check_deleteextattr||
           !mpc_ops.mpo_vnode_check_exchangedata||
           !mpc_ops.mpo_vnode_check_getattrlist||
           !mpc_ops.mpo_vnode_check_getextattr||
           !mpc_ops.mpo_vnode_check_ioctl||
           !mpc_ops.mpo_vnode_check_link||
           !mpc_ops.mpo_vnode_check_listextattr||
           !mpc_ops.mpo_vnode_check_open||
           !mpc_ops.mpo_vnode_check_readlink||
           !mpc_ops.mpo_vnode_check_revoke||
           !mpc_ops.mpo_vnode_check_setattrlist||
           !mpc_ops.mpo_vnode_check_setextattr||
           !mpc_ops.mpo_vnode_check_setflags||
           !mpc_ops.mpo_vnode_check_setmode||
           !mpc_ops.mpo_vnode_check_setowner||
           !mpc_ops.mpo_vnode_check_setutimes||
           !mpc_ops.mpo_vnode_check_stat||
           !mpc_ops.mpo_vnode_check_truncate||
           !mpc_ops.mpo_vnode_check_unlink||
           !mpc_ops.mpo_file_check_mmap){
            DEBUGLog("[ERROR] Failed to read sbops!");
            goto fail;
        }
 
#ifdef __LP64__
        // ret/x30 reg
        proc_check_fork_ret             = KOFFSET(region, find_proc_check_fork_ret(region, kdata, ksize, mpc_ops.mpo_proc_check_fork));
        proc_check_fork_lr              = KOFFSET(region, find_proc_check_fork_lr(region, kdata, ksize, mpc_ops.mpo_proc_check_fork));
        
        iokit_check_open_ret            = KOFFSET(region, find_iokit_check_open_ret(region, kdata, ksize, mpc_ops.mpo_iokit_check_open));
        iokit_check_open_lr             = KOFFSET(region, find_iokit_check_open_lr(region, kdata, ksize, mpc_ops.mpo_iokit_check_open));
        
        mount_check_fsctl_ret           = KOFFSET(region, find_mount_check_fsctl_ret(region, kdata, ksize, mpc_ops.mpo_mount_check_fsctl));
        mount_check_fsctl_lr            = KOFFSET(region, find_mount_check_fsctl_lr(region, kdata, ksize, mpc_ops.mpo_mount_check_fsctl));
        
        vnode_check_rename_ret          = KOFFSET(region, find_vnode_check_rename_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_rename));
        vnode_check_rename_lr_1         = KOFFSET(region, find_vnode_check_rename_lr_1(region, kdata, ksize, mpc_ops.mpo_vnode_check_rename));
        vnode_check_rename_lr_2         = KOFFSET(region, find_vnode_check_rename_lr_2(region, kdata, ksize, mpc_ops.mpo_vnode_check_rename));
        vnode_check_rename_lr_3         = KOFFSET(region, find_vnode_check_rename_lr_3(region, kdata, ksize, mpc_ops.mpo_vnode_check_rename));
        vnode_check_rename_lr_4         = KOFFSET(region, find_vnode_check_rename_lr_4(region, kdata, ksize, mpc_ops.mpo_vnode_check_rename));
        
        vnode_check_access_ret          = KOFFSET(region, find_vnode_check_access_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_access));
        vnode_check_access_lr           = KOFFSET(region, find_vnode_check_access_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_access));
        
        vnode_check_chroot_ret          = KOFFSET(region, find_vnode_check_chroot_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_chroot));
        vnode_check_chroot_lr           = KOFFSET(region, find_vnode_check_chroot_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_chroot));
        
        vnode_check_create_ret          = KOFFSET(region, find_vnode_check_create_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_create));
        vnode_check_create_lr_1         = KOFFSET(region, find_vnode_check_create_lr_1(region, kdata, ksize, mpc_ops.mpo_vnode_check_create));
        vnode_check_create_lr_2         = KOFFSET(region, find_vnode_check_create_lr_2(region, kdata, ksize, mpc_ops.mpo_vnode_check_create));
        vnode_check_create_lr_3         = KOFFSET(region, find_vnode_check_create_lr_3(region, kdata, ksize, mpc_ops.mpo_vnode_check_create));
        
        vnode_check_deleteextattr_ret   = KOFFSET(region, find_vnode_check_deleteextattr_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_deleteextattr));
        vnode_check_deleteextattr_lr    = KOFFSET(region, find_vnode_check_deleteextattr_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_deleteextattr));
        
        vnode_check_exchangedata_ret    = KOFFSET(region, find_vnode_check_exchangedata_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_exchangedata));
        vnode_check_exchangedata_lr_1   = KOFFSET(region, find_vnode_check_exchangedata_lr_1(region, kdata, ksize, mpc_ops.mpo_vnode_check_exchangedata));
        vnode_check_exchangedata_lr_2   = KOFFSET(region, find_vnode_check_exchangedata_lr_2(region, kdata, ksize, mpc_ops.mpo_vnode_check_exchangedata));
        
        vnode_check_getattrlist_ret     = KOFFSET(region, find_vnode_check_getattrlist_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_getattrlist));
        vnode_check_getattrlist_lr      = KOFFSET(region, find_vnode_check_getattrlist_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_getattrlist));
        
        vnode_check_getextattr_ret      = KOFFSET(region, find_vnode_check_getextattr_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_getextattr));
        vnode_check_getextattr_lr       = KOFFSET(region, find_vnode_check_getextattr_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_getextattr));
        
        vnode_check_ioctl_ret           = KOFFSET(region, find_vnode_check_ioctl_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_ioctl));
        vnode_check_ioctl_lr            = KOFFSET(region, find_vnode_check_ioctl_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_ioctl));
        
        vnode_check_link_ret            = KOFFSET(region, find_vnode_check_link_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_link));
        vnode_check_link_lr_1           = KOFFSET(region, find_vnode_check_link_lr_1(region, kdata, ksize, mpc_ops.mpo_vnode_check_link));
        vnode_check_link_lr_2           = KOFFSET(region, find_vnode_check_link_lr_2(region, kdata, ksize, mpc_ops.mpo_vnode_check_link));
        vnode_check_link_lr_3           = KOFFSET(region, find_vnode_check_link_lr_3(region, kdata, ksize, mpc_ops.mpo_vnode_check_link));
        
        vnode_check_listextattr_ret     = KOFFSET(region, find_vnode_check_listextattr_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_listextattr));
        vnode_check_listextattr_lr      = KOFFSET(region, find_vnode_check_listextattr_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_listextattr));
        
        vnode_check_open_ret            = KOFFSET(region, find_vnode_check_open_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_open));
        vnode_check_open_lr             = KOFFSET(region, find_vnode_check_open_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_open));
        
        vnode_check_readlink_ret        = KOFFSET(region, find_vnode_check_readlink_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_readlink));
        vnode_check_readlink_lr         = KOFFSET(region, find_vnode_check_readlink_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_readlink));
        
        vnode_check_revoke_ret          = KOFFSET(region, find_vnode_check_revoke_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_revoke));
        vnode_check_revoke_lr           = KOFFSET(region, find_vnode_check_revoke_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_revoke));
        
        vnode_check_setattrlist_ret     = KOFFSET(region, find_vnode_check_setattrlist_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_setattrlist));
        vnode_check_setattrlist_lr      = KOFFSET(region, find_vnode_check_setattrlist_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_setattrlist));
        
        vnode_check_setextattr_ret      = KOFFSET(region, find_vnode_check_setextattr_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_setextattr));
        vnode_check_setextattr_lr       = KOFFSET(region, find_vnode_check_setextattr_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_setextattr));
        
        vnode_check_setflags_ret        = KOFFSET(region, find_vnode_check_setflags_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_setflags));
        vnode_check_setflags_lr         = KOFFSET(region, find_vnode_check_setflags_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_setflags));
        
        vnode_check_setmode_ret         = KOFFSET(region, find_vnode_check_setmode_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_setmode));
        vnode_check_setmode_lr          = KOFFSET(region, find_vnode_check_setmode_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_setmode));
        
        vnode_check_setowner_ret        = KOFFSET(region, find_vnode_check_setowner_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_setowner));
        vnode_check_setowner_lr         = KOFFSET(region, find_vnode_check_setowner_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_setowner));
        
        vnode_check_setutimes_ret       = KOFFSET(region, find_vnode_check_setutimes_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_setutimes));
        vnode_check_setutimes_lr        = KOFFSET(region, find_vnode_check_setutimes_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_setutimes));
        
        vnode_check_stat_ret            = KOFFSET(region, find_vnode_check_stat_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_stat));
        vnode_check_stat_lr             = KOFFSET(region, find_vnode_check_stat_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_stat));
        
        vnode_check_truncate_ret        = KOFFSET(region, find_vnode_check_truncate_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_truncate));
        vnode_check_truncate_lr         = KOFFSET(region, find_vnode_check_truncate_lr(region, kdata, ksize, mpc_ops.mpo_vnode_check_truncate));
        
        vnode_check_unlink_ret          = KOFFSET(region, find_vnode_check_unlink_ret(region, kdata, ksize, mpc_ops.mpo_vnode_check_unlink));
        vnode_check_unlink_lr_1         = KOFFSET(region, find_vnode_check_unlink_lr_1(region, kdata, ksize, mpc_ops.mpo_vnode_check_unlink));
        vnode_check_unlink_lr_2         = KOFFSET(region, find_vnode_check_unlink_lr_2(region, kdata, ksize, mpc_ops.mpo_vnode_check_unlink));

        file_check_mmap_ret             = KOFFSET(region, find_file_check_mmap_ret(region, kdata, ksize, mpc_ops.mpo_file_check_mmap));
        file_check_mmap_lr              = KOFFSET(region, find_file_check_mmap_lr(region, kdata, ksize, mpc_ops.mpo_file_check_mmap));
        
        if(!proc_check_fork_ret||
           !proc_check_fork_lr||
           !iokit_check_open_ret||
           !iokit_check_open_lr||
           !mount_check_fsctl_ret||
           !mount_check_fsctl_lr||
           !vnode_check_rename_ret||
           !vnode_check_rename_lr_1||
           !vnode_check_rename_lr_2||
           !vnode_check_rename_lr_3||
           !vnode_check_rename_lr_4||
           !vnode_check_access_ret||
           !vnode_check_access_lr||
           !vnode_check_chroot_ret||
           !vnode_check_chroot_lr||
           !vnode_check_create_ret||
           !vnode_check_create_lr_1||
           !vnode_check_create_lr_2||
           !vnode_check_create_lr_3||
           !vnode_check_deleteextattr_ret||
           !vnode_check_deleteextattr_lr||
           !vnode_check_exchangedata_ret||
           !vnode_check_exchangedata_lr_1||
           !vnode_check_exchangedata_lr_2||
           !vnode_check_getattrlist_ret||
           !vnode_check_getattrlist_lr||
           !vnode_check_getextattr_ret||
           !vnode_check_getextattr_lr||
           !vnode_check_ioctl_ret||
           !vnode_check_ioctl_lr||
           !vnode_check_link_ret||
           !vnode_check_link_lr_1||
           !vnode_check_link_lr_2||
           !vnode_check_link_lr_3||
           !vnode_check_listextattr_ret||
           !vnode_check_listextattr_lr||
           !vnode_check_open_ret||
           !vnode_check_open_lr||
           !vnode_check_readlink_ret||
           !vnode_check_readlink_lr||
           !vnode_check_revoke_ret||
           !vnode_check_revoke_lr||
           !vnode_check_setattrlist_ret||
           !vnode_check_setattrlist_lr||
           !vnode_check_setextattr_ret||
           !vnode_check_setextattr_lr||
           !vnode_check_setflags_ret||
           !vnode_check_setflags_lr||
           !vnode_check_setmode_ret||
           !vnode_check_setmode_lr||
           !vnode_check_setowner_ret||
           !vnode_check_setowner_lr||
           !vnode_check_setutimes_ret||
           !vnode_check_setutimes_lr||
           !vnode_check_stat_ret||
           !vnode_check_stat_lr||
           !vnode_check_truncate_ret||
           !vnode_check_truncate_lr||
           !vnode_check_unlink_ret||
           !vnode_check_unlink_lr_1||
           !vnode_check_unlink_lr_2||
           !file_check_mmap_ret||
           !file_check_mmap_lr){
            DEBUGLog("[ERROR] Failed to search ret/lr!");
            goto fail;
        }
#endif
        
    }
    
    {
        DEBUGLog("Sandbox __got");
        if(!(sb_PE_i_can_has_debugger_got = KOFFSET(region, find_sb_PE_i_can_has_debugger_got(region, kdata, ksize, mpc_ops.mpo_vnode_check_exec)))) goto fail;
#ifdef __LP64__
        if(!(sb_memset_got = KOFFSET(region, find_sb_memset_got(region, kdata, ksize, mpc_ops.mpo_proc_check_fork)))) goto fail;
#endif
        // remount stuff
        if(!(sb_vfs_rootvnode_got = KOFFSET(region, find_sb_vfs_rootvnode_got(region, kdata, ksize, mpc_ops.mpo_mount_check_remount)))) goto fail;
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
            last_section = 0;
        } else {
            last_section += 0x100;
            last_section = (last_section & ~0xFF);
        }
        printf("__TEXT last: %016llx\n", (uint64_t)last_section);
        
    } else {
        printf("wtf!?\n");
        last_section = 0;
    }
#endif
    
    DEBUGLog("patching kernel");
    
#ifdef __LP64__
    /*--- shellcode ---*/
    kaddr_t shellcode = 0;
    kaddr_t ptr = 0;
    mach_vm_allocate(tfp0, (mach_vm_address_t*)&shellcode, 0x1000, VM_FLAGS_ANYWHERE); // r-x region
    mach_vm_allocate(tfp0, (mach_vm_address_t*)&ptr, 0x1000, VM_FLAGS_ANYWHERE); // rw- region
    DEBUGLog("[*] shellcode: %llx", shellcode);
    DEBUGLog("[*] ptr: %llx", ptr);
    
    {
        printLog("[AMFI] shellcode");
        // amfi
        amfiBase = shellcode + 0x200;
        wk32(shellcode + 0x200, 0x580003c8); // ldr        x8, _amfi_execve_hook
        wk32(shellcode + 0x204, 0xeb0803df); // cmp        x30, x8
        wk32(shellcode + 0x208, 0x54000060); // b.eq       _shellcode+0x214
        wk32(shellcode + 0x20c, 0x580003a8); // ldr        x8, _vnode_isreg
        wk32(shellcode + 0x210, 0xd61f0100); // br         x8
        
        wk32(shellcode + 0x214, 0xf9400fb0); // ldr        x16, [x29, #0x18]
        wk32(shellcode + 0x218, 0xb9400208); // ldr        w8, [x16]
        wk32(shellcode + 0x21c, 0x32060108); // orr        w8, w8, #0x4000000
        wk32(shellcode + 0x220, 0x321e0108); // orr        w8, w8, #0x4
        wk32(shellcode + 0x224, 0x321d0108); // orr        w8, w8, #0x8
        wk32(shellcode + 0x228, 0x12146d08); // and        w8, w8, #0xfffffffffffff0ff
        wk32(shellcode + 0x22c, 0xb9000208); // str        w8, [x16]
        wk32(shellcode + 0x230, 0xf94007a8); // ldr        x8, [x29, #0x8]
        wk32(shellcode + 0x234, 0x580002b0); // ldr        x16, ptr
        wk32(shellcode + 0x238, 0xf9000208); // str        x8, [x16]
        wk32(shellcode + 0x23c, 0x10000088); // adr        x8, #0x24c
        wk32(shellcode + 0x240, 0xf90007a8); // str        x8, [x29, #0x8]
        wk32(shellcode + 0x244, 0x580001e8); // ldr        x8, _vnode_isreg
        wk32(shellcode + 0x248, 0xd61f0100); // br         x8
        
        wk32(shellcode + 0x24c, 0xf94007f0); // ldr        x16, [sp, #0x8]
        wk32(shellcode + 0x250, 0xb9400208); // ldr        w8, [x16]
        wk32(shellcode + 0x254, 0x32060108); // orr        w8, w8, #0x4000000
        wk32(shellcode + 0x258, 0x321e0108); // orr        w8, w8, #0x4
        wk32(shellcode + 0x25c, 0x321d0108); // orr        w8, w8, #0x8
        wk32(shellcode + 0x260, 0x12146d08); // and        w8, w8, #0xfffffffffffff0ff
        wk32(shellcode + 0x264, 0xb9000208); // str        w8, [x16]
        wk32(shellcode + 0x268, 0x58000110); // ldr        x16, ptr
        wk32(shellcode + 0x26c, 0xf9400210); // ldr        x16, [x16]
        wk32(shellcode + 0x270, 0xd2800000); // movz       x0, #0x0
        wk32(shellcode + 0x274, 0xd61f0200); // br         x16
        
        wkptr(shellcode + 0x278, _amfi_execve_hook);
        wkptr(shellcode + 0x280, _vnode_isreg);
        wkptr(shellcode + 0x288, ptr);
    }
    
    {
        printLog("[Sandbox] shellcode");
        // sandbox
        kaddr_t shc = 0;
        kaddr_t next = 0;
        
        shc = shellcode + 0x2a0;
        sbWriteCode(shc, proc_check_fork_lr, proc_check_fork_ret, memset_stub); next = shc; shc += 0x40;
        sbWriteCode(shc, iokit_check_open_lr, iokit_check_open_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, mount_check_fsctl_lr, mount_check_fsctl_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_rename_lr_1, vnode_check_rename_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_rename_lr_2, vnode_check_rename_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_rename_lr_3, vnode_check_rename_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_rename_lr_4, vnode_check_rename_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_access_lr, vnode_check_access_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_chroot_lr, vnode_check_chroot_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_create_lr_1, vnode_check_create_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_create_lr_2, vnode_check_create_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_create_lr_3, vnode_check_create_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_deleteextattr_lr, vnode_check_deleteextattr_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_exchangedata_lr_1, vnode_check_exchangedata_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_exchangedata_lr_2, vnode_check_exchangedata_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_getattrlist_lr, vnode_check_getattrlist_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_getextattr_lr, vnode_check_getextattr_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_ioctl_lr, vnode_check_ioctl_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_link_lr_1, vnode_check_link_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_link_lr_2, vnode_check_link_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_link_lr_3, vnode_check_link_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_listextattr_lr, vnode_check_listextattr_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_open_lr, vnode_check_open_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_readlink_lr, vnode_check_readlink_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_revoke_lr, vnode_check_revoke_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_setattrlist_lr, vnode_check_setattrlist_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_setextattr_lr, vnode_check_setextattr_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_setflags_lr, vnode_check_setflags_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_setmode_lr, vnode_check_setmode_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_setowner_lr, vnode_check_setowner_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_setutimes_lr, vnode_check_setutimes_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_stat_lr, vnode_check_stat_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_truncate_lr, vnode_check_truncate_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_unlink_lr_1, vnode_check_unlink_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, vnode_check_unlink_lr_2, vnode_check_unlink_ret, next); next = shc; shc += 0x40;
        sbWriteCode(shc, file_check_mmap_lr, file_check_mmap_ret, next);
        
        mach_vm_protect(tfp0, shellcode, 0x1000, 0x0, VM_PROT_READ|VM_PROT_EXECUTE);
        mach_vm_protect(tfp0, ptr, 0x1000, 0x0, VM_PROT_READ|VM_PROT_WRITE);
        
        sbBase = shc;
    }
#else
    {   // armv7
        // amfi_execve_hook: makes sure amfi doesn't try to kill our binaries
        // make writable that free space on __TEXT
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
    
    // __got hook
    printLog("[*] Hooking __DATA.__got");
    {
        // LwVM
        printLog("[LwVM] _PE_i_can_has_kernel_configuration: isWriteProtected check bypass");
        wkptr(lwvm_krnl_conf_got, lwvm_jump);
        
        // AMFI
        printLog("[AMFI] _PE_i_can_has_debugger: ret1 gadget");
        wkptr(amfi_PE_i_can_has_debugger_got, ret1_gadget);
        printLog("[AMFI] _cs_enforcement: ret0 gadget");
        wkptr(amfi_cs_enforcement_got, ret0_gadget);
        
#ifdef __LP64__
        printLog("[AMFI] _vnode_isreg: shellcode");
        wkptr(amfi_vnode_isreg_got, amfiBase);
#else
        printLog("[AMFI] execve_hook (__TEXT patch)");
        patch_page_table(tte_virt, tte_phys, (amfi_execve_ret & ~0xFFF));
        uint32_t unbase_addr = amfi_execve_ret - region;
        uint32_t unbase_shc = last_section - region;
        uint32_t val = make_b_w(unbase_addr, unbase_shc);
        wk32(amfi_execve_ret, val); // b.w shellcode
#endif
        
        // Sandbox
        printLog("[Sandbox] _PE_i_can_has_debugger: ret1 gadget");
        wkptr(sb_PE_i_can_has_debugger_got, ret1_gadget);
        
#ifdef __LP64__
        printLog("[Sandbox] _memset: shellcode");
        wkptr(sb_memset_got, sbBase);
#else
        {
            printLog("[Sandbox] MAC policies");
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
        wk8(cs_enforcement_disable, 1);
    }
    printLog("[*] DONE");
#endif
    
    sleep(1);
    
    {
        // remount
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
        printf("[*] remounting: %d\n", rv);
        
        v_mount = rkptr(rootfs_vnode + v_mount_off);
        wk32(v_mount + v_flag_off, v_flag);
    }
    
    printLog("[*] patched!");
    
    return 0;
    
fail:
    printLog("[ERROR] Failed to search koffset!");
    return -1;
}

int unjail9(mach_port_t pt, kaddr_t region, int lwvm_type, int kpp)
{
    int ret=0;
    
    tfp0 = pt;
    
    //if(kpp == 1){
    //    ret = kpp9(region, lwvm_type);
    //
    //    char *nmz = strdup("/dev/disk0s1s1");
    //    int rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz); // remount?
    //    printLog("remounting: %d", rv);
    //
    //} else {
    ret = kpatch9(region, lwvm_type);
    //    // already remounted
    //}
    
    return ret;
}
