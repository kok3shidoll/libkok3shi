//
//  patchfinder64.h
//  kokeshidoll
//
//  Created by dora on 2021/12/02.
//  Copyright (c) 2016 -2017 FriedApple Team. All rights reserved.
//  Copyright (c) 2021 sakuRdev. All rights reserved.
//

#ifndef patchfinder64_h
#define patchfinder64_h

#ifdef __LP64__

#include <stdint.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach/vm_map.h>

// helper
uint64_t find_all_proc(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_ret0_gadget(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_ret1_gadget(uint64_t region, uint8_t* kdata, size_t ksize);

// LvWM
uint64_t find_LwVM_PE_i_can_has_debugger_got(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_PE_i_can_has_kernel_configuration_got(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_lwvm_jump(uint64_t region, uint8_t* kdata, size_t ksize);

// AMFI
uint64_t find_vnode_isreg_in_amfi_execve_hook(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_amfi_cs_enforcement_got(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_amfi_PE_i_can_has_debugger_got(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_amfi_execve_hook(uint64_t region, uint8_t* kdata, size_t ksize);

// Sandbox
uint64_t find_memset(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_GOT_address_with_bl_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t *insn);
uint64_t find_sb_memset_got(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_sb_PE_i_can_has_debugger_got(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_sb_vfs_rootvnode_got(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_rootvnode_offset(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t fn);

uint64_t find_sandbox_mac_policy_ops(uint64_t region, uint8_t* kdata, size_t ksize);

uint64_t find_file_check_mmap_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_file_check_mmap_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_unlink_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_unlink_lr_1(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_unlink_lr_2(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_truncate_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_truncate_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_stat_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_stat_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_setutimes_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_setutimes_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_setowner_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_setowner_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_setmode_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_setmode_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_setflags_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_setflags_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_setextattr_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_setextattr_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_setattrlist_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_setattrlist_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_revoke_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_revoke_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_readlink_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_readlink_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_open_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_open_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_listextattr_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_listextattr_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_link_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_link_lr_1(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_link_lr_2(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_link_lr_3(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_ioctl_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_ioctl_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_getextattr_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_getextattr_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_getattrlist_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_getattrlist_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_exchangedata_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_exchangedata_lr_1(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_exchangedata_lr_2(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_deleteextattr_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_deleteextattr_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_create_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_create_lr_1(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_create_lr_2(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_create_lr_3(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_chroot_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_chroot_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_access_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_access_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_vnode_check_rename_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_rename_lr_1(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_rename_lr_2(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_rename_lr_3(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_vnode_check_rename_lr_4(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_mount_check_fsctl_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_mount_check_fsctl_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_iokit_check_open_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_iokit_check_open_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

uint64_t find_proc_check_fork_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);
uint64_t find_proc_check_fork_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb);

// KPP
uint64_t find_cpacr_el1(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_pmap_location(uint64_t region, uint8_t *kdata, size_t ksize);
uint64_t find_ttbr1_el1(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_gPhysAddr(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_gVirtAddr(uint64_t region, uint8_t* kdata, size_t ksize);

uint64_t find_debug_enabled(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_amfi_allow_any_signature(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_ml_get_wake_timebase(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_mac_mount_patch(uint64_t region, uint8_t* kdata, size_t ksize);
uint64_t find_amfi_ret(uint64_t region, uint8_t* kdata, size_t ksize);

// tfp0
uint64_t find_task_for_pid(uint64_t region, uint8_t* kdata, size_t ksize);

// xerub's patchfinder
uint64_t search_handler(uint64_t reg, uint32_t opcode);
uint64_t find_register_value(uint8_t* kernel, uint64_t where, int reg);

#endif

#endif /* patchfinder64_h */
