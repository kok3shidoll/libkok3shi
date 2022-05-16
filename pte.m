/*
 *  pte.m
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

#include <mach/mach.h>
#include <sys/utsname.h>

#include "common.h"
#include "kernel.h"
#include "pte.h"

extern void (*printLog)(const char *text, ...);
extern uint64_t slide;
extern uint64_t gPhysBase;
extern uint64_t gVirtBase;
extern uint64_t level1_table;
extern uint64_t ttbr1_el1;

extern mach_port_t tfp0;

#ifdef __LP64__
// aarch64
static char pagebuf[0x4000];

char isvad = 0;
vm_size_t sz = 0;

void checkvad(void)
{
    if (!sz) {
        struct utsname u = { 0 };
        uname(&u);
        host_page_size(mach_host_self(), &sz);
        printLog("checkvad: %lx %x", sz, getpagesize());
        if (strstr(u.machine, "iPad5,") == u.machine) {
            sz = 4096; // this is 4k but host_page_size lies to us
        }
        assert(sz);
        if (sz == 4096) {
            isvad = 1;
        }
    }
}

/*-- Remapping utils for KPP bypass --*/

// allocate for the size
uint64_t physalloc(uint64_t size)
{
    uint64_t ret = 0;
    mach_vm_allocate(tfp0, (mach_vm_address_t*) &ret, size, VM_FLAGS_ANYWHERE);
    return ret;
}

// look up the pagetable for vaddr.
// retval == RETVAL_PHYS: return PA
// retval == RETVAL_VIRT: return VA.
uint64_t pagetable_lookup(uint64_t vaddr, uint64_t ttbr, bool retval)
{
    const uint64_t pg_bits = isvad == 0 ? 14:12;
    const uint64_t l1_size = isvad == 0 ? 11:9;
    const uint64_t l2_size = isvad == 0 ? 11:9;
    const uint64_t l3_size = isvad == 0 ? 11:9;
    
    const uint64_t tte_physaddr_mask = ((1uLL << 40) - 1) & ~((1 << pg_bits) - 1);
    //DEBUGLog("vaddr: %llx", vaddr);
    
    uint64_t l1_table = ttbr;
    uint64_t l1_index = (vaddr >> (l2_size + l3_size + pg_bits)) & ((1 << l1_size) - 1);
    uint64_t l2_index = (vaddr >> (l3_size + pg_bits)) & ((1 << l2_size) - 1);
    uint64_t l3_index = (vaddr >> pg_bits) & ((1 << l3_size) - 1);
    uint64_t pg_offset = vaddr & ((1 << pg_bits) - 1);
    uint64_t p_l1_tte = l1_table + 8 * l1_index;
    //DEBUGLog("p_l1_tte: %llx", p_l1_tte);
    
    uint64_t l1_tte = rk64(p_l1_tte - gPhysBase + gVirtBase);
    //DEBUGLog("l1_tte: %llx", l1_tte);
    
    uint64_t l2_table = l1_tte & tte_physaddr_mask;
    uint64_t p_l2_tte = l2_table + 8 * l2_index;
    //DEBUGLog("l2_table: %llx", l2_table);
    //DEBUGLog("p_l2_tte: %llx", p_l2_tte);
    
    uint64_t l2_tte = rk64(p_l2_tte - gPhysBase + gVirtBase);
    //DEBUGLog("l2_tte: %llx", l2_tte);
    
    uint64_t l3_table = l2_tte & tte_physaddr_mask;
    uint64_t p_l3_tte = l3_table + 8 * l3_index;
    //DEBUGLog("l3_table: %llx", l3_table);
    //DEBUGLog("p_l3_tte: %llx", p_l3_tte);
    
    uint64_t l3_tte = rk64(p_l3_tte - gPhysBase + gVirtBase);
    //DEBUGLog("l3_tte: %llx", l3_tte);
    
    uint64_t frame = l3_tte & tte_physaddr_mask;
    
    uint64_t phys = (frame | pg_offset);
    if(retval == RETVAL_PHYS) return phys;
    
    uint64_t virt = phys - gPhysBase + gVirtBase;
    
    return virt;
}

// search the fake page table and find the remapped addr.
// if fakepage with addr has not yet been existed, make it.
uint64_t fakepage_lookup(uint64_t addr, uint64_t ttbr1_el1_fake, bool xn)
{
    int bk=0;
    
    const uint64_t pg_bits = isvad == 0 ? 14:12;
    const uint64_t l1_size = isvad == 0 ? 11:9;
    const uint64_t l2_size = isvad == 0 ? 11:9;
    const uint64_t l3_size = isvad == 0 ? 11:9;
    
    const uint64_t tte_physaddr_mask = ((1uLL << 40) - 1) & ~((1 << pg_bits) - 1);
    
    uint64_t vaddr = addr & ~ (isvad == 0 ? 0x3fff:0xfff);
    uint64_t vmask = addr & (isvad == 0 ? 0x3fff:0xfff);
    
    uint64_t l1_index = (vaddr >> (l2_size + l3_size + pg_bits)) & ((1 << l1_size) - 1);
    uint64_t l2_index = (vaddr >> (l3_size + pg_bits)) & ((1 << l2_size) - 1);
    uint64_t l3_index = (vaddr >> pg_bits) & ((1 << l3_size) - 1);
    __unused uint64_t pg_offset = vaddr & ((1 << pg_bits) - 1);
    //DEBUGLog("Page: %llx", vaddr);
    
    /*-- original pagetable --*/
    //DEBUGLog("Original Page Table");
    __unused uint64_t level1_table_orig = ttbr1_el1 - gPhysBase + gVirtBase;
    
    uint64_t L1_PA_orig = ((rk64((ttbr1_el1 + 8 * l1_index) - gPhysBase + gVirtBase)) & tte_physaddr_mask);
    uint64_t L2_PA_orig = ((rk64((L1_PA_orig + 8 * l2_index) - gPhysBase + gVirtBase)) & tte_physaddr_mask);
    uint64_t L3_PA_orig = ((rk64((L2_PA_orig + 8 * l3_index) - gPhysBase + gVirtBase)) & tte_physaddr_mask);
    
    //DEBUGLog("level1_table: %llx", level1_table_orig);
    //DEBUGLog("level1 phys: %llx", L1_PA_orig);
    //DEBUGLog("level2 phys: %llx", L2_PA_orig);
    //DEBUGLog("level3 phys: %llx", L3_PA_orig);
    /*---- end ----*/
    
    /*-- setting for fakepage --*/
    uint64_t level1_table_fake = (ttbr1_el1_fake + 8 * l1_index) - gPhysBase + gVirtBase;
    uint64_t level1_entry = rk64(level1_table_fake);
    uint64_t L1_PA = (level1_entry & tte_physaddr_mask);
    
    uint64_t level2_base = L1_PA - gPhysBase + gVirtBase;
    
    if(L1_PA == L1_PA_orig){
        /*-- Remap for fakeL1 --*/
        bzero(pagebuf, isvad == 0 ? 0x4000 : 0x1000);
        uint64_t level1_pte = physalloc(isvad == 0 ? 0x4000 : 0x1000); // Create New L2 table
        copyin(pagebuf, level2_base, isvad == 0 ? 0x4000 : 0x1000);
        copyout(level1_pte, pagebuf, isvad == 0 ? 0x4000 : 0x1000);
        uint64_t level1_pte_phys = pagetable_lookup(level1_pte, ttbr1_el1_fake, RETVAL_PHYS);
        TTE_SET(level1_entry, TTE_PHYS_VALUE_MASK, level1_pte_phys);
        TTE_SET(level1_entry, TTE_BLOCK_ATTR_UXN_MASK, 0);
        TTE_SET(level1_entry, TTE_BLOCK_ATTR_PXN_MASK, 0);
        //DEBUGLog("level1_entry: %llx", level1_entry);
        wk64(level1_table_fake, level1_entry);
        
        L1_PA = (level1_entry & tte_physaddr_mask);
        level2_base = L1_PA - gPhysBase + gVirtBase;
    }
    
    uint64_t level2_table = (L1_PA + 8 * l2_index) - gPhysBase + gVirtBase;
    uint64_t level2_entry = rk64(level2_table);
    
    if((level2_entry & 0x3) != 0x3){
        uint64_t fakep = physalloc(isvad == 0 ? 0x4000 : 0x1000);
        uint64_t realp = TTE_GET(level2_entry, TTE_PHYS_VALUE_MASK);
        TTE_SETB(level2_entry, TTE_IS_TABLE_MASK);
        for (int i = 0; i < (isvad == 0 ? 0x4000 : 0x1000/8); i++) {
            TTE_SET(level2_entry, TTE_PHYS_VALUE_MASK, realp + i * isvad == 0 ? 0x4000 : 0x1000);
            wk64(fakep+i*8, level2_entry);
        }
        TTE_SET(level2_entry, TTE_PHYS_VALUE_MASK, pagetable_lookup(fakep, ttbr1_el1_fake, RETVAL_PHYS));
        wk64(level2_table, level2_entry);
        bk = 1;
    }
    
    
    uint64_t L2_PA = (level2_entry & tte_physaddr_mask);
    
    uint64_t level3_base = L2_PA - gPhysBase + gVirtBase;
    
    if(bk == 1 || L2_PA == L2_PA_orig){
        /*-- Remap for fakeL2 --*/
        bzero(pagebuf, isvad == 0 ? 0x4000 : 0x1000);
        uint64_t level2_pte = physalloc(isvad == 0 ? 0x4000 : 0x1000);
        copyin(pagebuf, level3_base, isvad == 0 ? 0x4000 : 0x1000);
        copyout(level2_pte, pagebuf, isvad == 0 ? 0x4000 : 0x1000);
        uint64_t level2_pte_phys = pagetable_lookup(level2_pte, ttbr1_el1_fake, RETVAL_PHYS);
        TTE_SET(level2_entry, TTE_PHYS_VALUE_MASK, level2_pte_phys);
        TTE_SET(level2_entry, TTE_BLOCK_ATTR_UXN_MASK, 0);
        TTE_SET(level2_entry, TTE_BLOCK_ATTR_PXN_MASK, 0);
        //DEBUGLog("level2_entry: %llx", level2_entry);
        wk64(level2_table, level2_entry);
        
        L2_PA = (level2_entry & tte_physaddr_mask);
        level3_base = L2_PA - gPhysBase + gVirtBase;
    }
    
    uint64_t level3_table = (L2_PA + 8 * l3_index) - gPhysBase + gVirtBase;
    uint64_t level3_entry = rk64(level3_table);
    
    if((level3_entry & 0x3) != 0x3){
        uint64_t fakep = physalloc(isvad == 0 ? 0x4000 : 0x1000);
        uint64_t realp = TTE_GET(level3_entry, TTE_PHYS_VALUE_MASK);
        TTE_SETB(level3_entry, TTE_IS_TABLE_MASK);
        for (int i = 0; i < (isvad == 0 ? 0x4000 : 0x1000/8); i++) {
            TTE_SET(level3_entry, TTE_PHYS_VALUE_MASK, realp + i * isvad == 0 ? 0x4000 : 0x1000);
            wk64(fakep+i*8, level3_entry);
        }
        TTE_SET(level3_entry, TTE_PHYS_VALUE_MASK, pagetable_lookup(fakep, ttbr1_el1_fake, RETVAL_PHYS));
        wk64(level3_table, level3_entry);
        bk = 1;
    }
    
    uint64_t L3_PA = (level3_entry & tte_physaddr_mask);
    
    uint64_t page_base = L3_PA - gPhysBase + gVirtBase;
    
    if(bk == 1 || L3_PA == L3_PA_orig){
        /*-- Remap for fakeL3 --*/
        bzero(pagebuf, isvad == 0 ? 0x4000 : 0x1000);
        uint64_t level3_pte = physalloc(isvad == 0 ? 0x4000 : 0x1000);
        copyin(pagebuf, page_base, isvad == 0 ? 0x4000 : 0x1000);
        copyout(level3_pte, pagebuf, isvad == 0 ? 0x4000 : 0x1000);
        uint64_t fakePage = pagetable_lookup(level3_pte, ttbr1_el1_fake, RETVAL_PHYS);
        TTE_SET(level3_entry, TTE_PHYS_VALUE_MASK, fakePage);
        if (xn == true) {
            TTE_SET(level3_entry, TTE_BLOCK_ATTR_UXN_MASK, 0);
            TTE_SET(level3_entry, TTE_BLOCK_ATTR_PXN_MASK, 0);
        }
        //DEBUGLog("level3_entry: %llx", level3_entry);
        wk64(level3_table, level3_entry);
        
        L3_PA = (level3_entry & tte_physaddr_mask);
        page_base = L3_PA - gPhysBase + gVirtBase;
    }
    
    printLog("New_VA: %llx -> %llx", addr, page_base+vmask);
    return page_base+vmask;
}

#else
// aarch32
void patch_page_table(uint32_t tte_virt, uint32_t tte_phys, uint32_t page)
{
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

unsigned int make_b_w(int pos, int tgt)
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
