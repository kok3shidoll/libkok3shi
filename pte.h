/*
 *  pte.h
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

#ifndef pte_h
#define pte_h

#include "common.h"

#ifdef __LP64__
// aarch64
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

void checkvad(void);
uint64_t physalloc(uint64_t size);
uint64_t pagetable_lookup(uint64_t vaddr, uint64_t ttbr, bool retval);
uint64_t fakepage_lookup(uint64_t addr, uint64_t ttbr1_el1_fake, bool xn);

#else
// aarch32
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

void patch_page_table(uint32_t tte_virt, uint32_t tte_phys, uint32_t page);
unsigned int make_b_w(int pos, int tgt);

#endif

#endif /* pte_h */
