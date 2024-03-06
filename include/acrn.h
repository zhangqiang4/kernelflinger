/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __ACRN_H__
#define __ACRN_H__

#include "multiboot.h"

struct efi_memmap_info {
        UINTN map_size;
        UINTN map_key;
        UINT32 desc_version;
        UINTN desc_size;
        EFI_MEMORY_DESCRIPTOR *mmap;
};

/*
 * We allocate memory for the following struct together with hyperivosr itself
 * memory allocation during boot.
 */
#define MBOOT_MMAP_NUMS        256
#define MBOOT_MMAP_SIZE (sizeof(struct multiboot_mmap) * MBOOT_MMAP_NUMS)
#define MBOOT_INFO_SIZE (sizeof(struct multiboot_info))
#define MBOOT_MODS_NUMS        4
#define MBOOT_MODS_SIZE (sizeof(struct multiboot_module) * MBOOT_MODS_NUMS)
#define BOOT_LOADER_NAME "kernelflinger"
#define BOOT_LOADER_NAME_SIZE (strlen(BOOT_LOADER_NAME) + 1)
#define EFI_BOOT_MEM_SIZE \
        (MBOOT_MMAP_SIZE + MBOOT_INFO_SIZE + MBOOT_MODS_SIZE + BOOT_LOADER_NAME_SIZE)
#define MBOOT_MMAP_PTR(addr) \
        ((struct multiboot_mmap *)((VOID *)(addr)))
#define MBOOT_INFO_PTR(addr)  \
        ((struct multiboot_info *)((VOID *)(addr) + MBOOT_MMAP_SIZE))
#define MBOOT_MODS_PTR(addr)  \
        ((struct multiboot_module *)((VOID *)(addr) + MBOOT_MMAP_SIZE + MBOOT_INFO_SIZE))
#define BOOT_LOADER_NAME_PTR(addr)      \
        ((char *)((VOID *)(addr) + MBOOT_MMAP_SIZE + MBOOT_INFO_SIZE + MBOOT_MODS_SIZE))


EFI_STATUS acrn_mb2_add_kernel(
		IN struct mb2_images *images,
		IN EFI_PHYSICAL_ADDRESS kernel_start,
		IN UINTN kernel_size,
		IN EFI_PHYSICAL_ADDRESS cmdline_start,
		IN UINTN cmdline_size,
		IN EFI_PHYSICAL_ADDRESS ramdisk_start,
		IN INTN ramdisk_size);

/* Functions to load acrn multiboot2 image and modules. */
EFI_STATUS acrn_image_start(
                IN EFI_HANDLE parent_image,
                IN struct mb2_images *images);

#endif /* __ACRN_H__ */
