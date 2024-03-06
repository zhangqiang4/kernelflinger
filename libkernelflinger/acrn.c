#include <efi.h>
#include <efilib.h>
#include <ui.h>

#include "android.h"
#include "efilinux.h"
#include "lib.h"
#include "security.h"
#include "vars.h"
#include "power.h"
#include "targets.h"
#include "gpt.h"
#include "storage.h"
#include "text_parser.h"
#include "watchdog.h"
#ifdef HAL_AUTODETECT
#include "blobstore.h"
#endif
#include "slot.h"
#include "pae.h"
#include "timer.h"
#include "android_vb2.h"
#include "acpi.h"
#ifdef USE_FIRSTSTAGE_MOUNT
#include "firststage_mount.h"
#endif
#ifdef USE_TRUSTY
#include "trusty_common.h"
#endif

#include "uefi_utils.h"
#include "libxbc.h"

#include "acrn.h"

#if 0
static int mb2_images_add(struct mb2_images *images,
		VOID *start, UINTN size,
		CHAR8 *cmdline, UINTN cmdline_buf_size)
{
	if (images->cnt >= 15) {
		error(L"too many multiboot images");
		return -1;
	}

	images->mods[images->cnt].start = start;
	images->mods[images->cnt].size = size;
	images->mods[images->cnt].cmdline = cmdline;
	images->mods[images->cnt].cmdline_buf_size = cmdline_buf_size;
	images->cnt++;
	return 0;
}
#endif

static void mb2_images_dump(struct mb2_images *images)
{
	int i;
	struct mb2_module *mod;
	CHAR16* str;

	for(i = 0; i < images->cnt; i++) {
		mod = &images->mods[i];
		str = stra_to_str(mod->cmdline);
		debug(L"Image%d, start: 0x%lx, size: 0x%lx, cmdlen: %d, cmdline: %s",
				i, mod->start, mod->size, strnlen(mod->cmdline, mod->cmdline_buf_size), str);
	}
}

EFI_STATUS acrn_mb2_add_kernel(
		IN struct mb2_images *images,
		IN EFI_PHYSICAL_ADDRESS kernel_start,
		IN UINTN kernel_size,
		IN EFI_PHYSICAL_ADDRESS cmdline_start,
		IN UINTN cmdline_size,
		IN EFI_PHYSICAL_ADDRESS ramdisk_start,
		IN INTN ramdisk_size)
{
	EFI_STATUS ret;
	EFI_PHYSICAL_ADDRESS tag_buf;

	if (images->cnt >= 14)
		return EFI_OUT_OF_RESOURCES;

	/* append kernel cmdline to acrn cmdline line */
	struct mb2_module *acrn = &images->mods[0];
	UINTN cur_len = strnlen(acrn->cmdline, acrn->cmdline_buf_size);
	UINTN kernel_cmdlen = strnlen((char*)cmdline_start, cmdline_size);
	acrn->cmdline[cur_len] = ' ';
	cur_len ++;
	if (acrn->cmdline_buf_size < cur_len + kernel_cmdlen) {
		error(L"acrn cmdline buffer is to small to hold kernel cmdline");
	}
	memcpy_s(acrn->cmdline + cur_len, acrn->cmdline_buf_size - cur_len,
			(VOID *)cmdline_start, kernel_cmdlen);
	free_pages(cmdline_start, EFI_SIZE_TO_PAGES(cmdline_size));

        ret = emalloc(4096, 4, &tag_buf, FALSE);
        if (EFI_ERROR(ret))
                return ret;

	/* bzImage multiboot2 mod */
	CHAR8 *tag = "asos_bzimage";
	UINTN tag_size = strlen(tag);
	images->mods[images->cnt].start = (VOID *)kernel_start;
	images->mods[images->cnt].size = kernel_size;
	images->mods[images->cnt].cmdline = (CHAR8 *)tag_buf;
	images->mods[images->cnt].cmdline_buf_size = 2048;
	memcpy_s((VOID *)tag_buf, 2048, tag, tag_size);
	*((CHAR8*)tag_buf + tag_size) = '\0';
	images->cnt++;

	/* ramdisk mod */
	tag = "asos_ramdisk";
	tag_size = strlen(tag);
	images->mods[images->cnt].start = (VOID *)ramdisk_start;
	images->mods[images->cnt].size = ramdisk_size;
	images->mods[images->cnt].cmdline = (CHAR8*)(tag_buf + 2048);
	images->mods[images->cnt].cmdline_buf_size = 2048;
	memcpy_s((VOID *)(tag_buf + 2048), 2048, tag, tag_size);
	*((CHAR8*)tag_buf + 2048 + tag_size) = '\0';
	images->cnt++;

	return EFI_SUCCESS;
}

static EFI_STATUS get_efi_memmap(struct efi_memmap_info *mi, int size_only)
{
        UINTN map_size, map_key;
        UINT32 desc_version;
        UINTN desc_size;
        EFI_MEMORY_DESCRIPTOR *map_buf;
        EFI_STATUS err = EFI_SUCCESS;

        /* We're just interested in the map's size for now */
        map_size = 0;
        err = get_memory_map(&map_size, NULL, NULL, &desc_size, NULL);
        if (err != EFI_SUCCESS && err != EFI_BUFFER_TOO_SMALL)
                goto out;

        if (size_only) {
                mi->map_size = map_size;
                mi->desc_size = desc_size;
                return err;
        }

again:
        err = allocate_pool(EfiLoaderData, map_size, (void **) &map_buf);
        if (err != EFI_SUCCESS)
                goto out;

        /*
         * Remember! We've already allocated map_buf with emalloc (and
         * 'map_size' contains its size) which means that it should be
         * positioned below our allocation for the kernel. Use that
         * space for the memory map.
         */
        err = get_memory_map(&map_size, map_buf, &map_key,
                                 &desc_size, &desc_version);
        if (err != EFI_SUCCESS) {
                if (err == EFI_BUFFER_TOO_SMALL) {
                        /*
                         * Argh! The buffer that we allocated further
                         * up wasn't large enough which means we need
                         * to allocate them again, but this time
                         * larger. 'map_size' has been updated by the
                         * call to memory_map().
                         */
                        free_pool(map_buf);
                        goto again;
                }
                goto out;
        }

        mi->map_size = map_size;
        mi->map_key = map_key;
        mi->desc_version = desc_version;
        mi->desc_size = desc_size;
        mi->mmap = map_buf;

out:
        return err;
}

static UINT32 calc_mbi_size(struct mb2_images *images,
		struct efi_memmap_info *emi, UINT32 sorted_mmap_cnt, UINT32 rsdp_len)
{
	uint32_t allmods_len = 0;
	int i;
	for(i = 1; i < images->cnt; i++) {
		allmods_len += ALIGN_UP(sizeof(struct multiboot2_tag_module) + strnlen(images->mods[i].cmdline, images->mods[i].cmdline_buf_size) + 1, MULTIBOOT2_TAG_ALIGN); /* tailing '\0' */
	}

        return 2 * sizeof(uint32_t) \
                /* Boot command line */
                + ALIGN_UP(sizeof(struct multiboot2_tag_string) + strnlen(images->mods[0].cmdline, images->mods[0].cmdline_buf_size) + 1, MULTIBOOT2_TAG_ALIGN) \

                /* Boot loader name */
                + ALIGN_UP(sizeof(struct multiboot2_tag_string) + BOOT_LOADER_NAME_SIZE, MULTIBOOT2_TAG_ALIGN) \

                /* Modules */
		+ allmods_len \

                /* Memory Map */
                + ALIGN_UP((sizeof(struct multiboot2_tag_mmap) + sorted_mmap_cnt * sizeof(struct multiboot2_mmap_entry)), MULTIBOOT2_TAG_ALIGN) \

                /* ACPI new */
                + ALIGN_UP(sizeof(struct multiboot2_tag_new_acpi) + rsdp_len, MULTIBOOT2_TAG_ALIGN) \

                /* EFI64 system table */
                + ALIGN_UP(sizeof(struct multiboot2_tag_efi64), MULTIBOOT2_TAG_ALIGN) \

                /* EFI memmap: Add an extra page since UEFI can alter the memory map */
                + ALIGN_UP(sizeof(struct multiboot2_tag_efi_mmap) + ALIGN_UP(emi->map_size + 0x1000, 0x1000), MULTIBOOT2_TAG_ALIGN) \

                /* END */
                + ALIGN_UP(sizeof(struct multiboot2_tag), MULTIBOOT2_TAG_ALIGN);
}

#define E820_UNDEFINED    0
#define E820_RAM          1
#define E820_RESERVED     2
#define E820_ACPI         3
#define E820_NVS          4
#define E820_UNUSABLE     5

UINT32 efimmap_to_mb2(
		struct efi_memmap_info *emi,
		struct multiboot2_mmap_entry *sorted,
		UINT32 len)
{
	UINT32 i, j, k, sorted_len = 0;
	for (i = 0; i < emi->map_size/emi->desc_size; i++) {
		uint32_t e820_type = 0;
                EFI_MEMORY_DESCRIPTOR *d = (EFI_MEMORY_DESCRIPTOR *)((UINT64)emi->mmap + i * emi->desc_size);

		switch(d->Type) {
		case EfiReservedMemoryType:
		case EfiRuntimeServicesCode:
		case EfiRuntimeServicesData:
		case EfiMemoryMappedIO:
		case EfiMemoryMappedIOPortSpace:
		case EfiPalCode:
			e820_type = E820_RESERVED;
			break;

		case EfiUnusableMemory:
			e820_type = E820_UNUSABLE;
			break;

		case EfiACPIReclaimMemory:
			e820_type = E820_ACPI;
			break;

		case EfiLoaderCode:
		case EfiLoaderData:
		case EfiBootServicesCode:
		case EfiBootServicesData:
		case EfiConventionalMemory:
			e820_type = E820_RAM;
			break;

		case EfiACPIMemoryNVS:
			e820_type = E820_NVS;
			break;

		default:
			error(L"unknown efi mmap type");
			;//possible ?
		}
		struct multiboot2_mmap_entry e;
		e.addr = d->PhysicalStart;
                e.len = d->NumberOfPages << EFI_PAGE_SHIFT;
		e.type = e820_type;
                e.zero = 0;

		for (j = 0; j < sorted_len; j++) {
			if (e.addr < sorted[j].addr) {
				for (k = sorted_len; k > j; k--) {
					sorted[k] = sorted[k-1];
				}
				sorted[j] = e;
				sorted_len++;
				break;
			}
		}
		if (j == sorted_len) {
			sorted[sorted_len++] = e;
		}
		if (sorted_len > len) {
			error(L"should panic");
			break;
		}
	}
	for (i = sorted_len - 1; i > 0; i--) {
		if ((sorted[i].type == sorted[i-1].type) && (sorted[i-1].addr + sorted[i-1].len >= sorted[i].addr)) {
			sorted[i-1].len += sorted[i].len;
			for (j = i; j < sorted_len -1; j++) {
				sorted[j] = sorted[j+1];
			}
			sorted_len--;
		}
	}
	for (i = 0; i < sorted_len; i++) {
		debug(L"mmap entry: addr: 0x%lx, len: 0x%lx, type: %d",
				sorted[i].addr, sorted[i].len, sorted[i].type);
	}
	return sorted_len;

}
static EFI_STATUS construct_mbi2(
		struct mb2_images *images,
		EFI_PHYSICAL_ADDRESS *pmbi)
{
	EFI_STATUS ret;
	struct RSDP_TABLE *rsdp;
	VOID *mbi;
	UINT32 mbi_size, mmap_cnt, sorted_mmap_cnt;
	struct efi_memmap_info emi;
	struct multiboot2_mmap_entry *sorted_mmap_entries; 

	ret = get_acpi_rsdp((VOID **)&rsdp);
	if (EFI_ERROR(ret)) {
		error(L"fail to get rsdp");
		return ret;
	}

	ret = get_efi_memmap(&emi, 0);
	if (EFI_ERROR(ret)) {
		error(L"fail to get efi memmap");
		return ret;
	}

	mmap_cnt = emi.map_size / emi.desc_size;
        ret = allocate_pool(EfiLoaderData, mmap_cnt * sizeof(struct multiboot2_mmap_entry), (void **)&sorted_mmap_entries);
	if (EFI_ERROR(ret)) {
		error(L"fail to alloc buffer for MB2 mmap");
		return ret;
	}
	sorted_mmap_cnt = efimmap_to_mb2(&emi, sorted_mmap_entries, mmap_cnt);
	mbi_size = calc_mbi_size(images, &emi, sorted_mmap_cnt, rsdp->length);
	/* This allocation is guaranteed to be 8-bytes aligned */
        ret = allocate_pool(EfiLoaderData, mbi_size, (void **) &mbi);
	if (EFI_ERROR(ret)) {
		error(L"fail to alloc buffer for MBI");
		return ret;
	}
	memset(mbi, 0, mbi_size);

	UINT64 *p = mbi;
	p += (2 * sizeof(UINT32)) / sizeof(UINT64);

	/* TODO setup MBI per image's request */
        /* Boot command line */
        {
                struct multiboot2_tag_string *tag = (struct multiboot2_tag_string *)p;
                UINTN cmdline_size = strnlen(images->mods[0].cmdline, images->mods[0].cmdline_buf_size) + 1;
                tag->type = MULTIBOOT2_TAG_TYPE_CMDLINE;
                tag->size = sizeof(struct multiboot2_tag_string) + cmdline_size;
                memcpy(tag->string, images->mods[0].cmdline, cmdline_size);
                p += ALIGN_UP(tag->size, MULTIBOOT2_TAG_ALIGN) / sizeof(uint64_t);
        }

        /* Boot loader name */
        {
                struct multiboot2_tag_string *tag = (struct multiboot2_tag_string *)p;
                tag->type = MULTIBOOT2_TAG_TYPE_BOOT_LOADER_NAME;
                tag->size = sizeof(struct multiboot2_tag_string) + BOOT_LOADER_NAME_SIZE;
                memcpy(tag->string, BOOT_LOADER_NAME, BOOT_LOADER_NAME_SIZE);
                p += ALIGN_UP(tag->size, MULTIBOOT2_TAG_ALIGN) / sizeof(uint64_t);
        }

        /* Modules */
        {
                unsigned i;
                uint32_t mod_count = images->cnt;
                for (i = 1; i < mod_count; i++) {
			struct mb2_module *mod = &images->mods[i];
                        struct multiboot2_tag_module *tag = (struct multiboot2_tag_module *)p;
                        tag->type = MULTIBOOT2_TAG_TYPE_MODULE;
                        tag->size = sizeof(struct multiboot2_tag_module) + strnlen(mod->cmdline, mod->cmdline_buf_size) + 1;
                        tag->mod_start = (uint32_t)mod->start;
                        tag->mod_end = tag->mod_start + mod->size;
                        memcpy(tag->cmdline, mod->cmdline, strnlen(mod->cmdline, mod->cmdline_buf_size) + 1);
                        p += ALIGN_UP(tag->size, MULTIBOOT2_TAG_ALIGN) / sizeof(uint64_t);
                }
        }

        /* Memory map */
        {
                struct multiboot2_tag_mmap *tag = (struct multiboot2_tag_mmap *)p;
                tag->type = MULTIBOOT2_TAG_TYPE_MMAP;
                tag->size = sizeof(struct multiboot2_tag_mmap) + sizeof(struct multiboot2_mmap_entry) * sorted_mmap_cnt;
                tag->entry_size = sizeof(struct multiboot2_mmap_entry);
                tag->entry_version = 0;
		memcpy(tag->entries, sorted_mmap_entries, sorted_mmap_cnt * sizeof(struct multiboot2_mmap_entry));
                p += ALIGN_UP(tag->size, MULTIBOOT2_TAG_ALIGN) / sizeof(uint64_t);
        }

        /* ACPI new */
        {
                struct multiboot2_tag_new_acpi *tag = (struct multiboot2_tag_new_acpi *)p;
                tag->type = MULTIBOOT2_TAG_TYPE_ACPI_NEW;
                tag->size = sizeof(struct multiboot2_tag_new_acpi) + rsdp->length;
                memcpy((char *)tag->rsdp, (char *)rsdp, rsdp->length);
                p += ALIGN_UP(tag->size, MULTIBOOT2_TAG_ALIGN) / sizeof(uint64_t);
        }

        /* EFI64 system table */
        {
                struct multiboot2_tag_efi64 *tag = (struct multiboot2_tag_efi64 *)p;
                tag->type = MULTIBOOT2_TAG_TYPE_EFI64;
                tag->size = sizeof(struct multiboot2_tag_efi64);
                tag->pointer = (uint64_t)ST;
                p += ALIGN_UP(tag->size, MULTIBOOT2_TAG_ALIGN) / sizeof(uint64_t);
        }

        /* EFI memory map */
        {
                struct multiboot2_tag_efi_mmap *tag = (struct multiboot2_tag_efi_mmap *)p;
                tag->type = MULTIBOOT2_TAG_TYPE_EFI_MMAP;
                tag->size = sizeof(struct multiboot2_tag_efi_mmap) + emi.map_size;
                tag->descr_size = emi.desc_size;
                tag->descr_vers = emi.desc_version;
                memcpy((char *)tag->efi_mmap, (char *)emi.mmap, emi.map_size);
                p += ALIGN_UP(tag->size, MULTIBOOT2_TAG_ALIGN) / sizeof(uint64_t);
        }

        /* END */
        {
                struct multiboot2_tag *tag = (struct multiboot2_tag *)p;
                tag->type = MULTIBOOT2_TAG_TYPE_END;
                tag->size = sizeof(struct multiboot2_tag);
                p += ALIGN_UP(tag->size, MULTIBOOT2_TAG_ALIGN) / sizeof(uint64_t);
        }

        ((uint32_t *)mbi)[0] = (uint64_t)((char *)p - (char *)mbi);
        ((uint32_t *)mbi)[1] = 0;

        *pmbi = (EFI_PHYSICAL_ADDRESS)mbi;

	return EFI_SUCCESS;
}

static EFI_STATUS get_mb2_entry(struct mb2_images *images, EFI_PHYSICAL_ADDRESS *entry)
{
	VOID *acrn = images->mods[0].start;
	const struct multiboot2_header *mb2header = find_mb2header((uint8_t *)acrn, 4096);
	struct mb2header_tag_list tags;
	int ret = parse_mb2header(mb2header, &tags);
	if (ret) {
		error(L"fail to parse multiboot2 header of acrn image");
		return EFI_INVALID_PARAMETER;
	}
	struct multiboot2_header_tag_address *addr_tag = tags.addr;
	struct multiboot2_header_tag_entry_address *entry_tag = tags.entry;
	*entry = (EFI_PHYSICAL_ADDRESS)acrn + entry_tag->entry_addr - addr_tag->load_addr;

	return EFI_SUCCESS;
}

static inline void hv_jump(EFI_PHYSICAL_ADDRESS hv_entry, uint32_t mbi, int32_t magic)
{
        asm volatile (
                "cli\n\t"
                "jmp *%2\n\t"
                :
                : "a"(magic), "b"(mbi), "r"(hv_entry)
                );
}

EFI_STATUS acrn_image_start(
                IN EFI_HANDLE parent_image,
                IN struct mb2_images *images)
{
        EFI_STATUS ret;
	EFI_PHYSICAL_ADDRESS mbi, acrn_entry;
        UINTN nr_entries, entry_sz, key;
        UINT32 entry_ver;
        EFI_MEMORY_DESCRIPTOR *mem_entries;

	mb2_images_dump(images);

        ret = construct_mbi2(images, &mbi);
        if (EFI_ERROR(ret))
                return ret;
	debug(L"constructed mbi at 0x%lx", mbi);

	debug(L"exit boot services");
        mem_entries = LibMemoryMap(&nr_entries, &key, &entry_sz, &entry_ver);
        if (!mem_entries) {
		error(L"fail to get memmap to exit bootservice");
                return EFI_OUT_OF_RESOURCES;
	}
        FreePool(mem_entries);
	ret = uefi_call_wrapper(BS->ExitBootServices, 2, parent_image, key);
        if (!EFI_ERROR(ret)) {
		error(L"fail to exit bootservice");
		return ret;
	}

	ret = get_mb2_entry(images, &acrn_entry);
	if (EFI_ERROR(ret)) {
		error(L"fail to get acrn entry point");
		return ret;
	}
	debug(L"jump to acrn entrypint at 0x%lx", acrn_entry);
        hv_jump(acrn_entry, (uint32_t)mbi, MULTIBOOT2_INFO_MAGIC);

        return ret;
}


