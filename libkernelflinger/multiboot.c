/*
 * Copyright (c) 2021 - 2022, Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *    * Neither the name of Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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

#include "multiboot.h"
#include "lib.h"


/**
 * @brief Search the first len bytes in buffer for multiboot2 header.
 *
 * @param[in] buffer Buffer to be searched
 * @param[in] len    Search length
 *
 * @return A pointer to the multiboot2 header if found. NULL otherwise.
 */
const struct multiboot2_header *find_mb2header(const uint8_t *buffer, uint64_t len)
{
	const struct multiboot2_header *header;

	for (header = (const struct multiboot2_header *)buffer;
		((char *)header <= (char *)buffer + len - 12);
		header = (struct multiboot2_header *)((uint64_t)header + MULTIBOOT2_HEADER_ALIGN / 4))
	{
		if (header->magic == MULTIBOOT2_HEADER_MAGIC &&
			!(header->magic + header->architecture + header->header_length + header->checksum) &&
			header->architecture == MULTIBOOT2_ARCHITECTURE_I386)
			return header;
	}

	return NULL;
}

/**
 * @brief Parse the multiboot2 header and return a list of pointers to the header tags.
 *
 * @param[in]  header     Multiboot2 header to be parsed.
 * @param[out] tags       An mb2header_tag_list struct that contains pointers to all possible
 *                        tags in a multiboot2 header. If a field in this struct is not NULL, it
 *                        means the tag was found in the given header. NULL otherwise.
 *
 * @return 0 on success. -1 on error.
 */
int parse_mb2header(const struct multiboot2_header *header, struct mb2header_tag_list *tags)
{
	struct multiboot2_header_tag *tag;

	memset(tags, 0, sizeof(struct mb2header_tag_list));

	for (tag = (struct multiboot2_header_tag *)(header + 1);
		tag->type != MULTIBOOT2_TAG_TYPE_END;
		tag = (struct multiboot2_header_tag *)((uint32_t *)tag + ALIGN_UP(tag->size, MULTIBOOT2_TAG_ALIGN) / 4))
	{
		switch (tag->type) {
			case MULTIBOOT2_HEADER_TAG_INFORMATION_REQUEST:
				/* Ignored. Currently we didn't support all categories of requested information,
				 * only the part that ACRN requests. So we don't parse the requests here. */
				break;

			case MULTIBOOT2_HEADER_TAG_ADDRESS:
				tags->addr = (struct multiboot2_header_tag_address *)tag;
				break;

			case MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS:
				tags->entry = (struct multiboot2_header_tag_entry_address *)tag;
				break;

			case MULTIBOOT2_HEADER_TAG_RELOCATABLE:
				tags->reloc = (struct multiboot2_header_tag_relocatable *)tag;
				break;

			default:
				Print(L"Unsupported multiboot2 tag type: %d\n", tag->type);
				return -1;
		}
	}

	if (tags->addr && !tags->entry)
		return -1;

	return 0;
}

void dump_mb2_partition(struct mb2_image_header *hdr)
{
	CHAR16* cmdline16 = stra_to_str(hdr->cmdline);
	debug(L"mb2 mod offset: 0x%lx", hdr->mod_offset);
	debug(L"mb2 mod size: 0x%lx", hdr->mod_size);
	debug(L"mb2 mod cmdline: %s", cmdline16);
	FreePool(cmdline16);
}

static bool check_mb2_image(struct mb2_image_header *hdr)
{
	return strncmp(hdr->magic, MB2_MAGIC, MB2_MAGIC_SIZE) == 0;
}

EFI_STATUS load_mb2_images(IN struct mb2_images *images)
{
	EFI_STATUS ret;
	uint8_t i;

	for (i = 0; i < images->cnt; i++) {
		struct mb2_image_header *hdr = images->headers[i];
		struct mb2_module *mod = &images->mods[i];

		CHAR16* str = stra_to_str(images->names[i]);
		info(L"loading multiboot2 image/module: %s", str);
		FreePool(str);

		if (!check_mb2_image(hdr)) {
			return EFI_LOAD_ERROR;
		}

		if (i == 0) {
			EFI_PHYSICAL_ADDRESS acrn_addr;
			uint8_t *buf = (uint8_t *)hdr + hdr->mod_offset;
			const struct multiboot2_header *mb2_header = find_mb2header(buf, 4096);
			struct mb2header_tag_list tags;
			if(parse_mb2header(mb2_header, &tags)) {
				error(L"fail to parse multiboot2 header");
				return EFI_LOAD_ERROR;
			}
			uint32_t acrn_size = tags.addr->load_end_addr - tags.addr->load_addr;

			/* copy acrn to a proper place to meet alignment requirements */
			ret = emalloc(acrn_size, 4*1024*1024, &acrn_addr, FALSE);
			if (EFI_ERROR(ret)) {
				error(L"fail to allocate memory for acrn image");
				return ret;
			}
			memset((VOID *)acrn_addr, 0, acrn_size);
			memcpy((VOID *)acrn_addr, (void *)hdr + hdr->mod_offset, hdr->mod_size);
			mod->start = (VOID *)acrn_addr;
			mod->size = acrn_size;
			mod->cmdline = hdr->cmdline;
			mod->cmdline_buf_size = MB2_CMDLINE_SIZE;
		} else {
			/* TODO add pre launch vms */
		}
	}

	return ret;
}


