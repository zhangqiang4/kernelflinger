/*	[ORIGIN: src/sys/arch/i386/include/...				*/
/*	$NetBSD: multiboot.h,v 1.8 2009/02/22 18:05:42 ahoka Exp $	*/

/*-
 * Copyright (c) 2005, 2006 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Julio M. Merino Vidal.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * multiboot.h
 */

#ifndef _MULTIBOOT_H
#define _MULTIBOOT_H

#include <stdint.h>

struct multiboot2_header
{
  uint32_t magic;
  uint32_t architecture;
  uint32_t header_length;
  uint32_t checksum;
} __attribute__((__packed__));

#define MULTIBOOT2_SEARCH                        32768

#define MULTIBOOT2_HEADER_ALIGN				8

#define MULTIBOOT2_HEADER_MAGIC				0xe85250d6U

/*  This should be in %eax. */
#define MULTIBOOT2_INFO_MAGIC				0x36d76289U

/*  Alignment of the multiboot info structure. */
#define MULTIBOOT2_INFO_ALIGN				0x00000008U

/*  Flags set in the 'flags' member of the multiboot header. */

#define MULTIBOOT2_TAG_ALIGN				8U
#define MULTIBOOT2_TAG_TYPE_END				0U
#define MULTIBOOT2_TAG_TYPE_CMDLINE			1U
#define MULTIBOOT2_TAG_TYPE_BOOT_LOADER_NAME		2U
#define MULTIBOOT2_TAG_TYPE_MODULE			3U
#define MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO		4U
#define MULTIBOOT2_TAG_TYPE_BOOTDEV			5U
#define MULTIBOOT2_TAG_TYPE_MMAP			6U
#define MULTIBOOT2_TAG_TYPE_VBE				7U
#define MULTIBOOT2_TAG_TYPE_FRAMEBUFFER			8U
#define MULTIBOOT2_TAG_TYPE_ELF_SECTIONS		9U
#define MULTIBOOT2_TAG_TYPE_APM				10U
#define MULTIBOOT2_TAG_TYPE_EFI32			11U
#define MULTIBOOT2_TAG_TYPE_EFI64			12U
#define MULTIBOOT2_TAG_TYPE_SMBIOS			13U
#define MULTIBOOT2_TAG_TYPE_ACPI_OLD			14U
#define MULTIBOOT2_TAG_TYPE_ACPI_NEW			15U
#define MULTIBOOT2_TAG_TYPE_NETWORK			16U
#define MULTIBOOT2_TAG_TYPE_EFI_MMAP			17U
#define MULTIBOOT2_TAG_TYPE_EFI_BS			18U
#define MULTIBOOT2_TAG_TYPE_EFI32_IH			19U
#define MULTIBOOT2_TAG_TYPE_EFI64_IH			20U
#define MULTIBOOT2_TAG_TYPE_LOAD_BASE_ADDR		21U

#define MULTIBOOT2_HEADER_TAG_END			0
#define MULTIBOOT2_HEADER_TAG_INFORMATION_REQUEST	1
#define MULTIBOOT2_HEADER_TAG_ADDRESS			2
#define MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS		3
#define MULTIBOOT2_HEADER_TAG_CONSOLE_FLAGS		4
#define MULTIBOOT2_HEADER_TAG_FRAMEBUFFER		5
#define MULTIBOOT2_HEADER_TAG_MODULE_ALIGN		6
#define MULTIBOOT2_HEADER_TAG_EFI_BS			7
#define MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS_EFI32	8
#define MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS_EFI64	9
#define MULTIBOOT2_HEADER_TAG_RELOCATABLE		10
#define MULTIBOOT2_HEADER_TAG_OPTIONAL			1

#define MULTIBOOT2_ARCHITECTURE_I386			0

struct multiboot2_header_tag
{
	uint16_t type;
	uint16_t flags;
	uint32_t size;
}__attribute__((__packed__));

struct multiboot2_header_tag_information_request
{
	uint16_t type;
	uint16_t flags;
	uint32_t size;
	uint32_t requests[0];
}__attribute__((__packed__));

struct multiboot2_header_tag_address
{
	uint16_t type;
	uint16_t flags;
	uint32_t size;
	uint32_t header_addr;
	uint32_t load_addr;
	uint32_t load_end_addr;
	uint32_t bss_end_addr;
}__attribute__((__packed__));

struct multiboot2_header_tag_entry_address
{
	uint16_t type;
	uint16_t flags;
	uint32_t size;
	uint32_t entry_addr;
}__attribute__((__packed__));

struct multiboot2_header_tag_console_flags
{
	uint16_t type;
	uint16_t flags;
	uint32_t size;
	uint32_t console_flags;
}__attribute__((__packed__));

struct multiboot2_header_tag_framebuffer
{
	uint16_t type;
	uint16_t flags;
	uint32_t size;
	uint32_t width;
	uint32_t height;
	uint32_t depth;
}__attribute__((__packed__));

struct multiboot2_header_tag_module_align
{
	uint16_t type;
	uint16_t flags;
	uint32_t size;
}__attribute__((__packed__));

struct multiboot2_header_tag_relocatable
{
	uint16_t type;
	uint16_t flags;
	uint32_t size;
	uint32_t min_addr;
	uint32_t max_addr;
	uint32_t align;
	uint32_t preference;
}__attribute__((__packed__));

struct multiboot2_mmap_entry
{
	uint64_t addr;
	uint64_t len;
	uint32_t type;
	uint32_t zero;
}__attribute__((__packed__));

struct multiboot2_tag
{
	uint32_t type;
	uint32_t size;
}__attribute__((__packed__));

struct multiboot2_tag_string
{
	uint32_t type;
	uint32_t size;
	char string[0];
}__attribute__((__packed__));

struct multiboot2_tag_module
{
	uint32_t type;
	uint32_t size;
	uint32_t mod_start;
	uint32_t mod_end;
	char cmdline[0];
}__attribute__((__packed__));

struct multiboot2_tag_mmap
{
	uint32_t type;
	uint32_t size;
	uint32_t entry_size;
	uint32_t entry_version;
	struct multiboot2_mmap_entry entries[0];
}__attribute__((__packed__));

struct multiboot2_tag_new_acpi
{
	uint32_t type;
	uint32_t size;
	uint8_t rsdp[0];
}__attribute__((__packed__));

struct multiboot2_tag_efi64
{
	uint32_t	type;
	uint32_t	size;
	uint64_t	pointer;
}__attribute__((__packed__));

struct multiboot2_tag_efi_mmap {
	uint32_t	type;
	uint32_t	size;
	uint32_t	descr_size;
	uint32_t	descr_vers;
	uint8_t		efi_mmap[0];
}__attribute__((__packed__));

struct mb2header_tag_list {
	struct multiboot2_header_tag_information_request *info_req;
	struct multiboot2_header_tag_address *addr;
	struct multiboot2_header_tag_entry_address *entry;
	struct multiboot2_header_tag_console_flags *console_flags;
	struct multiboot2_header_tag_framebuffer *frbuf;
	struct multiboot2_header_tag_module_align *modalign;
	struct multiboot2_header_tag_relocatable *reloc;
};

const struct multiboot2_header *find_mb2header(const uint8_t *buffer, uint64_t len);
int parse_mb2header(const struct multiboot2_header *header, struct mb2header_tag_list *tags);

#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))


/* in-partitioin MB2 image format, irralevant to multiboot protocol. We may
 * change the image format in future.
 */
struct mb2_image_header {
#define MB2_MAGIC_SIZE	8
#define MB2_MAGIC "ACRNMB2"
	uint8_t magic[MB2_MAGIC_SIZE];
	uint32_t header_version;
	uint32_t header_size;
	uint32_t mod_offset;
	uint32_t mod_size;
	uint32_t mod_align;
#define MB2_CMDLINE_SIZE 4096
	uint8_t cmdline[MB2_CMDLINE_SIZE];	/* NULL terminated */
}__attribute__((__packed__));
void dump_mb2_partition(struct mb2_image_header *hdr);

struct mb2_module {
	void *start;
	uint64_t size;
	char *cmdline;
	uint64_t cmdline_buf_size;
};

#define MAX_MB2_IMAGES 16
struct mb2_images {
	struct mb2_image_header *headers[MAX_MB2_IMAGES];
	const char *names[MAX_MB2_IMAGES];
	struct mb2_module mods[16];
	uint8_t cnt;
};

EFI_STATUS load_mb2_images(IN struct mb2_images *images);



#endif /* _MULTIBOOT_H */
