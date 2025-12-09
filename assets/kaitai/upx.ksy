meta:
  id: upx_pe
  title: UPX-packed Microsoft PE
  ks-version: 0.9
  endian: le
  imports:
    - microsoft_pe

seq:
  - id: pe
    type: microsoft_pe

instances:
  upx1_section:
    value: pe.pe.sections[1]
  version:
    doc: eg 3.96
    type: strz
    encoding: ASCII
    pos: upx1_section.pointer_to_raw_data - 37
  header:
    type: header
    pos: upx1_section.pointer_to_raw_data - 32
  upx1:
    pos: upx1_section.pointer_to_raw_data
    size: upx1_section.size_of_raw_data

types:
  header:
    doc-ref: https://github.com/upx/upx/blob/devel/src/stub/src/include/header.S
    seq:
      - id: magic
        contents: "UPX!"
      - id: version
        type: u1
      - id: format
        type: u1
        enum: format
      - id: method
        type: u1
        enum: method
      - id: level
        type: u1
      - id: uncompressed_adler32
        type: u4
      - id: compressed_adler32
        type: u4
      - id: uncompressed_len
        type: u4
      - id: compressed_len
        type: u4
      - id: original_file_size
        type: u4
      - id: filter_id
        type: u1
      - id: filter_cto
        type: u1
      - id: n_mru
        type: u1
      - id: header_checksum
        type: u1
enums:
  format:
    # https://github.com/upx/upx/blob/devel/src/conf.h
    1: dos_com
    2: dos_sys
    3: dos_exe
    4: djgpp2_coff
    5: watcom_le
    6: vxd_le
    7: dos_exeh
    8: tmt_adam
    9: w32pe_i386
    10: linux_i386
    11: win16_ne
    12: linux_elf_i386
    13: linux_sep_i386
    14: linux_sh_i386
    15: vmlinuz_i386
    16: bvmlinuz_i386
    17: elks_8086
    18: ps1_exe
    19: vmlinux_i386
    20: linux_elfi_i386
    21: wince_arm
    22: linux_elf64_amd64
    23: linux_elf32_arm
    24: bsd_i386
    25: bsd_elf_i386
    26: bsd_sh_i386
    27: vmlinux_amd64
    28: vmlinux_arm
    29: mach_i386
    30: linux_elf32_mipsel
    31: vmlinuz_arm
    32: mach_arm
    33: dylib_i386
    34: mach_amd64
    35: dylib_amd64
    36: w64pe_amd64
    37: mach_arm64
    38: mach_ppc64le
    39: linux_elf64_ppc64le
    40: vmlinux_ppc64le
    41: dylib_ppc64le
    42: linux_elf64_arm64
    43: w64pe_arm64
    44: w64pe_arm64ec
    129: atari_tos
    130: solaris_sparc
    131: mach_ppc32
    132: linux_elf32_ppc32
    133: linux_elf32_armeb
    134: mach_fat
    135: vmlinux_armeb
    136: vmlinux_ppc32
    137: linux_elf32_mips
    138: dylib_ppc32
    139: mach_ppc64
    140: linux_elf64_ppc64
    141: vmlinux_ppc64
    142: dylib_ppc64
  method:
    2: nrv2b_le32
    3: nrv2b_8
    4: nrv2b_le16
    5: nrv2d_le32
    6: nrv2d_8
    7: nrv2d_le16
    8: nrv2e_le32
    9: nrv2e_8
    10: nrv2e_le16
    11: cl1b_le32
    12: cl1b_8
    13: cl1b_le16
    14: lzma
    15: deflate
    16: zstd
    17: bzip2
  