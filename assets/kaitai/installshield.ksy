# yaml-language-server: $schema=https://raw.githubusercontent.com/kaitai-io/ksy_schema/refs/heads/master/ksy_schema.json
meta:
  id: installshield
  endian: le
  imports:
    - microsoft_pe

seq:
  - id: pe
    type: microsoft_pe
instances:
  overlay_offset:
    value: pe.pe.sections[pe.pe.coff_hdr.number_of_sections - 1].pointer_to_raw_data +
      pe.pe.sections[pe.pe.coff_hdr.number_of_sections - 1].size_of_raw_data

  pdb_magic:
    pos: overlay_offset
    type: str
    size: 4
    encoding: ASCII

  overlay:
    pos: overlay_offset
    type:
      switch-on: pdb_magic
      cases:
        '"NB10"': installshield_overlay_pdb
        _: installshield_overlay

types:
  pdb:
    seq:
      - id: signature
        type: str
        size: 4
        encoding: ASCII
      - id: offset
        type: u4
      - id: timestamp
        type: u4
      - id: age
        type: u4
      - id: pdb_path
        type: strz
        encoding: ASCII

  installshield_overlay_pdb:
    seq:
      - id: pdb
        type: pdb
      - id: installshield
        type: installshield_overlay

  installshield_overlay:
    seq:
      - id: magic
        type: str
        size: 13
        encoding: ASCII
      - id: sig_term
        type: u1
        doc: 1-byte terminator/padding (usually 0x00)
      - id: num_files
        type: u2
      - id: type
        type: u4
      - id: x4
        size: 8
      - id: x5
        type: u2
      - id: x6
        size: 16
      - id: entries
        type:
          switch-on: magic
          cases:
            '"InstallShield"': file_entry_plain
            '"ISSetupStream"': file_entry_stream
        repeat: expr
        repeat-expr: num_files

  file_entry_plain:
    seq:
      - id: file_name
        type: strz
        size: 260
        encoding: UTF-8
        doc: char file_name[_MAX_PATH]; // 260 bytes in C code. really ANSI
      - id: encoded_flags
        type: u4
      - id: x3
        type: u4
      - id: file_len
        type: u4
      - id: x5
        size: 8
      - id: is_unicode_launcher
        type: u2
      - id: x7
        size: 30
      - id: data
        size: file_len

  file_entry_stream:
    seq:
      - id: attrs
        type: file_attributes_stream
      - id: attrs_duplicate
        type: file_attributes_stream
        if: _parent.type == 4
      - id: filename_utf16
        type: str
        size: attrs.filename_len
        encoding: UTF-16LE
      - id: data
        size: attrs.file_len
  file_attributes_stream:
    seq:
      - id: filename_len
        type: u4
        doc: bytes of UTF-16LE filename
      - id: encoded_flags
        type: u4
      - id: x3
        size: 2
      - id: file_len
        type: u4
      - id: x5
        size: 8
      - id: is_unicode_launcher
        type: u2
