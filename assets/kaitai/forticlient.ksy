meta:
  id: forticlient
  imports:
    - microsoft_pe
    - microsoft_cfb

seq:
  - id: pe
    type: microsoft_pe

instances:
  data:
    value: pe.pe.sections[3].resource_table.id_entries[4].subdirectory.named_entries[1].subdirectory.id_entries[0].data_entry

  msi:
    type: microsoft_cfb
    pos: (data.data_rva - data._parent.section_virtual_address) + data._parent.section_file_offset
    size: data.len_resource_data_entry
