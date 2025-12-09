# yaml-language-server: $schema=https://raw.githubusercontent.com/kaitai-io/ksy_schema/refs/heads/master/ksy_schema.json
meta:
  id: squirrel
  endian: le
  imports:
    - microsoft_pe
    - zip

# 298f0 is the zip in HPClick
seq:
  - id: pe
    type: microsoft_pe
    
instances:
  data:
    value: pe.pe.sections[3].resource_table.named_entries[0].subdirectory.id_entries[0].subdirectory.id_entries[0].data_entry
  
  zip:
    type: zip
    pos: pe.pe.sections[3].pointer_to_raw_data + (data.data_rva - pe.pe.sections[3].virtual_address)
    size: data.len_resource_data_entry
