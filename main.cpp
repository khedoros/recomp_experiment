#include<iostream>
#include<fstream>
#include<stdint.h>
#include<assert.h>
#include<vector>

#include "dos_header.h"

//include for libudis86
#include<udis86.h>

using namespace std;

int main(int argc, char *argv[]) {
    //Get the filesize
    assert(sizeof(mz_header) == 32);
    ifstream in;
    in.open(argv[1]);
    in.seekg(0,ios::end);
    size_t size = in.tellg();

    //Read the header
    in.seekg(0,ios::beg);
    cout<<"Filename: "<<argv[1]<<endl<<"Filesize: "<<size<<endl;
    mz_header h;
    in.read(reinterpret_cast<char *>(&h), sizeof(mz_header));

    //Read the relocation table
    vector<uint16_t> reloc_table;
    reloc_table.resize(h.reloc_entries*2);
    in.seekg(h.reloc_offset,ios::beg);
    in.read(reinterpret_cast<char *>(&(reloc_table[0])), h.reloc_entries*4);

    //Output information gathered about the binary
    printf("Bytes on last page: 0x%04x\nTotal pages: 0x%04x\nRelocation entries: %d\nHeader size in paragraphs: 0x%04x\nMin mem needed after exe: 0x%04x\nMax mem needed after exe: 0x%04x\nSS offset: 0x%04x\nInitial SP: 0x%04x\nChecksum: 0x%04x\nEntry point: %04x:%04x\nOffset of relocation table: 0x%04x\nOverlay number (expect 0): 0x%04x\nCould be ID: %02x %02x %02x %02x\n",h.last_page_bytes,h.total_pages,h.reloc_entries,h.header_para_size,h.min_paras_after_code,h.max_paras_after_code,h.stack_seg_offset,h.initial_sp,h.chksum,h.init_cs,h.init_ip,h.reloc_offset,h.overlay_num,h.poss_id[0],h.poss_id[1],h.poss_id[2],h.poss_id[3]);
    if(h.poss_id[0] == 0x01 && h.poss_id[1] == 0x00 && h.poss_id[2] == 0xfb) {
        std::cout<<"Probably Borland TLink, version "<<h.poss_id[3]/16<<endl;
    }
    cout<<"Relocation table: "<<h.reloc_entries<<" entries"<<endl;
    {
        bool odd=false;
        uint16_t offset=0;
        for(uint16_t off:reloc_table) {
            if(odd)
                printf("%04x:%04x\n",off,offset);
            else
                offset = off;
            odd=!odd;
        }
    }

    //Read the rest of the contents of the binary
    vector<uint8_t> bin(size - h.header_para_size * 0x10,0);
    in.seekg(h.header_para_size * 0x10, ios::beg);
    in.read(reinterpret_cast<char *>(&bin[0]), bin.size());

    size_t offset = h.header_para_size * 0x10;
    
    ud_t ud_obj;
    ud_init(&ud_obj);
    ud_set_input_buffer(&ud_obj, &bin[0], bin.size());
    ud_set_mode(&ud_obj, 16);
    ud_set_syntax(&ud_obj, UD_SYN_INTEL);
    while (ud_disassemble(&ud_obj)) {
        printf("\t%08lx %s\n", ud_insn_off(&ud_obj), ud_insn_asm(&ud_obj));
    }

    return 0;
}
