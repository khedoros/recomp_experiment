#pragma once

typedef struct {
    char magic[2];
    uint16_t last_page_bytes;
    uint16_t total_pages;
    uint16_t reloc_entries;
    uint16_t header_para_size;
    uint16_t min_paras_after_code;
    uint16_t max_paras_after_code;
    uint16_t stack_seg_offset;
    uint16_t initial_sp;
    uint16_t chksum;
    uint16_t init_ip;
    uint16_t init_cs;
    uint16_t reloc_offset;
    uint16_t overlay_num;
    uint8_t poss_id[4];
} mz_header;

