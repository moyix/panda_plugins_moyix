/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS
 
extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"

#include "panda_plugin.h"
}

#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <string>

#include <iostream>
#include <unordered_map>
using namespace std;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);
int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

}

#include "critbit.h"

unordered_map<string,int> matches;

#define MINWORD 4
#define WINDOW_SIZE 20
unsigned int ridx = 0;
uint8_t read_window[WINDOW_SIZE];
unsigned int widx = 0;
uint8_t write_window[WINDOW_SIZE];

critbit0_tree t;

int mem_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf, bool is_write,
                       uint8_t (&window)[WINDOW_SIZE]) {
    unsigned int idx;
    if (is_write) idx = widx;
    else idx = ridx;
    for (unsigned int i = 0; i < size; i++) {
        uint8_t val = ((uint8_t *)buf)[i];
        // Hack: skip NULLs to get free UTF-16 support
        // Also skip punctuation
        switch (val) {
            case 0: case '!': case '"': case '#': case '$':
            case '%': case '&': case '\'': case '(': case ')':
            case '*': case '+': case ',': case '-': case '.':
            case '/': case ':': case ';': case '<': case '=':
            case '>': case '?': case '@': case '[': case '\\':
            case ']': case '^': case '_': case '`': case '{':
            case '|': case '}': case '~':
                continue;
        }

        if ('a' <= val && val <= 'z') val &= ~0x20;
        window[idx++] = val;
        if (idx >= WINDOW_SIZE) idx -= WINDOW_SIZE;
    }

    unsigned int midx = idx;
    char search[WINDOW_SIZE+1] = {};
    char search_tmp[WINDOW_SIZE+1] = {};
    memcpy(search, window+midx, WINDOW_SIZE-midx);
    memcpy(search+(WINDOW_SIZE-midx), window, midx);
    memcpy(search_tmp, search, WINDOW_SIZE);
    critbit0_node *nearest = (critbit0_node *)t.root;
    for (int i = MINWORD; i < WINDOW_SIZE; i++) {
        search_tmp[i] = '\0';
        if(critbit0_contains(&t, search_tmp, &nearest))
            matches[search_tmp]++;
        search_tmp[i] = search[i];
    }
    if (is_write) widx = idx;
    else ridx = idx;
    return 1;
}

int mem_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, false, read_window);

}

int mem_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {
    return mem_callback(env, pc, addr, size, buf, true, write_window);
}

FILE *mem_report = NULL;

bool init_plugin(void *self) {
    panda_cb pcb;

    printf("Initializing plugin manyss_crit\n");

    panda_arg_list *args = panda_get_args("manyss_crit");

    const char *prefix = panda_parse_string(args, "name", "manyss_crit");
    char stringsfile[128] = {};
    sprintf(stringsfile, "%s_search_strings.txt", prefix);

    printf ("search strings file [%s]\n", stringsfile);

    std::ifstream search_strings(stringsfile);
    if (!search_strings) {
        printf("Couldn't open %s; no strings to search for. Exiting.\n", stringsfile);
        return false;
    }

    // Format: strings, one per line, uppercase
    std::string line;
    size_t nstrings = 0;
    bool too_short = false;
    bool too_long = false;
    while(std::getline(search_strings, line)) {
        if (line.length() > WINDOW_SIZE) {
            too_long = true;
            continue;
        }
        if (line.length() < MINWORD) {
            too_short = true;
            continue;
        }
        critbit0_insert(&t, line.c_str());
        if (nstrings % 100000 == 1) {
            printf("*");
            fflush(stdout);
        }
        nstrings++;
    }
    printf("\nAdded %zu strings to the hash table.\n", nstrings);
    if (too_long)
        printf("WARNING: Some lines in the input were too long (more than %d characters) and were skipped.\n", WINDOW_SIZE);
    if (too_short)
        printf("WARNING: Some lines in the input were too short (less than %d characters) and were skipped.\n", MINWORD);

    char matchfile[128] = {};
    sprintf(matchfile, "%s_string_matches.txt", prefix);
    mem_report = fopen(matchfile, "w");
    if(!mem_report) {
        printf("Couldn't write report:\n");
        perror("fopen");
        return false;
    }

    // Enable memory logging
    panda_enable_memcb();

    pcb.virt_mem_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_WRITE, pcb);
    pcb.virt_mem_read = mem_read_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_READ, pcb);


    return true;
}

void uninit_plugin(void *self) {
    for (auto &kvp : matches)
        if (kvp.second)
            fprintf(mem_report, "%s %u\n", kvp.first.c_str(), kvp.second);
    fclose(mem_report);
}
