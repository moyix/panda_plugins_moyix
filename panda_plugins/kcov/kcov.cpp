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

#include "panda_plugin.h"

}

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#include <zlib.h>

const char *prefix;
uint8_t kern[0x80000000 >> 3] = {};

static int before_block_exec(CPUState *env, TranslationBlock *tb) {
    // Only count kernel basic blocks
    if (tb->pc < 0x80000000 || tb->pc > 0xFFFFFFFF) return 0;
    for (target_ulong addr = tb->pc ; addr < tb->pc + tb->size; addr++) {
        unsigned int byte_offset = (addr - 0x80000000) / 8;
        unsigned int bit_offset =  (addr - 0x80000000) % 8;
        kern[byte_offset] |= (1 << bit_offset);
    }
    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec };

    panda_arg_list *args = panda_get_args("kcov");
    prefix = panda_parse_string(args, "name", "kcov");
    printf("kcov: will log to %s_kcov.dat.gz\n", prefix);

    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
 
    return true;
}

void uninit_plugin(void *self) {
    char logfile[260] = {};
    sprintf(logfile, "%s_kcov.dat.gz", prefix);
    gzFile bblog = gzopen(logfile, "w");
    if (!bblog) {
        perror("gzopen");
        return;
    }
    int written = gzwrite(bblog, kern, sizeof(kern));
    printf("kcov: wrote %d bytes to log file.\n", written);
    gzclose(bblog);
}
