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

#include "rr_log.h"
#include "panda_plugin.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

}

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#include <fstream>
#include <vector>
#include <algorithm>

#if TARGET_LONG_SIZE == 4 
#define PRItlx "x"
#elif TARGET_LONG_SIZE == 8
#define PRItlx PRIx64 
#else
#error TARGET_LONG_SIZE undefined
#endif

FILE *pluginlog;
const char *outdir;
std::vector<target_ulong> pcs;

static void dump_mod(CPUState *env, const char *name, target_ulong start, target_ulong size) {
    FILE *f = fopen(name, "wb");
    uint8_t buf[0x1000];
    uint8_t zeros[0x1000] = {};
    for (target_ulong addr = start; addr < start+size; addr += 0x1000) {
        if (-1 == panda_virtual_memory_rw(env, addr, buf, 0x1000, false)) {
            fwrite(zeros, 0x1000, 1, f);
        }
        else {
            fwrite(buf, 0x1000, 1, f);
        }
    }
    fclose(f);
}

static int before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (tb->pc < 0x80000000 || tb->pc > 0xFFFFFFFF) return 0;

    auto begin = std::lower_bound(pcs.begin(), pcs.end(), tb->pc);
    auto end = std::upper_bound(pcs.begin(), pcs.end(), tb->pc + tb->size - 1);
    
    if (begin == end) {
        // Nothing to see here, move along
        return 0;
    }

    OsiModules *kms = get_modules(env);
    if (kms == NULL) {
        // No luck listing mods this time, try again later
        printf("PC match but failed to list kernel modules, will try again later...\n");
        return 0;
    }
    else {
        bool found = false;
        unsigned int i;

        for (i = 0; i < kms->num; i++) {
            if (kms->module[i].base <= tb->pc && tb->pc < kms->module[i].base + kms->module[i].size) {
                found = true;
                break;
            }
        }

        if (!found) {
            for (auto p = begin; p != end; ++p) {
                fprintf(pluginlog, TARGET_FMT_lx " no_mod\n", *p);
            }
        }
        else {
            for (auto p = begin; p != end; ++p) {
                fprintf(pluginlog, TARGET_FMT_lx " %s %s\n", *p, kms->module[i].name, kms->module[i].file);
            }
            char mod[128];
            sprintf(mod, "%s/%08" PRItlx ".%s", outdir, tb->pc, kms->module[i].name);
            dump_mod(env, mod, kms->module[i].base, kms->module[i].size);
        }

        // No need to search for these any more. Either we found
        // the correct module and dumped it or it was unknown.
        pcs.erase(begin, end);

        // We can terminate early if we're done searching
        if (pcs.empty())
            rr_end_replay_requested = 1;
    }
    free_osimodules(kms);
    return 0;
}

bool init_plugin(void *self) {
    panda_require("osi");
    if(!init_osi_api()) return false;

    panda_arg_list *args = panda_get_args("kmodcheck");
    outdir = panda_parse_string(args, "outdir", ".");
    const char *logname = panda_parse_string(args, "log", "kmodcheck.log");
    const char *pcfile = panda_parse_string(args, "pcfile", "kmodcheck.pcs");

    pluginlog = fopen(logname, "w");
    if (!pluginlog) {
        printf("Couldn't open supplied log filename %s for writing. Exiting.\n", logname);
        return false;
    }
    
    std::ifstream pcf(pcfile);
    if (!pcf) {
        printf("Couldn't open %s; no PCs to search for. Exiting.\n", pcfile);
        return false;
    }

    target_ulong pc;
    while (pcf >> std::hex >> pc) {
        pcs.push_back(pc);
    }
    pcf.close();
    std::sort(pcs.begin(), pcs.end());

    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
    fclose(pluginlog);
}
