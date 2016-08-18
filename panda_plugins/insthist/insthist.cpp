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
#include "panda/panda_common.h"
#include "rr_log.h"
#include <capstone/capstone.h>

}

#include <map>
#include <string>

typedef std::map<std::string,int> instr_hist;


// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#define WINDOW_SIZE 100

csh handle;
cs_insn *insn;
bool init_capstone_done = false;
target_ulong asid;
int sample_rate = 100;
FILE *histlog;

// PC => Mnemonic histogram
std::map<target_ulong,instr_hist> code_hists;

// PC => number of instructions in the TB
std::map<target_ulong,int> tb_insns;

// Circular buffer PCs in the window
target_ulong window[WINDOW_SIZE] = {};

// Rolling histogram of PCs
instr_hist window_hist;
uint64_t window_insns = 0;
uint64_t bbcount = 0;

void init_capstone(CPUState *env) {
    cs_arch arch;
    cs_mode mode;
#ifdef TARGET_I386
    arch = CS_ARCH_X86;
    mode = env->hflags & HF_LMA_MASK ? CS_MODE_64 : CS_MODE_32;
#elif defined(TARGET_ARM)
    arch = CS_ARCH_ARM;
    mode = env->thumb ? CS_MODE_THUMB : CS_MODE_ARM;
#endif

    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        printf("Error initializing capstone\n");
    }
    init_capstone_done = true;
}

void add_hist(instr_hist &a, instr_hist &b) {
    for (auto &kvp : b) a[kvp.first] += kvp.second;
}

void sub_hist(instr_hist &a, instr_hist &b) {
    for (auto &kvp : b) a[kvp.first] -= kvp.second;
}

void print_hist(instr_hist &ih, uint64_t window_insns) { 
    fprintf(histlog, "%" PRIu64 " ", rr_get_guest_instr_count());
    fprintf(histlog, "{");
    for (auto &kvp : ih) {
        // Don't print the mnemonic if it wasn't seen. Saves log space.
        if (kvp.second)
            fprintf (histlog, "\"%s\": %f, ", kvp.first.c_str(), kvp.second/(float)window_insns);
    }
    fprintf(histlog, "}\n");
}

// During retranslation we may end up with different
// instructions. Since we don't have TB generations we just
// remove it from the rolling histogram first.
void clear_hist(target_ulong pc) {
    for (int i = 0; i < WINDOW_SIZE; i++) {
        if (window[i] == pc) {
            window[i] = 0;
            window_insns -= tb_insns[pc];
            sub_hist(window_hist, code_hists[pc]);
        }
    }
}

static int after_block_translate(CPUState *env, TranslationBlock *tb) {
    size_t count;
    uint8_t mem[1024] = {};

    if (asid && panda_current_asid(env) != asid) return 0;

    if (!init_capstone_done) init_capstone(env);

    if (code_hists.find(tb->pc) != code_hists.end()) {
        clear_hist(tb->pc);
        return 0;
    }

    panda_virtual_memory_rw(env, tb->pc, mem, tb->size, false);
    count = cs_disasm_ex(handle, mem, tb->size, tb->pc, 0, &insn);
    for (unsigned i = 0; i < count; i++)
        code_hists[tb->pc][insn[i].mnemonic]++;
    tb_insns[tb->pc] = count;
    return 1;
}

static int before_block_exec(CPUState *env, TranslationBlock *tb) {
    if (asid && panda_current_asid(env) != asid) return 0;

    if (window[bbcount % WINDOW_SIZE] != 0) {
        target_ulong old_pc = window[bbcount % WINDOW_SIZE];
        window_insns -= tb_insns[old_pc];
        sub_hist(window_hist, code_hists[old_pc]);
    }

    window[bbcount % WINDOW_SIZE] = tb->pc;
    window_insns += tb_insns[tb->pc];
    add_hist(window_hist, code_hists[tb->pc]);

    bbcount++;

    if (bbcount % sample_rate == 0) {
        // write out to the histlog
        print_hist(window_hist, window_insns);
    }
    return 1;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    panda_arg_list *args = panda_get_args("insthist");
    const char *name = panda_parse_string(args, "name", "insthist");
    asid = panda_parse_ulong(args, "asid", 0);
    sample_rate = panda_parse_uint32(args, "sample_rate", 1000);

    char fname[260];
    sprintf(fname, "%s_insthist.txt", name);
    histlog = fopen(fname, "w");

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
    print_hist(window_hist, window_insns);
    fclose(histlog);
}
