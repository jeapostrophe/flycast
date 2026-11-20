#pragma once
#include "types.h"

namespace virtmem
{

struct Mapping {
	u64 start_address, end_address;
	u64 memoffset, memsize;
	bool allow_writes;
};

// Platform specific vmemory API
// To initialize (maybe) the vmem subsystem
bool init(void **vmem_base_addr, void **sh4rcb_addr, size_t ramSize);
// To reset the on-demand allocated pages.
void reset_mem(void *ptr, unsigned size_bytes);
// To handle a fault&allocate an ondemand page.
void ondemand_page(void *address, unsigned size_bytes);
// To create the mappings in the address space.
void create_mappings(const Mapping *vmem_maps, unsigned nummaps);
// Just tries to wipe as much as possible in the relevant area.
void destroy();
// A host-provided source of executable memory, installed by the shell.
//
// Some hosts will not let a process execute pages it mapped itself: only memory
// the host prepared for it will run. An iOS 26 device with SPTM/TXM is one, and
// libretro's RETRO_ENVIRONMENT_EXEC_MEM_ALLOC is how a frontend hands such
// memory to a core. alloc() returns two mappings of the same physical pages: rx
// to execute from, rw to write through.
//
// While an allocator is installed it is the ONLY source of JIT memory:
// prepare_jit_block() maps nothing itself and returns false when the host has
// none to give, so that each recompiler falls back to its interpreter rather
// than emitting code it may not branch into. Only the two-address-space
// (FEAT_NO_RWX_PAGES) overload can use it, and only the POSIX backend honours
// it today — win_vmem and libnx_vmem ignore an installed allocator.
using JitAllocator = bool (*)(size_t size, void **rx, void **rw);
using JitDeallocator = void (*)(void *rx);
void setJitAllocator(JitAllocator alloc, JitDeallocator dealloc);
// The installed allocator, or nullptr.
JitAllocator getJitAllocator();
// The installed deallocator, or nullptr.
JitDeallocator getJitDeallocator();
// While denied, prepare_jit_block() (POSIX) maps nothing and returns false, so each recompiler
// falls back to its interpreter: the SH4 AOT image modes run the process as a host with no JIT
// would (rec-ARM64/aot_arm64.cpp).
void setJitDenied(bool denied);
bool jitDenied();

// Given a block of data in the .text section, prepares it for JIT action.
// both code_area and size are page aligned. Returns success.
bool prepare_jit_block(void *code_area, size_t size, void **code_area_rwx);
// Same as above but uses two address spaces one with RX and RW protections.
// Note: this function doesnt have to be implemented, it's a fallback for the above one.
//
// A ZERO rx_offset is meaningful and must be handled: it means only one mapping
// could be had, so the r-w address is also the r-x one. CC_RW2RX/CC_RX2RW are
// then the identity, and code the recompiler writes through it becomes
// executable at once — which is why a caller that toggles W^X protection must
// still do so at a zero offset, and must not at a non-zero one.
bool prepare_jit_block(void *code_area, size_t size, void **code_area_rw, ptrdiff_t *rx_offset);
// This might not need an implementation (ie x86/64 cpus).
void flush_cache(void *icache_start, void *icache_end, void *dcache_start, void *dcache_end);
// Change a code buffer permissions from r-x to/from rw-
void jit_set_exec(void* code, size_t size, bool enable);
// Release a jit block previously allocated by prepare_jit_block
void release_jit_block(void *code_area, size_t size);
// Release a jit block previously allocated by prepare_jit_block (with dual RW and RX areas)
void release_jit_block(void *code_area1, void *code_area2, size_t size);

bool region_lock(void *start, std::size_t len);
bool region_unlock(void *start, std::size_t len);
bool region_set_exec(void *start, std::size_t len);

} // namespace vmem
