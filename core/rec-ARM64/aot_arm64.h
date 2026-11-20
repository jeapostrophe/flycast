/*
	retro-trainer PLAN-handheld HH-23/HH-35: the SH4 arm64 recompiler's AOT form, which runs a
	game's blocks from an image compiled on the Mac, on a host that maps no executable memory.
	aot_arm64.cpp says what each mode does and holds the image format.
 */
#pragma once
#include "types.h"
#include <string>

// The AOT form exists for the Apple arm64 hosts, the Mac that makes images and the devices that run
// them; everywhere else the stubs below keep the stock recompiler.
#if FEAT_SHREC == DYNAREC_JIT && HOST_CPU == CPU_ARM64 && defined(__APPLE__)
#define FEAT_SH4_AOT
#endif

struct RuntimeBlockInfo;
typedef void (*DynarecCodeEntryPtr)();

namespace aot
{

enum Mode {
	Off,	// the stock recompiler
	Shape,	// the JIT, emitting AOT-shaped blocks, each logged
	Emit,	// re-emit a shape log's blocks into an image, then exit
	Load,	// run from the image; a block it lacks stops the process
	Interp,	// run from the image; a block it lacks runs on the interpreter
};

// The stubs every AOT-shaped block reaches through the import table, and the mainloop's labels
// the image carries (their offsets in its code), each with its import's name.
#define AOT_STUBS(X) \
	X(Mainloop, "mainloop") X(NoUpdate, "no_update") X(IntcSched, "intc_sched") X(Miss, "miss") \
	X(DoInterrupts, "do_interrupts") X(EndMainloop, "end_mainloop") X(BlockCheckFail, "block_check_fail") \
	X(DoDispatch, "do_dispatch")
enum Stub {
#define AOT_STUB_ENUM(id, name) Stub##id,
	AOT_STUBS(AOT_STUB_ENUM)
#undef AOT_STUB_ENUM
	StubCount
};

constexpr u32 BlockAlign = 16;
static inline u32 alignBlock(u32 size) { return (size + BlockAlign - 1) & ~(BlockAlign - 1); }

#ifdef FEAT_SH4_AOT

// From the frontend (libretro.cpp, at each game load): the mode the next Init puts in force, the
// image a Load or Interp runs, the log Shape writes and Emit reads, and for Emit the LC_UUID of the
// core build that will load the image (none: this one). `corrupt`: Emit's address of a block to
// emit wrongly, Interp's number of cycles to charge too many per interpreted block (red receipts).
void configure(const char *mode, const char *image, const char *log, u32 corrupt, const char *coreUuid);
// What the core did with the image, once per decision (admit()'s): true while one is waiting for
// the frontend, which retro_run hands it on the frontend's thread.
bool takeReport(int& admitted, std::string& detail);
Mode configured();
Mode mode();
// Blocks hold no host address, are never linked, and each checks its own bytes.
static inline bool shaped() { return mode() != Off; }
// No code cache: the blocks and the mainloop are the image's.
static inline bool imageOnly() { return mode() == Load || mode() == Interp; }
// Whether imgread should take the content's digest (the image names its game by it).
bool wantsContentDigest();

// Sh4Recompiler::Init: put the configured mode in force; Sh4Recompiler::Run: true when the
// mainloop may run (Emit writes its image and exits here; an image refused runs the interpreter).
void beginInit();
bool admit();

// The import table x27 holds in an AOT-shaped mainloop, and the slot of each thing a block reaches.
void **imports();
u32 slotOf(const void *fnOrData);
u32 slotOfOpcode(u16 op);
u32 slotOfStub(Stub stub);
// GenMainloop (the JIT's stubs) or the image (its own) names where each stub is.
void setStub(Stub stub, void *addr);
void *stub(Stub stub);
// GenMainloop's code, which an image carries at its start (Shape logs its digest, Emit copies it).
void stubsGenerated(const u8 *code, u32 size);

// Shape: log a compiled block. Every AOT-shaped block starts BlockAlign-aligned.
void blockCompiled(const RuntimeBlockInfo *block);

// Load, Interp: rdv_FailedToFindBlock's and rdv_BlockCheckFail's forms; resetCache drops what
// the interpreter has decoded.
DynarecCodeEntryPtr miss(u32 pc);
DynarecCodeEntryPtr checkFailed(u32 addr);
void resetCache();

#else
// Every other recompiler is the stock one.
static inline void configure(const char *, const char *, const char *, u32, const char *) {}
static inline bool takeReport(int&, std::string&) { return false; }
static inline Mode configured() { return Off; }
static inline Mode mode() { return Off; }
static inline bool shaped() { return false; }
static inline bool imageOnly() { return false; }
static inline bool wantsContentDigest() { return false; }
static inline void beginInit() {}
static inline bool admit() { return true; }
static inline void blockCompiled(const RuntimeBlockInfo *) {}
static inline DynarecCodeEntryPtr miss(u32) { return nullptr; }
static inline DynarecCodeEntryPtr checkFailed(u32) { return nullptr; }
static inline void resetCache() {}
static inline void **imports() { return nullptr; }
static inline u32 slotOf(const void *) { return 0; }
static inline u32 slotOfOpcode(u16) { return 0; }
static inline u32 slotOfStub(Stub) { return 0; }
static inline void setStub(Stub, void *) {}
static inline void *stub(Stub) { return nullptr; }
static inline void stubsGenerated(const u8 *, u32) {}
#endif

}
