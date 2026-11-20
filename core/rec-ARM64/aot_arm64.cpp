/*
	retro-trainer PLAN-handheld HH-23/HH-35: the SH4 arm64 recompiler's AOT form, for games that
	run without the MMU. aot::configure (libretro.cpp: the frontend's `rt_aot_image` option, or the
	FLYCAST_AOT* environment) chooses a mode, in force from the next Sh4Recompiler::Init:

	- Shape (the Mac's tooling): the JIT, emitting AOT-shaped blocks (rec_arm64.cpp, wherever it
	  tests aot::shaped()). Such a block holds no host address: everything it calls or reads that
	  is not the guest's context reaches it through the import table x27 holds (helpers, the
	  interpreter's handlers by opcode-table row, the canonical implementations, sin_table, mem_b,
	  the stubs); it is never linked to another; it checks its own bytes at every entry (read_only
	  is never set, so no page is protected, and the passes that read a block's neighbours or
	  trust its pages never run); and it never uses a fast memory access, which a fault would
	  rewrite in place. So its bytes are a function of its address, its bytes, PR, SZ and RM==1 of
	  the FPSCR it was compiled under, and this build, and they run anywhere. (A block outside
	  area-3 RAM, in BIOS or ROM, has no check of its own, as in stock: its bytes are compared where
	  it is installed.) Every compiled block is logged to `log` (blockCompiled). Configured from
	  the environment at retro_init, every AOT mode denies the ARM7 and DSP recompilers their JIT,
	  so that a Shape run and an image's run differ in the SH4 only.
	- Emit: re-compiles each distinct block of a Shape log from its logged bytes into plain RW
	  memory, checks its code against the JIT's (length and fnv64, and the stubs' too: the two
	  processes load the core at different slides, so a host address in any block would differ),
	  writes `image`.code and `image`.meta, and exits the process (emitAll). `corrupt` names a
	  block to emit from wrong bytes while the meta keeps its true ones (the red receipt).
	- Load: no code cache; the mainloop and blocks are the image's, a block installed where the
	  JIT would compile one, when the image holds the block for that address whose bytes guest
	  memory holds now (and, for a block with an FPU op, whose FPSCR mode is the current one); a
	  block the image lacks stops the process. The SH4 maps no executable memory.
	- Interp: Load, but a block the image lacks runs on the interpreter, charged the cycles the
	  decoder counts for it once at entry, as the recompiler charges them (runInterp), not the
	  interpreter's own 8 a cycle. This is the mode for a device. `corrupt` there charges that many
	  cycles more per interpreted block (the red receipt for the cycle model).

	admit(), which Sh4Recompiler::Run asks before the mainloop runs, opens the image in Load and
	Interp and refuses one made for another core build or another game (checkHeader): the
	interpreter runs the game instead. Either way the frontend hears of it (takeReport).
	The image format is ImageHeader's.
 */
#include "types.h"

#include "aot_arm64.h"
#ifdef FEAT_SH4_AOT
#include "arm64_unwind.h"
#include "hw/sh4/dyna/ngen.h"
#include "hw/sh4/dyna/blockmanager.h"
#include "hw/sh4/dyna/shil.h"
#define SHIL_MODE 2
#include "hw/sh4/dyna/shil_canonical.h"
#include <mutex>
#include "hw/sh4/sh4_core.h"
#include "hw/sh4/sh4_interrupts.h"
#include "hw/sh4/sh4_interpreter.h"
#include "hw/sh4/sh4_mem.h"
#include "hw/sh4/sh4_rom.h"
#include "hw/sh4/sh4_sched.h"
#include "hw/sh4/sh4_opcode_list.h"
#include "hw/sh4/modules/mmu.h"
#include "oslib/virtmem.h"
#include "cfg/option.h"
#include "stdclass.h"

#include <dlfcn.h>
#include <unistd.h>
#include <algorithm>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>
#ifdef __APPLE__
#include <mach-o/loader.h>
#endif
#if !defined(TARGET_IPHONE)
// The Mac's tooling: Shape, Emit, and the VM report. A device core carries Load and Interp alone.
#define AOT_TOOLING
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

void describeMainloopFrame(Arm64UnwindInfo& unwinder);
void aotHelperImports(void (*add)(const char *name, const void *ptr));
extern u32 unprotected_blocks;

namespace aot
{

#define AOT_CHECK(cond, ...) do { if (!(cond)) { \
		fprintf(stderr, "flycast AOT: "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); \
		fflush(stderr); die("flycast AOT check failed"); } } while (0)

/*
	**The image format: this is its one home** (retro-trainer's cores/README.md, "AOT images", says
	how an image is made, keyed and shipped). Its meta, little-endian, is this header (the same
	104 bytes, magic and version as mupen64plus_next's, so retro-trainer's tools read both), then
	  u32 stub_size, u32 stub_off[StubCount]   the mainloop's code, at the start of the code
	  per block: u32 vaddr, key (KEY_*), size (its bytes), code_off, code_len,
	             then its bytes, padded to whole u32s
	and its code is the stubs' bytes, then each block's at its code_off (BlockAlign apart).
	A load refuses an image unless each checked field is this core's (checkHeader, which names the
	first that differs, with both values).
 */
struct ImageHeader {
	u32 magic;			// MAGIC
	u32 version;		// VERSION, which fixes everything else here, the header's size too
	u32 import_count;	// the import table's entries
	u32 nblocks;
	u8 core_uuid[16];	// the LC_UUID of the core build that may load it (Emit writes the one it is
						// told, FLYCAST_AOT_CORE_UUID, or its own)
	u8 emit_uuid[16];	// the LC_UUID of the build that emitted it: not checked here;
						// retro-trainer's `cores.sh aot pin` requires the Mac build its lock pins
	u8 rom_md5[16];		// the game's content: MD5 of settings.network.md5's game and bios digests
						// (flycast takes the BIOS's under GGPO only, so it is zero otherwise). A
						// block's bytes are checked where it is installed, but its neighbours and
						// timing are the game's, so another game or revision is refused here
	u64 imports_hash;	// fnv64 of the import table's names, in order
	u64 layout_hash;	// fnv64 of every Sh4Context member the code addresses off x28, by name,
						// offset and size, with the struct sizes and the FPCB's place
	u64 abi_hash;		// fnv64 of the constants the code and this core's C++ share (ABI_TEXT)
	u32 sh4_clock;		// config::Sh4Clock, which each block's cycles were scaled by (the shared
						// reader names this slot count_per_op)
	u32 ram_size;		// RAM_SIZE, which every dynamic exit masks by (count_per_op_denom_pot there)
	u32 code_size;		// the bytes between rt_aot_code and rt_aot_code_end
	u32 reserved;		// padding to the header's 8-byte alignment: written 0, never read
};
static_assert(sizeof(ImageHeader) == 104, "the header's size is part of VERSION");
constexpr u32 MAGIC = 0x31415452;	// "RTA1"
constexpr u32 VERSION = 3;

// A block's key: the FPSCR mode it was compiled under, and whether it has an FPU op (a block
// without one compiles the same under every mode, so it is installed under any).
constexpr u32 KEY_PR = 1, KEY_SZ = 2, KEY_RTZ = 4, KEY_FPU = 8, KEY_MODE = KEY_PR | KEY_SZ | KEY_RTZ;
constexpr u32 KEYS_KNOWN = KEY_MODE | KEY_FPU;

static u32 modeKey(const fpscr_t& f)
{
	return (f.PR ? KEY_PR : 0) | (f.SZ ? KEY_SZ : 0) | (f.RM == 1 ? KEY_RTZ : 0);
}

static fpscr_t keyFpscr(u32 key)
{
	fpscr_t f{};
	f.PR = (key & KEY_PR) != 0;
	f.SZ = (key & KEY_SZ) != 0;
	f.RM = (key & KEY_RTZ) != 0 ? 1 : 0;
	return f;
}

/**** configuration ****/

static struct {
	Mode mode = Off;
	std::string image, log;
	u32 corrupt = 0;
	bool hasCoreUuid = false;
	u8 coreUuid[16]{};
} cfg;
static Mode active = Off;

static struct {
	unsigned long compiled, installs, misses, interpRuns, interpInsns, checkFails, emitDiffers;
} stats;

// 32 hex digits into 16 bytes, dashes skipped (an LC_UUID as otool prints it); false otherwise
static bool parseHex16(const char *s, u8 out[16])
{
	int n = 0;
	memset(out, 0, 16);
	for (; *s && n < 32; s++)
	{
		if (*s == '-')
			continue;
		int v = *s >= '0' && *s <= '9' ? *s - '0' : *s >= 'a' && *s <= 'f' ? *s - 'a' + 10 : *s >= 'A' && *s <= 'F' ? *s - 'A' + 10 : -1;
		if (v < 0)
			return false;
		out[n / 2] |= (u8)(n & 1 ? v : v << 4);
		n++;
	}
	return n == 32 && !*s;
}

static void releaseImage();
enum Admission { Unknown, Admitted, Refused };
static Admission admission = Unknown;

void configure(const char *mode, const char *image, const char *log, u32 corrupt, const char *coreUuid)
{
	Mode m = Off;
	if (mode != nullptr && *mode)
	{
		if (!strcmp(mode, "load"))
			m = Load;
		else if (!strcmp(mode, "interp"))
			m = Interp;
#ifdef AOT_TOOLING
		else if (!strcmp(mode, "shape"))
			m = Shape;
		else if (!strcmp(mode, "emit"))
			m = Emit;
		else
			AOT_CHECK(false, "the mode %s is none of load, interp, shape, emit", mode);
#else
		else
			AOT_CHECK(false, "the mode %s is neither load nor interp, the only ones a device core has", mode);
#endif
	}
	// the next game's run opens and checks the image its configuration names
	admission = Unknown;
	releaseImage();
	cfg.mode = m;
	cfg.image = image != nullptr ? image : "";
	cfg.log = log != nullptr ? log : "";
	cfg.corrupt = corrupt;
	cfg.hasCoreUuid = coreUuid != nullptr && *coreUuid;
	AOT_CHECK(!cfg.hasCoreUuid || parseHex16(coreUuid, cfg.coreUuid), "%s is not a uuid", coreUuid);
	// every AOT mode runs the process as a host with no JIT would, but for Shape's SH4 (driver.cpp);
	// a recompiler that already has its memory (the ARM7's, from retro_init) keeps it
	virtmem::setJitDenied(m != Off);
}

Mode configured()
{
	return cfg.mode;
}

Mode mode()
{
	return active;
}

bool wantsContentDigest()
{
	return cfg.mode != Off;
}

/**** the frontend's report ****/

// admit() runs on the emulator's thread when rendering is threaded, retro_run on the frontend's
static std::mutex reportMutex;
static bool reportPending;
static int reportAdmitted;
static std::string reportDetail;

static void report(bool admitted, const std::string& detail)
{
	std::lock_guard<std::mutex> lock(reportMutex);
	reportPending = true;
	reportAdmitted = admitted;
	reportDetail = detail;
}

bool takeReport(int& admitted, std::string& detail)
{
	std::lock_guard<std::mutex> lock(reportMutex);
	if (!reportPending)
		return false;
	reportPending = false;
	admitted = reportAdmitted;
	detail = reportDetail;
	return true;
}

/**** the import table ****/

static std::vector<std::string> importNames;
static std::vector<void *> importTable;
static std::unordered_map<const void *, u32> slotByPtr;
static std::unordered_map<const void *, u32> slotByRow;	// an opcode table row -> its handler's slot
static u32 firstStubSlot;

static void addImport(const std::string& name, const void *ptr)
{
	slotByPtr.emplace(ptr, (u32)importTable.size());	// a pointer listed twice keeps its first slot
	importNames.push_back(name);
	importTable.push_back(const_cast<void *>(ptr));
}

static void buildImports()
{
	if (!importTable.empty())
		return;
	aotHelperImports([](const char *name, const void *ptr) { addImport(name, ptr); });
	addImport("sin_table", &sin_table);
	addImport("mem_b", &mem_b[0]);
	firstStubSlot = (u32)importTable.size();
#define AOT_STUB_IMPORT(id, name) importNames.push_back("stub:" name); importTable.push_back(nullptr);
	AOT_STUBS(AOT_STUB_IMPORT)
#undef AOT_STUB_IMPORT
	const sh4_opcodelistentry *rows, *missing;
	size_t nrows = sh4_opcode_rows(&rows, &missing);
	for (size_t i = 0; i <= nrows; i++)
	{
		const sh4_opcodelistentry *row = i < nrows ? &rows[i] : missing;
		slotByRow[row] = (u32)importTable.size();
		importNames.push_back("op" + std::to_string(i) + ":" + row->diss);
		importTable.push_back((void *)row->oph);
	}
	shil_canonical_list([](const char *op, const char *fn, void *impl, void *) {
		addImport(std::string("canon:") + op + "." + fn, impl);
	}, nullptr);
	// an unsigned LDR's offset reaches 4095 slots
	AOT_CHECK(importTable.size() <= 4096, "%zu imports, more than an LDR off x27 reaches", importTable.size());
}

void **imports()
{
	return importTable.data();
}

u32 slotOf(const void *ptr)
{
	auto it = slotByPtr.find(ptr);
	AOT_CHECK(it != slotByPtr.end(), "an AOT-shaped block reaches %p, which is no import", ptr);
	return it->second;
}

u32 slotOfOpcode(u16 op)
{
	auto it = slotByRow.find(OpDesc[op]);
	AOT_CHECK(it != slotByRow.end(), "opcode %04x has no row", op);
	return it->second;
}

u32 slotOfStub(Stub s)
{
	return firstStubSlot + s;
}

void setStub(Stub s, void *addr)
{
	importTable[firstStubSlot + s] = addr;
}

void *stub(Stub s)
{
	return importTable[firstStubSlot + s];
}

static u64 fnv(u64 h, const void *p, size_t n)
{
	const u8 *b = (const u8 *)p;
	while (n--)
	{
		h ^= *b++;
		h *= 1099511628211ULL;
	}
	return h;
}
constexpr u64 FNV_BASIS = 1469598103934665603ULL;

static u64 importsHash()
{
	u64 h = FNV_BASIS;
	for (const std::string& name : importNames)
		h = fnv(h, name.c_str(), name.size() + 1);
	return h;
}

// Every Sh4Context member, in declaration order: the code addresses each off x28 (the registers
// through getRegOffset, the rest by name), so a layout that differs refuses the image.
#define AOT_CONTEXT(X) \
	X(sq_buffer) X(xf) X(fr) X(r) X(mac) X(r_bank) X(gbr) X(ssr) X(spc) X(sgr) X(dbr) X(vbr) X(pr) \
	X(fpul) X(pc) X(jdyn) X(sr) X(fpscr) X(old_sr) X(old_fpscr) X(CpuRunning) X(sh4_sched_next) \
	X(interrupt_pend) X(temp_reg) X(cycle_counter) X(doSqWrite)

// *gap names a member AOT_CONTEXT cannot be complete around (one before it, unlisted, would fit
// in the space before it), or is nullptr
static u64 layoutHash(const char **gap)
{
	u64 h = FNV_BASIS;
	size_t end = 0;
	*gap = nullptr;
#define AOT_MEMBER(m) { size_t off = offsetof(Sh4Context, m), size = sizeof(((Sh4Context *)nullptr)->m); \
		u32 w[2] = { (u32)off, (u32)size }; \
		if (*gap == nullptr && (off < end || off - end >= alignof(decltype(((Sh4Context *)nullptr)->m)))) *gap = #m; \
		h = fnv(h, #m, sizeof #m); h = fnv(h, w, sizeof w); end = off + size; }
	AOT_CONTEXT(AOT_MEMBER)
#undef AOT_MEMBER
	u32 sizes[4] = { (u32)sizeof(Sh4Context), (u32)offsetof(Sh4RCB, cntx), (u32)sizeof(Sh4RCB), (u32)FPCB_SIZE };
	return fnv(h, sizes, sizeof sizes);
}

#define AOT_XSTR(x) AOT_STR(x)
#define AOT_STR(x) #x
// What the code and this core's C++ agree on besides the layout: the time slice the stubs add,
// the registers each side keeps what in (x27 imports, x28 context, w29 next pc, the allocator's
// w19-w26 and s8-s15, x4 the call scratch: rec_arm64.cpp's, written out here), and the pointer
// size; the block alignment is hashed beside it (makeHeader).
static const char ABI_TEXT[] = "SH4_TIMESLICE=" AOT_XSTR(SH4_TIMESLICE)
		" regs=x27:imports,x28:ctx,w29:next_pc,w19-w26,s8-s15,x4:call sizeof(void*)=" AOT_XSTR(__SIZEOF_POINTER__);

static bool selfUuid(u8 out[16])
{
#ifdef __APPLE__
	Dl_info info;
	if (!dladdr((void *)&configure, &info) || info.dli_fbase == nullptr)
		return false;
	const mach_header_64 *mh = (const mach_header_64 *)info.dli_fbase;
	if (mh->magic != MH_MAGIC_64)
		return false;
	const load_command *lc = (const load_command *)(mh + 1);
	for (u32 i = 0; i < mh->ncmds; i++, lc = (const load_command *)((const u8 *)lc + lc->cmdsize))
		if (lc->cmd == LC_UUID)
		{
			memcpy(out, ((const uuid_command *)lc)->uuid, 16);
			return true;
		}
#endif
	return false;
}

static bool contentMd5(u8 out[16])
{
	static const u8 zero[16]{};
	if (!memcmp(settings.network.md5.game, zero, 16))
		return false;
	MD5Sum().add(settings.network.md5.game, 16).add(settings.network.md5.bios, 16).getDigest(out);
	return true;
}

enum { HEADER_NO_UUID = 1, HEADER_NO_MD5 = 2 };

// The header this core writes for an image of nblocks blocks and codeSize bytes, for the core
// build coreUuid (nullptr: this one), and the one a load compares against; nonzero (HEADER_*)
// when this core has no LC_UUID or the game no digest, those fields then zero.
static int makeHeader(ImageHeader& h, u32 nblocks, u32 codeSize, const u8 *coreUuid)
{
	memset(&h, 0, sizeof h);
	h.magic = MAGIC;
	h.version = VERSION;
	h.import_count = (u32)importTable.size();
	h.nblocks = nblocks;
	int missing = selfUuid(h.emit_uuid) ? 0 : HEADER_NO_UUID;
	memcpy(h.core_uuid, coreUuid != nullptr ? coreUuid : h.emit_uuid, 16);
	if (!contentMd5(h.rom_md5))
		missing |= HEADER_NO_MD5;
	const char *gap;
	h.imports_hash = importsHash();
	h.layout_hash = layoutHash(&gap);
	h.abi_hash = fnv(fnv(FNV_BASIS, ABI_TEXT, sizeof ABI_TEXT), &BlockAlign, sizeof BlockAlign);
	h.sh4_clock = (u32)(int)config::Sh4Clock;
	h.ram_size = RAM_SIZE;
	h.code_size = codeSize;
	return missing;
}

static std::string formatUuid(const u8 u[16])
{
	char s[40];
	snprintf(s, sizeof s, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
			u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
	return s;
}

// Why this core may not load an image with header h (the first field that differs, with both
// values); empty when it may.
static std::string checkHeader(const ImageHeader& h)
{
	ImageHeader w;
	int missing = makeHeader(w, h.nblocks, h.code_size, nullptr);
	char why[256];
#define AOT_FIELD(f, fmt) if (h.f != w.f) { snprintf(why, sizeof why, #f ": the image has " fmt ", this core " fmt, h.f, w.f); return why; }
#define AOT_BYTES(f, what) if (memcmp(h.f, w.f, 16)) { \
		return std::string(#f ": the image is for ") + what + " " + formatUuid(h.f) + ", this is " + formatUuid(w.f); }
	AOT_FIELD(magic, "%#x")
	AOT_FIELD(version, "%u")
	if (missing & HEADER_NO_UUID)
		return "core_uuid: this core has no LC_UUID to match";
	AOT_BYTES(core_uuid, "core")
	if (missing & HEADER_NO_MD5)
		return "rom_md5: this game's content has no digest to match";
	AOT_BYTES(rom_md5, "the game whose digest is")
	AOT_FIELD(import_count, "%u")
	AOT_FIELD(imports_hash, "%016llx")
	AOT_FIELD(layout_hash, "%016llx")
	AOT_FIELD(abi_hash, "%016llx")
	AOT_FIELD(sh4_clock, "%u")
	AOT_FIELD(ram_size, "%u")
#undef AOT_FIELD
#undef AOT_BYTES
	return "";
}

/**** Shape: the stubs and the log ****/

static const u8 *stubCode;
static u32 stubSize;
#ifdef AOT_TOOLING
static FILE *logFile;
static u64 loggedStubHash;
#endif

void stubsGenerated(const u8 *code, u32 size)
{
	stubCode = code;
	stubSize = size;
#ifdef AOT_TOOLING
	u64 h = fnv(FNV_BASIS, code, size);
	if (active == Shape && logFile != nullptr && h != loggedStubHash)
	{
		fprintf(logFile, "stubs %u %016llx\n", size, (unsigned long long)h);
		fflush(logFile);
		loggedStubHash = h;
	}
#endif
}

void blockCompiled(const RuntimeBlockInfo *block)
{
	AOT_CHECK(!mmu_enabled(), "the MMU is on: AOT-shaped blocks are for games without it");
	stats.compiled++;
#ifdef AOT_TOOLING
	if (active != Shape || logFile == nullptr)
		return;
	// a block without an FPU op compiles the same under every FPSCR mode: logged under none
	u32 key = block->has_fpu_op ? modeKey(block->fpu_cfg) | KEY_FPU : 0;
	fprintf(logFile, "%08x %x %u %u %016llx", block->vaddr, key, block->sh4_code_size, block->host_code_size,
			(unsigned long long)fnv(FNV_BASIS, (const void *)block->code, block->host_code_size));
	for (u32 i = 0; i < block->sh4_code_size; i += 2)
		fprintf(logFile, " %04x", IReadMem16(block->vaddr + i));
	fputc('\n', logFile);
	fflush(logFile);
#endif
}

/**** the VM report (the Mac's tooling): what this process maps executable ****/

static void vmReport(const char *when)
{
#ifdef AOT_TOOLING
	mach_vm_address_t addr = 0;
	mach_vm_size_t size;
	u32 wx = 0, x = 0, depth = 0;
	for (;;)
	{
		vm_region_submap_info_data_64_t info;
		mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
		if (mach_vm_region_recurse(mach_task_self(), &addr, &size, &depth, (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS)
			break;
		if (info.is_submap)
		{
			depth++;
			continue;
		}
		if (info.protection & VM_PROT_EXECUTE)
		{
			x++;
			if (info.protection & VM_PROT_WRITE)
				wx++;
		}
		addr += size;
	}
	fprintf(stderr, "flycast AOT VM (%s): %u executable regions, %u writable and executable\n", when, x, wx);
#else
	(void)when;
#endif
}

/**** Load and Interp: the image ****/

struct ImageBlock {
	u32 vaddr, key, size, codeOff, codeLen;
	const u16 *bytes;
};

// An image block whose own check failed though its bytes were found in guest memory (a corrupt
// image): never installed again, so the miss it leaves runs on the interpreter or stops a load.
static const u8 *badCode;
static void *imageLib;
static const u8 *imageCode;
static std::vector<ImageBlock> imageBlocks;	// by vaddr
static std::string imagePath;
static Arm64UnwindInfo imageUnwinder;
static std::vector<u8> imageFde;

static void releaseImage()
{
	badCode = nullptr;
	imageUnwinder.clear();
	imageBlocks.clear();
	imageCode = nullptr;
	imagePath.clear();
	if (imageLib != nullptr)
	{
		dlclose(imageLib);
		imageLib = nullptr;
	}
}

// Open the image at path and read its blocks, unless this core may not run it: then nothing stays
// open and the result says why (checkHeader's field, or what is malformed); empty when admitted.
static std::string openImage(const std::string& path)
{
	releaseImage();
	std::string why;
	const u8 *codeEnd;
	const u32 *meta, *metaEnd, *p;
	ImageHeader h;
	size_t left;
	u32 stubsEnd;
	imageLib = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
	if (imageLib == nullptr)
	{
		why = std::string("dlopen: ") + dlerror();
		goto refuse;
	}
	imageCode = (const u8 *)dlsym(imageLib, "rt_aot_code");
	codeEnd = (const u8 *)dlsym(imageLib, "rt_aot_code_end");
	meta = (const u32 *)dlsym(imageLib, "rt_aot_meta");
	metaEnd = (const u32 *)dlsym(imageLib, "rt_aot_meta_end");
	if (imageCode == nullptr || codeEnd == nullptr || meta == nullptr || metaEnd == nullptr || codeEnd < imageCode || metaEnd < meta)
	{
		why = "symbols: no rt_aot_code, rt_aot_code_end, rt_aot_meta or rt_aot_meta_end in order";
		goto refuse;
	}
	if ((size_t)(metaEnd - meta) * 4 < sizeof h)
	{
		why = "meta: shorter than a header";
		goto refuse;
	}
	memcpy(&h, meta, sizeof h);
	why = checkHeader(h);
	if (!why.empty())
		goto refuse;
	if (h.code_size != (size_t)(codeEnd - imageCode))
	{
		why = "code_size: the header says " + std::to_string(h.code_size) + " bytes, the image holds " + std::to_string(codeEnd - imageCode);
		goto refuse;
	}
	p = meta + sizeof h / 4;
	if ((size_t)(metaEnd - p) < 1 + StubCount)
	{
		why = "meta: no stub table";
		goto refuse;
	}
	if (p[0] > h.code_size)
	{
		why = "meta: the stubs overrun the code";
		goto refuse;
	}
	stubsEnd = p[0];
	for (u32 s = 0; s < StubCount; s++)
	{
		if (p[1 + s] >= p[0])
		{
			why = "meta: stub " + std::to_string(s) + " is outside the stubs";
			goto refuse;
		}
		setStub((Stub)s, (void *)(imageCode + p[1 + s]));
	}
	p += 1 + StubCount;
	for (u32 i = 0; i < h.nblocks; i++)
	{
		left = (size_t)(metaEnd - p);
		if (left < 5)
		{
			why = "meta: it ends inside block " + std::to_string(i);
			goto refuse;
		}
		ImageBlock b{ p[0], p[1], p[2], p[3], p[4], (const u16 *)(p + 5) };
		size_t words = (b.size + 3) / 4;
		if (b.size == 0 || (b.size & 1) || b.size > 2 * 4096 || left < 5 + words)
		{
			why = "meta: block " + std::to_string(i) + " has " + std::to_string(b.size) + " bytes or overruns the meta";
			goto refuse;
		}
		// the code bound without wraparound
		if (b.codeOff < stubsEnd || b.codeOff > h.code_size || b.codeLen > h.code_size - b.codeOff)
		{
			why = "meta: block " + std::to_string(i) + " overruns the code";
			goto refuse;
		}
		if (b.key & ~KEYS_KNOWN)
		{
			char k[160];
			snprintf(k, sizeof k, "block_flags: block %u (%08x) has key %#x, this core knows %#x", i, b.vaddr, b.key, KEYS_KNOWN);
			why = k;
			goto refuse;
		}
		imageBlocks.push_back(b);
		p += 5 + words;
	}
	if (p != metaEnd)
	{
		why = "meta: " + std::to_string(metaEnd - p) + " words after the last block";
		goto refuse;
	}
	std::stable_sort(imageBlocks.begin(), imageBlocks.end(), [](const ImageBlock& a, const ImageBlock& b) { return a.vaddr < b.vaddr; });
	// an exception thrown through the image's code unwinds as through the JIT's
	imageFde.assign(512, 0);
	imageUnwinder.start((void *)imageCode);
	describeMainloopFrame(imageUnwinder);
	AOT_CHECK(imageUnwinder.endAt(imageFde.data(), h.code_size) <= imageFde.size(), "the image's unwind info outgrew its buffer");
	imagePath = path;
	fprintf(stderr, "flycast AOT load: %s: %u blocks, %u bytes of code, emitted by core %s at %p\n", path.c_str(), h.nblocks,
			h.code_size, formatUuid(h.emit_uuid).c_str(), imageCode);
	return std::string();
refuse:
	releaseImage();
	return why.empty() ? "refused" : why;
}

// Whether guest memory holds `size` bytes `bytes` at vaddr
static bool guestHolds(u32 vaddr, const u16 *bytes, u32 size)
{
	if (const u8 *ram = GetMemPtr(vaddr, size))
		return !memcmp(ram, bytes, size);
	for (u32 i = 0; i < size; i += 2)
		if (IReadMem16(vaddr + i) != bytes[i / 2])
			return false;
	return true;
}

static const ImageBlock *findBlock(u32 pc)
{
	auto it = std::lower_bound(imageBlocks.begin(), imageBlocks.end(), pc, [](const ImageBlock& b, u32 a) { return b.vaddr < a; });
	const u32 mode = modeKey(Sh4cntx.fpscr);
	for (; it != imageBlocks.end() && it->vaddr == pc; ++it)
	{
		if ((it->key & KEY_FPU) && (it->key & KEY_MODE) != mode)
			continue;
		if (imageCode + it->codeOff != badCode && guestHolds(pc, it->bytes, it->size))
			return &*it;
	}
	return nullptr;
}

// Register b where the JIT would have compiled a block at its address, as bm_AddBlock registers one.
static DynarecCodeEntryPtr install(const ImageBlock& b)
{
	RuntimeBlockInfo *rbi = sh4Dynarec->allocateBlock();
	rbi->vaddr = rbi->addr = b.vaddr;
	rbi->code = (DynarecCodeEntryPtr)(imageCode + b.codeOff);
	rbi->host_code_size = b.codeLen;
	rbi->sh4_code_size = b.size;
	rbi->fpu_cfg = keyFpscr(b.key);
	rbi->has_fpu_op = (b.key & KEY_FPU) != 0;
	rbi->guest_cycles = rbi->guest_opcodes = rbi->host_opcodes = 0;
	rbi->temp_block = false;
	rbi->read_only = false;
	rbi->blockcheck_failures = 0;
	rbi->BranchBlock = rbi->NextBlock = NullAddress;
	rbi->pBranchBlock = rbi->pNextBlock = nullptr;
	rbi->relink_offset = rbi->relink_data = 0;
	rbi->BlockType = BET_DynamicJump;
	rbi->has_jcond = false;
	unprotected_blocks++;	// its destructor's count
	// bm_AddBlock puts CC_RW2RX(code) in the FPCB: an image has one mapping, so no offset (Init)
	AOT_CHECK((const void *)CC_RW2RX(rbi->code) == (const void *)rbi->code,
			"the code cache's offset %td moves the image's block at %08x", (ptrdiff_t)((const u8 *)CC_RW2RX(rbi->code) - (const u8 *)rbi->code), b.vaddr);
	bm_AddBlock(rbi);
	stats.installs++;
	return rbi->code;
}

/**** Interp: a block the image lacks, run on the interpreter ****/

struct InterpBlock {
	u32 vaddr, size, cycles;
	BlockEndType type;
	std::vector<u16> bytes;
	struct Division { u32 pc, reg[3]; bool isSigned; };
	std::vector<Division> divisions;	// where the decoder folds one (dec_FoldsDivision)
};
// A folded division's extent: its div0u or div0s and the 32 rotcl/div1 pairs (MatchDiv32's 65)
constexpr u32 FoldedDivisionBytes = 65 * 2;

// By FPCB slot, as the JIT's block would be found: a jump to another mirror of the address it was
// decoded at runs it as decoded there.
static std::unordered_map<u32, InterpBlock> interpBlocks;
// The blocks of the last resetCache, kept until the next miss: a handler runInterp runs can reset
// the cache (an MMUCR write, CCN_MMUCR_write), and the block it is running must outlive that.
static std::unordered_map<u32, InterpBlock> retiredInterpBlocks;

static u32 fpcbSlot(u32 pc)
{
	return (pc >> 1) & FPCB_MASK;
}

// Decode the block at pc as rdv_CompilePC would, for its extent and its cycles; false when the
// decoder raised an exception instead (Setup has then run it, as a compile would have).
static bool decode(u32 pc, InterpBlock& e)
{
	RuntimeBlockInfo rbi;
	if (!rbi.Setup(pc, Sh4cntx.fpscr))
		return false;
	e.vaddr = pc;
	e.size = rbi.sh4_code_size;
	e.cycles = rbi.guest_cycles;
	e.type = rbi.BlockType;	// after the optimiser, which can make a dynamic exit static
	e.bytes.resize(e.size / 2);
	for (u32 i = 0; i < e.size; i += 2)
		e.bytes[i / 2] = IReadMem16(pc + i);
	e.divisions.clear();
	for (u32 i = 0; i + FoldedDivisionBytes <= e.size; i += 2)
	{
		InterpBlock::Division d{ pc + i, {}, e.bytes[i / 2] != 0x0019 };
		if (dec_FoldsDivision(e.bytes[i / 2], pc + i, d.reg))
		{
			e.divisions.push_back(d);
			i += FoldedDivisionBytes - 2;	// the folded rotcl/div1 hold no division of their own
		}
	}
	return true;
}


/*
	Run e as an AOT-shaped block of it would run, from the miss stub (whose caller left w29 alone):
	- a block's bytes changed since it was decoded fail its check, and it is decoded again
	  (rdv_BlockCheckFail's recompile);
	- the time slice is checked at entry exactly as the block's prologue and the intc_sched stub
	  check it, the pc stored being the block's own address;
	- the block's cycles, the decoder's count scaled as the recompiler scales it, are charged
	  once, at entry, and nothing per instruction (the interpreter's own charge is CPU_RATIO, 8,
	  per cycle, its underclock);
	- its instructions run on the interpreter's handlers from its address until the pc leaves the
	  sequence (a branch taken, with its delay slot; an exception; an interrupt taken by an SR
	  write) or reaches the block's end;
	- where the decoder folds a division (a div0u or div0s and the 32 rotcl/div1 pairs after it)
	  into one, it runs as the recompiler runs it (runDivision), not stepwise;
	- no instruction is checked for the FPU being disabled: the recompiler checks once, decoding
	  (decode, as Setup), and never again.
	- it ends as the block's exit does: one that ends with an SR write (*Intr) takes a pending
	  interrupt; a dynamic exit goes to the next block whether the emulator is still running or
	  not (do_dispatch, without no_update's check), so a frame stops where the recompiler's does.
	The stub it returns continues there: do_dispatch, or do_interrupts, which reads the pc into w29
	for no_update; or end_mainloop when the emulator was stopped at the time-slice check.
 */
// The decoder's DM_DIV0 sequence for a folded division, on the recompiler's own canonical
// implementations: the quotient and remainder (including a divisor of 0 and an overflowing
// quotient, where stepping rotcl/div1 would leave others) and T; Q and M as they were.
static void runDivision(Sh4Context *ctx, const InterpBlock::Division& d)
{
	u32& r1 = ctx->r[d.reg[0]];
	u32& r2 = ctx->r[d.reg[1]];
	u32& r3 = ctx->r[d.reg[2]];
	u32 T;
	u64 rv;
	if (!d.isSigned)
	{
		rv = shil_opcl_div32u::f1::impl(r1, r2, r3);
		r1 = (u32)rv;
		r3 = (u32)(rv >> 32);
		T = r1 & 1;
		r1 >>= 1;
		r3 = shil_opcl_div32p2::f1::impl(r3, r2, T);
	}
	else
	{
		T = (r3 ^ r2) & (1u << 31);
		rv = shil_opcl_div32s::f1::impl(r1, r2, r3);
		r1 = (u32)rv;
		r3 = (u32)(rv >> 32);
		T |= r1 & 1;
		r1 = (u32)((s32)r1 >> 1);
		r3 = shil_opcl_div32p2::f1::impl(r3, r2, T);
		T &= 1;
	}
	ctx->sr.T = T;
}

static DynarecCodeEntryPtr runInterp(InterpBlock& e)
{
	Sh4Context *ctx = &Sh4cntx;
	if (!guestHolds(e.vaddr, e.bytes.data(), e.size))
	{
		stats.checkFails++;
		if (!decode(e.vaddr, e))
		{
			interpBlocks.erase(fpcbSlot(e.vaddr));
			return (DynarecCodeEntryPtr)stub(StubDoInterrupts);
		}
	}
	int cc = ctx->cycle_counter;
	if (cc < 0)	// the prologue's `cmp w1, 0; b.pl`: a counter of exactly 0 runs the block
	{
		ctx->pc = e.vaddr;
		ctx->cycle_counter = cc + SH4_TIMESLICE;
		if (!ctx->CpuRunning)
			return (DynarecCodeEntryPtr)stub(StubEndMainloop);
		if (UpdateSystem_INTC())
			return (DynarecCodeEntryPtr)stub(StubDoInterrupts);
		cc = ctx->cycle_counter;
	}
	ctx->cycle_counter = cc - (int)e.cycles - (int)(active == Interp ? cfg.corrupt : 0);
	stats.interpRuns++;

	// the branch handlers run their delay slot through Sh4Interpreter::Instance
	struct InstanceGuard {
		Sh4Interpreter *saved = Sh4Interpreter::Instance;
		InstanceGuard() { Sh4Interpreter::Instance = Sh4Recompiler::Instance; }
		~InstanceGuard() { Sh4Interpreter::Instance = saved; }
	} instance;
	const u32 end = e.vaddr + e.size;
	ctx->pc = e.vaddr;
	size_t nextDivision = 0;
	try {
		for (;;)
		{
			const u32 pc = ctx->pc;
			if (nextDivision < e.divisions.size() && pc == e.divisions[nextDivision].pc)
			{
				runDivision(ctx, e.divisions[nextDivision++]);
				ctx->pc = pc + FoldedDivisionBytes;
				if (ctx->pc >= end)
					break;
				continue;
			}
			const u16 op = IReadMem16(pc);
			ctx->pc = pc + 2;
			Sh4Recompiler::Instance->ExecuteAsRecompiled(op);
			stats.interpInsns++;
			// a branch taken (with its delay slot), an exception or an interrupt leaves the
			// sequence; a bt/s or bf/s not taken goes on into its delay slot, which is the block's
			if (ctx->pc != pc + 2 || ctx->pc >= end)
				break;
		}
	} catch (const SH4ThrownException& ex) {
		Do_Exception(ex.epc, ex.expEvn);
		return (DynarecCodeEntryPtr)stub(StubDoInterrupts);
	}
	if (BET_GET_CLS(e.type) != BET_CLS_COND && ((e.type >> 1) & 3) == BET_SCL_Intr)
	{
		UpdateINTC();
		return (DynarecCodeEntryPtr)stub(StubDoInterrupts);
	}
	if (BET_GET_CLS(e.type) == BET_CLS_Dynamic)
		return (DynarecCodeEntryPtr)stub(StubDoDispatch);
	return (DynarecCodeEntryPtr)stub(StubDoInterrupts);
}

/**** the image modes' miss and check-failure paths ****/

DynarecCodeEntryPtr miss(u32 pc)
{
	retiredInterpBlocks.clear();	// no runInterp is running
	AOT_CHECK(!mmu_enabled(), "the MMU is on: an AOT image is for games without it");
	if (pc & 1)
	{
		// RuntimeBlockInfo::Setup's address error
		Do_Exception(pc, Sh4Ex_AddressErrorRead);
		return (DynarecCodeEntryPtr)stub(StubDoInterrupts);
	}
	// A block the JIT would have compiled is found without compiling it again, so without the flush
	auto interp = interpBlocks.find(fpcbSlot(pc));
	if (interp != interpBlocks.end())
		return runInterp(interp->second);
	// rdv_CompilePC's, at the addresses where games load new code
	if (rdv_IsCodeLoadAddress(pc))
		Sh4Recompiler::Instance->ResetCache();
	if (const ImageBlock *b = findBlock(pc))
	{
		if ((b->key & KEY_FPU) && Sh4cntx.sr.FD == 1)
		{
			// the decoder's: an FPU op with the FPU disabled raises the exception, not a block
			Do_Exception(pc, Sh4Ex_FpuDisabled);
			return (DynarecCodeEntryPtr)stub(StubDoInterrupts);
		}
		return install(*b);
	}
	stats.misses++;
	AOT_CHECK(active == Interp, "load: miss at %08x (FPSCR %08x)", pc, Sh4cntx.fpscr.full);
	InterpBlock e;
	if (!decode(pc, e))
		return (DynarecCodeEntryPtr)stub(StubDoInterrupts);
	return runInterp(interpBlocks.emplace(fpcbSlot(pc), std::move(e)).first->second);
}

DynarecCodeEntryPtr checkFailed(u32 addr)
{
	stats.checkFails++;
	RuntimeBlockInfoPtr block = bm_GetBlock(addr);
	if (block)
	{
		const ImageBlock *b = findBlock(addr);
		if (b != nullptr && (const void *)(imageCode + b->codeOff) == (const void *)block->code)
		{
			// guest memory holds the bytes this block checks as wrong: the image is corrupt
			fprintf(stderr, "flycast AOT: the image's block at %08x fails its own check\n", addr);
			badCode = imageCode + b->codeOff;
		}
	}
	rdv_DiscardBlockAt(addr);
	return miss(addr);
}

void resetCache()
{
	retiredInterpBlocks.clear();
	retiredInterpBlocks.swap(interpBlocks);
}

/**** Emit ****/

#ifdef AOT_TOOLING
struct Record {
	u32 vaddr, key, size, codeLen;
	u64 hash;
	std::vector<u16> bytes;
	bool operator<(const Record& o) const {
		if (vaddr != o.vaddr) return vaddr < o.vaddr;
		if (key != o.key) return key < o.key;
		return bytes < o.bytes;
	}
	bool sameBlock(const Record& o) const { return vaddr == o.vaddr && key == o.key && bytes == o.bytes; }
};

static void putWords(std::vector<u32>& out, const std::vector<u16>& bytes)
{
	for (size_t i = 0; i < bytes.size(); i += 2)
		out.push_back(bytes[i] | (i + 1 < bytes.size() ? (u32)bytes[i + 1] << 16 : 0));
}

// The red receipt: the first `add #imm,Rn` or `mov #imm,Rn` of the block, its immediate one higher
static bool corruptBytes(std::vector<u16>& bytes)
{
	for (u16& op : bytes)
		if ((op & 0xf000) == 0x7000 || (op & 0xf000) == 0xe000)
		{
			op = (op & 0xff00) | ((op + 1) & 0xff);
			return true;
		}
	return false;
}

// Put bytes at vaddr in guest memory, for the decoder to read; false when they would not stay
// there (ROM that holds other bytes).
static bool placeBytes(u32 vaddr, const std::vector<u16>& bytes)
{
	for (size_t i = 0; i < bytes.size(); i++)
	{
		u32 a = vaddr + 2 * (u32)i;
		if (IReadMem16(a) != bytes[i])
			addrspace::write16(a, bytes[i]);
		if (IReadMem16(a) != bytes[i])
			return false;
	}
	return true;
}

/* Re-emit each distinct block of the Shape log cfg.log into the image cfg.image (.code, .meta),
   checking each against the JIT's own compile of it, then exit the process: 0 when the image was
   written, 3 when a block re-emits otherwise than the JIT ran it (or the JIT compiled one block
   two ways, or the stubs differ), 4 when a block could not be placed or decoded; on 3 or 4 no
   image is left behind. */
[[noreturn]] static void emitAll()
{
	AOT_CHECK(!cfg.log.empty() && !cfg.image.empty(), "emit needs a log to read and an image to write");
	FILE *f = fopen(cfg.log.c_str(), "r");
	AOT_CHECK(f != nullptr, "cannot read %s", cfg.log.c_str());
	std::vector<Record> recs;
	u32 logStubSize = 0;
	unsigned long long logStubHash = 0;
	char line[1 << 16];
	while (fgets(line, sizeof line, f))
	{
		if (!strncmp(line, "stubs ", 6))
		{
			AOT_CHECK(sscanf(line + 6, "%u %llx", &logStubSize, &logStubHash) == 2, "a bad stubs line in %s", cfg.log.c_str());
			continue;
		}
		Record r;
		unsigned long long hash;
		int n;
		AOT_CHECK(sscanf(line, "%x %x %u %u %llx%n", &r.vaddr, &r.key, &r.size, &r.codeLen, &hash, &n) == 5,
				"a bad record in %s: %.60s", cfg.log.c_str(), line);
		r.hash = hash;
		const char *s = line + n;
		for (u32 i = 0; i < r.size; i += 2)
		{
			unsigned w;
			int m;
			AOT_CHECK(sscanf(s, " %x%n", &w, &m) == 1, "a short record in %s", cfg.log.c_str());
			r.bytes.push_back((u16)w);
			s += m;
		}
		recs.push_back(std::move(r));
	}
	fclose(f);
	std::sort(recs.begin(), recs.end());

	// the stubs, as the JIT generated them
	sh4Dynarec->allocateBlock();	// generates the mainloop, into this process's plain memory
	const u64 stubHash = fnv(FNV_BASIS, stubCode, stubSize);
	if (stubSize != logStubSize || stubHash != logStubHash)
	{
		fprintf(stderr, "flycast AOT emit: the stubs are %u bytes %016llx, the JIT's were %u bytes %016llx\n",
				stubSize, (unsigned long long)stubHash, logStubSize, logStubHash);
		stats.emitDiffers++;
	}
	std::vector<u8> code(stubCode, stubCode + stubSize);
	std::vector<u32> meta;
	meta.push_back(stubSize);
	const u8 *base = rdv_CodeBase();
	for (u32 s = 0; s < StubCount; s++)
		meta.push_back((u32)((const u8 *)stub((Stub)s) - base));
	const u32 at = rdv_CodeOffset();	// past the stubs, aligned as Shape aligns the first block

	unsigned long unique = 0, skipped = 0, corrupted = 0;
	for (size_t i = 0; i < recs.size(); i++)
	{
		const Record& r = recs[i];
		if (i > 0 && r.sameBlock(recs[i - 1]))
		{
			if (r.hash != recs[i - 1].hash || r.codeLen != recs[i - 1].codeLen)
			{
				if (stats.emitDiffers++ < 10)
					fprintf(stderr, "flycast AOT emit: the JIT compiled %08x two ways: %u bytes %016llx and %u bytes %016llx\n",
							r.vaddr, recs[i - 1].codeLen, (unsigned long long)recs[i - 1].hash, r.codeLen, (unsigned long long)r.hash);
			}
			continue;
		}
		unique++;
		std::vector<u16> source = r.bytes;
		const bool corrupt = cfg.corrupt != 0 && r.vaddr == cfg.corrupt && corrupted == 0;
		if (corrupt)
		{
			AOT_CHECK(corruptBytes(source), "the block at %08x holds no add #imm or mov #imm to corrupt", r.vaddr);
			fprintf(stderr, "flycast AOT emit: %08x re-emitted from corrupted bytes, on purpose\n", r.vaddr);
			corrupted++;
		}
		if (!placeBytes(r.vaddr, source))
		{
			if (skipped++ < 10)
				fprintf(stderr, "flycast AOT emit: %08x: guest memory there will not hold the block's bytes\n", r.vaddr);
			continue;
		}
		Sh4cntx.sr.FD = 0;
		RuntimeBlockInfo *rbi = sh4Dynarec->allocateBlock();
		if (!rbi->Setup(r.vaddr, keyFpscr(r.key)) || rbi->sh4_code_size != r.size
				|| rbi->has_fpu_op != ((r.key & KEY_FPU) != 0))
		{
			if (skipped++ < 10)
				fprintf(stderr, "flycast AOT emit: %08x decodes otherwise than the log says\n", r.vaddr);
			delete rbi;
			continue;
		}
		// the corrupted block computes from the wrong bytes and checks the true ones, so it
		// installs and runs (CheckBlock reads guest memory as the block compiles)
		if (corrupt)
			placeBytes(r.vaddr, r.bytes);
		const u8 *blockCode = (const u8 *)rdv_CompileAt(rbi, at);
		const u32 len = rbi->host_code_size;
		const u64 h = fnv(FNV_BASIS, blockCode, len);
		if (!corrupt && (len != r.codeLen || h != r.hash))
		{
			if (stats.emitDiffers++ < 10)
				fprintf(stderr, "flycast AOT emit: %08x re-emits as %u bytes %016llx, the JIT ran %u bytes %016llx\n",
						r.vaddr, len, (unsigned long long)h, r.codeLen, (unsigned long long)r.hash);
		}
		code.resize(alignBlock((u32)code.size()));
		const u32 off = (u32)code.size();
		code.insert(code.end(), blockCode, blockCode + len);
		meta.push_back(r.vaddr);
		meta.push_back(r.key);
		meta.push_back(r.size);
		meta.push_back(off);
		meta.push_back(len);
		putWords(meta, r.bytes);	// the true bytes, the ones guest memory must hold to install it
		delete rbi;
	}
	const int status = stats.emitDiffers ? 3 : skipped ? 4 : 0;
	fprintf(stderr, "flycast AOT emit: %zu records, %lu blocks, %lu emitted (%zu bytes of code), %lu skipped, %lu differ from the JIT's\n",
			recs.size(), unique, unique - skipped, code.size(), skipped, stats.emitDiffers);
	const std::string codePath = cfg.image + ".code", metaPath = cfg.image + ".meta";
	if (status != 0)
	{
		unlink(codePath.c_str());
		unlink(metaPath.c_str());
		fprintf(stderr, "flycast AOT emit: no image written\n");
		fflush(stderr);
		_exit(status);
	}
	ImageHeader h;
	const char *gap;
	layoutHash(&gap);
	AOT_CHECK(gap == nullptr, "AOT_CONTEXT lists no member before %s, which Sh4Context has: add it", gap);
	AOT_CHECK(!makeHeader(h, (u32)(unique - skipped), (u32)code.size(), cfg.hasCoreUuid ? cfg.coreUuid : nullptr),
			"this core has no LC_UUID or the game no content digest, so the image could name neither");
	fprintf(stderr, "flycast AOT emit: an image for core %s and the game %s, emitted by core %s\n",
			formatUuid(h.core_uuid).c_str(), formatUuid(h.rom_md5).c_str(), formatUuid(h.emit_uuid).c_str());
	f = fopen(codePath.c_str(), "wb");
	AOT_CHECK(f != nullptr && fwrite(code.data(), 1, code.size(), f) == code.size(), "cannot write %s", codePath.c_str());
	fclose(f);
	f = fopen(metaPath.c_str(), "wb");
	AOT_CHECK(f != nullptr && fwrite(&h, sizeof h, 1, f) == 1 && fwrite(meta.data(), 4, meta.size(), f) == meta.size(),
			"cannot write %s", metaPath.c_str());
	fclose(f);
	fflush(stderr);
	_exit(0);
}
#endif

/**** Init and admission ****/

static void endOfRun()
{
	if (active == Off)
		return;
	fprintf(stderr, "flycast AOT %s: %lu compiled, %lu installed, %lu missed, %lu interpreted runs (%lu instructions), %lu check failures\n",
			active == Shape ? "shape" : active == Emit ? "emit" : active == Load ? "load" : "interp",
			stats.compiled, stats.installs, stats.misses, stats.interpRuns, stats.interpInsns, stats.checkFails);
	vmReport("end of run");
}

void beginInit()
{
	static bool atExit;
	if (!atExit)
	{
		atexit(endOfRun);
		atExit = true;
	}
	active = cfg.mode;
	admission = Unknown;
	interpBlocks.clear();
	retiredInterpBlocks.clear();
	if (active == Off)
		return;
	buildImports();
#ifdef AOT_TOOLING
	if (active == Shape && logFile == nullptr && !cfg.log.empty())
	{
		logFile = fopen(cfg.log.c_str(), "w");
		AOT_CHECK(logFile != nullptr, "cannot write %s", cfg.log.c_str());
	}
#endif
}

bool admit()
{
	if (admission != Unknown)
		return admission == Admitted;
	AOT_CHECK(!mmu_enabled(), "the MMU is on: AOT-shaped blocks are for games without it");
#ifdef AOT_TOOLING
	if (active == Emit)
		emitAll();
#endif
	if (!imageOnly())
	{
		admission = Admitted;
		return true;
	}
	std::string why = cfg.image.empty() ? std::string("no image is configured") : openImage(cfg.image);
	if (!why.empty())
	{
		fprintf(stderr, "flycast AOT: refused %s: %s; the interpreter runs instead\n", cfg.image.c_str(), why.c_str());
		admission = Refused;
		report(false, why);
		return false;
	}
	admission = Admitted;
	rdv_SetFailedToFindBlockHandler((void (*)())stub(StubMiss));
	Sh4Recompiler::Instance->ResetCache();	// every FPCB entry now the image's miss stub
	vmReport("image loaded");
	report(true, imagePath + ": " + std::to_string(imageBlocks.size()) + " blocks");
	return true;
}

}	// namespace aot
#endif
