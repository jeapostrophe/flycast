#pragma once
#include "types.h"
#include "sh4_cycles.h"

class Sh4Interpreter : public Sh4Executor
{
public:
	void Run() override;
	void ResetCache() override  {}
	void Start() override;
	void Stop() override;
	void Step() override;
	void Reset(bool hard) override;
	void Init() override;
	void Term() override;
	bool IsCpuRunning() override;
	void ExecuteDelayslot();
	void ExecuteDelayslot_RTE();
	Sh4Context *getContext() { return ctx; }
	// The SH4 AOT interp (rec-ARM64/aot_arm64.cpp) runs a block the image lacks one instruction at
	// a time as the recompiler runs it: no cycles per instruction (it charges the block's), and no
	// FPU-disabled check (the recompiler makes it once, decoding), the delay slots' included.
	void ExecuteAsRecompiled(u16 op)
	{
		struct Guard {
			bool& flag;
			Guard(bool& f) : flag(f) { flag = true; }
			~Guard() { flag = false; }
		} guard(asRecompiled);
		ExecuteOpcode(op);
	}

	static Sh4Interpreter *Instance;

protected:
	Sh4Context *ctx = nullptr;

private:
	void ExecuteOpcode(u16 op);
	u16 ReadNexOp();

	Sh4Cycles sh4cycles{CPU_RATIO};
	bool asRecompiled = false;
	// SH4 underclock factor when using the interpreter so that it's somewhat usable
#ifdef STRICT_MODE
	static constexpr int CPU_RATIO = 1;
#else
	static constexpr int CPU_RATIO = 8;
#endif
};
