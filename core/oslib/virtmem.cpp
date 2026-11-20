/*
	Copyright 2026 flyinghead

	This file is part of Flycast.

    Flycast is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Flycast is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Flycast.  If not, see <https://www.gnu.org/licenses/>.
*/
#include "virtmem.h"

// The host-provided JIT memory allocator, if any. Lives here rather than in one
// of the per-platform vmem files so that the shell can install it without
// knowing which of them was compiled in.
namespace virtmem
{

static JitAllocator jitAllocator;
static JitDeallocator jitDeallocator;

void setJitAllocator(JitAllocator alloc, JitDeallocator dealloc)
{
	jitAllocator = alloc;
	jitDeallocator = dealloc;
}

JitAllocator getJitAllocator()
{
	return jitAllocator;
}

JitDeallocator getJitDeallocator()
{
	return jitDeallocator;
}

static bool denied;

void setJitDenied(bool d)
{
	denied = d;
}

bool jitDenied()
{
	return denied;
}

} // namespace virtmem
