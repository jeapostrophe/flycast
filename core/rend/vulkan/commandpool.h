/*
	Created on: Oct 8, 2019

	Copyright 2019 flyinghead

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
#pragma once
#include "vulkan.h"

#include <algorithm>
#include <vector>
#include <memory>

class CommandPool : public FlightManager
{
public:
	// How many frames a pool keeps in flight by default. BeginFrame() waits the fence
	// of the frame `defaultChainSize` back, so the command buffers of the frames after
	// that one are still pending when a new frame starts: every per-frame resource a
	// drawer recycles (descriptor sets included) must be ringed at least this deep.
	static constexpr size_t defaultChainSize = 2;

	void Init(size_t chainSize = defaultChainSize);
	void Term();
	void BeginFrame();
	void EndFrame();
	void EndFrameAndWait();
	vk::CommandBuffer Allocate(bool submitLast = false);

	int GetIndex() const {
		return index;
	}

	void addToFlight(Deletable *object) override {
		inFlightObjects[index].emplace_back(object);
	}

private:
	int index = 0;
	std::vector<std::vector<vk::UniqueCommandBuffer>> freeBuffers;
	std::vector<std::vector<vk::UniqueCommandBuffer>> inFlightBuffers;
	std::vector<bool> lastBuffers;
	std::vector<vk::UniqueCommandPool> commandPools;
	std::vector<vk::UniqueFence> fences;
	// size should be the same as used by client: 2 for renderer (texCommandPool)
	size_t chainSize;
	std::vector<std::vector<std::unique_ptr<Deletable>>> inFlightObjects;
	bool frameStarted = false;
	vk::Device device{};
};

// **The depth any ring of per-frame resources must have.**
//
// A resource that is recycled once per frame -- a descriptor set, a framebuffer, a
// staging texture -- may only be rewritten once the command buffer that last used it
// has completed, and what decides that is the CommandPool it was recorded into, never
// the frontend: a pool of `chainSize` frames waits the fence of the frame `chainSize`
// back, so every frame after that one is still pending when a new frame starts.
//
// Rings that took their depth from the presentation swapchain -- or, under libretro,
// from get_sync_index_mask() -- were only ever right because that number happened to
// be >= the pool's. libretro_vulkan.h allows a frontend to advertise a single sync
// index ("If bit #N is set in the return value, get_sync_index can return N"), and at
// that depth the two disagree. Clamp.
inline u32 frameRingSize(u32 frontendImages) {
	return std::max<u32>((u32)CommandPool::defaultChainSize, frontendImages);
}
