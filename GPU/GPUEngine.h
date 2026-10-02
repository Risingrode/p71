/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef GPUENGINEH
#define GPUENGINEH

#include <vector>
#include <tuple>
#include <cstdint>

typedef uint16_t prefix_t;

// ── AB+CD 组合搜索（独立接口）─────────────────────────────
struct ABCDContext;

// 选择使用的 GPU（失败返回 false）
bool abcdSetDevice(int gpuId);

// 失败返回 nullptr
ABCDContext *abcdSetup(
    uint64_t *abTable, uint32_t abSize,
    uint64_t *cdTable, uint32_t cdSize,
    uint8_t *targetH160, prefix_t targetPrefix, uint32_t maxFound);

void abcdFree(ABCDContext *ctx);

bool abcdLaunch(ABCDContext *ctx, uint64_t startCombo, uint64_t numCombos,
                std::vector<std::tuple<uint32_t,uint32_t,uint8_t>> &found);

#endif // GPUENGINEH
