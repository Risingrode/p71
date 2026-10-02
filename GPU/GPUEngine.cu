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

#include "GPUEngine.h"
#include <cuda.h>
#include <cuda_runtime.h>
#include <stdio.h>
#include <stdint.h>

#include "GPUMath.h"
#include "GPUHash.h"
#include "GPUCombineABCD.h"

// ── AB+CD 组合搜索 ─────────────────────────────────────────

struct ABCDContext {
  uint64_t *d_ab,  *d_cd;
  uint32_t *d_out, *h_out;
  uint32_t abSize, cdSize, maxFound;
  prefix_t targetPrefix;
  int      optimal_nc;
};

// 每线程处理的组合数。必须是 abcdLaunch 里 switch 支持的值，否则网格会按 NC 计算、
// 核函数却用另一个 NC，导致部分组合漏算。
static const int ABCD_NC_LIST[] = {16, 24, 32, 48, 64, 96, 128, 192, 256};

static int abcdSelectNC(int gpuId)
{
  cudaDeviceProp prop; cudaGetDeviceProperties(&prop, gpuId);
  int nc = ABCD_DEFAULT_NC;
  if (const char *e = getenv("ABCD_NC")) nc = atoi(e);
  bool ok = false;
  for (int v : ABCD_NC_LIST) if (v == nc) ok = true;
  if (!ok) { printf("ABCD_NC=%d 不受支持，改用 %d\n", nc, ABCD_DEFAULT_NC); nc = ABCD_DEFAULT_NC; }
  static bool printed = false;   // 按组多次 setup，只打印一次
  if (!printed) { printed = true; printf("GPU #%d %s (SM %d.%d) NC=%d\n", gpuId, prop.name, prop.major, prop.minor, nc); }
  return nc;
}

// 任何一步 CUDA 调用失败都返回 nullptr（调用方必须终止，继续扫会读到垃圾数据而漏解）
#define ABCD_CHECK(call) do { cudaError_t _e = (call); if (_e != cudaSuccess) { \
    printf("abcdSetup: %s 失败: %s\n", #call, cudaGetErrorString(_e)); abcdFree(ctx); return nullptr; } } while (0)

void abcdFree(ABCDContext *ctx);

bool abcdSetDevice(int gpuId)
{
  cudaError_t e = cudaSetDevice(gpuId);
  if (e != cudaSuccess) { printf("cudaSetDevice(%d): %s\n", gpuId, cudaGetErrorString(e)); return false; }
  return true;
}

ABCDContext *abcdSetup(
    uint64_t *abTable, uint32_t abSize,
    uint64_t *cdTable, uint32_t cdSize,
    uint8_t *targetH160, prefix_t targetPrefix, uint32_t maxFound)
{
  ABCDContext *ctx = new ABCDContext();
  ctx->d_ab = ctx->d_cd = nullptr; ctx->d_out = ctx->h_out = nullptr;
  ctx->abSize=abSize; ctx->cdSize=cdSize; ctx->maxFound=maxFound;
  ctx->targetPrefix=targetPrefix;

  int gpuId=0; cudaGetDevice(&gpuId);
  ctx->optimal_nc = abcdSelectNC(gpuId);

  ABCD_CHECK(cudaMalloc(&ctx->d_ab, (size_t)abSize*8*sizeof(uint64_t)));
  ABCD_CHECK(cudaMemcpy(ctx->d_ab, abTable, (size_t)abSize*8*sizeof(uint64_t), cudaMemcpyHostToDevice));
  ABCD_CHECK(cudaMalloc(&ctx->d_cd, (size_t)cdSize*8*sizeof(uint64_t)));
  ABCD_CHECK(cudaMemcpy(ctx->d_cd, cdTable, (size_t)cdSize*8*sizeof(uint64_t), cudaMemcpyHostToDevice));

  ABCD_CHECK(cudaMemcpyToSymbol(_abcd_target, targetH160, 20));

  size_t outBytes = (1+(size_t)maxFound*ABCD_ITEM32)*sizeof(uint32_t);
  ABCD_CHECK(cudaMalloc(&ctx->d_out, outBytes));
  ABCD_CHECK(cudaHostAlloc(&ctx->h_out, outBytes, cudaHostAllocDefault));
  return ctx;
}

void abcdFree(ABCDContext *ctx) {
  if (ctx->d_ab)  cudaFree(ctx->d_ab);
  if (ctx->d_cd)  cudaFree(ctx->d_cd);
  if (ctx->d_out) cudaFree(ctx->d_out);
  if (ctx->h_out) cudaFreeHost(ctx->h_out);
  delete ctx;
}

// CUDA 块分配：gridSize×BLOCK 线程，每线程处理 NC 个组合
bool abcdLaunch(ABCDContext *ctx, uint64_t startCombo, uint64_t numCombos,
                std::vector<std::tuple<uint32_t,uint32_t,uint8_t>> &found)
{
  found.clear();
  if (numCombos==0) return true;
  if (cudaMemset(ctx->d_out,0,sizeof(uint32_t))!=cudaSuccess) { printf("ABCDKernel: cudaMemset 失败\n"); return false; }

  const int BLOCK=128, NC=ctx->optimal_nc;
  uint64_t threads=(numCombos+NC-1)/NC;
  uint64_t gridSize=(threads+BLOCK-1)/BLOCK;
  if (gridSize>0x7FFFFFFFULL) {   // x 维网格上限 2^31-1，超过就必须让调用方拆批，不能静默截断
    printf("ABCDKernel: batch too large (%llu blocks)\n",(unsigned long long)gridSize);
    return false;
  }

#define _LAUNCH(NCV) \
  comp_keys_abcd<NCV><<<(uint32_t)gridSize,BLOCK>>>( \
    ctx->d_ab, ctx->d_cd, ctx->abSize, ctx->cdSize, \
    startCombo, ctx->targetPrefix, ctx->maxFound, ctx->d_out)

  switch(NC) {
    case  16: _LAUNCH( 16); break; case  24: _LAUNCH( 24); break;
    case  32: _LAUNCH( 32); break; case  48: _LAUNCH( 48); break;
    case  64: _LAUNCH( 64); break; case  96: _LAUNCH( 96); break;
    case 128: _LAUNCH(128); break; case 192: _LAUNCH(192); break;
    case 256: _LAUNCH(256); break;
    default:
      printf("ABCDKernel: unsupported NC=%d\n",NC); return false;
  }
#undef _LAUNCH

  cudaError_t err=cudaGetLastError();
  if (err!=cudaSuccess) { printf("ABCDKernel: %s\n",cudaGetErrorString(err)); return false; }

  err=cudaDeviceSynchronize();
  if (err!=cudaSuccess) { printf("ABCDKernel sync: %s\n",cudaGetErrorString(err)); return false; }
  size_t outBytes=(1+(size_t)ctx->maxFound*ABCD_ITEM32)*sizeof(uint32_t);
  err=cudaMemcpy(ctx->h_out,ctx->d_out,outBytes,cudaMemcpyDeviceToHost);
  if (err!=cudaSuccess) { printf("ABCDKernel copy: %s\n",cudaGetErrorString(err)); return false; }

  uint32_t count=ctx->h_out[0];
  if (count>ctx->maxFound) count=ctx->maxFound;
  for (uint32_t i=0;i<count;i++) {
    found.push_back({ctx->h_out[1+i*ABCD_ITEM32+0],
                     ctx->h_out[1+i*ABCD_ITEM32+1],
                     (uint8_t)ctx->h_out[1+i*ABCD_ITEM32+2]});
  }
  return true;
}
