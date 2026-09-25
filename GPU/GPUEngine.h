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
#include "../crypto/SECP256k1.h"

#define SEARCH_COMPRESSED 0
#define SEARCH_UNCOMPRESSED 1
#define SEARCH_BOTH 2

static const char *searchModes[] = {"Compressed","Uncompressed","Compressed or Uncompressed"};

// Number of key per thread (must be a multiple of GRP_SIZE) per kernel call
#define STEP_SIZE 1024

// Number of thread per block
#define ITEM_SIZE 28
#define ITEM_SIZE32 (ITEM_SIZE/4)
#define _64K 65536

typedef uint16_t prefix_t;
typedef uint32_t prefixl_t;

typedef struct {
  uint32_t thId;
  int16_t  incr;
  int16_t  endo;
  uint8_t  *hash;
  bool mode;
} ITEM;

// Second level lookup
typedef struct {
  prefix_t sPrefix;
  std::vector<prefixl_t> lPrefixes;
} LPREFIX;

class GPUEngine {

public:

  GPUEngine(int nbThreadGroup,int nbThreadPerGroup,int gpuId,uint32_t maxFound,bool rekey);
  ~GPUEngine();
  void SetPrefix(std::vector<prefix_t> prefixes);
  void SetPrefix(std::vector<LPREFIX> prefixes,uint32_t totalPrefix);
  bool SetKeys(Point *p);
  void SetSearchMode(int searchMode);
  void SetSearchType(int searchType);
  void SetPattern(const char *pattern);
  bool Launch(std::vector<ITEM> &prefixFound,bool spinWait=false);
  int GetNbThread();
  int GetGroupSize();

  bool Check(Secp256K1 *secp);
  std::string deviceName;

  static void PrintCudaInfo();
  static void GenerateCode(Secp256K1 *secp, int size);

private:

  bool callKernel();
  static void ComputeIndex(std::vector<int> &s, int depth, int n);
  static void Browse(FILE *f,int depth, int max, int s);
  bool CheckHash(uint8_t *h, std::vector<ITEM>& found, int tid, int incr, int endo, int *ok);

  int nbThread;
  int nbThreadPerGroup;
  prefix_t *inputPrefix;
  prefix_t *inputPrefixPinned;
  uint32_t *inputPrefixLookUp;
  uint32_t *inputPrefixLookUpPinned;
  uint64_t *inputKey;
  uint64_t *inputKeyPinned;
  uint32_t *outputPrefix;
  uint32_t *outputPrefixPinned;
  bool initialised;
  uint32_t searchMode;
  uint32_t searchType;
  bool littleEndian;
  bool lostWarning;
  bool rekey;
  uint32_t maxFound;
  uint32_t outputSize;
  std::string pattern;
  bool hasPattern;

};

// ── AB+CD 组合搜索（独立接口，不通过 GPUEngine 类）─────────
struct ABCDContext;

ABCDContext *abcdSetup(
    uint64_t *abTable, uint8_t *abHwTable, uint8_t *abHwTable2, uint32_t abSize,
    uint64_t *cdTable, uint8_t *cdHwTable, uint8_t *cdHwTable2, uint32_t cdSize,
    uint8_t *targetH160, prefix_t targetPrefix,
    uint32_t maxFound,
    const std::vector<std::pair<int,int>> &hwPairs     = {},
    const std::vector<std::pair<int,int>> &hwXorPairs  = {},
    int      forced_nc    = 0,       // 0=自动选并打印，>0=静默使用该值
    uint8_t *abHwSumR13   = nullptr, // hw(r13) popcount per AB entry
    uint8_t *cdHwSumR14   = nullptr, // hw(r14) popcount per CD entry
    uint8_t *cdHwSumR15   = nullptr, // hw(r15) popcount per CD entry
    const std::vector<std::pair<int,int>> &hwSumPairs = {},
    uint8_t  hw_outer_sum = 0xFF);   // hw(r16)，0xFF=不启用和过滤

void abcdFree(ABCDContext *ctx);
int  abcdGetNC(ABCDContext *ctx);  // 返回 optimal_nc，用于有序搜索时复用

bool abcdLaunch(ABCDContext *ctx, uint64_t startCombo, uint64_t numCombos,
                std::vector<std::tuple<uint32_t,uint32_t,uint8_t>> &found);

#endif // GPUENGINEH
