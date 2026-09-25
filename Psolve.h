#pragma once
#include <string>
#include <vector>
#include <tuple>
#include <utility>
#include <cstdint>
#include "crypto/SECP256k1.h"
#include "GPU/GPUEngine.h"

// 16-bit 段值的高低字节范围约束
struct ByteRange {
    uint8_t hi_lo = 0, hi_hi = 255;  // 高字节（n0-n7）范围
    uint8_t lo_lo = 0, lo_hi = 255;  // 低字节（n8-n15）范围
    bool matches(uint16_t v) const {
        uint8_t hi = (uint8_t)(v >> 8), lo = (uint8_t)(v & 0xFF);
        return hi >= hi_lo && hi <= hi_hi && lo >= lo_lo && lo <= lo_hi;
    }
};
struct ABRangeRow { ByteRange a, b; };  // a=r13, b=r14
struct CDRangeRow { ByteRange c, d; };  // c=r15, d=r16(outer)

// AB+CD 组合搜索：
//   AB 表 = patterns[0..splitIdx-1] 的笛卡尔积
//   CD 表 = patterns[splitIdx..N-1] 的笛卡尔积
//   GPU kernel 检查所有 AB×CD 组合

class PuzzleSolve {
public:
    PuzzleSolve(Secp256K1 *secp, const std::string &target,
                const std::string &output);

    // 组合搜索（AB 预组合 + CD 预组合 + GPU 全速扫）
    // splitIdx: 前 splitIdx 个文件归 AB，其余归 CD（默认 2）
    void Search(std::vector<std::vector<uint16_t>> &patterns,
                int bits, int splitIdx,
                std::vector<int> gpuId, std::vector<int> gridSize,
                const std::vector<std::pair<int,int>> &hwPairs    = {},
                const std::vector<std::pair<int,int>> &hwXorPairs = {},
                const std::vector<ABRangeRow>         &abRanges   = {},
                const std::vector<CDRangeRow>         &cdRanges   = {},
                const std::vector<std::pair<int,int>> &hwSumPairs = {});

private:
    // 私钥重建与验证
    bool verifyAndOutput(uint32_t ab_idx, uint32_t cd_idx, uint8_t variant,
                         const std::vector<std::vector<uint16_t>> &abPats,
                         const std::vector<std::vector<uint16_t>> &cdPats,
                         int bits,
                         int outerValIdx = -1,
                         const std::vector<uint16_t> *outerVals = nullptr,
                         int outerShift = 0, int outerChunk = 0);

    void output(const std::string &addr, const std::string &wif,
                const std::string &hex);

    // 将组合索引分解为各文件的值索引
    static void decodeIdx(uint64_t idx,
                          const std::vector<std::vector<uint16_t>> &pats,
                          std::vector<int> &valIdx);

    // 组合索引 → 完整私钥（pats[0]=最高位...pats[N-1]=最低位）
    static void assembleKey(Int &key, const std::vector<int> &abVals,
                            const std::vector<int> &cdVals,
                            const std::vector<std::vector<uint16_t>> &allPats,
                            int bits);

    // 预计算 EC 点表
    // pats[i] = 一个 r 文件的值列表
    // shift   = 该文件起始位在密钥中的位置（从 0 算，0=最低位）
    // base    = 该文件的基底点 = (1 << shift) * G
    // 返回：table[v] = v * base，仿射坐标
    void buildSubTable(const std::vector<uint16_t> &vals, int shift, int chunk,
                       std::vector<Point> &table);

    // 把多个子表的所有点加起来，得到完整的 AB 或 CD EC 点表
    // pats    = 该组的文件列表（每个文件一个子表）
    // shifts  = 每个文件对应的 shift
    // result  = 输出：所有组合的 EC 点（仿射，64字节/点）
    void buildCombinedTable(const std::vector<std::vector<uint16_t>> &pats,
                            const std::vector<int> &shifts,
                            const std::vector<int> &chunks,
                            std::vector<uint64_t> &result,
                            std::vector<uint8_t>  &hwResult,
                            std::vector<uint8_t>  &hwXorResult,
                            uint32_t &size,
                            bool hasBase = false,
                            const Point &basePoint = Point());

    Secp256K1  *secp;
    std::string targetAddr;
    uint8_t     targetHash160[20];
    prefix_t    targetPrefix;
    int         searchType;

    Int beta, lambda, beta2, lambda2;

    bool     endOfSearch;
    int      nbFoundKey;
    std::string outputFile;

#ifdef WIN64
    HANDLE ghMutex;
#else
    pthread_mutex_t ghMutex;
#endif
};
