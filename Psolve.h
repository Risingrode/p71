#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "crypto/SECP256k1.h"
#include "GPU/GPUEngine.h"

// AB 过滤行（a=r13 字节范围，b=r14 字节范围）
struct ABRow {
    uint8_t a_hi_lo, a_hi_hi, a_lo_lo, a_lo_hi;
    uint8_t b_hi_lo, b_hi_hi, b_lo_lo, b_lo_hi;
    bool matchA(uint16_t v) const {
        uint8_t hi=v>>8, lo=v&0xFF;
        return hi>=a_hi_lo&&hi<=a_hi_hi&&lo>=a_lo_lo&&lo<=a_lo_hi;
    }
    bool matchB(uint16_t v) const {
        uint8_t hi=v>>8, lo=v&0xFF;
        return hi>=b_hi_lo&&hi<=b_hi_hi&&lo>=b_lo_lo&&lo<=b_lo_hi;
    }
};

// CD 过滤行（c=r15 字节范围，d=r16 字节范围）
struct CDRow {
    uint8_t c_hi_lo, c_hi_hi, c_lo_lo, c_lo_hi;
    uint8_t d_hi_lo, d_hi_hi, d_lo_lo, d_lo_hi;
    bool matchC(uint16_t v) const {
        uint8_t hi=v>>8, lo=v&0xFF;
        return hi>=c_hi_lo&&hi<=c_hi_hi&&lo>=c_lo_lo&&lo<=c_lo_hi;
    }
    bool matchD(uint16_t v) const {
        uint8_t hi=v>>8, lo=v&0xFF;
        return hi>=d_hi_lo&&hi<=d_hi_hi&&lo>=d_lo_lo&&lo<=d_lo_hi;
    }
};

class PuzzleSolve {
public:
    PuzzleSolve(Secp256K1 *secp, const std::string &target,
                const std::string &output);

    // patterns = [r12, r13, r14, r15, r16]
    // AB = r12×r13×r14，CD = r15×r16，GPU 全速扫 AB×CD
    // 返回找到的密钥个数（0 = 扫完未找到）
    int Search(std::vector<std::vector<uint16_t>> &patterns,
                int bits,
                std::vector<int> gpuId,
                const std::vector<ABRow> &abRows,
                const std::vector<CDRow> &cdRows,
                const std::vector<std::pair<int,int>> &hwPairs    = {},
                const std::vector<std::pair<int,int>> &hwXorPairs = {},
                // 附加条件 (r13+r14+r15+r16) % sumMod == sumRem；sumMod<=1 表示不启用
                int sumMod = 0, int sumRem = 0);

private:
    bool verifyAndOutput(uint32_t ab_idx, uint32_t cd_idx,
                         const std::vector<std::vector<uint16_t>> &abPats,
                         const std::vector<std::vector<uint16_t>> &cdPats,
                         int bits);

    void output(const std::string &addr, const std::string &wif,
                const std::string &hex);

    static void decodeIdx(uint64_t idx,
                          const std::vector<std::vector<uint16_t>> &pats,
                          std::vector<int> &valIdx);

    void buildSubTable(const std::vector<uint16_t> &vals, int shift, int chunk,
                       std::vector<Point> &table);

    // 预计算 EC 点表（所有文件的笛卡尔积）
    void buildCombinedTable(const std::vector<std::vector<uint16_t>> &pats,
                            const std::vector<int> &shifts,
                            const std::vector<int> &chunks,
                            std::vector<uint64_t> &result,
                            uint32_t &size,
                            bool hasBase, const Point &basePoint);

    Secp256K1  *secp;
    std::string targetAddr;
    uint8_t     targetHash160[20];
    prefix_t    targetPrefix;
    int         searchType;
    bool        endOfSearch;
    int         nbFoundKey;
    int         badHits;     // GPU 命中但 CPU 验证失败的次数（正常应为 0）
    std::string outputFile;

#ifndef WIN64
    pthread_mutex_t ghMutex;
#else
    HANDLE ghMutex;
#endif
};
