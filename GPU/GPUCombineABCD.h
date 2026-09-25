// AB+CD 组合搜索 GPU kernel（模板化 NC 支持自动适配）
//
// ABCD_NC 由运行时根据 GPU L1 cache 大小自动选取：
//   SM 7.5 (T4 / RTX 20xx)   : L1 ~32KB  → NC=128
//   SM 7.0 (V100)             : L1 ~128KB → NC=512
//   SM 8.0 (A100)             : L1 ~192KB → NC=512
//   SM 8.6/8.9 (RTX 30/40xx) : L1 ~128KB → NC=512
//   SM 9.0 (H100)             : L1 ~256KB → NC=512

#ifndef GPU_COMBINE_ABCD_H
#define GPU_COMBINE_ABCD_H

#define ABCD_ITEM32    3
#define ABCD_MAX_FOUND 1024

__device__ __constant__ uint32_t _abcd_target[5];  // 目标 hash160

// ── hw 联合过滤 ──────────────────────────────────────────────────────────────
// _hw_valid  : hw(a & b) / hw(c & d) 有效对表
// _hw_valid2 : hw(a ^ b) / hw(c ^ d) 有效对表
// _sum_valid : hw(a)+hw(b) / hw(c)+hw(d) 有效对表  sum ∈ [0,32]
// _hw_r16_sum: 当前外层 r16 值的 popcount（和过滤器用）
__device__ __constant__ uint8_t _hw_valid [17][17];
__device__ __constant__ uint8_t _hw_valid2[17][17];
__device__ __constant__ uint8_t _sum_valid[33][33];
__device__ __constant__ uint8_t _hw_r16_sum;  // hw(r16)，每轮外层迭代前更新

__device__ __forceinline__ bool _hwValidFilter(
    uint8_t hw_ab,  uint8_t hw_cd,   // AND hw
    uint8_t hw_ab2, uint8_t hw_cd2)  // XOR hw
{
    // 0xFF = 该过滤器未启用，直接放行
    if (hw_ab != 0xFFu) {
        if (hw_ab > 16u || hw_cd > 16u) return false;
        if (!_hw_valid[hw_ab][hw_cd]) return false;
    }
    if (hw_ab2 != 0xFFu) {
        if (hw_ab2 > 16u || hw_cd2 > 16u) return false;
        if (!_hw_valid2[hw_ab2][hw_cd2]) return false;
    }
    return true;
}

// hw(r13)+hw(r14) 和 hw(r15)+hw(r16) 联合检查
// hw_r13: popcount(r13 value), hw_r14/hw_r15: popcount(r14/r15 values)
// 0xFF 表示该过滤器未启用
__device__ __forceinline__ bool _sumValidFilter(
    uint8_t hw_r13, uint8_t hw_r14, uint8_t hw_r15)
{
    if (hw_r13 == 0xFFu) return true;
    uint32_t s_ab = (uint32_t)hw_r13 + hw_r14;
    uint32_t s_cd = (uint32_t)hw_r15 + _hw_r16_sum;
    if (s_ab > 32u || s_cd > 32u) return false;
    return _sum_valid[s_ab][s_cd] != 0;
}

__device__ __forceinline__ void _ABCDStore(uint32_t ab, uint32_t cd,
                                            uint32_t maxFound, uint32_t *out)
{
    uint32_t pos = atomicAdd(out, 1);
    if (pos < maxFound) {
        out[1 + pos*ABCD_ITEM32 + 0] = ab;
        out[1 + pos*ABCD_ITEM32 + 1] = cd;
        out[1 + pos*ABCD_ITEM32 + 2] = 0;
    }
}

// ── 批量求逆（NC 元素，模板化）────────────────────────────────────────────
template<int NC>
__device__ __noinline__ void _ModInvGroupedN(uint64_t r[][4])
{
    uint64_t subp[NC + 1][4];
    uint64_t newValue[4];
    uint64_t inverse[5];

    Load256(subp[0], r[0]);
    for (int i = 1; i <= NC; i++)
        _ModMult(subp[i], subp[i - 1], r[i]);

    Load256(inverse, subp[NC]);
    inverse[4] = 0;
    _ModInv(inverse);

    for (int i = NC; i > 0; i--) {
        _ModMult(newValue, subp[i - 1], inverse);
        _ModMult(inverse, r[i]);
        Load256(r[i], newValue);
    }
    Load256(r[0], inverse);
}

// ── 主 kernel（模板化 NC）────────────────────────────────────────────────
template<int NC>
__global__ void comp_keys_abcd(
    const uint64_t *abTable,
    const uint8_t  *abHwTable,    // hw(c&d) AND  per AB entry，nullptr=不过滤
    const uint8_t  *abHwTable2,   // hw(c^d) XOR  per AB entry，nullptr=不过滤
    const uint8_t  *abHwSumR13,   // hw(r13) popcount per AB entry，nullptr=不过滤
    const uint64_t *cdTable,
    const uint8_t  *cdHwTable,    // hw(a&b) AND  per CD entry，nullptr=不过滤
    const uint8_t  *cdHwTable2,   // hw(a^b) XOR  per CD entry，nullptr=不过滤
    const uint8_t  *cdHwSumR14,   // hw(r14) popcount per CD entry
    const uint8_t  *cdHwSumR15,   // hw(r15) popcount per CD entry
    uint32_t abSize, uint32_t cdSize,
    uint64_t startCombo,
    prefix_t tPfx,
    uint32_t maxFound,
    uint32_t *out)
{
    uint64_t base = startCombo +
        ((uint64_t)blockIdx.x * blockDim.x + threadIdx.x) * (uint64_t)NC;
    uint64_t total = (uint64_t)abSize * cdSize;

    uint64_t dx[NC + 1][4];
    bool skip[NC];

    dx[NC][0] = 1; dx[NC][1] = dx[NC][2] = dx[NC][3] = 0;

    // ── Pass 1：计算分母 dx = CD.x - AB.x ────────────────────────────────
    // NC << cdSize，同批次 ab 几乎不变，提前取 hw_cd* 一次
    uint32_t ab_batch = (uint32_t)(base / (uint64_t)cdSize);
    uint8_t hw_cd_batch  = (abHwTable  && ab_batch < abSize) ? abHwTable [ab_batch] : 0xFFu;
    uint8_t hw_cd2_batch = (abHwTable2 && ab_batch < abSize) ? abHwTable2[ab_batch] : 0xFFu;

    for (int c = 0; c < NC; c++) {
        uint64_t ci = base + c;
        if (ci >= total) {
            dx[c][0]=1; dx[c][1]=dx[c][2]=dx[c][3]=0; skip[c]=true; continue;
        }
        uint32_t ab = (uint32_t)(ci / cdSize);
        uint32_t cd = (uint32_t)(ci % cdSize);

        // hw 联合过滤（AND + XOR 同时检查）
        uint8_t hw_ab  = cdHwTable  ? cdHwTable [cd] : 0xFFu;
        uint8_t hw_ab2 = cdHwTable2 ? cdHwTable2[cd] : 0xFFu;
        uint8_t hw_cd  = (ab == ab_batch) ? hw_cd_batch
                         : (abHwTable  ? abHwTable [ab] : 0xFFu);
        uint8_t hw_cd2 = (ab == ab_batch) ? hw_cd2_batch
                         : (abHwTable2 ? abHwTable2[ab] : 0xFFu);
        if (!_hwValidFilter(hw_ab, hw_cd, hw_ab2, hw_cd2)) {
            dx[c][0]=1; dx[c][1]=dx[c][2]=dx[c][3]=0; skip[c]=true; continue;
        }
        // 和过滤：hw(r13)+hw(r14)  /  hw(r15)+hw(r16)
        if (abHwSumR13) {
            uint8_t h13 = abHwSumR13[ab];
            uint8_t h14 = cdHwSumR14 ? cdHwSumR14[cd] : 0u;
            uint8_t h15 = cdHwSumR15 ? cdHwSumR15[cd] : 0u;
            if (!_sumValidFilter(h13, h14, h15)) {
                dx[c][0]=1; dx[c][1]=dx[c][2]=dx[c][3]=0; skip[c]=true; continue;
            }
        }

        uint64_t ax[4], bx[4];
        for (int j=0;j<4;j++) { ax[j]=abTable[ab*8+j]; bx[j]=cdTable[cd*8+j]; }
        bool czero = (bx[0]==0 && bx[1]==0 && bx[2]==0 && bx[3]==0);
        skip[c] = czero;
        if (czero) { dx[c][0]=1; dx[c][1]=dx[c][2]=dx[c][3]=0; }
        else        ModSub256(dx[c], bx, ax);
    }

    // ── 批量求逆 ────────────────────────────────────────────────────────
    _ModInvGroupedN<NC>(dx);

    // ── Pass 2：完成点加 + hash + 比对 ───────────────────────────────────
    for (int c = 0; c < NC; c++) {
        uint64_t ci = base + c;
        if (ci >= total) break;
        uint32_t ab = (uint32_t)(ci / cdSize);
        uint32_t cd = (uint32_t)(ci % cdSize);
        uint64_t ax[4], ay[4], bx[4], by[4];
        for (int j=0;j<4;j++) {
            ax[j]=abTable[ab*8+j]; ay[j]=abTable[ab*8+4+j];
            bx[j]=cdTable[cd*8+j]; by[j]=cdTable[cd*8+4+j];
        }
        uint64_t rx[4], ry[4];
        if (skip[c]) {
            for (int j=0;j<4;j++) { rx[j]=ax[j]; ry[j]=ay[j]; }
        } else {
            uint64_t dy[4], lam[4], t[4];
            ModSub256(dy, by, ay);
            _ModMult(lam, dy, dx[c]);
            _ModSqr(t, lam);
            ModSub256(rx, t, ax); ModSub256(rx, rx, bx);
            ModSub256(t, ax, rx);
            _ModMult(ry, lam, t); ModSub256(ry, ry, ay);
        }
        uint32_t h[5];
        _GetHash160Comp(rx, (uint8_t)(ry[0]&1), (uint8_t*)h);
        if ((uint16_t)h[0] == (uint16_t)tPfx &&
            h[0]==_abcd_target[0] && h[1]==_abcd_target[1] &&
            h[2]==_abcd_target[2] && h[3]==_abcd_target[3] &&
            h[4]==_abcd_target[4])
            _ABCDStore(ab, cd, maxFound, out);
    }
}

#endif
