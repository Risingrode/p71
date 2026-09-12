// AB+CD 组合搜索 GPU kernel
// AB 表（含前导点 A）× CD 表，每组合做一次仿射点加法
// 已移除端态形变（×6），速度即真实私钥检查速度

#ifndef GPU_COMBINE_ABCD_H
#define GPU_COMBINE_ABCD_H

#define ABCD_ITEM32   3      // 每条命中：ab_idx, cd_idx, 0（保留）
#define ABCD_MAX_FOUND 1024

__device__ __constant__ uint32_t _abcd_target[5];  // 目标 hash160

// 存储命中
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

// ── 主 kernel：每线程处理 GRP_SIZE/2=512 个组合（批量求逆）──────
// Pass1：计算分母 dx = CD.x - AB.x，批量求逆
// Pass2：完成点加，hash，比对
__global__ void comp_keys_abcd(
    const uint64_t *abTable,   // AB 预计算点 [abSize][8]
    const uint64_t *cdTable,   // CD 预计算点 [cdSize][8]
    uint32_t abSize, uint32_t cdSize,
    uint64_t startCombo,
    prefix_t tPfx,
    uint32_t maxFound,
    uint32_t *out)
{
    const int NC = GRP_SIZE / 2;   // 512 个组合/线程

    uint64_t base = startCombo +
        ((uint64_t)blockIdx.x * blockDim.x + threadIdx.x) * (uint64_t)NC;
    uint64_t total = (uint64_t)abSize * cdSize;

    uint64_t dx[GRP_SIZE / 2 + 1][4];
    bool skip[GRP_SIZE / 2];   // CD = 无穷远则跳过加法

    // dx[512] 是 _ModInvGrouped 内部需要的第 513 个元素，必须初始化
    dx[NC][0] = 1; dx[NC][1] = dx[NC][2] = dx[NC][3] = 0;

    // ── Pass 1：计算分母 ─────────────────────────────────────
    for (int c = 0; c < NC; c++) {
        uint64_t ci = base + c;
        if (ci >= total) {
            dx[c][0]=1; dx[c][1]=dx[c][2]=dx[c][3]=0; skip[c]=true; continue;
        }
        uint32_t ab = (uint32_t)(ci / cdSize);
        uint32_t cd = (uint32_t)(ci % cdSize);

        uint64_t ax[4], bx[4];
        for (int j=0;j<4;j++) { ax[j]=abTable[ab*8+j]; bx[j]=cdTable[cd*8+j]; }

        bool czero = (bx[0]==0 && bx[1]==0 && bx[2]==0 && bx[3]==0);
        skip[c] = czero;
        if (czero) { dx[c][0]=1; dx[c][1]=dx[c][2]=dx[c][3]=0; }
        else        ModSub256(dx[c], bx, ax);
    }

    // ── 批量求逆（1次 ModInv 覆盖 512 个分母）──────────────────
    _ModInvGrouped(dx);

    // ── Pass 2：完成点加 + hash + 比对 ──────────────────────────
    for (int c = 0; c < NC; c++) {
        uint64_t ci = base + c;
        if (ci >= total) break;

        uint32_t ab = (uint32_t)(ci / cdSize);
        uint32_t cd = (uint32_t)(ci % cdSize);

        uint64_t ax[4],ay[4],bx[4],by[4];
        for (int j=0;j<4;j++) {
            ax[j]=abTable[ab*8+j]; ay[j]=abTable[ab*8+4+j];
            bx[j]=cdTable[cd*8+j]; by[j]=cdTable[cd*8+4+j];
        }

        uint64_t rx[4], ry[4];
        if (skip[c]) {
            // CD = 无穷远 → P = AB
            for (int j=0;j<4;j++) { rx[j]=ax[j]; ry[j]=ay[j]; }
        } else {
            uint64_t dy[4], lam[4], t[4];
            ModSub256(dy, by, ay);
            _ModMult(lam, dy, dx[c]);      // λ = (CD.y-AB.y) / (CD.x-AB.x)
            _ModSqr(t, lam);
            ModSub256(rx, t, ax); ModSub256(rx, rx, bx);  // rx = λ²-ax-bx
            ModSub256(t, ax, rx);
            _ModMult(ry, lam, t); ModSub256(ry, ry, ay);  // ry = λ(ax-rx)-ay
        }

        // hash160(压缩公钥) 并与目标比对
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
