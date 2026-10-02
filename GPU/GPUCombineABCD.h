// AB+CD 组合搜索 GPU kernel
// 每个线程处理 NC 个连续组合：批量求逆（Montgomery trick）+ 点加 + hash 比对

#ifndef GPU_COMBINE_ABCD_H
#define GPU_COMBINE_ABCD_H

#define ABCD_ITEM32    3
#define ABCD_MAX_FOUND 1024
#ifndef ABCD_DEFAULT_NC
#define ABCD_DEFAULT_NC 64
#endif

__device__ __constant__ uint32_t _abcd_target[5];

__device__ __forceinline__ void _ABCDStore(uint32_t ab, uint32_t cd,
                                            uint32_t maxFound, uint32_t *out)
{
    uint32_t pos = atomicAdd(out, 1);
    if (pos < maxFound) {
        out[1+pos*ABCD_ITEM32+0] = ab;
        out[1+pos*ABCD_ITEM32+1] = cd;
        out[1+pos*ABCD_ITEM32+2] = 0;
    }
}

// dx = CD.x - AB.x；CD 表项 x 全 0 表示"无 CD 点"（结果就是 AB 点本身），此时 dx=1 不参与求逆
// 返回 true 表示这一项需要做点加
__device__ __forceinline__ bool _abcdDx(const uint64_t *abTable, const uint64_t *cdTable,
                                        uint32_t ab, uint32_t cd, uint64_t *dx)
{
    uint64_t ax[4], bx[4];
    for (int j=0;j<4;j++) { ax[j]=abTable[(size_t)ab*8+j]; bx[j]=cdTable[(size_t)cd*8+j]; }
    if (bx[0]==0&&bx[1]==0&&bx[2]==0&&bx[3]==0) { dx[0]=1; dx[1]=dx[2]=dx[3]=0; return false; }
    ModSub256(dx, bx, ax);
    return true;
}

#ifndef ABCD_FUSED
#define ABCD_FUSED 1
#endif

#if ABCD_FUSED

// 主 kernel：前向算前缀积 → 一次求逆 → 反向逐个还原逆元并立即完成点加 / hash / 比对。
// 不再存放 dx 数组（反向时从表里重新读取 AB/CD 点，这些点本来就要读），栈占用约减半。
template<int NC>
__global__ void comp_keys_abcd(
    const uint64_t *abTable,
    const uint64_t *cdTable,
    uint32_t abSize, uint32_t cdSize,
    uint64_t startCombo,
    prefix_t tPfx,
    uint32_t maxFound,
    uint32_t *out)
{
    uint64_t base = startCombo +
        ((uint64_t)blockIdx.x * blockDim.x + threadIdx.x) * (uint64_t)NC;
    uint64_t total = (uint64_t)abSize * cdSize;

    uint64_t subp[NC][4];   // subp[c] = dx[0]*...*dx[c]
    uint64_t inverse[5];

    // 前向：前缀积
    for (int c = 0; c < NC; c++) {
        uint64_t ci = base + c;
        uint64_t dx[4] = {1,0,0,0};
        if (ci < total) _abcdDx(abTable, cdTable, (uint32_t)(ci / cdSize), (uint32_t)(ci % cdSize), dx);
        if (c == 0) { Load256(subp[0], dx); }
        else        { _ModMult(subp[c], subp[c-1], dx); }
    }

    Load256(inverse, subp[NC-1]);
    inverse[4] = 0;
    _ModInv(inverse);

    // 反向：inverse 始终等于 1/(dx[0]*...*dx[c])
    for (int c = NC-1; c >= 0; c--) {
        uint64_t ci = base + c;
        uint64_t dx[4] = {1,0,0,0};
        bool valid = ci < total;
        bool add = false;
        uint32_t ab = 0, cd = 0;
        if (valid) {
            ab = (uint32_t)(ci / cdSize);
            cd = (uint32_t)(ci % cdSize);
            add = _abcdDx(abTable, cdTable, ab, cd, dx);
        }

        uint64_t inv[4];
        if (c > 0) {
            _ModMult(inv, subp[c-1], inverse);       // 1/dx[c]
            if (add) _ModMult(inverse, dx);          // 1/(dx[0]*...*dx[c-1])
        } else {
            Load256(inv, inverse);
        }
        if (!valid) continue;

        uint64_t ax[4],ay[4],bx[4],by[4];
        for (int j=0;j<4;j++) {
            ax[j]=abTable[(size_t)ab*8+j]; ay[j]=abTable[(size_t)ab*8+4+j];
            bx[j]=cdTable[(size_t)cd*8+j]; by[j]=cdTable[(size_t)cd*8+4+j];
        }
        uint64_t rx[4],ry[4];
        if (!add) {
            for (int j=0;j<4;j++) { rx[j]=ax[j]; ry[j]=ay[j]; }
        } else {
            uint64_t dy[4],lam[4],t[4];
            ModSub256(dy,by,ay);
            _ModMult(lam,dy,inv);
            _ModSqr(t,lam);
            ModSub256(rx,t,ax); ModSub256(rx,rx,bx);
            ModSub256(t,ax,rx);
            _ModMult(ry,lam,t); ModSub256(ry,ry,ay);
        }
        uint32_t h[5];
        _GetHash160Comp(rx,(uint8_t)(ry[0]&1),(uint8_t*)h);
        if ((uint16_t)h[0]==(uint16_t)tPfx &&
            h[0]==_abcd_target[0] && h[1]==_abcd_target[1] &&
            h[2]==_abcd_target[2] && h[3]==_abcd_target[3] &&
            h[4]==_abcd_target[4])
            _ABCDStore(ab,cd,maxFound,out);
    }
}

#else  // ---- 对照版：先存 dx 数组，求逆后再做第二遍（与原实现结构相同，仅去掉了 GPU 内过滤）----

template<int NC>
__device__ __noinline__ void _ModInvGroupedN(uint64_t r[][4])
{
    uint64_t subp[NC+1][4], newValue[4], inverse[5];
    Load256(subp[0], r[0]);
    for (int i=1;i<=NC;i++) _ModMult(subp[i], subp[i-1], r[i]);
    Load256(inverse, subp[NC]);
    inverse[4]=0;
    _ModInv(inverse);
    for (int i=NC;i>0;i--) {
        _ModMult(newValue, subp[i-1], inverse);
        _ModMult(inverse, r[i]);
        Load256(r[i], newValue);
    }
    Load256(r[0], inverse);
}

template<int NC>
__global__ void comp_keys_abcd(
    const uint64_t *abTable,
    const uint64_t *cdTable,
    uint32_t abSize, uint32_t cdSize,
    uint64_t startCombo,
    prefix_t tPfx,
    uint32_t maxFound,
    uint32_t *out)
{
    uint64_t base = startCombo +
        ((uint64_t)blockIdx.x * blockDim.x + threadIdx.x) * (uint64_t)NC;
    uint64_t total = (uint64_t)abSize * cdSize;

    uint64_t dx[NC+1][4];
    bool skip[NC];
    dx[NC][0]=1; dx[NC][1]=dx[NC][2]=dx[NC][3]=0;

    for (int c = 0; c < NC; c++) {
        uint64_t ci = base + c;
        dx[c][0]=1; dx[c][1]=dx[c][2]=dx[c][3]=0; skip[c]=true;
        if (ci >= total) continue;
        skip[c] = !_abcdDx(abTable, cdTable, (uint32_t)(ci / cdSize), (uint32_t)(ci % cdSize), dx[c]);
    }

    _ModInvGroupedN<NC>(dx);

    for (int c = 0; c < NC; c++) {
        uint64_t ci = base + c;
        if (ci >= total) break;
        uint32_t ab = (uint32_t)(ci / cdSize);
        uint32_t cd = (uint32_t)(ci % cdSize);
        uint64_t ax[4],ay[4],bx[4],by[4];
        for (int j=0;j<4;j++) {
            ax[j]=abTable[(size_t)ab*8+j]; ay[j]=abTable[(size_t)ab*8+4+j];
            bx[j]=cdTable[(size_t)cd*8+j]; by[j]=cdTable[(size_t)cd*8+4+j];
        }
        uint64_t rx[4],ry[4];
        if (skip[c]) {
            for (int j=0;j<4;j++) { rx[j]=ax[j]; ry[j]=ay[j]; }
        } else {
            uint64_t dy[4],lam[4],t[4];
            ModSub256(dy,by,ay);
            _ModMult(lam,dy,dx[c]);
            _ModSqr(t,lam);
            ModSub256(rx,t,ax); ModSub256(rx,rx,bx);
            ModSub256(t,ax,rx);
            _ModMult(ry,lam,t); ModSub256(ry,ry,ay);
        }
        uint32_t h[5];
        _GetHash160Comp(rx,(uint8_t)(ry[0]&1),(uint8_t*)h);
        if ((uint16_t)h[0]==(uint16_t)tPfx &&
            h[0]==_abcd_target[0] && h[1]==_abcd_target[1] &&
            h[2]==_abcd_target[2] && h[3]==_abcd_target[3] &&
            h[4]==_abcd_target[4])
            _ABCDStore(ab,cd,maxFound,out);
    }
}

#endif // ABCD_FUSED

#endif
