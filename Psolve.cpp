#include "Psolve.h"
#ifndef ABCD_MAX_FOUND
#define ABCD_MAX_FOUND 1024
#endif
#include "encoding/Base58.h"
#include "encoding/Bech32.h"
#include "hash/ripemd160.h"
#include "math/IntGroup.h"
#include "util/Timer.h"
#include <string.h>
#include <math.h>
#ifndef WIN64
#include <pthread.h>
#endif

using namespace std;

PuzzleSolve::PuzzleSolve(Secp256K1 *secp, const string &target,
                         const string &output)
{
    this->secp       = secp;
    this->outputFile = output;
    this->nbFoundKey = 0;
    this->endOfSearch = false;
    this->targetAddr = target;

    bool ok = false;
    if (!target.empty() && (target[0]=='1'||target[0]=='3')) {
        vector<unsigned char> dec;
        if (DecodeBase58(target,dec) && dec.size()==25) {
            searchType = (target[0]=='1') ? P2PKH : P2SH;
            memcpy(targetHash160, dec.data()+1, 20); ok=true;
        }
    } else if (target.size()>3 && (target[0]=='b'||target[0]=='B')) {
        uint8_t wp[40]; size_t wplen; int wv;
        string la=target; for(auto &c:la) c=tolower(c);
        if (segwit_addr_decode(&wv,wp,&wplen,"bc",la.c_str())&&wplen==20){
            searchType=BECH32; memcpy(targetHash160,wp,20); ok=true;
        }
    }
    if (!ok) { printf("无法解析地址: %s\n",target.c_str()); exit(1); }

    targetPrefix = *(prefix_t *)targetHash160;

    beta.SetBase16("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");
    lambda.SetBase16("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");
    beta2.SetBase16("851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40");
    lambda2.SetBase16("ac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283ce");

#ifndef WIN64
    ghMutex = PTHREAD_MUTEX_INITIALIZER;
#else
    ghMutex = CreateMutex(NULL,FALSE,NULL);
#endif

    printf("目标: %s\n",target.c_str());
}

void PuzzleSolve::output(const string &addr, const string &wif, const string &hex)
{
#ifdef WIN64
    WaitForSingleObject(ghMutex,INFINITE);
#else
    pthread_mutex_lock(&ghMutex);
#endif
    FILE *f=stdout; bool nc=false;
    if(!outputFile.empty()){f=fopen(outputFile.c_str(),"a");if(!f)f=stdout;else nc=true;}
    if(!nc) printf("\n");
    fprintf(f,"找到: %s\nWIF : p2pkh:%s\nHEX : 0x%s\n",
            addr.c_str(),wif.c_str(),hex.c_str());
    if(nc) fclose(f);
#ifdef WIN64
    ReleaseMutex(ghMutex);
#else
    pthread_mutex_unlock(&ghMutex);
#endif
}

// 将组合索引解码为各文件的值索引
void PuzzleSolve::decodeIdx(uint64_t idx,
                             const vector<vector<uint16_t>> &pats,
                             vector<int> &valIdx)
{
    // pats[0]=最高位文件，pats[N-1]=最低位文件
    // idx 的分解方式：先对最低位文件取模
    int n = (int)pats.size();
    valIdx.resize(n);
    uint64_t rem = idx;
    for (int i = n-1; i >= 0; i--) {
        valIdx[i] = (int)(rem % pats[i].size());
        rem /= pats[i].size();
    }
}

// 拼装完整私钥
// abVals: AB 各文件的值索引
// cdVals: CD 各文件的值索引
// allPats: 全部 r 文件（AB + CD 顺序）
void PuzzleSolve::assembleKey(Int &key,
                               const vector<int> &abVals,
                               const vector<int> &cdVals,
                               const vector<vector<uint16_t>> &allPats,
                               int bits)
{
    // 合并 ab+cd 值索引为完整 valIdx
    vector<int> allVals(abVals);
    allVals.insert(allVals.end(), cdVals.begin(), cdVals.end());

    key.SetInt32(0);
    int unknownBits = bits-1;
    int bitPos = unknownBits-1;

    for (int i = 0; i < (int)allPats.size() && bitPos >= 0; i++) {
        uint32_t val = allPats[i][allVals[i]];
        int chunk = (bitPos+1>=16) ? 16 : (bitPos+1);
        val &= (1u<<chunk)-1;
        Int seg; seg.SetInt32(val); seg.ShiftL((uint32_t)(bitPos-chunk+1));
        key.Add(&seg);
        bitPos -= chunk;
    }
    Int lead; lead.SetInt32(1); lead.ShiftL((uint32_t)unknownBits);
    key.Add(&lead);
}

// 构建单文件的子 EC 点表
// vals[i] = 第 i 条 r 值（16 位整数）
// shift   = 该文件在密钥中的起始位（低位到高位，0=最低位）
// 返回：table[v] = vals[v] * base，仿射坐标（base = 2^shift * G）
// shift = 该文件在密钥中的起始位，chunk = 该文件有效位数（vals 只有低 chunk 位有效）
// table[i] = (vals[i] & mask) * 2^shift * G
// 注意：全部使用单独 ComputePublicKey，适合小量（几千条）
void PuzzleSolve::buildSubTable(const vector<uint16_t> &vals, int shift, int chunk,
                                 vector<Point> &table)
{
    table.resize(vals.size());
    uint32_t mask = (chunk >= 16) ? 0xFFFFu : ((1u << chunk) - 1u);

    for (int i = 0; i < (int)vals.size(); i++) {
        uint32_t v = vals[i] & mask;   // 只取有效位
        if (v == 0) {
            table[i].x.SetInt32(0);
            table[i].y.SetInt32(0);
            table[i].z.SetInt32(0);    // z=0 = 无穷远点标记
        } else {
            Int keyVal;
            keyVal.SetInt32(v);
            keyVal.ShiftL((uint32_t)shift);  // v * 2^shift
            table[i] = secp->ComputePublicKey(&keyVal);
        }
    }
}

// 构建组合 EC 点表
// pats         = 文件列表（pats[0]=最高位，pats[N-1]=最低位）
// shifts       = 每个文件的起始位
// basePoint    = 可选的基底点（对 AB 表传入 A = 2^unknownBits*G）
// hasBase      = 是否有基底点
// result       = 输出，packed uint64_t[size×8]（x[4]+y[4]，仿射坐标）
//
// 对 AB 表：每个条目 = A + r12*2^s12*G + r13*2^s13*G + ...
// 对 CD 表：每个条目 = r14*2^s14*G + r15*2^s15*G + ...（全零表示无穷远，GPU 特判）
void PuzzleSolve::buildCombinedTable(const vector<vector<uint16_t>> &pats,
                                      const vector<int> &shifts,
                                      const vector<int> &chunks,
                                      vector<uint64_t> &result,
                                      uint32_t &size,
                                      bool hasBase,
                                      const Point &basePoint)
{
    int n = (int)pats.size();
    uint64_t total = 1;
    for (auto &p : pats) total *= p.size();
    if (total == 0) total = 1;  // 空 pats = 1 个 entry（只含基底点或全零）
    size = (uint32_t)total;
    result.resize(total * 8);

    // 预计算每个文件的子点表：sub[i][j] = (vals[j] & chunk_mask) * 2^shifts[i] * G
    vector<vector<Point>> sub(n);
    for (int i = 0; i < n; i++)
        buildSubTable(pats[i], shifts[i], chunks[i], sub[i]);

    // 最内层文件用 IntGroup 批量求逆加速（4000 次 ModInv → 1 次）
    int innerN = (int)pats[n-1].size();
    uint64_t outerTotal = (n >= 2) ? (total / (uint64_t)innerN) : 1;
    IntGroup *grp = (n >= 2 && innerN > 1) ? new IntGroup(innerN + 1) : nullptr;

    vector<Int> dxArr(innerN + 1);  // 分母数组（含批量求逆用的哨兵位）

    vector<int> outerIdx(max(n-1, 1), 0);
    uint64_t combo = 0;

    for (uint64_t outer = 0; outer < outerTotal; outer++) {
        // 计算外层基底点（除最内层文件外的所有贡献）
        Point outerP;
        bool outerInf = !hasBase;
        if (hasBase) outerP = basePoint;
        for (int i = 0; i < n-1; i++) {
            Point &Q = sub[i][outerIdx[i]];
            if (Q.z.IsZero()) continue;
            if (outerInf) { outerP = Q; outerInf = false; }
            else outerP = secp->AddDirect(outerP, Q);
        }

        if (grp && !outerInf) {
            // 批量计算 outerP + sub[n-1][j] for all j
            for (int j = 0; j <= innerN; j++) {
                if (j < innerN && !sub[n-1][j].z.IsZero())
                    dxArr[j].ModSub(&sub[n-1][j].x, &outerP.x);
                else
                    dxArr[j].SetInt32(1);  // 占位（无穷远或哨兵）
            }
            grp->Set(dxArr.data());
            grp->ModInv();  // 一次批量求逆覆盖所有 innerN 个分母

            for (int j = 0; j < innerN; j++) {
                Point &Q = sub[n-1][j];
                if (Q.z.IsZero()) {
                    // Q=无穷远 → 结果=outerP
                    result[combo*8+0]=outerP.x.bits64[0]; result[combo*8+1]=outerP.x.bits64[1];
                    result[combo*8+2]=outerP.x.bits64[2]; result[combo*8+3]=outerP.x.bits64[3];
                    result[combo*8+4]=outerP.y.bits64[0]; result[combo*8+5]=outerP.y.bits64[1];
                    result[combo*8+6]=outerP.y.bits64[2]; result[combo*8+7]=outerP.y.bits64[3];
                } else {
                    // 完成仿射加法：dxArr[j] 已经是 inv(Q.x - outerP.x)
                    Int dy; dy.ModSub(&Q.y, &outerP.y);
                    Int lam; lam.ModMulK1(&dy, &dxArr[j]);
                    Int t;   t.ModSquareK1(&lam);
                    Int rx;  rx.ModSub(&t, &outerP.x); rx.ModSub(&rx, &Q.x);
                    Int rx0(rx);
                    t.ModSub(&outerP.x, &rx0);
                    Int ry; ry.ModMulK1(&lam, &t); ry.ModSub(&ry, &outerP.y);
                    result[combo*8+0]=rx.bits64[0]; result[combo*8+1]=rx.bits64[1];
                    result[combo*8+2]=rx.bits64[2]; result[combo*8+3]=rx.bits64[3];
                    result[combo*8+4]=ry.bits64[0]; result[combo*8+5]=ry.bits64[1];
                    result[combo*8+6]=ry.bits64[2]; result[combo*8+7]=ry.bits64[3];
                }
                combo++;
            }
        } else {
            // 回退路径：单文件或外层点为无穷远
            for (int j = 0; j < innerN; j++) {
                Point P2 = outerInf ? Point() : outerP;
                bool inf2 = outerInf;
                Point &Q = sub[n-1][j];
                if (!Q.z.IsZero()) {
                    if (inf2) { P2 = Q; inf2 = false; }
                    else P2 = secp->AddDirect(P2, Q);
                }
                if (inf2) {
                    for (int k=0;k<8;k++) result[combo*8+k]=0;
                } else {
                    result[combo*8+0]=P2.x.bits64[0]; result[combo*8+1]=P2.x.bits64[1];
                    result[combo*8+2]=P2.x.bits64[2]; result[combo*8+3]=P2.x.bits64[3];
                    result[combo*8+4]=P2.y.bits64[0]; result[combo*8+5]=P2.y.bits64[1];
                    result[combo*8+6]=P2.y.bits64[2]; result[combo*8+7]=P2.y.bits64[3];
                }
                combo++;
            }
        }

        // 推进外层 idx
        for (int i = n-2; i >= 0; i--) {
            if (++outerIdx[i] < (int)pats[i].size()) break;
            outerIdx[i] = 0;
        }
    }
    delete grp;
}

// GPU 命中后的 CPU 私钥重建与验证
bool PuzzleSolve::verifyAndOutput(
    uint32_t ab_idx, uint32_t cd_idx, uint8_t variant,
    const vector<vector<uint16_t>> &abPats,
    const vector<vector<uint16_t>> &cdPats,
    int bits,
    int outerValIdx,
    const vector<uint16_t> *outerVals,
    int outerShift, int outerChunk)
{
    vector<int> abVals, cdVals;
    decodeIdx(ab_idx, abPats, abVals);
    decodeIdx(cd_idx, cdPats, cdVals);

    // 合并 ab + cd + 外层（如有）文件到 allPats
    vector<vector<uint16_t>> allPats(abPats);
    allPats.insert(allPats.end(), cdPats.begin(), cdPats.end());
    vector<int> allVals(abVals);
    allVals.insert(allVals.end(), cdVals.begin(), cdVals.end());

    // 用 computeShifts 相同的 LSB-first 逻辑重建私钥
    Int k;
    k.SetInt32(0);
    int unknownBits = bits - 1;

    // r12(pats[0])=低位，r16(pats[N-1])=高位（LSB-first）
    int firstChunk = unknownBits % 16;
    if (firstChunk == 0) firstChunk = 16;

    int bitPos = 0;
    for (int i = 0; i < (int)allPats.size() && bitPos < unknownBits; i++) {
        int chunk = (i == 0) ? firstChunk : min(16, unknownBits - bitPos);
        uint32_t mask = (1u << chunk) - 1;
        uint32_t val = allPats[i][allVals[i]] & mask;
        Int seg; seg.SetInt32(val); seg.ShiftL((uint32_t)bitPos);
        k.Add(&seg);
        bitPos += chunk;
    }

    // 外层文件的贡献
    if (outerVals && outerValIdx >= 0 && outerValIdx < (int)outerVals->size()) {
        uint32_t outerMask = (outerChunk >= 16) ? 0xFFFFu : ((1u << outerChunk) - 1u);
        uint32_t ov = (*outerVals)[outerValIdx] & outerMask;
        if (ov > 0) {
            Int seg; seg.SetInt32(ov); seg.ShiftL((uint32_t)outerShift);
            k.Add(&seg);
        }
    }

    // 前导 1
    Int lead; lead.SetInt32(1); lead.ShiftL((uint32_t)unknownBits);
    k.Add(&lead);

    (void)variant;

    Point p = secp->ComputePublicKey(&k);
    string addr = secp->GetAddress(searchType, true, p);
    if (addr != targetAddr) return false;

    output(addr, secp->GetPrivAddress(true, k), k.GetBase16());
    return true;
}

// 计算 bits 结构下各文件的 shift（起始位位置）
// pats 顺序：pats[0]=最高位文件，pats[N-1]=最低位文件
// 返回 shifts[i] = 文件 i 的起始 bit（从低位 0 开始数）
// r12=最低位，r16=最高位（从低到高分配）
// r12 优先拿余数位（unknownBits % 16），保证 r13-r16 各拿完整 16 位
static void computeShifts(const vector<vector<uint16_t>> &pats, int bits,
                           vector<int> &shifts, vector<int> &chunks)
{
    int unknownBits = bits - 1;
    int n = (int)pats.size();
    shifts.resize(n);
    chunks.resize(n);

    // r12（pats[0]）拿低位余数：如 puzzle70 unknownBits=69，69%16=5
    int firstChunk = unknownBits % 16;
    if (firstChunk == 0) firstChunk = 16;

    int bitPos = 0;  // 从 bit 0（最低位）开始
    for (int i = 0; i < n && bitPos < unknownBits; i++) {
        int chunk = (i == 0) ? firstChunk : min(16, unknownBits - bitPos);
        shifts[i] = bitPos;
        chunks[i] = chunk;
        bitPos += chunk;
    }
}

// 主搜索循环
void PuzzleSolve::Search(vector<vector<uint16_t>> &patterns,
                          int bits, int splitIdx,
                          vector<int> gpuId, vector<int> gridSize)
{
    if (splitIdx < 0 || splitIdx > (int)patterns.size())
        splitIdx = (int)patterns.size() / 2;

    // 当文件数 > split+2 时，最后一个文件作外层循环（避免 CD 表爆炸）
    // 例：5文件 split=2 → AB=r12×r13, outer=r16, CD=r14×r15
    int n = (int)patterns.size();
    bool hasOuter = (n > splitIdx + 2);  // CD 文件数超过2则取最后一个做外层

    vector<vector<uint16_t>> abPats(patterns.begin(), patterns.begin()+splitIdx);
    vector<vector<uint16_t>> cdPats;
    vector<uint16_t>          outerVals;

    if (hasOuter) {
        // 最后一个文件作外层循环，剩余给 CD
        cdPats = vector<vector<uint16_t>>(patterns.begin()+splitIdx, patterns.end()-1);
        outerVals = patterns.back();
    } else {
        cdPats = vector<vector<uint16_t>>(patterns.begin()+splitIdx, patterns.end());
        outerVals.push_back(0);  // 哨兵：只循环一次，外层贡献=0（无额外点）
    }

    // 计算各文件 shift/chunk
    vector<int> allShifts, allChunks;
    computeShifts(patterns, bits, allShifts, allChunks);
    vector<int> abShifts(allShifts.begin(), allShifts.begin()+splitIdx);
    vector<int> cdShifts(allShifts.begin()+splitIdx, allShifts.begin()+splitIdx+(int)cdPats.size());
    vector<int> abChunks(allChunks.begin(), allChunks.begin()+splitIdx);
    vector<int> cdChunks(allChunks.begin()+splitIdx, allChunks.begin()+splitIdx+(int)cdPats.size());
    // 外层文件的 shift/chunk
    int outerShift = hasOuter ? allShifts[n-1] : 0;
    int outerChunk = hasOuter ? allChunks[n-1] : 0;

    // 统计
    uint64_t abTotal = 1, cdTotal = 1;
    for (auto &p : abPats) abTotal *= p.size();
    for (auto &p : cdPats) cdTotal *= p.size();
    uint64_t perOuterCombos = abTotal * cdTotal;
    uint64_t totalCombos    = perOuterCombos * outerVals.size();

    printf("密钥位数   : %d  [2^%d, 2^%d)\n", bits, bits-1, bits);
    printf("AB 文件数  : %d  组合: %llu\n", (int)abPats.size(), (unsigned long long)abTotal);
    printf("CD 文件数  : %d  组合: %llu\n", (int)cdPats.size(), (unsigned long long)cdTotal);
    if (hasOuter)
        printf("外层文件   : 1  值数: %llu（逐个迭代）\n", (unsigned long long)outerVals.size());
    printf("总组合数   : %llu\n", (unsigned long long)totalCombos);

    // ── 预计算固定表（CD，只需算一次）────────────────────────
    // A = 2^(bits-1) * G
    Int leadKey; leadKey.SetInt32(1); leadKey.ShiftL((uint32_t)(bits-1));
    Point A_base = secp->ComputePublicKey(&leadKey);

    printf("预计算 CD 表（IntGroup 批量优化）...\n");
    vector<uint64_t> cdTable; uint32_t cdSize;
    buildCombinedTable(cdPats, cdShifts, cdChunks, cdTable, cdSize, false, Point());
    printf("CD 表: %u 个点\n", cdSize);

    if (gridSize.empty()) { gridSize.push_back(-1); gridSize.push_back(128); }

    // ── 外层循环：每个外层值重新构建 AB 表并启动 GPU ─────────
    uint32_t outerMask = hasOuter ? ((outerChunk>=16) ? 0xFFFFu : ((1u<<outerChunk)-1u)) : 0u;

    endOfSearch = false;
    nbFoundKey  = 0;
    setvbuf(stdout, NULL, _IONBF, 0);

    uint64_t totalDone = 0;
    double   t_global  = Timer::get_tick();

    for (int oi = 0; oi < (int)outerVals.size() && !endOfSearch; oi++) {
        // 计算外层值的 EC 贡献，加入 A 得到本轮基底点
        Point A_cur = A_base;
        if (hasOuter) {
            uint32_t ov = outerVals[oi] & outerMask;
            if (ov > 0) {
                Int outerKey; outerKey.SetInt32(ov); outerKey.ShiftL((uint32_t)outerShift);
                Point outerP = secp->ComputePublicKey(&outerKey);
                A_cur = secp->AddDirect(A_base, outerP);
            }
        }

        // 预计算本轮 AB 表（含 A_cur）
        vector<uint64_t> abTable; uint32_t abSize;
        if (oi == 0 || hasOuter)
            buildCombinedTable(abPats, abShifts, abChunks, abTable, abSize, true, A_cur);

        if (oi == 0)
            printf("AB 表: %u 个点，GPU 搜索开始...\n", abSize);

        ABCDContext *ctx = abcdSetup(
            abTable.data(), abSize,
            cdTable.data(), cdSize,
            targetHash160, targetPrefix,
            ABCD_MAX_FOUND);

        uint64_t done = 0;
        const uint64_t BATCH = (uint64_t)65535 * 128;

        while (done < perOuterCombos && !endOfSearch) {
            uint64_t batchSize = min(BATCH, perOuterCombos - done);
            vector<tuple<uint32_t,uint32_t,uint8_t>> hits;
            if (!abcdLaunch(ctx, done, batchSize, hits)) break;

            for (auto &[ab, cd, var] : hits) {
                // 外层文件值需传入验证
                vector<vector<uint16_t>> fullAbPats = abPats;
                vector<vector<uint16_t>> fullCdPats = cdPats;
                if (hasOuter) {
                    // 外层文件的值索引固定为 oi，作为额外 AB 贡献
                    // verifyAndOutput 只知道 AB+CD，外层通过 A_cur 已经融合进去
                }
                if (verifyAndOutput(ab, cd, var, abPats, cdPats, bits, oi, &outerVals, outerShift, outerChunk)) {
                    nbFoundKey++; endOfSearch = true; break;
                }
            }

            done += batchSize;
            totalDone += batchSize;

            double dt = Timer::get_tick() - t_global;
            double rate = (dt > 0) ? totalDone / dt : 0;
            double pct  = totalCombos > 0 ? totalDone*100.0/totalCombos : 0;
            if (hasOuter)
                printf("\r[GPU %.0f Mkey/s][外层%d/%d][%llu/%llu (%.2f%%)][找到 %d]  ",
                       rate/1e6, oi+1, (int)outerVals.size(),
                       (unsigned long long)totalDone, (unsigned long long)totalCombos,
                       pct, nbFoundKey);
            else
                printf("\r[GPU %.0f Mkey/s][%llu/%llu (%.2f%%)][找到 %d]  ",
                       rate/1e6, (unsigned long long)totalDone, (unsigned long long)totalCombos,
                       pct, nbFoundKey);
        }

        abcdFree(ctx);
    }

    printf("\n");
}
