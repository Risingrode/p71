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
#include <utility>
#include <set>
#include <map>
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
    printf("\n找到: %s\nWIF : p2pkh:%s\nHEX : 0x%s\n",
           addr.c_str(),wif.c_str(),hex.c_str());
    if(!outputFile.empty()){
        FILE *f=fopen(outputFile.c_str(),"a");
        if(f){
            fprintf(f,"找到: %s\nWIF : p2pkh:%s\nHEX : 0x%s\n",
                    addr.c_str(),wif.c_str(),hex.c_str());
            fclose(f);
        }
    }
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
                                      vector<uint8_t>  &hwResult,
                                      vector<uint8_t>  &hwXorResult,
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
    hwResult.resize(total, 0xFFu);     // AND hw，0xFF = 不过滤
    hwXorResult.resize(total, 0xFFu);  // XOR hw

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

        // 本 outer 轮的 hw 基础值：pats[n-2] 的当前值（n>=2 时有效）
        uint16_t hw_v1 = (n >= 2) ? pats[n-2][outerIdx[n-2]] : 0u;

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
                if (n >= 2) {
                    uint32_t v2 = pats[n-1][j];
                    hwResult   [combo] = (uint8_t)__builtin_popcount((uint32_t)hw_v1 & v2);
                    hwXorResult[combo] = (uint8_t)__builtin_popcount((uint32_t)hw_v1 ^ v2);
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
                hwResult[combo] = (n >= 2)
                    ? (uint8_t)__builtin_popcount((uint32_t)hw_v1 & (uint32_t)pats[n-1][j])
                    : 0xFFu;
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

// 计算 AB/CD 紧凑表中每条目对应段的 popcount 表
// AB 表: abSumR13[i] = popcount(r13 value of entry i)
// CD 表: cdSumR14[i] = popcount(r14), cdSumR15[i] = popcount(r15)
static void buildSumTables(
    const vector<vector<uint16_t>> &abPats,  // [r12, r13]
    const vector<vector<uint16_t>> &cdPats,  // [r14, r15]
    uint32_t abSize, uint32_t cdSize,
    vector<uint8_t> &abSumR13,
    vector<uint8_t> &cdSumR14,
    vector<uint8_t> &cdSumR15)
{
    int r13n = (int)abPats[1].size();
    abSumR13.resize(abSize);
    for (uint32_t i = 0; i < abSize; i++)
        abSumR13[i] = (uint8_t)__builtin_popcount(abPats[1][i % r13n]);

    int r15n = (int)cdPats[1].size();
    cdSumR14.resize(cdSize);
    cdSumR15.resize(cdSize);
    for (uint32_t i = 0; i < cdSize; i++) {
        cdSumR14[i] = (uint8_t)__builtin_popcount(cdPats[0][i / r15n]);
        cdSumR15[i] = (uint8_t)__builtin_popcount(cdPats[1][i % r15n]);
    }
}

// 主搜索循环
void PuzzleSolve::Search(vector<vector<uint16_t>> &patterns,
                          int bits, int splitIdx,
                          vector<int> gpuId, vector<int> gridSize,
                          const vector<pair<int,int>> &hwPairs,
                          const vector<pair<int,int>> &hwXorPairs,
                          const vector<ABRangeRow>   &abRanges,
                          const vector<CDRangeRow>   &cdRanges,
                          const vector<pair<int,int>> &hwSumPairs)
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
    vector<uint64_t> cdTable;
    vector<uint8_t> cdHwTable, cdHwXorTable;
    uint32_t cdSize;
    buildCombinedTable(cdPats, cdShifts, cdChunks,
                       cdTable, cdHwTable, cdHwXorTable, cdSize, false, Point());
    printf("CD 表: %u 个点\n", cdSize);

    if (gridSize.empty()) { gridSize.push_back(-1); gridSize.push_back(128); }

    // ── 外层循环：每个外层值重新构建 AB 表并启动 GPU ─────────
    uint32_t outerMask = hasOuter ? ((outerChunk>=16) ? 0xFFFFu : ((1u<<outerChunk)-1u)) : 0u;

    endOfSearch = false;
    nbFoundKey  = 0;
    setvbuf(stdout, NULL, _IONBF, 0);

    uint64_t totalDone = 0;
    double   t_global  = Timer::get_tick();
    const uint64_t BATCH = (uint64_t)65535 * 128;

    if (!abRanges.empty() && !cdRanges.empty()) {
        // ── 字节范围搜索：(AB行 × CD分区) 两级嵌套，范围过滤优先 ─────────────
        // a=r13(abPats[1])  b=r14(cdPats[0])  c=r15(cdPats[1])  d=r16(outer)
        printf("字节范围搜索：%zu 个 AB 优先级行 × %zu 个 CD 分区\n",
               abRanges.size(), cdRanges.size());
        bool useXor = !hwXorPairs.empty();
        if (useXor) printf("hw XOR 过滤已启用（%zu 对）\n", hwXorPairs.size());

        // 预计算各行/分区的有效索引
        int nr13 = (int)abPats[1].size(), nr14 = (int)cdPats[0].size();
        int nr15 = (int)cdPats[1].size();

        // AB 行：r13 和 r14 索引
        int nab = (int)abRanges.size();
        vector<vector<int>> r13_idx(nab), r14_idx(nab);
        for (int i = 0; i < nab; i++) {
            for (int k = 0; k < nr13; k++)
                if (abRanges[i].a.matches(abPats[1][k])) r13_idx[i].push_back(k);
            for (int k = 0; k < nr14; k++)
                if (abRanges[i].b.matches(cdPats[0][k])) r14_idx[i].push_back(k);
            printf("  AB行%d: r13=%d/%d  r14=%d/%d\n", i+1,
                   (int)r13_idx[i].size(), nr13,
                   (int)r14_idx[i].size(), nr14);
        }

        // CD 分区：r15 和 r16(outer) 索引
        int ncd = (int)cdRanges.size();
        vector<vector<int>> r15_idx(ncd), r16_idx(ncd);
        for (int j = 0; j < ncd; j++) {
            for (int k = 0; k < nr15; k++)
                if (cdRanges[j].c.matches(cdPats[1][k])) r15_idx[j].push_back(k);
            for (int k = 0; k < (int)outerVals.size(); k++)
                if (cdRanges[j].d.matches(outerVals[k])) r16_idx[j].push_back(k);
            printf("  CD区%d: r15=%d/%d  r16=%d/%d\n", j+1,
                   (int)r15_idx[j].size(), nr15,
                   (int)r16_idx[j].size(), (int)outerVals.size());
        }

        int cached_nc = 0;

        for (int i = 0; i < nab && !endOfSearch; i++) {
            if (r13_idx[i].empty() || r14_idx[i].empty()) continue;

            // 构建 r13 和 r14 子集（VALUES，不是索引）
            vector<uint16_t> r13_sub, r14_sub;
            for (int k : r13_idx[i]) r13_sub.push_back(abPats[1][k]);
            for (int k : r14_idx[i]) r14_sub.push_back(cdPats[0][k]);

            // AB 子模式：[r12, r13_sub]（结构与 abPats 相同，仅 r13 被过滤）
            vector<vector<uint16_t>> abPats_sub = {abPats[0], r13_sub};

            for (int j = 0; j < ncd && !endOfSearch; j++) {
                if (r15_idx[j].empty() || r16_idx[j].empty()) continue;

                vector<uint16_t> r15_sub;
                for (int k : r15_idx[j]) r15_sub.push_back(cdPats[1][k]);

                // CD 子模式：[r14_sub, r15_sub]
                vector<vector<uint16_t>> cdPats_sub = {r14_sub, r15_sub};

                printf("AB行%d/CD区%d: 预计算 CD 子表（%zu×%zu=%zu）...\n",
                       i+1, j+1, r14_sub.size(), r15_sub.size(),
                       r14_sub.size() * r15_sub.size());

                // 构建 CD 子表（cdShifts/cdChunks 与原始相同，结构不变）
                vector<uint64_t> cdTable_sub;
                vector<uint8_t>  cdHwTable_sub, cdHwXorTable_sub;
                uint32_t cdSize_sub;
                buildCombinedTable(cdPats_sub, cdShifts, cdChunks,
                                   cdTable_sub, cdHwTable_sub, cdHwXorTable_sub,
                                   cdSize_sub, false, Point());

                // 构建 CD sum 表（hw(r14)/hw(r15) per CD entry）
                vector<uint8_t> cdSumR14_sub, cdSumR15_sub;
                bool useSum = !hwSumPairs.empty();
                if (useSum) {
                    int r15n = (int)r15_sub.size();
                    cdSumR14_sub.resize(cdSize_sub);
                    cdSumR15_sub.resize(cdSize_sub);
                    for (uint32_t k = 0; k < cdSize_sub; k++) {
                        cdSumR14_sub[k] = (uint8_t)__builtin_popcount(r14_sub[k / r15n]);
                        cdSumR15_sub[k] = (uint8_t)__builtin_popcount(r15_sub[k % r15n]);
                    }
                }

                int outer_count = (int)r16_idx[j].size();
                int outer_done  = 0;

                for (int oi : r16_idx[j]) {
                    if (endOfSearch) break;
                    outer_done++;

                    // 计算本轮基底点 A_cur
                    Point A_cur = A_base;
                    if (hasOuter) {
                        uint32_t ov = outerVals[oi] & outerMask;
                        if (ov > 0) {
                            Int outerKey; outerKey.SetInt32(ov);
                            outerKey.ShiftL((uint32_t)outerShift);
                            Point outerP = secp->ComputePublicKey(&outerKey);
                            A_cur = secp->AddDirect(A_base, outerP);
                        }
                    }

                    // 构建 AB 子表（含 A_cur 基底点）
                    vector<uint64_t> abTable_sub;
                    vector<uint8_t>  abHwTable_sub, abHwXorTable_sub;
                    uint32_t abSize_sub;
                    buildCombinedTable(abPats_sub, abShifts, abChunks,
                                       abTable_sub, abHwTable_sub, abHwXorTable_sub,
                                       abSize_sub, true, A_cur);

                    // 构建 AB sum 表（hw(r13) per AB entry）
                    vector<uint8_t> abSumR13_sub;
                    if (useSum) {
                        int r13n = (int)r13_sub.size();
                        abSumR13_sub.resize(abSize_sub);
                        for (uint32_t k = 0; k < abSize_sub; k++)
                            abSumR13_sub[k] = (uint8_t)__builtin_popcount(r13_sub[k % r13n]);
                    }

                    // hw(r16) for this outer iteration
                    uint8_t hw_r16 = useSum
                        ? (uint8_t)__builtin_popcount((uint32_t)outerVals[oi])
                        : 0xFFu;

                    // GPU 启动（XOR hw 过滤 + sum 过滤可选）
                    uint8_t *abXorPtr   = useXor ? abHwXorTable_sub.data() : nullptr;
                    uint8_t *cdXorPtr   = useXor ? cdHwXorTable_sub.data() : nullptr;
                    uint8_t *abSumPtr   = useSum ? abSumR13_sub.data()     : nullptr;
                    uint8_t *cdSumR14Ptr= useSum ? cdSumR14_sub.data()     : nullptr;
                    uint8_t *cdSumR15Ptr= useSum ? cdSumR15_sub.data()     : nullptr;
                    ABCDContext *ctx = abcdSetup(
                        abTable_sub.data(), nullptr, abXorPtr, abSize_sub,
                        cdTable_sub.data(), nullptr, cdXorPtr, cdSize_sub,
                        targetHash160, targetPrefix,
                        ABCD_MAX_FOUND, {}, hwXorPairs, cached_nc,
                        abSumPtr, cdSumR14Ptr, cdSumR15Ptr, hwSumPairs, hw_r16);
                    if (cached_nc == 0) cached_nc = abcdGetNC(ctx);

                    uint64_t pair_total = (uint64_t)abSize_sub * cdSize_sub;
                    uint64_t done = 0;
                    while (done < pair_total && !endOfSearch) {
                        uint64_t batch = min(BATCH, pair_total - done);
                        vector<tuple<uint32_t,uint32_t,uint8_t>> hits;
                        if (!abcdLaunch(ctx, done, batch, hits)) break;

                        for (auto &[ab, cd, var] : hits) {
                            // 用子模式和当前 outer 值验证
                            vector<uint16_t> outerSingle = {outerVals[oi]};
                            if (verifyAndOutput(ab, cd, var,
                                                abPats_sub, cdPats_sub, bits,
                                                0, &outerSingle,
                                                outerShift, outerChunk)) {
                                nbFoundKey++; endOfSearch = true; break;
                            }
                        }
                        done += batch;
                        totalDone += batch;

                        double dt   = Timer::get_tick() - t_global;
                        double rate = dt > 0 ? totalDone / dt : 0;
                        printf("\r[GPU %.0f Mkey/s][AB%d/CD%d][r16 %d/%d][%llu/%llu]  ",
                               rate/1e6, i+1, j+1, outer_done, outer_count,
                               (unsigned long long)done, (unsigned long long)pair_total);
                    }
                    abcdFree(ctx);
                }
            }
        }
        printf("\n");
        return;
    }

    if (!hwPairs.empty()) {
        // ── 有序搜索：按 hwPairs 优先级逐对搜索 ─────────────────────────────
        // 每对只搜 hw(a&b)==hw_ab && hw(c&d)==hw_cd 的紧凑子集，找到即停
        printf("有序 hw 搜索：共 %zu 个优先级对\n", hwPairs.size());

        // CD 按 hw(c&d) 分组（只需分一次，CD 表不随外层变化）
        vector<vector<uint32_t>> cd_groups(17);
        for (uint32_t j = 0; j < cdSize; j++)
            if (cdHwTable[j] <= 16)
                cd_groups[cdHwTable[j]].push_back(j);

        // 为优先级列表中出现的 hw_cd 值，预先构建紧凑 CD 点表 + XOR hw 表 + sum 表（一次性）
        bool useXor = !hwXorPairs.empty();
        bool useSum = !hwSumPairs.empty();
        if (useXor) printf("hw XOR 过滤已启用（%zu 对）\n", hwXorPairs.size());
        if (useSum) printf("hw sum 过滤已启用（%zu 对）\n", hwSumPairs.size());

        set<int> need_hw_cd;
        for (auto &p : hwPairs)
            if (p.second >= 0 && p.second <= 16) need_hw_cd.insert(p.second);

        int cd_r15n = (int)cdPats[1].size();
        map<int, vector<uint64_t>> cd_compact;
        map<int, vector<uint8_t>>  cd_xor_compact;
        map<int, vector<uint8_t>>  cd_sum_r14_compact;  // hw(r14) per compact CD entry
        map<int, vector<uint8_t>>  cd_sum_r15_compact;  // hw(r15) per compact CD entry
        for (int hw : need_hw_cd) {
            auto &grp = cd_groups[hw];
            if (grp.empty()) continue;
            auto &ctbl = cd_compact[hw];
            ctbl.resize((size_t)grp.size() * 8);
            for (size_t i = 0; i < grp.size(); i++)
                memcpy(ctbl.data() + i*8, cdTable.data() + (size_t)grp[i]*8, 64);
            if (useXor) {
                auto &xhw = cd_xor_compact[hw];
                xhw.resize(grp.size());
                for (size_t i = 0; i < grp.size(); i++)
                    xhw[i] = cdHwXorTable[grp[i]];
            }
            if (useSum) {
                auto &sr14 = cd_sum_r14_compact[hw];
                auto &sr15 = cd_sum_r15_compact[hw];
                sr14.resize(grp.size());
                sr15.resize(grp.size());
                for (size_t i = 0; i < grp.size(); i++) {
                    uint32_t oi2 = grp[i];
                    sr14[i] = (uint8_t)__builtin_popcount(cdPats[0][oi2 / cd_r15n]);
                    sr15[i] = (uint8_t)__builtin_popcount(cdPats[1][oi2 % cd_r15n]);
                }
            }
        }

        int cached_nc = 0;  // 首次 abcdSetup 后缓存 optimal_nc，后续复用

        for (int oi = 0; oi < (int)outerVals.size() && !endOfSearch; oi++) {
            // 计算本轮基底点 A_cur
            Point A_cur = A_base;
            if (hasOuter) {
                uint32_t ov = outerVals[oi] & outerMask;
                if (ov > 0) {
                    Int outerKey; outerKey.SetInt32(ov); outerKey.ShiftL((uint32_t)outerShift);
                    Point outerP = secp->ComputePublicKey(&outerKey);
                    A_cur = secp->AddDirect(A_base, outerP);
                }
            }

            // 构建本轮 AB 表
            vector<uint64_t> abTable;
            vector<uint8_t>  abHwTable, abHwXorTable;
            uint32_t abSize;
            if (oi == 0 || hasOuter)
                buildCombinedTable(abPats, abShifts, abChunks,
                                   abTable, abHwTable, abHwXorTable, abSize, true, A_cur);
            if (oi == 0) printf("AB 表: %u 个点，有序 GPU 搜索开始...\n", abSize);

            // AB 按 hw(a&b) 分组
            vector<vector<uint32_t>> ab_groups(17);
            for (uint32_t i = 0; i < abSize; i++)
                if (abHwTable[i] <= 16)
                    ab_groups[abHwTable[i]].push_back(i);

            // 为优先级列表中出现的 hw_ab 值构建紧凑 AB 点表 + XOR hw 表 + sum 表
            set<int> need_hw_ab;
            for (auto &p : hwPairs)
                if (p.first >= 0 && p.first <= 16) need_hw_ab.insert(p.first);

            int ab_r13n = (int)abPats[1].size();
            map<int, vector<uint64_t>> ab_compact;
            map<int, vector<uint8_t>>  ab_xor_compact;
            map<int, vector<uint8_t>>  ab_sum_compact;  // hw(r13) per compact AB entry
            for (int hw : need_hw_ab) {
                auto &grp = ab_groups[hw];
                if (grp.empty()) continue;
                auto &atbl = ab_compact[hw];
                atbl.resize((size_t)grp.size() * 8);
                for (size_t i = 0; i < grp.size(); i++)
                    memcpy(atbl.data() + i*8, abTable.data() + (size_t)grp[i]*8, 64);
                if (useXor) {
                    auto &xhw = ab_xor_compact[hw];
                    xhw.resize(grp.size());
                    for (size_t i = 0; i < grp.size(); i++)
                        xhw[i] = abHwXorTable[grp[i]];
                }
                if (useSum) {
                    auto &sr13 = ab_sum_compact[hw];
                    sr13.resize(grp.size());
                    for (size_t i = 0; i < grp.size(); i++)
                        sr13[i] = (uint8_t)__builtin_popcount(abPats[1][grp[i] % ab_r13n]);
                }
            }

            // 按优先级顺序逐对搜索
            for (auto &[hw_ab, hw_cd] : hwPairs) {
                if (endOfSearch) break;
                if (hw_ab < 0 || hw_ab > 16 || hw_cd < 0 || hw_cd > 16) continue;

                auto ab_it = ab_compact.find(hw_ab);
                auto cd_it = cd_compact.find(hw_cd);
                if (ab_it == ab_compact.end() || cd_it == cd_compact.end()) continue;

                auto &ab_grp = ab_groups[hw_ab];
                auto &cd_grp = cd_groups[hw_cd];
                uint32_t ab_n = (uint32_t)ab_grp.size();
                uint32_t cd_n = (uint32_t)cd_grp.size();
                if (ab_n == 0 || cd_n == 0) continue;

                // 用紧凑子表启动 GPU（AND hw 已由分组消除，XOR/sum hw 由 GPU 过滤）
                uint8_t *ab_xhw    = useXor ? ab_xor_compact[hw_ab].data()      : nullptr;
                uint8_t *cd_xhw    = useXor ? cd_xor_compact[hw_cd].data()      : nullptr;
                uint8_t *ab_sr13   = useSum ? ab_sum_compact[hw_ab].data()       : nullptr;
                uint8_t *cd_sr14   = useSum ? cd_sum_r14_compact[hw_cd].data()   : nullptr;
                uint8_t *cd_sr15   = useSum ? cd_sum_r15_compact[hw_cd].data()   : nullptr;
                uint8_t  hw_r16_s  = useSum
                    ? (uint8_t)__builtin_popcount((uint32_t)outerVals[oi]) : 0xFFu;
                ABCDContext *ctx = abcdSetup(
                    ab_it->second.data(), nullptr, ab_xhw, ab_n,
                    cd_it->second.data(), nullptr, cd_xhw, cd_n,
                    targetHash160, targetPrefix,
                    ABCD_MAX_FOUND, {}, hwXorPairs, cached_nc,
                    ab_sr13, cd_sr14, cd_sr15, hwSumPairs, hw_r16_s);
                if (cached_nc == 0) cached_nc = abcdGetNC(ctx);

                uint64_t pair_total = (uint64_t)ab_n * cd_n;
                uint64_t done = 0;
                while (done < pair_total && !endOfSearch) {
                    uint64_t batchSize = min(BATCH, pair_total - done);
                    vector<tuple<uint32_t,uint32_t,uint8_t>> hits;
                    if (!abcdLaunch(ctx, done, batchSize, hits)) break;

                    for (auto &[sub_ab, sub_cd, var] : hits) {
                        // 将紧凑子表索引映射回原始 AB/CD 索引
                        uint32_t orig_ab = (sub_ab < ab_n) ? ab_grp[sub_ab] : sub_ab;
                        uint32_t orig_cd = (sub_cd < cd_n) ? cd_grp[sub_cd] : sub_cd;
                        if (verifyAndOutput(orig_ab, orig_cd, var, abPats, cdPats, bits,
                                            oi, &outerVals, outerShift, outerChunk)) {
                            nbFoundKey++; endOfSearch = true; break;
                        }
                    }
                    done += batchSize;
                    totalDone += batchSize;

                    double dt   = Timer::get_tick() - t_global;
                    double rate = (dt > 0) ? totalDone / dt : 0;
                    printf("\r[GPU %.0f Mkey/s][hw(%d,%d) %u×%u][外层%d/%d][%llu/%llu]  ",
                           rate/1e6, hw_ab, hw_cd, ab_n, cd_n,
                           oi+1, (int)outerVals.size(),
                           (unsigned long long)done, (unsigned long long)pair_total);
                }
                abcdFree(ctx);
            }
        }
        printf("\n");
        return;
    }

    // ── 非有序模式（hwPairs 为空）：原始单遍扫描 ────────────────────────────
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
        vector<uint64_t> abTable;
        vector<uint8_t> abHwTable, abHwXorTable;
        uint32_t abSize;
        if (oi == 0 || hasOuter)
            buildCombinedTable(abPats, abShifts, abChunks,
                               abTable, abHwTable, abHwXorTable, abSize, true, A_cur);

        if (oi == 0)
            printf("AB 表: %u 个点，GPU 搜索开始...\n", abSize);

        bool useXor2 = !hwXorPairs.empty();
        bool useSum2 = !hwSumPairs.empty();
        uint8_t *abHwXorPtr = useXor2 ? abHwXorTable.data() : nullptr;
        uint8_t *cdHwXorPtr = useXor2 ? cdHwXorTable.data() : nullptr;
        if (useXor2 && oi == 0) printf("hw XOR 过滤已启用（%zu 对）\n", hwXorPairs.size());
        if (useSum2 && oi == 0) printf("hw sum 过滤已启用（%zu 对）\n", hwSumPairs.size());

        // sum 表：hw(r13)/hw(r14)/hw(r15) per entry
        vector<uint8_t> abSumR13_f, cdSumR14_f, cdSumR15_f;
        if (useSum2) buildSumTables(abPats, cdPats, abSize, cdSize,
                                     abSumR13_f, cdSumR14_f, cdSumR15_f);
        uint8_t hw_r16_f = useSum2
            ? (uint8_t)__builtin_popcount((uint32_t)outerVals[oi]) : 0xFFu;

        ABCDContext *ctx = abcdSetup(
            abTable.data(), nullptr, abHwXorPtr, abSize,
            cdTable.data(), nullptr, cdHwXorPtr, cdSize,
            targetHash160, targetPrefix,
            ABCD_MAX_FOUND, {}, hwXorPairs, 0,
            useSum2 ? abSumR13_f.data() : nullptr,
            useSum2 ? cdSumR14_f.data() : nullptr,
            useSum2 ? cdSumR15_f.data() : nullptr,
            hwSumPairs, hw_r16_f);

        uint64_t done = 0;

        while (done < perOuterCombos && !endOfSearch) {
            uint64_t batchSize = min(BATCH, perOuterCombos - done);
            vector<tuple<uint32_t,uint32_t,uint8_t>> hits;
            if (!abcdLaunch(ctx, done, batchSize, hits)) break;

            for (auto &[ab, cd, var] : hits) {
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
