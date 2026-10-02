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

#ifndef WIN64
    ghMutex = PTHREAD_MUTEX_INITIALIZER;
#else
    ghMutex = CreateMutex(NULL,FALSE,NULL);
#endif
    printf("目标: %s\n",target.c_str());
}

void PuzzleSolve::output(const string &addr, const string &wif, const string &hex)
{
#ifndef WIN64
    pthread_mutex_lock(&ghMutex);
#else
    WaitForSingleObject(ghMutex,INFINITE);
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
#ifndef WIN64
    pthread_mutex_unlock(&ghMutex);
#else
    ReleaseMutex(ghMutex);
#endif
}

void PuzzleSolve::decodeIdx(uint64_t idx,
                             const vector<vector<uint16_t>> &pats,
                             vector<int> &valIdx)
{
    int n = (int)pats.size();
    valIdx.resize(n);
    uint64_t rem = idx;
    for (int i = n-1; i >= 0; i--) {
        valIdx[i] = (int)(rem % pats[i].size());
        rem /= pats[i].size();
    }
}

void PuzzleSolve::buildSubTable(const vector<uint16_t> &vals, int shift, int chunk,
                                 vector<Point> &table)
{
    table.resize(vals.size());
    uint32_t mask = (chunk >= 16) ? 0xFFFFu : ((1u << chunk) - 1u);
    for (int i = 0; i < (int)vals.size(); i++) {
        uint32_t v = vals[i] & mask;
        if (v == 0) {
            table[i].x.SetInt32(0);
            table[i].y.SetInt32(0);
            table[i].z.SetInt32(0);
        } else {
            Int keyVal;
            keyVal.SetInt32(v);
            keyVal.ShiftL((uint32_t)shift);
            table[i] = secp->ComputePublicKey(&keyVal);
        }
    }
}

// 构建所有文件笛卡尔积的 EC 点表（结果 = packed uint64_t[size×8]，x[4]+y[4]）
// 最内层文件用 IntGroup 批量求逆加速
void PuzzleSolve::buildCombinedTable(const vector<vector<uint16_t>> &pats,
                                      const vector<int> &shifts,
                                      const vector<int> &chunks,
                                      vector<uint64_t> &result,
                                      uint32_t &size,
                                      bool hasBase, const Point &basePoint)
{
    int n = (int)pats.size();
    uint64_t total = 1;
    for (auto &p : pats) total *= p.size();
    if (total == 0) total = 1;
    size = (uint32_t)total;
    result.resize(total * 8);

    vector<vector<Point>> sub(n);
    for (int i = 0; i < n; i++)
        buildSubTable(pats[i], shifts[i], chunks[i], sub[i]);

    int innerN = (int)pats[n-1].size();
    uint64_t outerTotal = (n >= 2) ? (total / (uint64_t)innerN) : 1;
    IntGroup *grp = (n >= 2 && innerN > 1) ? new IntGroup(innerN + 1) : nullptr;

    vector<Int> dxArr(innerN + 1);
    vector<int> outerIdx(max(n-1, 1), 0);
    uint64_t combo = 0;

    for (uint64_t outer = 0; outer < outerTotal; outer++) {
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
            for (int j = 0; j <= innerN; j++) {
                if (j < innerN && !sub[n-1][j].z.IsZero())
                    dxArr[j].ModSub(&sub[n-1][j].x, &outerP.x);
                else
                    dxArr[j].SetInt32(1);
            }
            grp->Set(dxArr.data());
            grp->ModInv();

            for (int j = 0; j < innerN; j++) {
                Point &Q = sub[n-1][j];
                if (Q.z.IsZero()) {
                    result[combo*8+0]=outerP.x.bits64[0]; result[combo*8+1]=outerP.x.bits64[1];
                    result[combo*8+2]=outerP.x.bits64[2]; result[combo*8+3]=outerP.x.bits64[3];
                    result[combo*8+4]=outerP.y.bits64[0]; result[combo*8+5]=outerP.y.bits64[1];
                    result[combo*8+6]=outerP.y.bits64[2]; result[combo*8+7]=outerP.y.bits64[3];
                } else {
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

        for (int i = n-2; i >= 0; i--) {
            if (++outerIdx[i] < (int)pats[i].size()) break;
            outerIdx[i] = 0;
        }
    }
    delete grp;
}

// GPU 命中后 CPU 端验证：重建私钥，计算地址，确认匹配后输出
bool PuzzleSolve::verifyAndOutput(
    uint32_t ab_idx, uint32_t cd_idx,
    const vector<vector<uint16_t>> &abPats,
    const vector<vector<uint16_t>> &cdPats,
    int bits)
{
    vector<int> abVals, cdVals;
    decodeIdx(ab_idx, abPats, abVals);
    decodeIdx(cd_idx, cdPats, cdVals);

    // allPats 顺序 = [r12, r13, r14, r15, r16]（LSB-first，r12=最低位）
    vector<vector<uint16_t>> allPats(abPats);
    allPats.insert(allPats.end(), cdPats.begin(), cdPats.end());
    vector<int> allVals(abVals);
    allVals.insert(allVals.end(), cdVals.begin(), cdVals.end());

    Int k;
    k.SetInt32(0);
    int unknownBits = bits - 1;
    int firstChunk  = unknownBits % 16;
    if (firstChunk == 0) firstChunk = 16;

    // 与 computeShifts 一致：从高位往低位，r12 在最高段
    int bitPos = unknownBits;
    for (int i = 0; i < (int)allPats.size() && bitPos > 0; i++) {
        int chunk = (i == 0) ? firstChunk : min(16, bitPos);
        bitPos -= chunk;
        uint32_t mask = (1u << chunk) - 1;
        uint32_t val  = allPats[i][allVals[i]] & mask;
        Int seg; seg.SetInt32(val); seg.ShiftL((uint32_t)bitPos);
        k.Add(&seg);
    }
    Int lead; lead.SetInt32(1); lead.ShiftL((uint32_t)unknownBits);
    k.Add(&lead);

    Point p   = secp->ComputePublicKey(&k);
    string addr = secp->GetAddress(searchType, true, p);
    if (addr != targetAddr) return false;

    output(addr, secp->GetPrivAddress(true, k), k.GetBase16());
    return true;
}

// 各文件在私钥中的起始位（MSB-first：r12=最高位，r16=最低位）
// 二进制从左到右：[r12(含前导1)][r13][r14][r15][r16]
// r12 拿余数位（unknownBits%16），放在最高段；r13-r16 各拿完整 16 位
static void computeShifts(const vector<vector<uint16_t>> &pats, int bits,
                           vector<int> &shifts, vector<int> &chunks)
{
    int unknownBits = bits - 1;
    int n = (int)pats.size();
    shifts.resize(n);
    chunks.resize(n);
    int firstChunk = unknownBits % 16;
    if (firstChunk == 0) firstChunk = 16;
    // 从高位往低位分配：patterns[0]=r12 拿最高位
    int bitPos = unknownBits;
    for (int i = 0; i < n && bitPos > 0; i++) {
        int chunk = (i == 0) ? firstChunk : min(16, bitPos);
        bitPos -= chunk;
        shifts[i] = bitPos;   // r12→shift=64, r13→48, r14→32, r15→16, r16→0
        chunks[i] = chunk;
    }
}

// 升级版主搜索（主机端 hw 预筛 + GPU 单次扫描）
// patterns = [r12, r13, r14, r15, r16]
// AB = r12×r13×r14，CD = r15×r16
// 流程：字节范围预过滤 → 计算 hw 数组 → 独立预筛 → GPU 单次扫描
void PuzzleSolve::Search(vector<vector<uint16_t>> &patterns,
                          int bits,
                          vector<int> gpuId, vector<int> gridSize,
                          const vector<ABRow> &abRows,
                          const vector<CDRow> &cdRows,
                          const vector<pair<int,int>> &hwPairs,
                          const vector<pair<int,int>> &hwXorPairs,
                          int sumMod, int sumRem)
{
    if (patterns.size() < 5) { printf("需要 5 个文件 (r12-r16)\n"); return; }

    vector<vector<uint16_t>> abPats(patterns.begin(), patterns.begin()+3);
    vector<vector<uint16_t>> cdPats(patterns.begin()+3, patterns.end());

    vector<int> allShifts, allChunks;
    computeShifts(patterns, bits, allShifts, allChunks);
    vector<int> abShifts(allShifts.begin(), allShifts.begin()+3);
    vector<int> cdShifts(allShifts.begin()+3, allShifts.end());
    vector<int> abChunks(allChunks.begin(), allChunks.begin()+3);
    vector<int> cdChunks(allChunks.begin()+3, allChunks.end());

    printf("密钥位数: %d  r13=%zu r14=%zu r15=%zu r16=%zu\n",
           bits, abPats[1].size(), abPats[2].size(), cdPats[0].size(), cdPats[1].size());
    printf("AND=%zu  XOR=%zu\n", hwPairs.size(), hwXorPairs.size());

    // (a+b+c+d) % sumMod == sumRem：AB 侧按 (a+b)%sumMod 分组，只与 CD 侧余数 (sumRem-x)%sumMod 的组配对
    const bool useMod = sumMod > 1;
    const int  M = useMod ? sumMod : 1;
    if (useMod) printf("附加条件: (r13+r14+r15+r16) %% %d == %d\n", sumMod, sumRem);

    const bool useAnd = !hwPairs.empty(), useXor = !hwXorPairs.empty();

    // 配对查找表：pairX[AB侧值][CD侧值] 为 true 表示这一对合法。
    // 启用了几类条件就要同时满足几类（AND/XOR/余数 全部成立才算合法组合）
    bool pairAnd[17][17]={}, pairXor[17][17]={};
    for (auto &[a,b]:hwPairs)    if (a>=0&&a<=16&&b>=0&&b<=16) pairAnd[a][b]=true;
    for (auto &[a,b]:hwXorPairs) if (a>=0&&a<=16&&b>=0&&b<=16) pairXor[a][b]=true;

    // 条目的键：(AND hw, XOR hw, 余数)，没启用的分量置 0。
    // 一个 AB 条目与一个 CD 条目能否组合，只取决于两者的键，所以按键分组即可
    auto packKey = [&](uint32_t u, uint32_t v)->uint64_t {
        uint64_t an = useAnd ? __builtin_popcount(u&v) : 0;
        uint64_t xr = useXor ? __builtin_popcount(u^v) : 0;
        uint64_t rs = useMod ? (u+v) % (uint32_t)M : 0;
        return an | xr<<8 | rs<<16;
    };
    auto compat = [&](uint64_t ka, uint64_t kc)->bool {
        if (useAnd && !pairAnd[ka&0xFF][kc&0xFF]) return false;
        if (useXor && !pairXor[(ka>>8)&0xFF][(kc>>8)&0xFF]) return false;
        if (useMod && (int)(((ka>>16)+(kc>>16)) % (uint64_t)M) != sumRem) return false;
        return true;
    };

    Int leadKey; leadKey.SetInt32(1); leadKey.ShiftL((uint32_t)(bits-1));
    Point A_base = secp->ComputePublicKey(&leadKey);

    endOfSearch = false; nbFoundKey = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    double t_global = Timer::get_tick();
    const uint64_t BATCH = (uint64_t)65535 * 128;
    uint64_t totalDone = 0;
    int nAB = (int)abRows.size(), nCD = (int)cdRows.size();

    for (int ai = 0; ai < nAB && !endOfSearch; ai++) {
        const ABRow &ar = abRows[ai];

        // 字节范围过滤 r13, r14
        vector<uint16_t> r13_sub, r14_sub;
        for (auto v:abPats[1]) if(ar.matchA(v)) r13_sub.push_back(v);
        for (auto v:abPats[2]) if(ar.matchB(v)) r14_sub.push_back(v);
        if (r13_sub.empty()||r14_sub.empty()) continue;

        vector<vector<uint16_t>> abSub = {abPats[0], r13_sub, r14_sub};
        printf("\nAB行%d: r13=%zu r14=%zu\n", ai+1, r13_sub.size(), r14_sub.size());

        // 构建完整 AB 表，并按键分组（组内存原始索引）
        vector<uint64_t> abTable_full;
        uint32_t abSize_full;
        buildCombinedTable(abSub, abShifts, abChunks, abTable_full, abSize_full, true, A_base);

        int r13n=(int)r13_sub.size(), r14n=(int)r14_sub.size();
        map<uint64_t, vector<uint32_t>> ab_grp;
        for (uint32_t i=0;i<abSize_full;i++)
            ab_grp[packKey(r13_sub[(i/r14n)%r13n], r14_sub[i%r14n])].push_back(i);
        printf("  AB: %u 条 %zu 组\n", abSize_full, ab_grp.size());

        vector<uint64_t> abKeys; vector<const vector<uint32_t>*> abIdx;
        for (auto &kv:ab_grp) { abKeys.push_back(kv.first); abIdx.push_back(&kv.second); }

        for (int ci = 0; ci < nCD && !endOfSearch; ci++) {
            const CDRow &cr = cdRows[ci];

            // 字节范围过滤 r15, r16
            vector<uint16_t> r15_sub, r16_sub;
            for (auto v:cdPats[0]) if(cr.matchC(v)) r15_sub.push_back(v);
            for (auto v:cdPats[1]) if(cr.matchD(v)) r16_sub.push_back(v);
            if (r15_sub.empty()||r16_sub.empty()) continue;

            vector<vector<uint16_t>> cdSub = {r15_sub, r16_sub};

            // 构建完整 CD 表，并按键分组
            vector<uint64_t> cdTable_full;
            uint32_t cdSize_full;
            buildCombinedTable(cdSub, cdShifts, cdChunks, cdTable_full, cdSize_full, false, Point());

            int r16n=(int)r16_sub.size();
            map<uint64_t, vector<uint32_t>> cd_grp;
            for (uint32_t j=0;j<cdSize_full;j++)
                cd_grp[packKey(r15_sub[j/r16n], r16_sub[j%r16n])].push_back(j);
            vector<uint64_t> cdKeys; vector<const vector<uint32_t>*> cdIdx;
            for (auto &kv:cd_grp) { cdKeys.push_back(kv.first); cdIdx.push_back(&kv.second); }

            // 每个 AB 组求出兼容的 CD 组集合（签名）；签名相同的 AB 组合并成一次扫描
            map<vector<uint32_t>, vector<uint32_t>> sig2ab;
            for (uint32_t k=0;k<abKeys.size();k++) {
                vector<uint32_t> sig;
                for (uint32_t m=0;m<cdKeys.size();m++) if (compat(abKeys[k], cdKeys[m])) sig.push_back(m);
                if (!sig.empty()) sig2ab[sig].push_back(k);
            }

            uint64_t pair_total=0;
            for (auto &[sig,aks]:sig2ab) {
                uint64_t na=0, nc=0;
                for (uint32_t k:aks) na+=abIdx[k]->size();
                for (uint32_t m:sig) nc+=cdIdx[m]->size();
                pair_total += na*nc;
            }
            printf("  CD区%d: r15=%zu r16=%zu  CD %u 条 %zu 组  扫描批次=%zu  总=%llu\n",
                   ci+1, r15_sub.size(), r16_sub.size(), cdSize_full, cd_grp.size(),
                   sig2ab.size(), (unsigned long long)pair_total);
            if (pair_total==0) { printf("  无合法组合，跳过\n"); continue; }

            uint64_t done=0;
            for (auto &[sig,aks]:sig2ab) {
                if (endOfSearch) break;
                vector<uint32_t> A, C;
                for (uint32_t k:aks) A.insert(A.end(), abIdx[k]->begin(), abIdx[k]->end());
                for (uint32_t m:sig) C.insert(C.end(), cdIdx[m]->begin(), cdIdx[m]->end());

                // 紧凑子表（只含本批条目）
                vector<uint64_t> abTable(A.size()*8), cdTable(C.size()*8);
                for (size_t i=0;i<A.size();i++) memcpy(abTable.data()+i*8, abTable_full.data()+(size_t)A[i]*8, 64);
                for (size_t j=0;j<C.size();j++) memcpy(cdTable.data()+j*8, cdTable_full.data()+(size_t)C[j]*8, 64);

                ABCDContext *ctx = abcdSetup(
                    abTable.data(), (uint32_t)A.size(), cdTable.data(), (uint32_t)C.size(),
                    targetHash160, targetPrefix, ABCD_MAX_FOUND);

                uint64_t grp_total=(uint64_t)A.size()*C.size(), grp_done=0;
                while (grp_done<grp_total && !endOfSearch) {
                    uint64_t batch=min(BATCH,grp_total-grp_done);
                    vector<tuple<uint32_t,uint32_t,uint8_t>> hits;
                    if (!abcdLaunch(ctx,grp_done,batch,hits)) break;

                    for (auto &[sub_ab,sub_cd,var]:hits) {
                        // 批内紧凑索引 → 原始索引 → verify
                        if (verifyAndOutput(A[sub_ab],C[sub_cd],abSub,cdSub,bits)) {
                            nbFoundKey++; endOfSearch=true; break;
                        }
                    }
                    grp_done+=batch; done+=batch; totalDone+=batch;
                    double dt=Timer::get_tick()-t_global;
                    double rate=dt>0?totalDone/dt:0;
                    printf("\r[AB%d/CD%d][GPU %.0f Mkey/s][%llu/%llu (%.1f%%)]  ",
                           ai+1,ci+1,rate/1e6,
                           (unsigned long long)done,(unsigned long long)pair_total,
                           done*100.0/pair_total);
                }
                abcdFree(ctx);
            }
        }
    }
    printf("\n");
}
