#include "util/Timer.h"
#include "Psolve.h"
#include "crypto/SECP256k1.h"
#include <string>
#include <string.h>
#include <fstream>
#include <sstream>
#include <map>

using namespace std;

#define RELEASE "4.0"

struct Config {
    string target;
    int    bits   = 0;
    map<string,string> rPaths;
    vector<int> gpuIds = {0};
    string output = "";
    vector<ABRow> abRows;
    vector<CDRow> cdRows;
    vector<pair<int,int>> hwPairs;
    vector<pair<int,int>> hwXorPairs;
    int sumMod = 0, sumRem = 0;   // sum_mod = M R：(r13+r14+r15+r16) % M == R
};

// 退出码：0 = 扫完未找到，10 = 找到解，1 = 配置/运行错误
#define EXIT_FOUND 10

static string trim(const string &s) {
    size_t a=s.find_first_not_of(" \t\r\n"), b=s.find_last_not_of(" \t\r\n");
    return (a==string::npos)?"":s.substr(a,b-a+1);
}

// 配置有任何问题都直接终止：写错的行如果被静默丢弃，真解可能因此永远扫不到
[[noreturn]] static void fail(const string &path, int lineNo, const string &msg) {
    if (lineNo > 0) printf("配置错误 %s 第 %d 行: %s\n", path.c_str(), lineNo, msg.c_str());
    else            printf("错误 %s: %s\n", path.c_str(), msg.c_str());
    exit(1);
}

// 把一行里的整数全部读出来；出现非整数内容则返回 false
static bool readInts(const string &s, vector<long> &out, char sep=' ') {
    string t = s;
    if (sep != ' ') for (auto &c:t) if (c==sep) c=' ';
    istringstream ss(t); string tok;
    while (ss >> tok) {
        char *end; long x = strtol(tok.c_str(), &end, 10);
        if (*end != '\0') return false;
        out.push_back(x);
    }
    return true;
}

static Config parseConf(const string &path) {
    Config cfg;
    ifstream f(path); if(!f) { printf("无法打开: %s\n",path.c_str()); exit(1); }
    string line; int ln = 0;
    bool haveGpu = false;
    while(getline(f,line)) {
        ln++;
        line=trim(line); if(line.empty()||line[0]=='#') continue;
        auto eq=line.find('='); if(eq==string::npos) fail(path, ln, "缺少 '=': " + line);
        string k=trim(line.substr(0,eq));
        string v=trim(line.substr(eq+1));
        auto cm=v.find('#'); if(cm!=string::npos) v=trim(v.substr(0,cm));
        vector<long> n;

        if      (k=="target") cfg.target = v;
        else if (k=="output") cfg.output = v;
        else if (k=="bits") {
            if (!readInts(v,n) || n.size()!=1) fail(path, ln, "bits 必须是一个整数");
            // 位段是固定的 r12(余数位)+4×16 结构：bits-1 必须在 65..80
            if (n[0] < 66 || n[0] > 81) fail(path, ln, "bits 必须在 66..81 之间（r12 + 4×16 位的固定结构）");
            cfg.bits = (int)n[0];
        }
        else if (k=="r12"||k=="r13"||k=="r14"||k=="r15"||k=="r16") {
            if (v.empty()) fail(path, ln, k + " 路径为空");
            cfg.rPaths[k]=v;
        }
        else if (k=="gpu_id") {
            if (!haveGpu) { cfg.gpuIds.clear(); haveGpu = true; }
            if (!readInts(v,n,',') || n.empty()) fail(path, ln, "gpu_id 必须是逗号分隔的整数");
            for (long x:n) { if (x<0) fail(path, ln, "gpu_id 不能为负"); cfg.gpuIds.push_back((int)x); }
        }
        else if (k=="ab_row" || k=="cd_row") {
            if (!readInts(v,n) || n.size()!=8) fail(path, ln, k + " 需要恰好 8 个整数");
            for (long x:n) if (x<0||x>255) fail(path, ln, k + " 的值必须在 0..255");
            for (int i=0;i<8;i+=2) if (n[i]>n[i+1]) fail(path, ln, k + " 的范围下限不能大于上限");
            uint8_t b[8]; for (int i=0;i<8;i++) b[i]=(uint8_t)n[i];
            if (k=="ab_row") {
                ABRow r; r.a_hi_lo=b[0]; r.a_hi_hi=b[1]; r.a_lo_lo=b[2]; r.a_lo_hi=b[3];
                         r.b_hi_lo=b[4]; r.b_hi_hi=b[5]; r.b_lo_lo=b[6]; r.b_lo_hi=b[7];
                cfg.abRows.push_back(r);
            } else {
                CDRow r; r.c_hi_lo=b[0]; r.c_hi_hi=b[1]; r.c_lo_lo=b[2]; r.c_lo_hi=b[3];
                         r.d_hi_lo=b[4]; r.d_hi_hi=b[5]; r.d_lo_lo=b[6]; r.d_lo_hi=b[7];
                cfg.cdRows.push_back(r);
            }
        }
        else if (k=="hw_pair" || k=="xor_pair") {
            if (!readInts(v,n) || n.size()!=2) fail(path, ln, k + " 需要恰好 2 个整数");
            if (n[0]<0||n[0]>16||n[1]<0||n[1]>16) fail(path, ln, k + " 的值必须在 0..16");
            (k=="hw_pair" ? cfg.hwPairs : cfg.hwXorPairs).push_back({(int)n[0],(int)n[1]});
        }
        else if (k=="sum_mod") {
            if (!readInts(v,n) || n.size()!=2) fail(path, ln, "sum_mod 需要恰好 2 个整数: M R");
            if (n[0] < 2) fail(path, ln, "sum_mod 的 M 必须 >= 2");
            if (n[1] < 0 || n[1] >= n[0]) fail(path, ln, "sum_mod 的余数 R 必须满足 0 <= R < M");
            cfg.sumMod = (int)n[0]; cfg.sumRem = (int)n[1];
        }
        else fail(path, ln, "未知配置项 '" + k + "'（拼写错误？已被移除的 sum_pair 也会在这里报错）");
    }
    return cfg;
}

// 每个非空、非注释行必须恰好是 16 个 0/1；否则报错（丢掉一行就可能丢掉真解）
static vector<uint16_t> loadR(const string &path) {
    vector<uint16_t> r;
    ifstream f(path); if(!f) { printf("无法打开: %s\n",path.c_str()); exit(1); }
    string line; int ln = 0;
    while(getline(f,line)) {
        ln++;
        line=trim(line); if(line.empty()||line[0]=='#') continue;
        if (line.size()!=16) fail(path, ln, "必须是恰好 16 位二进制，实际 " + to_string(line.size()) + " 个字符: " + line);
        uint16_t v=0;
        for(char c:line) {
            if(c!='0'&&c!='1') fail(path, ln, "含有非 0/1 字符: " + line);
            v=(uint16_t)((v<<1)|(c=='1'));
        }
        r.push_back(v);
    }
    if(r.empty()) fail(path, 0, "无有效数据");
    return r;
}

int main(int argc, char *argv[])
{
    Timer::Init();
    if(argc!=3||strcmp(argv[1],"--conf")!=0) {
        printf("PuzzleSolve v" RELEASE "\n用法: PuzzleSolve --conf <配置文件>\n退出码: 0=扫完未找到  10=找到解  1=错误\n");
        return 0;
    }

    Config cfg = parseConf(argv[2]);
    if(cfg.target.empty())  { printf("缺少 target\n"); return 1; }
    if(cfg.bits<=0)         { printf("缺少 bits\n");   return 1; }
    if(cfg.abRows.empty())  { printf("缺少 ab_row（至少一行）\n"); return 1; }
    if(cfg.cdRows.empty())  { printf("缺少 cd_row（至少一行）\n"); return 1; }

    vector<vector<uint16_t>> patterns;
    for(auto &k:{"r12","r13","r14","r15","r16"}) {
        auto it=cfg.rPaths.find(k);
        if(it==cfg.rPaths.end()) { printf("缺少 %s\n",k); return 1; }
        patterns.push_back(loadR(it->second));
    }

    printf("PuzzleSolve v" RELEASE "  配置: %s\n", argv[2]);
    printf("ab_row=%zu  cd_row=%zu  hw=%zu  xor=%zu\n",
           cfg.abRows.size(), cfg.cdRows.size(),
           cfg.hwPairs.size(), cfg.hwXorPairs.size());

    Secp256K1 *secp = new Secp256K1(); secp->Init();
    PuzzleSolve ps(secp, cfg.target, cfg.output);
    int found = ps.Search(patterns, cfg.bits, cfg.gpuIds,
                          cfg.abRows, cfg.cdRows, cfg.hwPairs, cfg.hwXorPairs,
                          cfg.sumMod, cfg.sumRem);
    return found > 0 ? EXIT_FOUND : 0;
}
