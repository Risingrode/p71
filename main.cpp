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

static string trim(const string &s) {
    size_t a=s.find_first_not_of(" \t\r\n"), b=s.find_last_not_of(" \t\r\n");
    return (a==string::npos)?"":s.substr(a,b-a+1);
}
static void splitInts(const string &s, char sep, vector<int> &out) {
    stringstream ss(s); string t;
    while(getline(ss,t,sep)) { t=trim(t); if(!t.empty()) out.push_back(stoi(t)); }
}
static bool parse8(const string &s, uint8_t out[8]) {
    istringstream ss(s); vector<int> nums; int x;
    while(ss>>x) nums.push_back(x);
    if((int)nums.size()<8) return false;
    for(int i=0;i<8;i++) out[i]=(uint8_t)(nums[i]<0?0:nums[i]>255?255:nums[i]);
    return true;
}

static Config parseConf(const string &path) {
    Config cfg;
    ifstream f(path); if(!f) { printf("无法打开: %s\n",path.c_str()); exit(1); }
    string line;
    while(getline(f,line)) {
        line=trim(line); if(line.empty()||line[0]=='#') continue;
        auto eq=line.find('='); if(eq==string::npos) continue;
        string k=trim(line.substr(0,eq));
        string v=trim(line.substr(eq+1));
        auto cm=v.find('#'); if(cm!=string::npos) v=trim(v.substr(0,cm));
        if      (k=="target") cfg.target = v;
        else if (k=="bits")   cfg.bits   = stoi(v);
        else if (k=="r12")    cfg.rPaths["r12"]=v;
        else if (k=="r13")    cfg.rPaths["r13"]=v;
        else if (k=="r14")    cfg.rPaths["r14"]=v;
        else if (k=="r15")    cfg.rPaths["r15"]=v;
        else if (k=="r16")    cfg.rPaths["r16"]=v;
        else if (k=="gpu_id") splitInts(v,',',cfg.gpuIds);
        else if (k=="output") cfg.output = v;
        else if (k=="ab_row") {
            uint8_t n[8]; if(parse8(v,n)) {
                ABRow r; r.a_hi_lo=n[0]; r.a_hi_hi=n[1]; r.a_lo_lo=n[2]; r.a_lo_hi=n[3];
                         r.b_hi_lo=n[4]; r.b_hi_hi=n[5]; r.b_lo_lo=n[6]; r.b_lo_hi=n[7];
                cfg.abRows.push_back(r);
            }
        }
        else if (k=="hw_pair") {
            istringstream ss(v); int a, b;
            if (ss >> a >> b) cfg.hwPairs.push_back({a, b});
        }
        else if (k=="xor_pair") {
            istringstream ss(v); int a, b;
            if (ss >> a >> b) cfg.hwXorPairs.push_back({a, b});
        }
        else if (k=="sum_mod") {
            istringstream ss(v); int m, r;
            if (ss >> m >> r && m > 0) { cfg.sumMod = m; cfg.sumRem = ((r % m) + m) % m; }
        }
        else if (k=="cd_row") {
            uint8_t n[8]; if(parse8(v,n)) {
                CDRow r; r.c_hi_lo=n[0]; r.c_hi_hi=n[1]; r.c_lo_lo=n[2]; r.c_lo_hi=n[3];
                         r.d_hi_lo=n[4]; r.d_hi_hi=n[5]; r.d_lo_lo=n[6]; r.d_lo_hi=n[7];
                cfg.cdRows.push_back(r);
            }
        }
    }
    return cfg;
}

static vector<uint16_t> loadR(const string &path) {
    vector<uint16_t> r;
    ifstream f(path); if(!f) { printf("无法打开: %s\n",path.c_str()); exit(1); }
    string line;
    while(getline(f,line)) {
        line=trim(line); if(line.empty()||line[0]=='#') continue;
        if(line.size()<16) continue; line=line.substr(0,16);
        uint16_t v=0; bool ok=true;
        for(char c:line) { if(c!='0'&&c!='1'){ok=false;break;} v=(v<<1)|(c=='1'); }
        if(ok) r.push_back(v);
    }
    if(r.empty()) printf("警告: %s 无有效数据\n",path.c_str());
    return r;
}

int main(int argc, char *argv[])
{
    Timer::Init();
    if(argc!=3||strcmp(argv[1],"--conf")!=0) {
        printf("PuzzleSolve v" RELEASE "\n用法: PuzzleSolve --conf <配置文件>\n");
        return 0;
    }

    Config cfg = parseConf(argv[2]);
    if(cfg.target.empty()) { printf("缺少 target\n"); return 1; }
    if(cfg.bits<=0)         { printf("缺少 bits\n");   return 1; }

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

    vector<int> gridSize;
    for(int i=0;i<(int)cfg.gpuIds.size();i++) { gridSize.push_back(-1); gridSize.push_back(128); }

    Secp256K1 *secp = new Secp256K1(); secp->Init();
    PuzzleSolve ps(secp, cfg.target, cfg.output);
    ps.Search(patterns, cfg.bits, cfg.gpuIds, gridSize,
              cfg.abRows, cfg.cdRows, cfg.hwPairs, cfg.hwXorPairs,
              cfg.sumMod, cfg.sumRem);
    return 0;
}
