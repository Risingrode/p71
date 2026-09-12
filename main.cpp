#include "util/Timer.h"
#include "Psolve.h"
#include "crypto/SECP256k1.h"
#include <string>
#include <string.h>
#include <fstream>
#include <sstream>
#include <map>

using namespace std;

#define RELEASE "3.0"

struct Config {
    string target;
    int    bits     = 0;
    int    split    = 2;   // 前 split 个文件归 AB，其余归 CD
    map<string,string> rPaths;
    vector<int> gpuIds   = {0};
    vector<int> gridSize;
    string output   = "";
};

static string trim(const string &s) {
    size_t a=s.find_first_not_of(" \t\r\n"), b=s.find_last_not_of(" \t\r\n");
    return (a==string::npos)?"":s.substr(a,b-a+1);
}
static void splitInts(const string &s, char sep, vector<int> &out) {
    stringstream ss(s); string t;
    while(getline(ss,t,sep)) { t=trim(t); if(!t.empty()) out.push_back(stoi(t)); }
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
        else if (k=="split")  cfg.split  = stoi(v);
        else if (k=="r12")    cfg.rPaths["r12"]=v;
        else if (k=="r13")    cfg.rPaths["r13"]=v;
        else if (k=="r14")    cfg.rPaths["r14"]=v;
        else if (k=="r15")    cfg.rPaths["r15"]=v;
        else if (k=="r16")    cfg.rPaths["r16"]=v;
        else if (k=="gpu_id") splitInts(v,',',cfg.gpuIds);
        else if (k=="output") cfg.output = v;
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
    if(cfg.rPaths.empty())  { printf("缺少 r 文件\n"); return 1; }

    if(cfg.gridSize.empty())
        for(int i=0;i<(int)cfg.gpuIds.size();i++) { cfg.gridSize.push_back(-1); cfg.gridSize.push_back(128); }

    vector<vector<uint16_t>> patterns;
    for(auto &k:{"r12","r13","r14","r15","r16"}) {
        auto it=cfg.rPaths.find(k);
        if(it!=cfg.rPaths.end()) patterns.push_back(loadR(it->second));
    }
    if(patterns.empty()) { printf("未加载到 r 文件\n"); return 1; }

    printf("PuzzleSolve v" RELEASE "  配置: %s\n", argv[2]);

    Secp256K1 *secp = new Secp256K1(); secp->Init();
    PuzzleSolve ps(secp, cfg.target, cfg.output);
    ps.Search(patterns, cfg.bits, cfg.split, cfg.gpuIds, cfg.gridSize);
    return 0;
}
