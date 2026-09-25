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
    int    bits      = 0;
    int    split     = 2;
    string hw_filter     = "";  // hw(a&b)/hw(c&d) AND 过滤对文件，空=不过滤
    string hw_xor_filter = "";  // hw(a^b)/hw(c^d) XOR 过滤对文件，空=不过滤
    string hw_sum_filter = "";  // hw(a)+hw(b)/hw(c)+hw(d) 和过滤对文件，空=不过滤
    string ab_ranges = "";      // AB 字节范围优先级文件（a=r13, b=r14）
    string cd_ranges = "";      // CD 字节范围分区文件（c=r15, d=r16）
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
        else if (k=="split")     cfg.split     = stoi(v);
        else if (k=="hw_filter")     cfg.hw_filter     = v;
        else if (k=="hw_xor_filter") cfg.hw_xor_filter = v;
        else if (k=="hw_sum_filter") cfg.hw_sum_filter = v;
        else if (k=="ab_ranges")     cfg.ab_ranges     = v;
        else if (k=="cd_ranges")     cfg.cd_ranges     = v;
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

// 从 txt 加载 (hw_ab, hw_cd) 对
// 支持 "hw_ab hw_cd" 或 "序号 hw_ab hw_cd" 两种格式，# 开头为注释
static vector<pair<int,int>> loadHwPairs(const string &path) {
    vector<pair<int,int>> pairs;
    ifstream f(path);
    if (!f) { printf("无法打开 hw_filter 文件: %s\n", path.c_str()); exit(1); }
    string line;
    while (getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        // 提取所有整数
        istringstream ss(line);
        vector<int> nums;
        int x;
        while (ss >> x) nums.push_back(x);
        if (nums.size() == 2)
            pairs.push_back({nums[0], nums[1]});
        else if (nums.size() >= 3)
            pairs.push_back({nums[1], nums[2]});  // 第一列为序号，跳过
    }
    return pairs;
}

// 解析一个 uint8_t 整数（0-255）
static uint8_t parseU8(const string &s) {
    int v = stoi(s);
    return (uint8_t)(v < 0 ? 0 : v > 255 ? 255 : v);
}

// 加载 AB 字节范围文件：每行 8 个整数
// a_hi_lo a_hi_hi a_lo_lo a_lo_hi  b_hi_lo b_hi_hi b_lo_lo b_lo_hi
static vector<ABRangeRow> loadABRanges(const string &path) {
    vector<ABRangeRow> rows;
    ifstream f(path);
    if (!f) { printf("无法打开 ab_ranges 文件: %s\n", path.c_str()); exit(1); }
    string line;
    while (getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        istringstream ss(line);
        vector<int> nums;
        int x;
        while (ss >> x) nums.push_back(x);
        if ((int)nums.size() < 8) continue;
        ABRangeRow row;
        row.a = {parseU8(to_string(nums[0])), parseU8(to_string(nums[1])),
                 parseU8(to_string(nums[2])), parseU8(to_string(nums[3]))};
        row.b = {parseU8(to_string(nums[4])), parseU8(to_string(nums[5])),
                 parseU8(to_string(nums[6])), parseU8(to_string(nums[7]))};
        rows.push_back(row);
    }
    return rows;
}

// 加载 CD 字节范围文件：每行 8 个整数
// c_hi_lo c_hi_hi c_lo_lo c_lo_hi  d_hi_lo d_hi_hi d_lo_lo d_lo_hi
static vector<CDRangeRow> loadCDRanges(const string &path) {
    vector<CDRangeRow> rows;
    ifstream f(path);
    if (!f) { printf("无法打开 cd_ranges 文件: %s\n", path.c_str()); exit(1); }
    string line;
    while (getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        istringstream ss(line);
        vector<int> nums;
        int x;
        while (ss >> x) nums.push_back(x);
        if ((int)nums.size() < 8) continue;
        CDRangeRow row;
        row.c = {parseU8(to_string(nums[0])), parseU8(to_string(nums[1])),
                 parseU8(to_string(nums[2])), parseU8(to_string(nums[3]))};
        row.d = {parseU8(to_string(nums[4])), parseU8(to_string(nums[5])),
                 parseU8(to_string(nums[6])), parseU8(to_string(nums[7]))};
        rows.push_back(row);
    }
    return rows;
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
    vector<pair<int,int>> hwPairs, hwXorPairs;
    if (!cfg.hw_filter.empty() && cfg.hw_filter != "0") {
        hwPairs = loadHwPairs(cfg.hw_filter);
        printf("hw AND 过滤: %s  (%zu 对)\n", cfg.hw_filter.c_str(), hwPairs.size());
    }
    if (!cfg.hw_xor_filter.empty() && cfg.hw_xor_filter != "0") {
        hwXorPairs = loadHwPairs(cfg.hw_xor_filter);
        printf("hw XOR 过滤: %s  (%zu 对)\n", cfg.hw_xor_filter.c_str(), hwXorPairs.size());
    }
    vector<pair<int,int>> hwSumPairs;
    if (!cfg.hw_sum_filter.empty() && cfg.hw_sum_filter != "0") {
        hwSumPairs = loadHwPairs(cfg.hw_sum_filter);
        printf("hw sum 过滤: %s  (%zu 对)\n", cfg.hw_sum_filter.c_str(), hwSumPairs.size());
    }
    vector<ABRangeRow> abRanges;
    vector<CDRangeRow> cdRanges;
    if (!cfg.ab_ranges.empty() && cfg.ab_ranges != "0") {
        abRanges = loadABRanges(cfg.ab_ranges);
        printf("AB 范围过滤: %s  (%zu 行)\n", cfg.ab_ranges.c_str(), abRanges.size());
    }
    if (!cfg.cd_ranges.empty() && cfg.cd_ranges != "0") {
        cdRanges = loadCDRanges(cfg.cd_ranges);
        printf("CD 范围过滤: %s  (%zu 区)\n", cfg.cd_ranges.c_str(), cdRanges.size());
    }
    ps.Search(patterns, cfg.bits, cfg.split, cfg.gpuIds, cfg.gridSize,
              hwPairs, hwXorPairs, abRanges, cdRanges, hwSumPairs);
    return 0;
}
