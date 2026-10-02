# PuzzleSolve — Bitcoin Puzzle 组合扫描器

给定 r12–r16 五个候选文件，把它们按位段拼成私钥，在 GPU 上穷举所有组合，找出哈希等于目标地址的那一个。
代码基于 [VanitySearch](https://github.com/JeanLucPons/VanitySearch)（GPL v3）。

只支持 **P2PKH（1 开头）** 目标地址、压缩公钥。

---

## 编译

```sh
make CCAP=75        # CCAP 是 GPU 计算能力：T4=75, RTX 30 系=86, RTX 40 系=89
```

需要 CUDA（默认 `/usr/local/cuda`）。

## 运行

```sh
./PuzzleSolve --conf p71/conf/G2G1G3G6.conf   # 单个配置
bash p71/run_all.sh                           # 依次跑 p71/conf/ 下全部 147 个组合，找到解就停
bash p71/run_all.sh G3G2G4G6                  # 从指定组合续跑
```

找到后打印并追加写入 `output` 指定的文件（默认 `found.txt`，已被 `.gitignore` 忽略，**不要提交它**）。
GPU 出错、配置有误会直接报错退出（退出码 1），不会静默跳过。

---

## 私钥位段

`bits=71` 时私钥在 `[2^70, 2^71)`，未知位数 `bits-1 = 70`，从高位到低位分配：

```
私钥 = 前导1 | r12 | r13 | r14 | r15 | r16
              6位  16位  16位  16位  16位      （r12 取 (bits-1)%16 位，余数为 0 时取 16 位）
shift:        64   48    32    16    0
```

- AB = r12 × r13 × r14，CD = r15 × r16，GPU 扫 AB × CD 的所有点加。
- 在 p71 配置里 a=r13、b=r14、c=r15、d=r16。

## r 文件格式

每行一个 16 位二进制候选值（只读前 16 个字符，`#` 开头为注释）：

```
0000000001010100
0000000001010101
```

空文件 / 无有效行会报错退出。

---

## 配置项

```ini
target=1PWo3JeB9jrGwfHDNpdGK38CRKd7XGabjq   # 目标地址（P2PKH）
bits=71
r12=p71/r12.txt
r13=p71/data/r13_G2.txt
r14=p71/data/r14_G1.txt
r15=p71/data/r15_G3.txt
r16=p71/data/r16_G6.txt
output=found.txt
gpu_id=0                                    # 可选，目前只用第一块

# 字节范围过滤（hi 字节范围, lo 字节范围；a b / c d 各一组）
ab_row = 32 63 0 255  0 31 0 255            # a_hi_lo a_hi_hi a_lo_lo a_lo_hi  b_hi_lo b_hi_hi b_lo_lo b_lo_hi
cd_row = 64 95 0 255  160 191 0 255

# 配对约束：(AB 侧值, CD 侧值) 必须是列表里的一对；写了几类就要同时满足几类
hw_pair  = 4 4        # hw(a&b) , hw(c&d)
xor_pair = 6 5        # hw(a^b) , hw(c^d)

# 附加条件：(r13+r14+r15+r16) % M == R
sum_mod = 33 24
```

`hw_pair`、`xor_pair`、`sum_mod` 都可省略，省略即不启用。配对约束是**精确**的，不是各筛一遍：

1. 每个条目算键 `(AND hw, XOR hw, 余数)`，AB、CD 各自按键分组；
2. 对每个 AB 组，找出所有兼容的 CD 组并成一张 CD 表；
3. 兼容集合相同的 AB 组合并，一次 GPU 扫描 `AB组 × 兼容CD`——不合法的组合根本不会被扫。

---

## p71 目录

```
p71/
├── r12.txt
├── data/            分组数据 r13_G2.txt … r16_G7.txt（G{n} = [(n-1)*8192, n*8192-1]）
├── conf/            147 个 G 组合配置，文件名 = a b c d 的 G 编号，如 G2G1G3G6.conf
└── run_all.sh
```

组合来自 `txt/G组合.txt`（a∈2–4, b∈1–5, c∈3–6, d∈5–7，种类数 3–4，和 8–23，极差 3–7，
5/6/7/8 至少出现一个，c 或 d ≥ 3，a<5 或 b<6），原始候选在 `txt/p71合集/`。

## 内存与速度

- 单个组合的 AB 表最多约 1700 万条 × 64 字节 ≈ 1.1 GB（主机内存里会有一份完整表和一份分批子表），显存同量级。
- T4 上约 450 Mkey/s；p71 全部 147 个组合合计约 9.7×10¹³ 次，单卡约 2.5 天。
- 环境变量 `ABCD_NC`（16/24/32/48/64/96/128/192/256）可调每线程处理的组合数，默认 64。

## 许可

GPL v3，见源文件头部版权声明。
