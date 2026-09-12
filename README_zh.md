# PuzzleSolve v3.0 — Bitcoin Puzzle 私钥搜索器

GPU 加速的比特币谜题搜索工具，通过 r 文件候选值组合定向搜索。

---

## 编译

```sh
make gpu=1 CCAP=75 all   # GPU 版（推荐）
make all                  # CPU 版
```

---

## 使用

```sh
./PuzzleSolve --conf conf/puzzle70.conf
```

---

## 配置文件

```ini
# conf/puzzle70.conf

target=19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR   # 目标地址（P2PKH）
bits=70                                         # 密钥位数（puzzle 70 在 [2^69, 2^70)）

r12=txt/r12.txt   # 低5位候选（bits 4-0，最多32个值）
r13=txt/r13.txt   # 次低16位（bits 20-5）
r14=txt/r14.txt   # 中间16位（bits 36-21）
r15=txt/r15.txt   # 次高16位（bits 52-37）
r16=txt/r16.txt   # 最高16位（bits 68-53）

split=2           # AB=r12×r13，外层=r16，CD=r14×r15
output=found.txt
```

---

## r 文件格式

每行一个 **16 位二进制**候选值，从小到大排序：

```
# r13.txt  示例
0000000000000001
0000000001100011
0110001001110111   ← 正确答案包含在某一行
...
```

**位段分配（puzzle 70，bits=70，unknownBits=69）：**

```
私钥 = 前导1 | r16(16位) | r15(16位) | r14(16位) | r13(16位) | r12(5位)
       bit69   bit68-53    bit52-37    bit36-21    bit20-5     bit4-0
```

- **r12**：5位，最多 32 个唯一值（2^5=32）
- **r13-r16**：各 16 位，填入分析得出的候选值

---

## 搜索架构（详细）

### 总览

```
总组合数 = r12(15) × r13(4000) × r14(4000) × r15(4000) × r16(4000)
         = 15 × 4000^4 = 3,840,000,000,000,000 （3840万亿）

分组策略（内存限制决定）：
  外层循环  = r16  → 4000 次迭代（最高16位，候选最多）
  AB 表     = r12 × r13 = 15 × 4000 = 60,000 个 EC 点（4MB，全进L2缓存）
  CD 表     = r14 × r15 = 4000 × 4000 = 16,000,000 个 EC 点（1GB，GPU显存）
  每轮 GPU  = 60K × 16M = 960,000,000,000 组合
```

---

### 第一步：CPU 预计算（程序启动时，只做一次）

**① 计算前导点 A**
```
A = 2^69 × G
  = secp256k1 生成元 G 的 2^69 倍
  = 私钥前导"1"对应的椭圆曲线基点
```

**② 预计算 CD 表（r14 × r15 = 16M 个 EC 点）**
```
对每个 r14 值（4000个），计算基底点：
  base_r14 = r14_val × 2^21 × G   （1次标量乘法）

对每组 r14，批量算出4000个 r15 贡献（IntGroup批量求逆）：
  CD[r14_idx × 4000 + r15_idx]
    = base_r14 + r15_val × 2^5 × G   （1次点加法）

总计：4000次标量乘法 + 16M次点加法（批量求逆优化，约30秒）
内存：16M × 64字节 = 1 GB → 上传GPU显存
```

---

### 第二步：外层循环（r16，共4000次迭代）

**每次迭代取 r16 文件中一个候选值，更新前导基点：**

```
r16_EC = r16_val × 2^53 × G    （1次标量乘法，约50μs）
A_cur  = A + r16_EC             （1次点加法，约2μs）
```

**重建 AB 表（r12 × r13 = 60,000 个 EC 点）：**
```
对每个 r12 值（15个），计算：
  base_r12 = A_cur + r12_val × 2^0 × G   （1次点加法）

对每组 r12，批量算出4000个 r13 贡献：
  AB[r12_idx × 4000 + r13_idx]
    = base_r12 + r13_val × 2^5 × G... 
    
等等，r13 覆盖 bits 20-5（shift=5）：
  AB[r12_idx × 4000 + r13_idx]
    = base_r12 + r13_val × 2^5 × G

总计：15次标量乘法 + 60K次点加法（约1秒）
上传GPU：60K × 64字节 = 3.75 MB（L2缓存全部命中）
```

---

### 第三步：GPU 核心搜索（每次外层迭代内）

**GPU 配置（Tesla T4）：**
```
40,960 个线程并行
每线程处理 512 个 (AB+CD) 组合
每次 kernel = 40,960 × 512 = 20,971,520 组合
```

**每个线程内部（512个组合，批量求逆优化）：**

```
Pass 1 —— 准备分母（512次减法）：
  for c in 0..511:
      dx[c] = CD[cd_idx].x - AB[ab_idx].x     ← 纯减法，极快

批量求逆 _ModInvGrouped(dx)：
  ┌─ 正常做法：512 × ModInv = 512 × 300次域乘法 = 153,600次
  └─ 批量做法：
       前缀积：P[0]=dx[0], P[i]=P[i-1]×dx[i]      （511次乘法）
       1次真正的 ModInv（P[511] 的逆元）
       回代推算：每个 inv(dx[i]) = 1次乘法         （512次乘法）
       共 1024次乘法 + 1次ModInv ≈ 1300次域乘法
  加速比：153,600 / 1,300 ≈ 118×

Pass 2 —— 完成点加法（512次）：
  for c in 0..511:
      λ  = (CD.y - AB.y) × inv(CD.x - AB.x)   ← inv已知
      Px = λ² - AB.x - CD.x
      Py = λ(AB.x - Px) - AB.y
      → 得到结果点 P = AB[i] + CD[j]

Pass 3 —— 计算地址并比对（512次）：
  for c in 0..511:
      hash160 = SHA256(RIPEMD160(压缩公钥))
      if hash160[0:2] == targetPrefix:         ← 16位快速过滤
          if hash160 == targetHash160:         ← 完整160位比对
              上报命中！
```

---

### 第四步：GPU 命中 → CPU 重建私钥

```
GPU 上报：(ab_idx, cd_idx)
CPU 解码：
  r12_idx = ab_idx / 4000,  r13_idx = ab_idx % 4000
  r14_idx = cd_idx / 4000,  r15_idx = cd_idx % 4000
  r16_idx = 当前外层迭代序号

还原各文件的值：
  r12_val = r12_file[r12_idx]   → bits 4-0  的候选值
  r13_val = r13_file[r13_idx]   → bits 20-5
  r14_val = r14_file[r14_idx]   → bits 36-21
  r15_val = r15_file[r15_idx]   → bits 52-37
  r16_val = r16_file[r16_idx]   → bits 68-53

组装私钥：
  key = 2^69
      + r16_val × 2^53
      + r15_val × 2^37
      + r14_val × 2^21
      + r13_val × 2^5
      + r12_val × 2^0

CPU验证：ComputePublicKey(key) → 地址 == 目标？ → 输出
```

---

### 速度分析

```
GPU 峰值（顺序扫描）：  410 Mkey/s
AB+CD 实测速度：        330 Mkey/s
差距原因：
  顺序扫描  → Gn[i].x 存常量内存（L1缓存广播，零延迟）
  AB+CD    → 随机读 AB[i] 和 CD[j]（L2缓存，有少量miss）

完整搜索时间估算（Tesla T4 单卡）：
  3840万亿 ÷ 330M = 11,636,363 秒 ≈ 135 天

测试配置（当前txt）：
  外层r16第1次 + AB[3125] + CD[0] = 50,000,000,000 次 ≈ 150秒
```

---

## 测试数据说明（puzzle 70）

私钥 `0x349b84b6431a6c4ef1` 的各位段值：

| 文件 | 位段 | 正确值 |
|------|------|--------|
| r12 | bits 4-0 | 17 |
| r13 | bits 20-5 | 25207 |
| r14 | bits 36-21 | 6355 |
| r15 | bits 52-37 | 9650 |
| r16 | bits 68-53 | 42204 |

测试文件已配置为扫描约 **50 亿次**后找到答案。

---

## 项目结构

```
vanitysearch/
├── conf/puzzle70.conf   配置文件
├── txt/r12-r16.txt      候选值文件
├── main.cpp             入口，解析 conf
├── Psolve.h/cpp         核心：AB+CD 组合搜索引擎
├── GPU/GPUCombineABCD.h 自定义 GPU kernel（批量求逆）
├── math/                大数运算（Int, IntGroup, Point）
├── crypto/              secp256k1 曲线
├── hash/                SHA256, RIPEMD160
└── GPU/                 CUDA 核心（PTX 汇编优化）
```

---

## 许可证

GPLv3 · 基于 [JeanLucPons/VanitySearch](https://github.com/JeanLucPons/VanitySearch)
