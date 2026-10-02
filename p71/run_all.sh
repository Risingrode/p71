#!/bin/bash
# 依次扫描 p71/conf/ 下的全部 G 组合，找到解（found.txt 变大）就停止
# 用法（在仓库根目录）: bash p71/run_all.sh [起始组合名，如 G3G2G4G6]
cd "$(dirname "$0")/.." || exit 1
start="$1"; skip=0; [ -n "$start" ] && skip=1
size() { stat -c %s found.txt 2>/dev/null || echo 0; }
for conf in p71/conf/*.conf; do
  name=$(basename "$conf" .conf)
  if [ $skip -eq 1 ]; then [ "$name" = "$start" ] && skip=0 || continue; fi
  echo "===== $name ====="
  before=$(size)
  ./PuzzleSolve --conf "$conf"
  if [ "$(size)" != "$before" ]; then echo "找到解: $name，见 found.txt"; exit 0; fi
done
