#!/bin/bash
# 依次扫描 p71/conf/ 下的全部 G 组合
# 退出码约定（PuzzleSolve）：0 = 扫完未找到，10 = 找到解，其他 = 错误
# 用法（任意目录）: bash p71/run_all.sh [起始组合名，如 G3G2G4G6]
cd "$(dirname "$0")/.." || exit 1
start="$1"; skip=0
if [ -n "$start" ]; then
  [ -f "p71/conf/$start.conf" ] || { echo "找不到组合 $start（应为 p71/conf/ 下的文件名，不带 .conf）"; exit 1; }
  skip=1
fi
for conf in p71/conf/*.conf; do
  name=$(basename "$conf" .conf)
  if [ $skip -eq 1 ]; then [ "$name" = "$start" ] && skip=0 || continue; fi
  echo "===== $name ====="
  ./PuzzleSolve --conf "$conf"
  rc=$?
  if [ $rc -eq 10 ]; then echo "找到解: $name（见上方输出和 found.txt）"; exit 0; fi
  if [ $rc -ne 0 ]; then echo "$name 运行失败（退出码 $rc），已停止；修复后可用: bash p71/run_all.sh $name 续跑"; exit 1; fi
done
echo "全部组合扫描完毕，未找到"
