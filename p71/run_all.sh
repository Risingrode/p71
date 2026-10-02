#!/bin/bash
# 依次扫描 p71/conf/ 下的全部 G 组合，支持中断后自动续跑
#
# 用法（任意目录均可）:
#   bash p71/run_all.sh                 从头开始；已完成的组合会自动跳过（断点续跑）
#   bash p71/run_all.sh G3G2G4G6        从指定组合开始，它及之后的全部重跑（忽略已完成记录）
#   bash p71/run_all.sh --status        只看进度，不运行
#   bash p71/run_all.sh --restart       清空进度，从头重新扫
#
# 进度记录在 p71/progress.txt：只有「正常扫完且未找到」的组合才会记入。
# 中途被 Ctrl+C / kill / 断电打断时，正在跑的那个组合不记入，下次会从它的开头重新扫（最多损失单个组合的时间）。
#
# PuzzleSolve 退出码：0 = 扫完未找到，10 = 找到解，其他 = 错误
cd "$(dirname "$0")/.." || exit 1

PROGRESS=p71/progress.txt
restart=0; status=0; start=""
for arg in "$@"; do
  case "$arg" in
    --restart) restart=1 ;;
    --status)  status=1 ;;
    -*)        echo "未知参数: $arg"; exit 1 ;;
    *)         start="$arg" ;;
  esac
done

confs=(p71/conf/*.conf)
total=${#confs[@]}
[ "$restart" -eq 1 ] && rm -f "$PROGRESS"
touch "$PROGRESS"
done_count() { sort -u "$PROGRESS" | grep -c .; }
is_done()    { grep -qx "$1" "$PROGRESS"; }

if [ "$status" -eq 1 ]; then
  echo "已完成 $(done_count) / $total"
  for c in "${confs[@]}"; do n=$(basename "$c" .conf); is_done "$n" || { echo "下一个: $n"; exit 0; }; done
  echo "全部完成"; exit 0
fi

if [ -n "$start" ] && [ ! -f "p71/conf/$start.conf" ]; then
  echo "找不到组合 $start（应为 p71/conf/ 下的文件名，不带 .conf）"; exit 1
fi

# 防止同时开两个实例（会重复扫描并写坏进度文件）
exec 9>p71/.run.lock
flock -n 9 || { echo "已有另一个 run_all.sh 在运行，退出"; exit 1; }

child=0
on_interrupt() {
  if [ "$child" -ne 0 ]; then kill "$child" 2>/dev/null; wait "$child" 2>/dev/null; fi
  echo; echo "已中断。进度已保存（已完成 $(done_count) / $total），再次运行本脚本即可继续。"
  exit 130
}
trap on_interrupt INT TERM

[ -n "$start" ] && skipping=1 || skipping=0
force=0   # 指定了起始组合后，从它开始的所有组合都强制重跑
echo "已完成 $(done_count) / $total，从断点继续"
for conf in "${confs[@]}"; do
  name=$(basename "$conf" .conf)
  if [ $skipping -eq 1 ]; then
    [ "$name" = "$start" ] && { skipping=0; force=1; } || continue
  fi
  if [ $force -eq 0 ] && is_done "$name"; then continue; fi

  echo "===== $name  [$(date '+%F %T')]  已完成 $(done_count)/$total ====="
  ./PuzzleSolve --conf "$conf" &
  child=$!
  wait "$child"; rc=$?
  child=0

  if [ $rc -eq 10 ]; then echo "找到解: $name（见上方输出和 found.txt）"; exit 0; fi
  if [ $rc -ge 128 ]; then on_interrupt; fi   # 被信号终止（例如单独 kill 了 PuzzleSolve）
  if [ $rc -ne 0 ]; then
    echo "$name 运行失败（退出码 $rc），已停止；修复后重新运行本脚本即可从这里继续"; exit 1
  fi
  echo "$name" >> "$PROGRESS"
done
echo "全部 $total 个组合扫描完毕，未找到"
