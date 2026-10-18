#!/usr/bin/env bash

if [ $# != 0 ]; then
  echo "$0: print processes sorted by OOM score"
  echo "Usage: $0"
  exit 1
fi

printf "%8s %-12s %10s %14s %s\n" \
    "PID" "USER" "OOM_SCORE" "OOM_SCORE_ADJ" "COMMAND"

for proc in /proc/[0-9]*; do
    pid=${proc##*/}

    [[ -r "$proc/oom_score" ]] || continue
    [[ -r "$proc/oom_score_adj" ]] || continue

    oom_score=$(<"$proc/oom_score")
    oom_adj=$(<"$proc/oom_score_adj")

    user=$(stat -c %U "$proc" 2>/dev/null)

    cmd=$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null)

    if [[ -z "$cmd" ]]; then
        cmd=$(<"$proc/comm" 2>/dev/null)
    fi

    printf "%8d\t%-12s\t%10d\t%14d\t%s\n" \
        "$pid" "$user" "$oom_score" "$oom_adj" "$cmd"

done | sort -k3,3n
