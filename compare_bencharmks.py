#!/usr/bin/env python3
import sys
from typing import Literal, Iterable


def _parse_pps(line: str) -> float | None:
    if "took" not in line:
        return None
    return float(line.split()[-2])


def _parse_memory(line: str) -> float | None:
    if " MB" not in line:
        return None
    return float(line.split()[-2])


def _format_ratio(
    x1: float, x2: float, better: Literal["higher", "lower"] = "higher"
) -> str:
    if x1 == 0:
        return "N/A"
    ratio = x2 / x1
    if 0.99 <= ratio <= 1.01:
        state = "same"
    elif (ratio > 1 and better == "higher") or (ratio < 1 and better == "lower"):
        state = "better"
    else:
        state = "worse"
    return f"x{ratio:.2f} ({state})"


def _is_benchmark_title(line: str) -> bool:
    return "Benchmark" in line


def _filter_intermediate_lines(lines: Iterable[str]) -> Iterable[str]:
    benchmarks_section_started = False
    for line in lines:
        benchmarks_section_started = benchmarks_section_started or _is_benchmark_title(
            line
        )
        if not benchmarks_section_started:
            continue
        if not line.startswith("  run"):
            yield line


baseline, benchmark = sys.argv[1:]

for l1, l2 in zip(
    _filter_intermediate_lines(open(baseline)),
    _filter_intermediate_lines(open(benchmark)),
):
    if _is_benchmark_title(l1) and _is_benchmark_title(l2):
        print(l1.strip(), end=":\t")
    elif (pps1 := _parse_pps(l1)) is not None and (pps2 := _parse_pps(l2)) is not None:
        print(_format_ratio(pps1, pps2, "higher"), end="\t")
    elif (mem1 := _parse_memory(l1)) is not None and (
        mem2 := _parse_memory(l2)
    ) is not None:
        print(_format_ratio(mem1, mem2, "lower"))
