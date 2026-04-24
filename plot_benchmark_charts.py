"""
Build two figures from benchmarks.csv: encryption and decryption,
each with four series (Vigenère, AES, 3DES, RSA).

Run after collecting timings:
  python benchmark.py
  python plot_benchmark_charts.py
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

SCRIPT_DIR = Path(__file__).resolve().parent
BENCHMARK_CSV = SCRIPT_DIR / "benchmarks.csv"
OUT_ENCRYPT = SCRIPT_DIR / "benchmark_encrypt.png"
OUT_DECRYPT = SCRIPT_DIR / "benchmark_decrypt.png"

ALGO_LABELS = {
  "vigenere": "Vigenère",
  "aes": "AES-256",
  "des3": "3DES",
  "rsa": "RSA (demo)",
}


def load_rows(path: Path) -> list[dict[str, str]]:
  with path.open(newline="", encoding="utf-8") as fh:
    return list(csv.DictReader(fh))


def series_by_algorithm(
  rows: list[dict[str, str]],
  operation: str,
) -> dict[str, list[tuple[int, float, float]]]:
  """
  { algorithm: sorted [(size_bytes, mean_ms, std_ms), ...] }
  """
  raw: dict[str, dict[int, list[int]]] = defaultdict(lambda: defaultdict(list))
  for row in rows:
    if row.get("operation") != operation:
      continue
    algo = row["algorithm"]
    size = int(row["size_bytes"])
    ns = int(row["elapsed_ns"])
    raw[algo][size].append(ns)
  out: dict[str, list[tuple[int, float, float]]] = {}
  for algo, by_size in raw.items():
    points: list[tuple[int, float, float]] = []
    for size, all_runs_ns in by_size.items():
      ms_vals = [ns / 1_000_000.0 for ns in all_runs_ns]
      mean_ms = mean(ms_vals)
      std_ms = stdev(ms_vals) if len(ms_vals) > 1 else 0.0
      points.append((size, mean_ms, std_ms))
    # sort by message size for a clean line
    points.sort(key=lambda t: t[0])
    out[algo] = points
  return out


def plot_operation(rows: list[dict[str, str]], operation: str, title: str, out_path: Path) -> None:
  series = series_by_algorithm(rows, operation)
  if not any(series.values()):
    raise SystemExit(f"No rows with operation={operation!r} in {BENCHMARK_CSV}")

  fig, ax = plt.subplots(figsize=(9, 5.5), dpi=120)
  for algo, label in ALGO_LABELS.items():
    if algo not in series:
      continue
    xs = [p[0] for p in series[algo]]
    ys = [p[1] for p in series[algo]]  # mean ms
    yerr = [p[2] for p in series[algo]]  # std-dev ms
    # markers + line with error bars (mean +/- std-dev)
    ax.errorbar(
      xs,
      ys,
      yerr=yerr,
      marker="o",
      linestyle="-",
      linewidth=1.5,
      markersize=5,
      capsize=3,
      label=label,
    )

  ax.set_xlabel("Message size (bytes)")
  ax.set_ylabel("Time (milliseconds, mean +/- std dev)")
  ax.set_title(title)
  ax.legend(loc="best")
  ax.grid(True, alpha=0.3)
  fig.tight_layout()
  fig.savefig(out_path, bbox_inches="tight")
  plt.close(fig)


def main() -> int:
  if not BENCHMARK_CSV.is_file():
    print(f"Missing {BENCHMARK_CSV.name}; run: python benchmark.py")
    return 1
  rows = load_rows(BENCHMARK_CSV)
  plot_operation(
    rows,
    "encrypt",
    "Encryption time vs. message size",
    OUT_ENCRYPT,
  )
  plot_operation(
    rows,
    "decrypt",
    "Decryption time vs. message size",
    OUT_DECRYPT,
  )
  print(f"Wrote {OUT_ENCRYPT.name}")
  print(f"Wrote {OUT_DECRYPT.name}")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
