import csv
import sys

total = 0.0
with open(sys.argv[1], newline="") as f:
    for row in csv.DictReader(f):
        total += float(row["amount"])
print(f"total: {total:.2f}")
