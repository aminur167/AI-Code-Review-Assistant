"""
NexusReview — Root entry point for dataset_tool.py
Enables running `python dataset_tool.py` directly from project root.
"""
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from benchmark.dataset_tool import (
    print_summary_report,
    print_concrete_samples,
    generate_markdown_report,
)

if __name__ == "__main__":
    print_summary_report()
    print_concrete_samples()
    generate_markdown_report()
