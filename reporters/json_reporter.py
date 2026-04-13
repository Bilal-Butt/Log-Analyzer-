"""
JSON Reporter — outputs structured analysis results
"""

import json


def generate_json_report(result: dict, output_path: str):
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
