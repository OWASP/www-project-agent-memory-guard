"""SARIF output formatter for Agent Memory Guard."""

import json


def write_sarif(results: list[dict], output_file: str):
    """Write scan results in SARIF 2.1.0 format."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Agent Memory Guard",
                        "organization": "OWASP",
                        "semanticVersion": "1.0.0",
                        "rules": list({
                            "id": r["rule_id"],
                            "shortDescription": {"text": r["message"]},
                            "defaultConfiguration": {"level": r["severity"]},
                        } for r in results),
                    }
                },
                "results": [
                    {
                        "ruleId": r["rule_id"],
                        "message": {"text": r["message"]},
                        "level": r["severity"],
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": r["file"]},
                                    "region": {
                                        "startLine": r["line"],
                                        "startColumn": r["column"],
                                    },
                                }
                            }
                        ],
                    }
                    for r in results
                ],
            }
        ],
    }

    with open(output_file, "w") as f:
        json.dump(sarif, f, indent=2)