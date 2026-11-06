"""Validate CyberThreat Intel JSON records and cross-references."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker # type: ignore

ROOT = Path(__file__).resolve().parents[1]
ERROR_COUNT = 0


def report_error(message: str) -> None:
    global ERROR_COUNT
    ERROR_COUNT += 1
    print(f"ERROR {message}")


def load_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        report_error(f"{path.relative_to(ROOT)}: could not read JSON: {error}")
        return None


def validate_records(folder: Path, schema_path: Path) -> list[dict]:
    schema = load_json(schema_path)
    if schema is None:
        return []

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    records = []

    for path in sorted(folder.glob("*.json")):
        record = load_json(path)
        if record is None:
            continue

        errors = sorted(validator.iter_errors(record), key=lambda error: list(error.path))
        if errors:
            for error in errors:
                location = ".".join(str(part) for part in error.path) or "<root>"
                report_error(f"{path.relative_to(ROOT)} [{location}]: {error.message}")
        else:
            print(f"OK    {path.relative_to(ROOT)}")
            records.append(record)

    return records


def main() -> int:
    actors = validate_records(
        ROOT / "data" / "threat-actors",
        ROOT / "schema" / "threat-actor.schema.json",
    )
    incidents = validate_records(
        ROOT / "data" / "incidents",
        ROOT / "schema" / "incident.schema.json",
    )

    source_registry = load_json(ROOT / "data" / "sources" / "source-registry.json") or []
    source_ids = {source["id"] for source in source_registry if isinstance(source, dict) and "id" in source}
    actor_ids = {actor["id"] for actor in actors}

    for actor in actors:
        for source_id in actor["source_ids"]:
            if source_id not in source_ids:
                report_error(f"{actor['id']}: unknown source reference {source_id}")

    for incident in incidents:
        for source_id in incident["source_ids"]:
            if source_id not in source_ids:
                report_error(f"{incident['id']}: unknown source reference {source_id}")
        for attribution in incident["attributions"]:
            actor_id = attribution["threat_actor_id"]
            if actor_id not in actor_ids:
                report_error(f"{incident['id']}: unknown threat actor reference {actor_id}")

    print(f"\nValidated {len(actors)} threat actor(s) and {len(incidents)} incident(s).")
    if ERROR_COUNT:
        print(f"Found {ERROR_COUNT} error(s).")
        return 1

    print("All records and references are valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
