"""Public dataset references. This module never downloads dataset content."""

SOURCES = {
    "botsv3": {
        "id": "botsv3", "name": "Splunk BOTS v3", "url": "https://github.com/splunk/botsv3",
        "purpose": "Blue-team investigation exercises using a pre-indexed Splunk dataset.",
        "workflow": "Install the BOTS app in Splunk, search index=botsv3, export selected events, then import those exports into a case.",
        "kind": "dataset_reference",
    },
    "otrf": {
        "id": "otrf", "name": "OTRF Security-Datasets", "url": "https://github.com/OTRF/Security-Datasets",
        "purpose": "Scenario-based benign and malicious security telemetry for detection and investigation.",
        "workflow": "Choose a scenario in the official repository, download only the selected scenario files, then import them into the intended case. Scenario details are optional metadata.",
        "kind": "dataset_reference",
    },
    "ethereum_bigquery": {
        "id": "ethereum_bigquery", "name": "Google Blockchain Analytics example queries",
        "url": "https://cloud.google.com/blockchain-analytics/docs/example-queries",
        "purpose": "Research examples for querying public Ethereum data in BigQuery.",
        "workflow": "Run the documented query against the public blockchain dataset with an appropriately configured Google Cloud project; export results locally if desired.",
        "kind": "research_reference",
    },
}


def declared_source(source_id: str) -> dict | None:
    return SOURCES.get(source_id)
