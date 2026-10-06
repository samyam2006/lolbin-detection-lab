#!/usr/bin/env bash
# Convert every rule to Splunk SPL and Elastic (Lucene) queries with sigma-cli.
# One-time setup:
#   pip install sigma-cli
#   sigma plugin install splunk
#   sigma plugin install elasticsearch
#   sigma plugin install sysmon
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p converted

echo "Converting to Splunk SPL..."
sigma convert -t splunk -p sysmon rules/ > converted/splunk.spl

echo "Converting to Elastic Lucene (ECS field names)..."
sigma convert -t lucene -p ecs_windows rules/ > converted/elastic.lucene

echo "Done. See converted/"
