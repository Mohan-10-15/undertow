#!/usr/bin/env bash
# Re-downloads the validation dataset from its original public source repo.
#
# Underlying data (this repo just aggregates it — see its own README):
#   Legitimate: University of New Brunswick URL-2016 dataset
#               https://www.unb.ca/cic/datasets/url-2016.html
#   Phishing:   PhishTank verified-phish export (https://www.phishtank.com)
#
# Not vendored in this repo (no clear redistribution license on the
# aggregating repo) — fetched fresh each time instead.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p data

REPO=shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques
BASE="https://raw.githubusercontent.com/${REPO}/master/DataFiles"

echo "Downloading legitimate URL list..."
curl -sL "${BASE}/1.Benign_list_big_final.csv" -o data/legitimate-urls.csv

echo "Downloading PhishTank verified phishing URL list..."
curl -sL "${BASE}/2.online-valid.csv" -o data/phishing-urls.csv

wc -l data/legitimate-urls.csv data/phishing-urls.csv
echo "Done. Run: node validate.js"
