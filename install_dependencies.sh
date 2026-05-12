#!/bin/sh
#install the external python libraries used by the analyzer and web app
set -eu

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
