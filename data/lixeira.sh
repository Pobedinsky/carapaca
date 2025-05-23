#!/bin/bash

# Script to delete files older than 30 days in the /keys/clients directory
# sudo crontab -e
# 0 0 1 * 0 <lixeira.sh>
current_dir=$(pwd)
find $current_dir/keys/clients -type f -name "*" -delete