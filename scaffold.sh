#!/bin/bash
# Run from inside your cloned scripts repo:
#   git clone git@github.com:YOUR-USERNAME/scripts.git
#   cd scripts && bash scaffold.sh

set -e
echo "Scaffolding scripts..."

mkdir -p alert-enricher/screenshots
mkdir -p ioc-extractor/screenshots
mkdir -p coverage-reporter/screenshots
mkdir -p lab-health/screenshots

find . -name "screenshots" -type d | while read d; do
  touch "$d/.gitkeep"
done

echo "Done."
echo ""
echo "Next: git add . && git commit -m 'Scaffold scripts repo' && git push"
