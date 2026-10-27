#!/bin/sh
# Creates a local copy of golang.org/x/mod from the Go distribution
# (GOROOT/src/cmd/vendor) so the differential tests can compare sm-go's
# implementations against the code the go command itself uses, without
# network access. The copy is git-ignored and never shipped.
set -e
cd "$(dirname "$0")"
src="$(go env GOROOT)/src/cmd/vendor/golang.org/x/mod"
rm -rf .xmod
mkdir -p .xmod
cp -R "$src"/. .xmod/
chmod -R u+w .xmod
printf 'module golang.org/x/mod\n\ngo 1.22\n' > .xmod/go.mod
echo "x/mod copied from $src"
