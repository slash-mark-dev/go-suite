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
# Use the Go version x/mod itself declares in this Go release
# (newer releases vendor an x/mod that needs newer language features).
gover="$(sed -n '/^# golang.org\/x\/mod /{n;s/.*; go \([0-9.]*\).*/\1/p;}' "$(go env GOROOT)/src/cmd/vendor/modules.txt")"
[ -n "$gover" ] || gover=1.22
printf 'module golang.org/x/mod\n\ngo %s\n' "$gover" > .xmod/go.mod
# The main module's go line must not be older than a dependency's.
go mod edit -go="$(printf '%s\n%s\n' "$(go mod edit -json | sed -n 's/.*"Go": "\(.*\)".*/\1/p')" "$gover" | sort -V | tail -1)"
echo "x/mod copied from $src"
