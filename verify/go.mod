module github.com/slash-mark-dev/go-suite/verify

go 1.23

require (
	github.com/slash-mark-dev/go-suite v0.0.0
	golang.org/x/mod v0.0.0
)

replace (
	github.com/slash-mark-dev/go-suite => ../
	golang.org/x/mod => ./.xmod
)
