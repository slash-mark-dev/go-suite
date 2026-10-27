// Command sm-go is the Slash Mark Go Suite: 30 advanced tools for Go
// modules on live data.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/slash-mark-dev/go-suite/internal/cli"

	_ "github.com/slash-mark-dev/go-suite/internal/tools/binary"
	_ "github.com/slash-mark-dev/go-suite/internal/tools/compliance"
	_ "github.com/slash-mark-dev/go-suite/internal/tools/deps"
	_ "github.com/slash-mark-dev/go-suite/internal/tools/origin"
	_ "github.com/slash-mark-dev/go-suite/internal/tools/security"
	_ "github.com/slash-mark-dev/go-suite/internal/tools/upgrade"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, os.Args[1:], os.Environ(), os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
