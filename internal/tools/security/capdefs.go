package security

import (
	"go/types"
	"sort"
	"strings"

	"github.com/slash-mark-dev/go-suite/internal/callgraph"
	"github.com/slash-mark-dev/go-suite/internal/report"
)

// Capability names.
const (
	CapExec    = "exec"
	CapNetwork = "network"
	CapFS      = "filesystem"
	CapUnsafe  = "unsafe"
	CapCgo     = "cgo"
	CapSyscall = "syscall"
	CapReflect = "reflect"
	CapPlugin  = "plugin"
	CapEnv     = "env"
	CapRuntime = "runtime"
)

// capOrder is the display order (most dangerous first).
var capOrder = []string{CapExec, CapNetwork, CapCgo, CapUnsafe, CapPlugin, CapSyscall, CapFS, CapReflect, CapEnv, CapRuntime}

var capInfo = map[string]struct {
	Desc     string
	Severity report.Severity
}{
	CapExec:    {"runs other programs (os/exec, os.StartProcess, syscall.Exec)", report.High},
	CapNetwork: {"opens network connections, listens or resolves names", report.High},
	CapCgo:     {"links C code through cgo", report.High},
	CapUnsafe:  {"imports unsafe (can break memory and type safety)", report.High},
	CapPlugin:  {"loads Go plugins at run time", report.High},
	CapSyscall: {"makes raw system calls (syscall, golang.org/x/sys)", report.Medium},
	CapFS:      {"reads or writes the file system", report.Medium},
	CapReflect: {"calls methods or forges pointers through reflection", report.Medium},
	CapEnv:     {"reads or changes environment variables", report.Low},
	CapRuntime: {"handles OS signals, exits or controls the process/runtime", report.Low},
}

func capRank(c string) int {
	for i, x := range capOrder {
		if x == c {
			return i
		}
	}
	return len(capOrder)
}

func sortCaps(cs []string) {
	sort.Slice(cs, func(i, j int) bool { return capRank(cs[i]) < capRank(cs[j]) })
}

// capRules maps "pkgpath.Symbol" patterns to capabilities. A trailing "*"
// matches a prefix; "pkgpath.*" matches every function and method of the
// package. Symbols use the vulndb convention ("F", "T.M").
var capRules = map[string][]string{
	CapExec: {
		"os/exec.*", "os.StartProcess", "syscall.Exec", "syscall.ForkExec", "syscall.StartProcess",
		"golang.org/x/sys/unix.Exec", "golang.org/x/sys/windows.CreateProcess*",
	},
	CapNetwork: {
		"net.Dial*", "net.Listen*", "net.Lookup*", "net.Dialer.Dial*", "net.ListenConfig.Listen*", "net.Resolver.Lookup*",
		"net.FileConn", "net.FileListener", "net.FilePacketConn", "net.Interfaces", "net.InterfaceAddrs", "net.InterfaceBy*",
		"net/http.Get", "net/http.Head", "net/http.Post", "net/http.PostForm", "net/http.ListenAndServe*", "net/http.Serve", "net/http.ServeTLS",
		"net/http.Client.*", "net/http.Server.ListenAndServe*", "net/http.Server.Serve*", "net/http.Transport.RoundTrip",
		"net/http.DefaultClient", "net/http.DefaultTransport",
		"net/rpc.Dial*", "net/rpc.Accept", "net/rpc.Server.Accept", "net/smtp.Dial", "net/smtp.SendMail",
		"crypto/tls.Dial*", "crypto/tls.Listen", "crypto/tls.Dialer.Dial*", "net/textproto.Dial",
		"log/syslog.Dial", "log/syslog.New", "log/syslog.NewLogger",
	},
	CapFS: {
		"os.Create", "os.CreateTemp", "os.Open", "os.OpenFile", "os.OpenRoot", "os.OpenInRoot", "os.ReadFile", "os.WriteFile",
		"os.ReadDir", "os.Readlink", "os.Remove", "os.RemoveAll", "os.Rename", "os.Mkdir", "os.MkdirAll", "os.MkdirTemp",
		"os.Chmod", "os.Chown", "os.Lchown", "os.Chtimes", "os.Chdir", "os.Link", "os.Symlink", "os.Truncate",
		"os.Stat", "os.Lstat", "os.DirFS", "os.CopyFS", "os.Getwd",
		"io/ioutil.ReadFile", "io/ioutil.WriteFile", "io/ioutil.ReadDir", "io/ioutil.TempFile", "io/ioutil.TempDir",
		"path/filepath.Walk", "path/filepath.WalkDir", "path/filepath.Glob", "path/filepath.EvalSymlinks",
	},
	CapSyscall: {"syscall.*", "golang.org/x/sys/unix.*", "golang.org/x/sys/windows.*"},
	CapReflect: {
		"reflect.Value.Call", "reflect.Value.CallSlice", "reflect.Value.Method", "reflect.Value.MethodByName",
		"reflect.Type.Method", "reflect.Type.MethodByName", "reflect.MakeFunc", "reflect.NewAt",
		"reflect.Value.UnsafeAddr", "reflect.Value.UnsafePointer", "reflect.Value.SetPointer",
	},
	CapPlugin: {"plugin.*"},
	CapEnv: {
		"os.Getenv", "os.LookupEnv", "os.Environ", "os.Setenv", "os.Unsetenv", "os.Clearenv", "os.ExpandEnv",
		"os.UserHomeDir", "os.UserCacheDir", "os.UserConfigDir",
		"syscall.Getenv", "syscall.Setenv", "syscall.Unsetenv", "syscall.Environ", "syscall.Clearenv",
	},
	CapRuntime: {
		"os/signal.*", "os.Exit", "os.FindProcess", "os.Process.Kill", "os.Process.Signal", "syscall.Kill",
		"runtime.LockOSThread", "runtime.Breakpoint", "runtime/debug.Set*", "runtime/debug.WriteHeapDump",
	},
}

type capMatcher struct {
	exact  map[string][]string // "pkg.Sym" -> caps
	prefix []struct {
		pfx  string
		caps string
	}
}

func newCapMatcher(rules map[string][]string) *capMatcher {
	m := &capMatcher{exact: map[string][]string{}}
	var names []string
	for c := range rules {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		for _, r := range rules[c] {
			if strings.HasSuffix(r, "*") {
				m.prefix = append(m.prefix, struct{ pfx, caps string }{strings.TrimSuffix(r, "*"), c})
			} else {
				m.exact[r] = append(m.exact[r], c)
			}
		}
	}
	return m
}

// match returns the capabilities of "pkg.Sym".
func (m *capMatcher) match(key string) []string {
	out := append([]string(nil), m.exact[key]...)
	for _, p := range m.prefix {
		if strings.HasPrefix(key, p.pfx) && !hasStr(out, p.caps) {
			out = append(out, p.caps)
		}
	}
	return out
}

func hasStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var stdCaps = newCapMatcher(capRules)

// objKey returns "pkgpath.Sym" for a package-level function, method or
// variable, or "" for other objects. Interface methods are keyed by their
// interface type ("reflect.Type.Method").
func objKey(obj types.Object) string {
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	switch o := obj.(type) {
	case *types.Func:
		return o.Pkg().Path() + "." + callgraph.SymbolOf(o.Origin())
	case *types.Var:
		if o.Parent() != nil && o.Parent() == o.Pkg().Scope() {
			return o.Pkg().Path() + "." + o.Name()
		}
	}
	return ""
}

// objCaps returns the capabilities exercised by using obj. Only
// functions, methods and package-level variables count; "pkg.*" rules
// match functions and methods only.
func objCaps(obj types.Object) []string {
	key := objKey(obj)
	if key == "" {
		return nil
	}
	if _, isVar := obj.(*types.Var); isVar {
		return stdCaps.exact[key]
	}
	return stdCaps.match(key)
}
