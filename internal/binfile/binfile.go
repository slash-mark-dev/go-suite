// Package binfile reads compiled Go executables (ELF, Mach-O and PE)
// without their source: format and target platform, embedded build
// information, the function table with addresses and sizes, section sizes
// and whether symbols / DWARF were stripped. It also splits Go symbol
// names into package and symbol and maps packages to modules using the
// binary's own dependency list.
package binfile

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"
)

// Section kinds used for size totals.
const (
	KindText    = "text"
	KindRodata  = "rodata"
	KindData    = "data"
	KindBSS     = "bss" // not stored in the file
	KindPclntab = "pclntab"
	KindSymtab  = "symtab"
	KindDWARF   = "dwarf"
	KindOther   = "other"
)

// Symbol sources.
const (
	SourceSymtab  = "symtab"  // object file symbol table
	SourcePclntab = "pclntab" // Go runtime function table
	SourceNone    = "none"
)

// Symbol is a function or data symbol with its address and size.
type Symbol struct {
	Name string `json:"name"`
	Addr uint64 `json:"addr"`
	Size uint64 `json:"size"`
}

// Section is one section of the file.
type Section struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Addr     uint64 `json:"addr"`
	Size     uint64 `json:"size"`     // in-memory size
	FileSize uint64 `json:"fileSize"` // bytes stored in the file
}

// File is an opened Go binary.
type File struct {
	Path   string `json:"path"`
	Format string `json:"format"` // elf, macho, pe
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	Size   int64  `json:"size"`
	// BuildInfo is the embedded build information (module list, settings).
	BuildInfo *debug.BuildInfo `json:"-"`
	// Funcs are the function symbols, sorted by address.
	Funcs []Symbol `json:"-"`
	// Data are sized data symbols (only when an object symbol table is
	// present), sorted by address.
	Data []Symbol `json:"-"`
	// SymbolSource says where Funcs came from.
	SymbolSource string    `json:"symbolSource"`
	Sections     []Section `json:"sections"`
	HasSymtab    bool      `json:"hasSymtab"`
	HasPclntab   bool      `json:"hasPclntab"`
	HasDWARF     bool      `json:"hasDWARF"`
	// Stripped reports that the object symbol table was removed (-s) or
	// holds no function symbols.
	Stripped bool `json:"stripped"`
}

// ErrNotGo is returned for files that are not Go executables.
var ErrNotGo = errors.New("not a Go binary")

// ErrFormat is returned for files that are not ELF, Mach-O or PE.
var ErrFormat = errors.New("not an ELF, Mach-O or PE executable")

// IsGoBinary reports cheaply whether path looks like a Go executable.
func IsGoBinary(path string) bool {
	_, err := buildinfo.ReadFile(path)
	return err == nil
}

// Open reads the Go binary at path.
func Open(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return nil, fmt.Errorf("%s: %w", path, ErrFormat)
	}
	bf := &File{Path: path, Size: fi.Size(), SymbolSource: SourceNone}
	switch {
	case bytes.Equal(magic[:], []byte("\x7fELF")):
		err = bf.readELF(f)
	case isMachO(magic[:]):
		err = bf.readMachO(f)
	case magic[0] == 'M' && magic[1] == 'Z':
		err = bf.readPE(f)
	default:
		return nil, fmt.Errorf("%s: %w", path, ErrFormat)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	bi, err := buildinfo.Read(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (%v)", path, ErrNotGo, err)
	}
	bf.BuildInfo = bi
	// Build settings name the target authoritatively; the header is the
	// fallback for binaries without them.
	for _, s := range bi.Settings {
		switch s.Key {
		case "GOOS":
			bf.GOOS = s.Value
		case "GOARCH":
			bf.GOARCH = s.Value
		}
	}
	sort.Slice(bf.Funcs, func(i, j int) bool { return bf.Funcs[i].Addr < bf.Funcs[j].Addr })
	sort.Slice(bf.Data, func(i, j int) bool { return bf.Data[i].Addr < bf.Data[j].Addr })
	return bf, nil
}

func isMachO(m []byte) bool {
	le := uint32(m[0]) | uint32(m[1])<<8 | uint32(m[2])<<16 | uint32(m[3])<<24
	be := uint32(m[3]) | uint32(m[2])<<8 | uint32(m[1])<<16 | uint32(m[0])<<24
	for _, v := range []uint32{le, be} {
		switch v {
		case macho.Magic32, macho.Magic64, macho.MagicFat:
			return true
		}
	}
	return false
}

// SectionTotal returns the file bytes of all sections of a kind.
func (f *File) SectionTotal(kind string) uint64 {
	var n uint64
	for _, s := range f.Sections {
		if s.Kind == kind {
			n += s.FileSize
		}
	}
	return n
}

// Totals returns file bytes per section kind.
func (f *File) Totals() map[string]uint64 {
	m := map[string]uint64{}
	for _, s := range f.Sections {
		m[s.Kind] += s.FileSize
	}
	return m
}

// SectionAt returns the section containing addr (the smallest one when
// sections overlap), or nil.
func (f *File) SectionAt(addr uint64) *Section {
	var best *Section
	for i := range f.Sections {
		s := &f.Sections[i]
		if s.Size == 0 || addr < s.Addr || addr >= s.Addr+s.Size {
			continue
		}
		if best == nil || s.Size < best.Size {
			best = s
		}
	}
	return best
}

// KindAt returns the kind of the section containing addr (KindOther if
// none does).
func (f *File) KindAt(addr uint64) string {
	if s := f.SectionAt(addr); s != nil {
		return s.Kind
	}
	return KindOther
}

// FuncBytes returns the sum of all function sizes.
func (f *File) FuncBytes() uint64 {
	var n uint64
	for _, s := range f.Funcs {
		n += s.Size
	}
	return n
}

// StripSavings estimates the bytes `-ldflags="-s -w"` would remove: the
// DWARF sections and the object symbol table.
func (f *File) StripSavings() uint64 {
	return f.SectionTotal(KindDWARF) + f.SectionTotal(KindSymtab)
}

// Setting returns a build setting from the build info ("" if absent).
func (f *File) Setting(key string) string {
	if f.BuildInfo == nil {
		return ""
	}
	for _, s := range f.BuildInfo.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

func classify(name string) string {
	n := strings.TrimLeft(name, "._")
	switch {
	case strings.HasPrefix(n, "debug_"), strings.HasPrefix(n, "zdebug_"):
		return KindDWARF
	case n == "text":
		return KindText
	case n == "gopclntab":
		return KindPclntab
	case n == "symtab", n == "strtab":
		return KindSymtab
	case n == "rodata", n == "rdata", n == "typelink", n == "itablink", n == "gosymtab", n == "gofunc",
		n == "go.buildinfo", n == "go_buildinfo", n == "go.fipsinfo", n == "go_fipsinfo", n == "noptrrodata":
		return KindRodata
	case n == "data", n == "noptrdata", n == "data.rel.ro", n == "go.module":
		return KindData
	case n == "bss", n == "noptrbss", n == "tbss":
		return KindBSS
	}
	return KindOther
}

// ---------------- ELF ----------------

func (bf *File) readELF(r io.ReaderAt) error {
	f, err := elf.NewFile(r)
	if err != nil {
		return err
	}
	bf.Format = "elf"
	bf.GOOS = elfOS(f)
	bf.GOARCH = elfArch(f)
	var pcln *elf.Section
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NULL || s.Name == "" {
			continue
		}
		kind := classify(s.Name)
		if s.Name == ".shstrtab" {
			kind = KindOther
		}
		// Size is the uncompressed size of SHF_COMPRESSED sections (the
		// linker compresses DWARF); FileSize is what the file holds.
		fs := s.FileSize
		if s.Type == elf.SHT_NOBITS {
			fs = 0
			if kind != KindBSS {
				kind = KindBSS
			}
		}
		bf.Sections = append(bf.Sections, Section{Name: s.Name, Kind: kind, Addr: s.Addr, Size: s.Size, FileSize: fs})
		if kind == KindDWARF {
			bf.HasDWARF = true
		}
		if s.Name == ".gopclntab" || s.Name == ".data.rel.ro.gopclntab" {
			pcln = s
		}
	}
	syms, err := f.Symbols()
	if err == nil && len(syms) > 0 {
		bf.HasSymtab = true
		containers := elfContainerSizes(f, syms)
		for i, s := range syms {
			if sz, ok := containers[i]; ok {
				bf.Data = append(bf.Data, Symbol{s.Name, s.Value, sz})
				continue
			}
			if s.Name == "" || s.Size == 0 {
				continue
			}
			switch elf.ST_TYPE(s.Info) {
			case elf.STT_FUNC:
				bf.Funcs = append(bf.Funcs, Symbol{s.Name, s.Value, s.Size})
			case elf.STT_OBJECT, elf.STT_TLS:
				bf.Data = append(bf.Data, Symbol{s.Name, s.Value, s.Size})
			}
		}
		if len(bf.Funcs) > 0 {
			bf.SymbolSource = SourceSymtab
		}
	}
	bf.Stripped = bf.SymbolSource != SourceSymtab
	if pcln == nil && bf.HasSymtab {
		// Position-independent / externally linked binaries may merge the
		// table into another section; find it through runtime.pclntab.
		pcln, _ = elfSymbolSection(f, syms, "runtime.pclntab")
	}
	if pcln != nil {
		data, err := pcln.Data()
		if err == nil {
			if pcln.Name != ".gopclntab" {
				data = elfSlice(syms, pcln, data)
			}
			bf.loadPclntab(data, textAddr(f.Section(".text")))
		}
	}
	return nil
}

// elfContainerSizes sizes the zero-sized symbols the Go linker emits for
// merged symbol groups ("type:*", "go:string.*", "go:func.*", ...): each
// spans up to the next symbol at a higher address in its section.
func elfContainerSizes(f *elf.File, syms []elf.Symbol) map[int]uint64 {
	out := map[int]uint64{}
	bySect := map[elf.SectionIndex][]uint64{}
	for _, s := range syms {
		if s.Section > 0 && int(s.Section) < len(f.Sections) {
			bySect[s.Section] = append(bySect[s.Section], s.Value)
		}
	}
	for _, addrs := range bySect {
		sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	}
	for i, s := range syms {
		if s.Size != 0 || !strings.HasSuffix(s.Name, "*") || s.Section == 0 || int(s.Section) >= len(f.Sections) {
			continue
		}
		sec := f.Sections[s.Section]
		end := sec.Addr + sec.Size
		addrs := bySect[s.Section]
		k := sort.Search(len(addrs), func(k int) bool { return addrs[k] > s.Value })
		if k < len(addrs) && addrs[k] < end {
			end = addrs[k]
		}
		if end > s.Value {
			out[i] = end - s.Value
		}
	}
	return out
}

func elfSymbolSection(f *elf.File, syms []elf.Symbol, name string) (*elf.Section, uint64) {
	for _, s := range syms {
		if s.Name == name && int(s.Section) < len(f.Sections) {
			return f.Sections[s.Section], s.Value
		}
	}
	return nil, 0
}

// elfSlice cuts runtime.pclntab..runtime.epclntab out of a merged section.
func elfSlice(syms []elf.Symbol, sec *elf.Section, data []byte) []byte {
	var start, end uint64
	for _, s := range syms {
		switch s.Name {
		case "runtime.pclntab":
			start = s.Value
		case "runtime.epclntab":
			end = s.Value
		}
	}
	if start < sec.Addr || end <= start || end-sec.Addr > uint64(len(data)) {
		return data
	}
	return data[start-sec.Addr : end-sec.Addr]
}

func textAddr(s *elf.Section) uint64 {
	if s == nil {
		return 0
	}
	return s.Addr
}

func elfOS(f *elf.File) string {
	switch f.OSABI {
	case elf.ELFOSABI_FREEBSD:
		return "freebsd"
	case elf.ELFOSABI_NETBSD:
		return "netbsd"
	case elf.ELFOSABI_OPENBSD:
		return "openbsd"
	case elf.ELFOSABI_SOLARIS:
		return "solaris"
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			b := make([]byte, p.Filesz)
			p.ReadAt(b, 0)
			if bytes.Contains(b, []byte("android")) {
				return "android"
			}
		}
	}
	if f.Section(".note.netbsd.ident") != nil {
		return "netbsd"
	}
	if f.Section(".note.openbsd.ident") != nil {
		return "openbsd"
	}
	return "linux"
}

func elfArch(f *elf.File) string {
	switch f.Machine {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_386:
		return "386"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_RISCV:
		return "riscv64"
	case elf.EM_PPC64:
		if f.ByteOrder.String() == "LittleEndian" {
			return "ppc64le"
		}
		return "ppc64"
	case elf.EM_S390:
		return "s390x"
	case elf.EM_MIPS:
		if f.Class == elf.ELFCLASS64 {
			if f.ByteOrder.String() == "LittleEndian" {
				return "mips64le"
			}
			return "mips64"
		}
		if f.ByteOrder.String() == "LittleEndian" {
			return "mipsle"
		}
		return "mips"
	case elf.EM_LOONGARCH:
		return "loong64"
	}
	return strings.ToLower(strings.TrimPrefix(f.Machine.String(), "EM_"))
}

// ---------------- Mach-O ----------------

func (bf *File) readMachO(r io.ReaderAt) error {
	f, err := macho.NewFile(r)
	if err != nil {
		var fe *macho.FormatError
		if errors.As(err, &fe) {
			if ff, ferr := macho.NewFatFile(r); ferr == nil && len(ff.Arches) > 0 {
				f = ff.Arches[0].File
				err = nil
			}
		}
		if err != nil {
			return err
		}
	}
	bf.Format = "macho"
	bf.GOOS = "darwin"
	switch f.Cpu {
	case macho.CpuAmd64:
		bf.GOARCH = "amd64"
	case macho.CpuArm64:
		bf.GOARCH = "arm64"
	case macho.Cpu386:
		bf.GOARCH = "386"
	case macho.CpuArm:
		bf.GOARCH = "arm"
	default:
		bf.GOARCH = strings.ToLower(f.Cpu.String())
	}
	var pcln *macho.Section
	var textStart uint64
	for _, s := range f.Sections {
		name := s.Name
		kind := classify(name)
		if s.Seg == "__DWARF" {
			kind = KindDWARF
		}
		fs := s.Size
		if s.Offset == 0 || kind == KindBSS {
			fs = 0
			kind = KindBSS
		}
		if name == "__text" {
			textStart = s.Addr
		}
		bf.Sections = append(bf.Sections, Section{Name: s.Seg + "," + name, Kind: kind, Addr: s.Addr, Size: s.Size, FileSize: fs})
		if kind == KindDWARF {
			bf.HasDWARF = true
		}
		if name == "__gopclntab" {
			pcln = s
		}
	}
	if f.Symtab != nil && len(f.Symtab.Syms) > 0 {
		bf.HasSymtab = true
		sz := machoSymtabSize(f)
		bf.Sections = append(bf.Sections, Section{Name: "LC_SYMTAB", Kind: KindSymtab, Size: sz, FileSize: sz})
		type sec struct{ start, end uint64 }
		secs := map[int]sec{}
		for i, s := range f.Sections {
			secs[i+1] = sec{s.Addr, s.Addr + s.Size}
		}
		var raw []Symbol
		var kinds []bool
		bySect := map[uint8][]int{}
		for _, s := range f.Symtab.Syms {
			if s.Name == "" || s.Sect == 0 || s.Type&0xe0 != 0 || s.Type&0x0e != 0x0e { // N_SECT, no stabs
				continue
			}
			bySect[s.Sect] = append(bySect[s.Sect], len(raw))
			// Mach-O prefixes every symbol with an underscore.
			raw = append(raw, Symbol{Name: strings.TrimPrefix(s.Name, "_"), Addr: s.Value})
			isText := int(s.Sect) <= len(f.Sections) && f.Sections[s.Sect-1].Name == "__text"
			kinds = append(kinds, isText)
		}
		for sect, idx := range bySect {
			sizeBySuccessor(raw, idx, secs[int(sect)].end)
		}
		for i, s := range raw {
			if s.Size == 0 {
				continue
			}
			if kinds[i] {
				bf.Funcs = append(bf.Funcs, s)
			} else {
				bf.Data = append(bf.Data, s)
			}
		}
		if len(bf.Funcs) > 0 {
			bf.SymbolSource = SourceSymtab
		}
	}
	bf.Stripped = bf.SymbolSource != SourceSymtab
	if pcln != nil {
		if data, err := pcln.Data(); err == nil {
			bf.loadPclntab(data, textStart)
		}
	}
	return nil
}

// machoSymtabSize returns the bytes of the symbol and string tables named
// by the LC_SYMTAB load command (debug/macho does not expose them).
func machoSymtabSize(f *macho.File) uint64 {
	entry := uint64(16)
	if f.Magic == macho.Magic32 {
		entry = 12
	}
	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) < 24 || f.ByteOrder.Uint32(raw[0:4]) != uint32(macho.LoadCmdSymtab) {
			continue
		}
		nsyms := uint64(f.ByteOrder.Uint32(raw[12:16]))
		strsize := uint64(f.ByteOrder.Uint32(raw[20:24]))
		return nsyms*entry + strsize
	}
	return uint64(len(f.Symtab.Syms)) * entry
}

// sizeBySuccessor sets sizes of syms[idx...] (one section) to the distance
// to the next symbol, the last one running to end.
//
// Several symbols may share an address (the linker's region markers such
// as runtime.types next to the real "type:*" symbol); only the preferred
// one of them is sized so bytes are not counted twice.
func sizeBySuccessor(syms []Symbol, idx []int, end uint64) {
	sort.SliceStable(idx, func(a, b int) bool {
		sa, sb := syms[idx[a]], syms[idx[b]]
		if sa.Addr != sb.Addr {
			return sa.Addr < sb.Addr
		}
		return isMarker(sa.Name) && !isMarker(sb.Name)
	})
	for k, i := range idx {
		if k+1 < len(idx) && syms[idx[k+1]].Addr == syms[i].Addr {
			continue // a later symbol at the same address takes the bytes
		}
		next := end
		for j := k + 1; j < len(idx); j++ {
			if syms[idx[j]].Addr > syms[i].Addr {
				next = syms[idx[j]].Addr
				break
			}
		}
		if next > syms[i].Addr {
			syms[i].Size = next - syms[i].Addr
		}
	}
}

// isMarker reports linker-defined region boundary symbols
// (runtime.text, runtime.etypes, ...), which carry no bytes of their own.
func isMarker(name string) bool {
	if !strings.HasPrefix(name, "runtime.") {
		return false
	}
	for _, p := range runtimeMeta {
		if name == p && strings.HasPrefix(p, "runtime.") {
			return true
		}
	}
	return false
}

// ---------------- PE ----------------

func (bf *File) readPE(r io.ReaderAt) error {
	f, err := pe.NewFile(r)
	if err != nil {
		return err
	}
	bf.Format = "pe"
	bf.GOOS = "windows"
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		bf.GOARCH = "amd64"
	case pe.IMAGE_FILE_MACHINE_I386:
		bf.GOARCH = "386"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		bf.GOARCH = "arm64"
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		bf.GOARCH = "arm"
	default:
		bf.GOARCH = fmt.Sprintf("pe-machine-%#x", f.Machine)
	}
	var pclnStart, pclnEnd uint32
	pclnSect := -1
	for _, s := range f.Symbols {
		switch s.Name {
		case "runtime.pclntab":
			pclnStart, pclnSect = s.Value, int(s.SectionNumber)
		case "runtime.epclntab":
			pclnEnd = s.Value
		}
	}
	for i, s := range f.Sections {
		kind := classify(s.Name)
		fs := uint64(s.Size)
		if s.Size == 0 {
			kind = KindBSS
		}
		sec := Section{Name: s.Name, Kind: kind, Addr: uint64(s.VirtualAddress), Size: uint64(s.VirtualSize), FileSize: fs}
		if i+1 == pclnSect && pclnEnd > pclnStart && kind == KindRodata {
			// .rdata contains the function table; report it separately.
			n := uint64(pclnEnd - pclnStart)
			if n <= sec.FileSize {
				sec.FileSize -= n
				sec.Size -= min(n, sec.Size)
				bf.Sections = append(bf.Sections, sec)
				sec = Section{Name: s.Name + "(pclntab)", Kind: KindPclntab, Addr: sec.Addr + uint64(pclnStart), Size: n, FileSize: n}
			}
		}
		bf.Sections = append(bf.Sections, sec)
		if kind == KindDWARF {
			bf.HasDWARF = true
		}
	}
	if len(f.Symbols) > 0 {
		bf.HasSymtab = true
		var raw []Symbol
		var isText []bool
		bySect := map[int][]int{}
		for _, s := range f.Symbols {
			if s.Name == "" || s.SectionNumber <= 0 || int(s.SectionNumber) > len(f.Sections) || s.StorageClass == 3 && strings.HasPrefix(s.Name, ".") {
				continue
			}
			sec := f.Sections[s.SectionNumber-1]
			bySect[int(s.SectionNumber)] = append(bySect[int(s.SectionNumber)], len(raw))
			raw = append(raw, Symbol{Name: s.Name, Addr: uint64(sec.VirtualAddress) + uint64(s.Value)})
			isText = append(isText, sec.Characteristics&pe.IMAGE_SCN_CNT_CODE != 0)
		}
		for n, idx := range bySect {
			sec := f.Sections[n-1]
			sizeBySuccessor(raw, idx, uint64(sec.VirtualAddress)+uint64(max(sec.VirtualSize, sec.Size)))
		}
		for i, s := range raw {
			if s.Size == 0 {
				continue
			}
			if isText[i] {
				bf.Funcs = append(bf.Funcs, s)
			} else {
				bf.Data = append(bf.Data, s)
			}
		}
		if len(bf.Funcs) > 0 {
			bf.SymbolSource = SourceSymtab
		}
	}
	bf.Stripped = bf.SymbolSource != SourceSymtab
	if pclnSect > 0 && pclnSect <= len(f.Sections) && pclnEnd > pclnStart {
		sec := f.Sections[pclnSect-1]
		data, err := sec.Data()
		if err == nil && int(pclnEnd) <= len(data) {
			var text uint64
			if t := f.Section(".text"); t != nil {
				text = uint64(t.VirtualAddress)
			}
			bf.loadPclntab(data[pclnStart:pclnEnd], text)
		}
	}
	if !bf.HasPclntab {
		// Without symbols (-ldflags=-s) the function table has no name;
		// find it in the read-only data by its header.
		var text uint64
		if t := f.Section(".text"); t != nil {
			text = uint64(t.VirtualAddress)
		}
		for _, s := range f.Sections {
			if classify(s.Name) != KindRodata {
				continue
			}
			data, err := s.Data()
			if err != nil {
				continue
			}
			if bf.scanPclntab(data, text) {
				break
			}
		}
	}
	return nil
}

// ---------------- pclntab ----------------

// loadPclntab parses the Go function table. When no object symbol table
// supplied functions, the table becomes the function list with sizes =
// next function start - start.
func (bf *File) loadPclntab(data []byte, textStart uint64) bool {
	if len(data) < 16 {
		return false
	}
	lt := gosym.NewLineTable(data, textStart)
	tab, err := safeTable(lt)
	if err != nil || len(tab.Funcs) == 0 || tab.LookupFunc("runtime.main") == nil {
		return false
	}
	bf.HasPclntab = true
	if bf.SymbolSource != SourceNone {
		return true
	}
	for _, fn := range tab.Funcs {
		size := uint64(0)
		if fn.End > fn.Entry {
			size = fn.End - fn.Entry
		}
		bf.Funcs = append(bf.Funcs, Symbol{Name: fn.Name, Addr: fn.Entry, Size: size})
	}
	bf.SymbolSource = SourcePclntab
	return true
}

// pclntab header magics (little-endian), newest first: Go 1.20+, 1.18,
// 1.16, 1.2.
var pclnMagics = [][]byte{
	{0xf1, 0xff, 0xff, 0xff, 0, 0},
	{0xf0, 0xff, 0xff, 0xff, 0, 0},
	{0xfa, 0xff, 0xff, 0xff, 0, 0},
	{0xfb, 0xff, 0xff, 0xff, 0, 0},
}

// scanPclntab looks for a function table header in data and loads the
// first candidate that parses into a table containing runtime.main.
func (bf *File) scanPclntab(data []byte, textStart uint64) bool {
	for _, magic := range pclnMagics {
		for off := 0; off+16 <= len(data); {
			i := bytes.Index(data[off:], magic)
			if i < 0 {
				break
			}
			at := off + i
			off = at + 1
			if at%4 != 0 || at+8 > len(data) {
				continue
			}
			minLC, ptr := data[at+6], data[at+7]
			if minLC != 1 && minLC != 2 && minLC != 4 || ptr != 4 && ptr != 8 {
				continue
			}
			if bf.loadPclntab(data[at:], textStart) {
				return true
			}
		}
	}
	return false
}

func safeTable(lt *gosym.LineTable) (t *gosym.Table, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("corrupt pclntab: %v", r)
		}
	}()
	return gosym.NewTable(nil, lt)
}
