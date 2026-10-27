// Package sumdb verifies module checksums against a Go checksum database
// (sum.golang.org by default). It implements the transparency-log math
// (RFC 6962 Merkle trees stored as tiles), signed notes, inclusion proofs for
// individual records and consistency proofs between tree sizes, so that a
// lookup is accepted only if it is provably part of the signed, append-only
// log. The implementation matches golang.org/x/mod/sumdb (verified by the
// differential tests in verify/).
package sumdb

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

// HashSize is the size of a tree hash.
const HashSize = 32

// Hash is a Merkle tree hash.
type Hash [HashSize]byte

func (h Hash) String() string { return base64.StdEncoding.EncodeToString(h[:]) }

// ParseHash parses a base64 hash.
func ParseHash(s string) (Hash, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(data) != HashSize {
		return Hash{}, fmt.Errorf("malformed hash")
	}
	var h Hash
	copy(h[:], data)
	return h, nil
}

// RecordHash returns the leaf hash of a record: SHA256(0x00 || data).
func RecordHash(data []byte) Hash {
	var h Hash
	buf := make([]byte, 1+len(data))
	copy(buf[1:], data)
	h = sha256.Sum256(buf)
	return h
}

// NodeHash returns the hash of an interior node: SHA256(0x01 || l || r).
func NodeHash(left, right Hash) Hash {
	var buf [1 + 2*HashSize]byte
	buf[0] = 1
	copy(buf[1:], left[:])
	copy(buf[1+HashSize:], right[:])
	return sha256.Sum256(buf[:])
}

// StoredHashIndex maps the tree coordinates (level, n) to a dense index in
// the order hashes are written to storage.
func StoredHashIndex(level int, n int64) int64 {
	for l := level; l > 0; l-- {
		n = 2*n + 1
	}
	i := int64(0)
	for ; n > 0; n >>= 1 {
		i += n
	}
	return i + int64(level)
}

// SplitStoredHashIndex is the inverse of StoredHashIndex.
func SplitStoredHashIndex(index int64) (level int, n int64) {
	n = index / 2
	indexN := StoredHashIndex(0, n)
	for {
		x := indexN + 1 + int64(bits.TrailingZeros64(uint64(n+1)))
		if x > index {
			break
		}
		n++
		indexN = x
	}
	level = int(index - indexN)
	return level, n >> uint(level)
}

// StoredHashCount returns the number of stored hashes for a tree of n records.
func StoredHashCount(n int64) int64 {
	if n == 0 {
		return 0
	}
	numHash := StoredHashIndex(0, n-1) + 1
	for i := uint64(n - 1); i&1 != 0; i >>= 1 {
		numHash++
	}
	return numHash
}

// HashReader returns stored hashes by index.
type HashReader interface {
	ReadHashes(indexes []int64) ([]Hash, error)
}

// HashReaderFunc adapts a function to HashReader.
type HashReaderFunc func([]int64) ([]Hash, error)

func (f HashReaderFunc) ReadHashes(indexes []int64) ([]Hash, error) { return f(indexes) }

func maxpow2(n int64) (k int64, l int) {
	l = 0
	for 1<<uint(l+1) < n {
		l++
	}
	return 1 << uint(l), l
}

var errProofFailed = errors.New("invalid transparency proof")

// TreeHash computes the root hash of a tree of n records.
func TreeHash(n int64, r HashReader) (Hash, error) {
	if n == 0 {
		return Hash{}, nil
	}
	indexes := subTreeIndex(0, n, nil)
	hashes, err := r.ReadHashes(indexes)
	if err != nil {
		return Hash{}, err
	}
	if len(hashes) != len(indexes) {
		return Hash{}, fmt.Errorf("tlog: ReadHashes(%d indexes) = %d hashes", len(indexes), len(hashes))
	}
	h, rest := subTreeHash(0, n, hashes)
	if len(rest) != 0 {
		return Hash{}, errors.New("tlog: bad index math in TreeHash")
	}
	return h, nil
}

func subTreeIndex(lo, hi int64, need []int64) []int64 {
	for lo < hi {
		k, level := maxpow2(hi - lo + 1)
		need = append(need, StoredHashIndex(level, lo>>uint(level)))
		lo += k
	}
	return need
}

func subTreeHash(lo, hi int64, hashes []Hash) (Hash, []Hash) {
	numTree := 0
	for lo < hi {
		k, _ := maxpow2(hi - lo + 1)
		numTree++
		lo += k
	}
	h := hashes[numTree-1]
	for i := numTree - 2; i >= 0; i-- {
		h = NodeHash(hashes[i], h)
	}
	return h, hashes[numTree:]
}

// RecordProof is a proof that a record is in a tree.
type RecordProof []Hash

// ProveRecord returns the proof that record n is in the tree of size t.
func ProveRecord(t, n int64, r HashReader) (RecordProof, error) {
	if t < 0 || n < 0 || n >= t {
		return nil, fmt.Errorf("tlog: invalid inputs in ProveRecord")
	}
	indexes := leafProofIndex(0, t, n, nil)
	if len(indexes) == 0 {
		return RecordProof{}, nil
	}
	hashes, err := r.ReadHashes(indexes)
	if err != nil {
		return nil, err
	}
	if len(hashes) != len(indexes) {
		return nil, fmt.Errorf("tlog: ReadHashes(%d indexes) = %d hashes", len(indexes), len(hashes))
	}
	p, _ := leafProof(0, t, n, hashes)
	return p, nil
}

func leafProofIndex(lo, hi, n int64, need []int64) []int64 {
	if lo+1 == hi {
		return need
	}
	if k, _ := maxpow2(hi - lo); n < lo+k {
		need = leafProofIndex(lo, lo+k, n, need)
		need = subTreeIndex(lo+k, hi, need)
	} else {
		need = subTreeIndex(lo, lo+k, need)
		need = leafProofIndex(lo+k, hi, n, need)
	}
	return need
}

func leafProof(lo, hi, n int64, hashes []Hash) (RecordProof, []Hash) {
	if lo+1 == hi {
		return RecordProof{}, hashes
	}
	var p RecordProof
	var th Hash
	if k, _ := maxpow2(hi - lo); n < lo+k {
		p, hashes = leafProof(lo, lo+k, n, hashes)
		th, hashes = subTreeHash(lo+k, hi, hashes)
	} else {
		th, hashes = subTreeHash(lo, lo+k, hashes)
		p, hashes = leafProof(lo+k, hi, n, hashes)
	}
	return append(p, th), hashes
}

// CheckRecord verifies that p proves record n with hash h is in the tree
// of size t with root hash th.
func CheckRecord(p RecordProof, t int64, th Hash, n int64, h Hash) error {
	if t < 0 || n < 0 || n >= t {
		return errProofFailed
	}
	th2, err := runRecordProof(p, 0, t, n, h)
	if err != nil {
		return err
	}
	if th2 == th {
		return nil
	}
	return errProofFailed
}

func runRecordProof(p RecordProof, lo, hi, n int64, leafHash Hash) (Hash, error) {
	if lo+1 == hi {
		if len(p) != 0 {
			return Hash{}, errProofFailed
		}
		return leafHash, nil
	}
	if len(p) == 0 {
		return Hash{}, errProofFailed
	}
	k, _ := maxpow2(hi - lo)
	if n < lo+k {
		th, err := runRecordProof(p[:len(p)-1], lo, lo+k, n, leafHash)
		if err != nil {
			return Hash{}, err
		}
		return NodeHash(th, p[len(p)-1]), nil
	}
	th, err := runRecordProof(p[:len(p)-1], lo+k, hi, n, leafHash)
	if err != nil {
		return Hash{}, err
	}
	return NodeHash(p[len(p)-1], th), nil
}

// TreeProof is a proof that a smaller tree is a prefix of a larger one.
type TreeProof []Hash

// ProveTree returns the proof that the tree of size n is a prefix of the
// tree of size t.
func ProveTree(t, n int64, h HashReader) (TreeProof, error) {
	if t < 1 || n < 1 || n > t {
		return nil, fmt.Errorf("tlog: invalid inputs in ProveTree")
	}
	indexes := treeProofIndex(0, t, n, nil)
	if len(indexes) == 0 {
		return TreeProof{}, nil
	}
	hashes, err := h.ReadHashes(indexes)
	if err != nil {
		return nil, err
	}
	if len(hashes) != len(indexes) {
		return nil, fmt.Errorf("tlog: ReadHashes(%d indexes) = %d hashes", len(indexes), len(hashes))
	}
	p, _ := treeProof(0, t, n, hashes)
	return p, nil
}

func treeProofIndex(lo, hi, n int64, need []int64) []int64 {
	if n == hi {
		if lo == 0 {
			return need
		}
		return subTreeIndex(lo, hi, need)
	}
	if k, _ := maxpow2(hi - lo); n <= lo+k {
		need = treeProofIndex(lo, lo+k, n, need)
		need = subTreeIndex(lo+k, hi, need)
	} else {
		need = subTreeIndex(lo, lo+k, need)
		need = treeProofIndex(lo+k, hi, n, need)
	}
	return need
}

func treeProof(lo, hi, n int64, hashes []Hash) (TreeProof, []Hash) {
	if n == hi {
		if lo == 0 {
			return TreeProof{}, hashes
		}
		th, hashes := subTreeHash(lo, hi, hashes)
		return TreeProof{th}, hashes
	}
	var p TreeProof
	var th Hash
	if k, _ := maxpow2(hi - lo); n <= lo+k {
		p, hashes = treeProof(lo, lo+k, n, hashes)
		th, hashes = subTreeHash(lo+k, hi, hashes)
	} else {
		th, hashes = subTreeHash(lo, lo+k, hashes)
		p, hashes = treeProof(lo+k, hi, n, hashes)
	}
	return append(p, th), hashes
}

// CheckTree verifies that p proves the tree of size n with hash h is a
// prefix of the tree of size t with hash th.
func CheckTree(p TreeProof, t int64, th Hash, n int64, h Hash) error {
	if t < 1 || n < 1 || n > t {
		return errProofFailed
	}
	h2, th2, err := runTreeProof(p, 0, t, n, h)
	if err != nil {
		return err
	}
	if th2 == th && h2 == h {
		return nil
	}
	return errProofFailed
}

func runTreeProof(p TreeProof, lo, hi, n int64, old Hash) (Hash, Hash, error) {
	if n == hi {
		if lo == 0 {
			if len(p) != 0 {
				return Hash{}, Hash{}, errProofFailed
			}
			return old, old, nil
		}
		if len(p) != 1 {
			return Hash{}, Hash{}, errProofFailed
		}
		return p[0], p[0], nil
	}
	if len(p) == 0 {
		return Hash{}, Hash{}, errProofFailed
	}
	k, _ := maxpow2(hi - lo)
	if n <= lo+k {
		oh, th, err := runTreeProof(p[:len(p)-1], lo, lo+k, n, old)
		if err != nil {
			return Hash{}, Hash{}, err
		}
		return oh, NodeHash(th, p[len(p)-1]), nil
	}
	oh, th, err := runTreeProof(p[:len(p)-1], lo+k, hi, n, old)
	if err != nil {
		return Hash{}, Hash{}, err
	}
	return NodeHash(p[len(p)-1], oh), NodeHash(p[len(p)-1], th), nil
}

// StoredHashes returns the hashes that must be stored when record n with
// the given data is added to a tree; r reads hashes already stored.
// It is used by the test server.
func StoredHashes(n int64, data []byte, r HashReader) ([]Hash, error) {
	return StoredHashesForRecordHash(n, RecordHash(data), r)
}

// StoredHashesForRecordHash is StoredHashes with a precomputed leaf hash.
func StoredHashesForRecordHash(n int64, h Hash, r HashReader) ([]Hash, error) {
	hashes := []Hash{h}
	m := int(bits.TrailingZeros64(uint64(n + 1)))
	indexes := make([]int64, m)
	for i := 0; i < m; i++ {
		indexes[m-1-i] = StoredHashIndex(i, n>>uint(i)-1)
	}
	old, err := r.ReadHashes(indexes)
	if err != nil {
		return nil, err
	}
	for i := 0; i < m; i++ {
		h = NodeHash(old[m-1-i], h)
		hashes = append(hashes, h)
	}
	return hashes, nil
}

// Tile is a tile of stored hashes: height H, level L, number N, width W.
// L == -1 denotes a data tile.
type Tile struct {
	H int
	L int
	N int64
	W int
}

// TileForIndex returns the minimal tile containing stored hash index.
func TileForIndex(h int, index int64) Tile {
	t, _, _ := tileForIndex(h, index)
	return t
}

func tileForIndex(h int, index int64) (t Tile, start, end int) {
	level, n := SplitStoredHashIndex(index)
	t.H = h
	t.L = level / h
	level -= t.L * h
	t.N = n << uint(level) >> uint(t.H)
	n -= t.N << uint(t.H) >> uint(level)
	t.W = int((n + 1) << uint(level))
	return t, int(n<<uint(level)) * HashSize, int((n+1)<<uint(level)) * HashSize
}

// HashFromTile returns the hash at index from the tile data.
func HashFromTile(t Tile, data []byte, index int64) (Hash, error) {
	if t.H < 1 || t.H > 30 || t.L < 0 || t.L >= 64 || t.W < 1 || t.W > 1<<uint(t.H) {
		return Hash{}, fmt.Errorf("invalid %v", t)
	}
	if len(data) < t.W*HashSize {
		return Hash{}, fmt.Errorf("data len %d too short for %v", len(data), t)
	}
	t1, start, end := tileForIndex(t.H, index)
	if t.L != t1.L || t.N != t1.N || t.W < t1.W {
		return Hash{}, fmt.Errorf("index %v is in %v not %v", index, t1, t)
	}
	return tileHash(data[start:end]), nil
}

func tileHash(data []byte) Hash {
	if len(data) == HashSize {
		var h Hash
		copy(h[:], data)
		return h
	}
	n := len(data) / 2
	return NodeHash(tileHash(data[:n]), tileHash(data[n:]))
}

// Path returns the tile's URL path ("tile/8/0/x123/456.p/12").
func (t Tile) Path() string {
	n := t.N
	nStr := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		nStr = fmt.Sprintf("x%03d/%s", n%1000, nStr)
	}
	pStr := ""
	if t.W != 1<<uint(t.H) {
		pStr = fmt.Sprintf(".p/%d", t.W)
	}
	var L string
	if t.L == -1 {
		L = "data"
	} else {
		L = strconv.Itoa(t.L)
	}
	return fmt.Sprintf("tile/%d/%s/%s%s", t.H, L, nStr, pStr)
}

// ParseTilePath parses a tile path.
func ParseTilePath(path string) (Tile, error) {
	f := strings.Split(path, "/")
	if len(f) < 4 || f[0] != "tile" {
		return Tile{}, fmt.Errorf("malformed tile path %q", path)
	}
	h, err := strconv.Atoi(f[1])
	if err != nil || h < 1 || h > 30 {
		return Tile{}, fmt.Errorf("malformed tile path %q", path)
	}
	l := -1
	if f[2] != "data" {
		l, err = strconv.Atoi(f[2])
		if err != nil || l < 0 || l > 63 {
			return Tile{}, fmt.Errorf("malformed tile path %q", path)
		}
	}
	w := 1 << uint(h)
	if dotP := f[len(f)-2]; strings.HasSuffix(dotP, ".p") {
		ww, err := strconv.Atoi(f[len(f)-1])
		if err != nil || ww <= 0 || ww >= w {
			return Tile{}, fmt.Errorf("malformed tile path %q", path)
		}
		w = ww
		f[len(f)-2] = dotP[:len(dotP)-len(".p")]
		f = f[:len(f)-1]
	}
	f = f[3:]
	var n int64
	for _, s := range f {
		nn, err := strconv.Atoi(strings.TrimPrefix(s, "x"))
		if err != nil || nn < 0 || nn >= 1000 {
			return Tile{}, fmt.Errorf("malformed tile path %q", path)
		}
		n = n*1000 + int64(nn)
	}
	return Tile{H: h, L: l, N: n, W: w}, nil
}

// TileWidth returns the width of tile (level L, number N) in a tree of
// size treeSize: full (1<<H) or the partial right-edge width.
func TileWidth(h, l int, n int64, treeSize int64) int {
	count := treeSize >> uint(l*h) // complete hashes at stored level l*h
	w := count - n<<uint(h)
	if w > 1<<uint(h) {
		w = 1 << uint(h)
	}
	if w < 0 {
		w = 0
	}
	return int(w)
}
