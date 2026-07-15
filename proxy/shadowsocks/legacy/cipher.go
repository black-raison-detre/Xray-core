// Package legacy implements the obsolete Shadowsocks stream ciphers kept only
// for wire compatibility. None of the methods in this package is recommended
// for new deployments.
package legacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	cryptorand "crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/proxy/shadowsocks/legacy/internal/camellia"
	"github.com/xtls/xray-core/proxy/shadowsocks/legacy/internal/idea"
	"github.com/xtls/xray-core/proxy/shadowsocks/legacy/internal/rc2"
	"github.com/xtls/xray-core/proxy/shadowsocks/legacy/internal/seed"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/salsa20/salsa"
)

// Method describes the key and IV sizes of a legacy Shadowsocks cipher.
type Method struct {
	Name    string
	KeySize int
	IVSize  int
	kind    methodKind
}

type methodKind uint8

const (
	kindNone methodKind = iota
	kindTable
	kindRC4
	kindRC4MD5
	kindAESCFB
	kindAESCTR
	kindBlowfishCFB
	kindCamelliaCFB
	kindCAST5CFB
	kindDESCFB
	kindIDEACFB
	kindRC2CFB
	kindSEEDCFB
	kindSalsa20
	kindChaCha20
)

var methodList = []Method{
	{Name: "none", KeySize: 16, kind: kindNone},
	{Name: "table", KeySize: 16, kind: kindTable},
	{Name: "rc4", KeySize: 16, kind: kindRC4},
	{Name: "rc4-md5-6", KeySize: 16, IVSize: 6, kind: kindRC4MD5},
	{Name: "rc4-md5", KeySize: 16, IVSize: 16, kind: kindRC4MD5},
	{Name: "aes-128-cfb", KeySize: 16, IVSize: 16, kind: kindAESCFB},
	{Name: "aes-192-cfb", KeySize: 24, IVSize: 16, kind: kindAESCFB},
	{Name: "aes-256-cfb", KeySize: 32, IVSize: 16, kind: kindAESCFB},
	{Name: "aes-128-ctr", KeySize: 16, IVSize: 16, kind: kindAESCTR},
	{Name: "aes-192-ctr", KeySize: 24, IVSize: 16, kind: kindAESCTR},
	{Name: "aes-256-ctr", KeySize: 32, IVSize: 16, kind: kindAESCTR},
	{Name: "bf-cfb", KeySize: 16, IVSize: 8, kind: kindBlowfishCFB},
	{Name: "camellia-128-cfb", KeySize: 16, IVSize: 16, kind: kindCamelliaCFB},
	{Name: "camellia-192-cfb", KeySize: 24, IVSize: 16, kind: kindCamelliaCFB},
	{Name: "camellia-256-cfb", KeySize: 32, IVSize: 16, kind: kindCamelliaCFB},
	{Name: "cast5-cfb", KeySize: 16, IVSize: 8, kind: kindCAST5CFB},
	{Name: "des-cfb", KeySize: 8, IVSize: 8, kind: kindDESCFB},
	{Name: "idea-cfb", KeySize: 16, IVSize: 8, kind: kindIDEACFB},
	{Name: "rc2-cfb", KeySize: 16, IVSize: 8, kind: kindRC2CFB},
	{Name: "seed-cfb", KeySize: 16, IVSize: 16, kind: kindSEEDCFB},
	{Name: "salsa20", KeySize: 32, IVSize: 8, kind: kindSalsa20},
	{Name: "chacha20", KeySize: 32, IVSize: 8, kind: kindChaCha20},
	{Name: "chacha20-ietf", KeySize: 32, IVSize: 12, kind: kindChaCha20},
}

var methods = func() map[string]Method {
	m := make(map[string]Method, len(methodList))
	for _, method := range methodList {
		m[method.Name] = method
	}
	return m
}()

// Methods returns all supported method names in the libev registry order.
func Methods() []string {
	names := make([]string, len(methodList))
	for i, method := range methodList {
		names[i] = method.Name
	}
	return names
}

// Lookup normalizes a method name and returns its metadata.
func Lookup(name string) (Method, bool) {
	method, ok := methods[strings.ToLower(strings.TrimSpace(name))]
	return method, ok
}

// Cipher contains immutable password-derived state. A Cipher is safe to reuse
// to create independent TCP streams and UDP packet ciphers.
type Cipher struct {
	method Method
	key    []byte
	random io.Reader
	enc    [256]byte
	dec    [256]byte
}

// New creates a legacy cipher using crypto/rand for all IV generation.
func New(method, password string) (*Cipher, error) {
	return NewWithRandom(method, []byte(password), cryptorand.Reader)
}

// NewWithRandom is intended for deterministic wire tests. Production callers
// should use New.
func NewWithRandom(method string, password []byte, random io.Reader) (*Cipher, error) {
	m, ok := Lookup(method)
	if !ok {
		return nil, fmt.Errorf("unsupported legacy Shadowsocks cipher %q", strings.TrimSpace(method))
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("legacy Shadowsocks cipher %q requires a non-empty password", m.Name)
	}
	if random == nil {
		return nil, fmt.Errorf("legacy Shadowsocks cipher %q requires a random source", m.Name)
	}
	c := &Cipher{method: m, random: random}
	if m.kind == kindTable {
		c.key = append([]byte(nil), password...)
		c.initTable(password)
	} else {
		c.key = EVPBytesToKey(password, m.KeySize)
	}
	return c, nil
}

func (c *Cipher) Method() Method { return c.method }

func (c *Cipher) Key() []byte { return append([]byte(nil), c.key...) }

// EVPBytesToKey implements the MD5 password expansion used by Shadowsocks.
func EVPBytesToKey(password []byte, keySize int) []byte {
	if keySize <= 0 {
		return nil
	}
	key := make([]byte, 0, keySize)
	var previous []byte
	for len(key) < keySize {
		h := md5.New()
		_, _ = h.Write(previous)
		_, _ = h.Write(password)
		previous = h.Sum(nil)
		key = append(key, previous...)
	}
	return key[:keySize]
}

// GenerateIV returns a fresh IV of the exact method-specific size.
func (c *Cipher) GenerateIV() ([]byte, error) {
	iv := make([]byte, c.method.IVSize)
	if len(iv) == 0 {
		return iv, nil
	}
	if _, err := io.ReadFull(c.random, iv); err != nil {
		return nil, fmt.Errorf("generate %s IV: %w", c.method.Name, err)
	}
	return iv, nil
}

// NewEncrypter creates a fresh stateful stream for one TCP direction or UDP packet.
func (c *Cipher) NewEncrypter(iv []byte) (cipher.Stream, error) {
	return c.newStream(iv, true)
}

// NewDecrypter creates a fresh stateful stream for one TCP direction or UDP packet.
func (c *Cipher) NewDecrypter(iv []byte) (cipher.Stream, error) {
	return c.newStream(iv, false)
}

func (c *Cipher) newStream(iv []byte, encrypt bool) (stream cipher.Stream, err error) {
	if len(iv) != c.method.IVSize {
		return nil, fmt.Errorf("%s requires a %d-byte IV, got %d", c.method.Name, c.method.IVSize, len(iv))
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			stream = nil
			err = fmt.Errorf("initialize legacy cipher %s: %v", c.method.Name, recovered)
		}
	}()

	switch c.method.kind {
	case kindNone:
		return copyStream{}, nil
	case kindTable:
		if encrypt {
			return tableStream{table: &c.enc}, nil
		}
		return tableStream{table: &c.dec}, nil
	case kindRC4:
		return rc4.NewCipher(c.key)
	case kindRC4MD5:
		sum := md5.Sum(append(append(make([]byte, 0, len(c.key)+len(iv)), c.key...), iv...))
		return rc4.NewCipher(sum[:])
	case kindAESCFB:
		block, blockErr := aes.NewCipher(c.key)
		return newCFB(block, blockErr, iv, encrypt)
	case kindAESCTR:
		block, blockErr := aes.NewCipher(c.key)
		return newCTR(block, blockErr, iv)
	case kindBlowfishCFB:
		block, blockErr := blowfish.NewCipher(c.key)
		return newCFB(block, blockErr, iv, encrypt)
	case kindCamelliaCFB:
		block, blockErr := camellia.NewCipher(c.key)
		return newCFB(block, blockErr, iv, encrypt)
	case kindCAST5CFB:
		block, blockErr := cast5.NewCipher(c.key)
		return newCFB(block, blockErr, iv, encrypt)
	case kindDESCFB:
		block, blockErr := des.NewCipher(c.key)
		return newCFB(block, blockErr, iv, encrypt)
	case kindIDEACFB:
		block, blockErr := idea.NewCipher(c.key)
		return newCFB(block, blockErr, iv, encrypt)
	case kindRC2CFB:
		block, blockErr := rc2.New(c.key, len(c.key)*8)
		return newCFB(block, blockErr, iv, encrypt)
	case kindSEEDCFB:
		block, blockErr := seed.NewCipher(c.key)
		return newCFB(block, blockErr, iv, encrypt)
	case kindSalsa20:
		return newSalsa20(c.key, iv)
	case kindChaCha20:
		return crypto.NewChaCha20Stream(c.key, iv), nil
	default:
		return nil, fmt.Errorf("legacy cipher %q has no stream constructor", c.method.Name)
	}
}

func newCFB(block cipher.Block, blockErr error, iv []byte, encrypt bool) (cipher.Stream, error) {
	if blockErr != nil {
		return nil, blockErr
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("CFB IV is %d bytes, block size is %d", len(iv), block.BlockSize())
	}
	if encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	}
	return cipher.NewCFBDecrypter(block, iv), nil
}

func newCTR(block cipher.Block, blockErr error, iv []byte) (cipher.Stream, error) {
	if blockErr != nil {
		return nil, blockErr
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("CTR IV is %d bytes, block size is %d", len(iv), block.BlockSize())
	}
	return cipher.NewCTR(block, iv), nil
}

type copyStream struct{}

func (copyStream) XORKeyStream(dst, src []byte) { copy(dst, src) }

type tableStream struct{ table *[256]byte }

func (s tableStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("legacy table cipher: output smaller than input")
	}
	for i, value := range src {
		dst[i] = s.table[value]
	}
}

type salsa20Stream struct {
	nonce   [8]byte
	key     [32]byte
	offset  uint64
	partial [64]byte
	used    int
}

func newSalsa20(key, iv []byte) (cipher.Stream, error) {
	if len(key) != 32 || len(iv) != 8 {
		return nil, fmt.Errorf("salsa20 requires a 32-byte key and 8-byte IV")
	}
	s := &salsa20Stream{}
	copy(s.key[:], key)
	copy(s.nonce[:], iv)
	return s, nil
}

func (s *salsa20Stream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("salsa20: output smaller than input")
	}
	for len(src) > 0 {
		if s.used == len(s.partial) {
			s.used = 0
		}
		if s.used == 0 {
			var counterNonce [16]byte
			copy(counterNonce[:8], s.nonce[:])
			binary.LittleEndian.PutUint64(counterNonce[8:], s.offset/64)
			var zero [64]byte
			salsa.XORKeyStream(s.partial[:], zero[:], &counterNonce, &s.key)
		}
		n := min(len(src), len(s.partial)-s.used)
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ s.partial[s.used+i]
		}
		s.used += n
		s.offset += uint64(n)
		dst = dst[n:]
		src = src[n:]
	}
}

// EncryptPacket encrypts one UDP payload with a fresh method-specific IV.
func (c *Cipher) EncryptPacket(plaintext []byte) ([]byte, error) {
	iv, err := c.GenerateIV()
	if err != nil {
		return nil, err
	}
	stream, err := c.NewEncrypter(iv)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, len(iv)+len(plaintext))
	copy(packet, iv)
	stream.XORKeyStream(packet[len(iv):], plaintext)
	return packet, nil
}

// DecryptPacket decrypts one UDP payload and removes its IV prefix.
func (c *Cipher) DecryptPacket(packet []byte) ([]byte, error) {
	if len(packet) < c.method.IVSize {
		return nil, fmt.Errorf("%s UDP packet is shorter than its %d-byte IV", c.method.Name, c.method.IVSize)
	}
	iv := packet[:c.method.IVSize]
	stream, err := c.NewDecrypter(iv)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(packet)-len(iv))
	stream.XORKeyStream(plaintext, packet[len(iv):])
	return plaintext, nil
}

func (c *Cipher) initTable(password []byte) {
	digest := md5.Sum(password)
	key := binary.LittleEndian.Uint64(digest[:8])
	for i := range c.enc {
		c.enc[i] = byte(i)
	}
	for salt := uint32(1); salt < 1024; salt++ {
		mergeSort(c.enc[:], salt, key)
	}
	for i, value := range c.enc {
		c.dec[value] = byte(i)
	}
}

func mergeSort(values []byte, salt uint32, key uint64) {
	if len(values) <= 1 {
		return
	}
	leftLen := len(values) - len(values)/2
	mergeSort(values[:leftLen], salt, key)
	mergeSort(values[leftLen:], salt, key)
	left := append([]byte(nil), values[:leftLen]...)
	right := append([]byte(nil), values[leftLen:]...)
	i, j, out := 0, 0, 0
	for i < len(left) && j < len(right) {
		x, y := uint64(left[i])+uint64(salt), uint64(right[j])+uint64(salt)
		if int64(key%x)-int64(key%y) <= 0 {
			values[out] = left[i]
			i++
		} else {
			values[out] = right[j]
			j++
		}
		out++
	}
	out += copy(values[out:], left[i:])
	copy(values[out:], right[j:])
}
