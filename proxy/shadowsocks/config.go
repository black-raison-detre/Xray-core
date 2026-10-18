package shadowsocks

import (
	"bytes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocks/legacy"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// MemoryAccount is an account type converted from Account.
type MemoryAccount struct {
	Cipher     Cipher
	CipherType CipherType
	Key        []byte
	Password   string
}

var ErrIVNotUnique = errors.New("IV is not unique")

// Equals implements protocol.Account.Equals().
func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if account, ok := another.(*MemoryAccount); ok {
		return bytes.Equal(a.Key, account.Key)
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		CipherType: a.CipherType,
		Password:   a.Password,
	}
}

func createAesGcm(key []byte) cipher.AEAD {
	return crypto.NewAesGcm(key)
}

func createChaCha20Poly1305(key []byte) cipher.AEAD {
	ChaChaPoly1305, err := chacha20poly1305.New(key)
	common.Must(err)
	return ChaChaPoly1305
}

func createXChaCha20Poly1305(key []byte) cipher.AEAD {
	XChaChaPoly1305, err := chacha20poly1305.NewX(key)
	common.Must(err)
	return XChaChaPoly1305
}

func (a *Account) getCipher() (Cipher, error) {
	switch a.CipherType {
	case CipherType_AES_128_CFB:
		return &LegacyCipher{MethodName: "aes-128-cfb"}, nil
	case CipherType_AES_256_CFB:
		return &LegacyCipher{MethodName: "aes-256-cfb"}, nil
	case CipherType_CHACHA20:
		return &LegacyCipher{MethodName: "chacha20"}, nil
	case CipherType_CHACHA20_IETF:
		return &LegacyCipher{MethodName: "chacha20-ietf"}, nil
	case CipherType_AES_128_GCM:
		return &AEADCipher{
			KeyBytes:        16,
			IVBytes:         16,
			AEADAuthCreator: createAesGcm,
		}, nil
	case CipherType_AES_256_GCM:
		return &AEADCipher{
			KeyBytes:        32,
			IVBytes:         32,
			AEADAuthCreator: createAesGcm,
		}, nil
	case CipherType_CHACHA20_POLY1305:
		return &AEADCipher{
			KeyBytes:        32,
			IVBytes:         32,
			AEADAuthCreator: createChaCha20Poly1305,
		}, nil
	case CipherType_XCHACHA20_POLY1305:
		return &AEADCipher{
			KeyBytes:        32,
			IVBytes:         32,
			AEADAuthCreator: createXChaCha20Poly1305,
		}, nil
	case CipherType_NONE:
		return &LegacyCipher{MethodName: "none"}, nil
	case CipherType_TABLE:
		return &LegacyCipher{MethodName: "table"}, nil
	case CipherType_RC4:
		return &LegacyCipher{MethodName: "rc4"}, nil
	case CipherType_RC4_MD5_6:
		return &LegacyCipher{MethodName: "rc4-md5-6"}, nil
	case CipherType_RC4_MD5:
		return &LegacyCipher{MethodName: "rc4-md5"}, nil
	case CipherType_AES_192_CFB:
		return &LegacyCipher{MethodName: "aes-192-cfb"}, nil
	case CipherType_AES_128_CTR:
		return &LegacyCipher{MethodName: "aes-128-ctr"}, nil
	case CipherType_AES_192_CTR:
		return &LegacyCipher{MethodName: "aes-192-ctr"}, nil
	case CipherType_AES_256_CTR:
		return &LegacyCipher{MethodName: "aes-256-ctr"}, nil
	case CipherType_BF_CFB:
		return &LegacyCipher{MethodName: "bf-cfb"}, nil
	case CipherType_CAMELLIA_128_CFB:
		return &LegacyCipher{MethodName: "camellia-128-cfb"}, nil
	case CipherType_CAMELLIA_192_CFB:
		return &LegacyCipher{MethodName: "camellia-192-cfb"}, nil
	case CipherType_CAMELLIA_256_CFB:
		return &LegacyCipher{MethodName: "camellia-256-cfb"}, nil
	case CipherType_CAST5_CFB:
		return &LegacyCipher{MethodName: "cast5-cfb"}, nil
	case CipherType_DES_CFB:
		return &LegacyCipher{MethodName: "des-cfb"}, nil
	case CipherType_IDEA_CFB:
		return &LegacyCipher{MethodName: "idea-cfb"}, nil
	case CipherType_RC2_CFB:
		return &LegacyCipher{MethodName: "rc2-cfb"}, nil
	case CipherType_SEED_CFB:
		return &LegacyCipher{MethodName: "seed-cfb"}, nil
	case CipherType_SALSA20:
		return &LegacyCipher{MethodName: "salsa20"}, nil
	default:
		return nil, errors.New("Unsupported cipher.")
	}
}

// AsAccount implements protocol.AsAccount.
func (a *Account) AsAccount() (protocol.Account, error) {
	accountCipher, err := a.getCipher()
	if err != nil {
		return nil, errors.New("failed to get cipher").Base(err)
	}
	var key []byte
	if legacyCipher, ok := accountCipher.(*LegacyCipher); ok {
		errors.PrintNonRemovalDeprecatedFeatureWarning(
			"Legacy Shadowsocks cipher "+legacyCipher.MethodName+" (compatibility only; cryptographically obsolete)",
			"Shadowsocks AEAD or a modern outbound protocol",
		)
		if err := legacyCipher.Initialize(a.Password); err != nil {
			return nil, errors.New("failed to initialize legacy cipher").Base(err)
		}
		key = legacyCipher.Core.Key()
	} else {
		key = passwordToCipherKey([]byte(a.Password), accountCipher.KeySize())
	}
	return &MemoryAccount{
		Cipher:     accountCipher,
		CipherType: a.CipherType,
		Key:        key,
		Password:   a.Password,
	}, nil
}

// Cipher is an interface for all Shadowsocks ciphers.
type Cipher interface {
	KeySize() int32
	IVSize() int32
	NewEncryptionWriter(key []byte, iv []byte, writer io.Writer) (buf.Writer, error)
	NewDecryptionReader(key []byte, iv []byte, reader io.Reader) (buf.Reader, error)
	IsAEAD() bool
	EncodePacket(key []byte, b *buf.Buffer) error
	DecodePacket(key []byte, b *buf.Buffer) error
}

// LegacyCipher adapts the shared legacy stream core to the Shadowsocks codec.
type LegacyCipher struct {
	MethodName string
	Core       *legacy.Cipher
}

func (c *LegacyCipher) Initialize(password string) error {
	core, err := legacy.New(c.MethodName, password)
	if err != nil {
		return err
	}
	c.Core = core
	return nil
}

func (c *LegacyCipher) method() (legacy.Method, error) {
	method, ok := legacy.Lookup(c.MethodName)
	if !ok {
		return legacy.Method{}, errors.New("unsupported legacy cipher: ", c.MethodName)
	}
	return method, nil
}

func (*LegacyCipher) IsAEAD() bool { return false }

func (c *LegacyCipher) KeySize() int32 {
	method, _ := c.method()
	return int32(method.KeySize)
}

func (c *LegacyCipher) IVSize() int32 {
	method, _ := c.method()
	return int32(method.IVSize)
}

func (c *LegacyCipher) initialized() error {
	if c.Core == nil {
		return errors.New("legacy cipher is not initialized")
	}
	return nil
}

func (c *LegacyCipher) NewEncryptionWriter(_ []byte, iv []byte, writer io.Writer) (buf.Writer, error) {
	if err := c.initialized(); err != nil {
		return nil, err
	}
	stream, err := c.Core.NewEncrypter(iv)
	if err != nil {
		return nil, err
	}
	return &buf.SequentialWriter{Writer: crypto.NewCryptionWriter(stream, writer)}, nil
}

func (c *LegacyCipher) NewDecryptionReader(_ []byte, iv []byte, reader io.Reader) (buf.Reader, error) {
	if err := c.initialized(); err != nil {
		return nil, err
	}
	stream, err := c.Core.NewDecrypter(iv)
	if err != nil {
		return nil, err
	}
	return &buf.SingleReader{Reader: crypto.NewCryptionReader(stream, reader)}, nil
}

func (c *LegacyCipher) EncodePacket(_ []byte, b *buf.Buffer) error {
	if err := c.initialized(); err != nil {
		return err
	}
	ivLen := c.IVSize()
	if b.Len() < ivLen {
		return errors.New("insufficient data for legacy cipher IV")
	}
	stream, err := c.Core.NewEncrypter(b.BytesTo(ivLen))
	if err != nil {
		return err
	}
	stream.XORKeyStream(b.BytesFrom(ivLen), b.BytesFrom(ivLen))
	return nil
}

func (c *LegacyCipher) DecodePacket(_ []byte, b *buf.Buffer) error {
	if err := c.initialized(); err != nil {
		return err
	}
	ivLen := c.IVSize()
	if b.Len() < ivLen {
		return errors.New("insufficient data for legacy cipher IV")
	}
	stream, err := c.Core.NewDecrypter(b.BytesTo(ivLen))
	if err != nil {
		return err
	}
	stream.XORKeyStream(b.BytesFrom(ivLen), b.BytesFrom(ivLen))
	b.Advance(ivLen)
	return nil
}

type AEADCipher struct {
	KeyBytes        int32
	IVBytes         int32
	AEADAuthCreator func(key []byte) cipher.AEAD
}

func (*AEADCipher) IsAEAD() bool {
	return true
}

func (c *AEADCipher) KeySize() int32 {
	return c.KeyBytes
}

func (c *AEADCipher) IVSize() int32 {
	return c.IVBytes
}

func (c *AEADCipher) createAuthenticator(key []byte, iv []byte) *crypto.AEADAuthenticator {
	subkey := make([]byte, c.KeyBytes)
	hkdfSHA1(key, iv, subkey)
	aead := c.AEADAuthCreator(subkey)
	nonce := crypto.GenerateAEADNonceWithSize(aead.NonceSize())
	return &crypto.AEADAuthenticator{
		AEAD:           aead,
		NonceGenerator: nonce,
	}
}

func (c *AEADCipher) NewEncryptionWriter(key []byte, iv []byte, writer io.Writer) (buf.Writer, error) {
	auth := c.createAuthenticator(key, iv)
	return crypto.NewAuthenticationWriter(auth, &crypto.AEADChunkSizeParser{
		Auth: auth,
	}, writer, protocol.TransferTypeStream, nil), nil
}

func (c *AEADCipher) NewDecryptionReader(key []byte, iv []byte, reader io.Reader) (buf.Reader, error) {
	auth := c.createAuthenticator(key, iv)
	return crypto.NewAuthenticationReader(auth, &crypto.AEADChunkSizeParser{
		Auth: auth,
	}, reader, protocol.TransferTypeStream, nil), nil
}

func (c *AEADCipher) EncodePacket(key []byte, b *buf.Buffer) error {
	ivLen := c.IVSize()
	payloadLen := b.Len()
	auth := c.createAuthenticator(key, b.BytesTo(ivLen))

	b.Extend(int32(auth.Overhead()))
	_, err := auth.Seal(b.BytesTo(ivLen), b.BytesRange(ivLen, payloadLen))
	return err
}

func (c *AEADCipher) DecodePacket(key []byte, b *buf.Buffer) error {
	if b.Len() <= c.IVSize() {
		return errors.New("insufficient data: ", b.Len())
	}
	ivLen := c.IVSize()
	payloadLen := b.Len()
	auth := c.createAuthenticator(key, b.BytesTo(ivLen))

	bbb, err := auth.Open(b.BytesTo(ivLen), b.BytesRange(ivLen, payloadLen))
	if err != nil {
		return err
	}
	b.Resize(ivLen, int32(len(bbb)))
	return nil
}

func passwordToCipherKey(password []byte, keySize int32) []byte {
	key := make([]byte, 0, keySize)

	md5Sum := md5.Sum(password)
	key = append(key, md5Sum[:]...)

	for int32(len(key)) < keySize {
		md5Hash := md5.New()
		common.Must2(md5Hash.Write(md5Sum[:]))
		common.Must2(md5Hash.Write(password))
		md5Hash.Sum(md5Sum[:0])

		key = append(key, md5Sum[:]...)
	}
	return key
}

func hkdfSHA1(secret, salt, outKey []byte) {
	r := hkdf.New(sha1.New, secret, salt, []byte("ss-subkey"))
	common.Must2(io.ReadFull(r, outKey))
}
