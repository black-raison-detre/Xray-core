package shadowsocksr

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/shadowsocks/legacy"
	ssrprotocol "github.com/xtls/xray-core/proxy/shadowsocksr/internal/protocol"
	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/ssr"
)

func TestAuthAESUDPReplyUsesServerKey(t *testing.T) {
	// The reference SSR server signs replies with server_info.key, even when
	// requests authenticate a uid:password with a separate per-user key.
	// https://github.com/shadowsocksrr/shadowsocksr/blob/manyuser/shadowsocks/obfsplugin/auth.py
	for _, protocol := range []struct {
		name string
		hash func() hash.Hash
	}{
		{"auth_aes128_md5", md5.New},
		{"auth_aes128_sha1", sha1.New},
	} {
		for _, userParam := range []bool{false, true} {
			name := protocol.name + "/server-key"
			if userParam {
				name = protocol.name + "/user-key"
			}
			t.Run(name, func(t *testing.T) {
				cipher, err := legacy.New("chacha20-ietf", "fixture-server-password")
				if err != nil {
					t.Fatal(err)
				}
				info := &ssr.ServerInfo{Key: cipher.Key(), KeyLen: len(cipher.Key())}
				requestKey := cipher.Key()
				if userParam {
					info.Param = "448:fixture-user-password"
					digest := protocol.hash()
					digest.Write([]byte("fixture-user-password"))
					requestKey = digest.Sum(nil)
				}
				p := ssrprotocol.NewProtocol(protocol.name)
				p.SetServerInfo(info)
				codec := &udpCodec{account: &MemoryAccount{Cipher: cipher}, protocol: p}
				dest := xnet.UDPDestination(xnet.IPAddress([]byte{8, 8, 8, 8}), 53)
				payload := []byte("fixture DNS datagram")
				request, err := codec.encode(dest, payload)
				if err != nil {
					t.Fatal(err)
				}
				plain, err := cipher.DecryptPacket(request)
				if err != nil {
					t.Fatal(err)
				}
				sign := func(key, body []byte) []byte {
					mac := hmac.New(protocol.hash, key)
					mac.Write(body)
					return mac.Sum(nil)[:4]
				}
				if len(plain) < 8 || !hmac.Equal(plain[len(plain)-4:], sign(requestKey, plain[:len(plain)-4])) {
					t.Fatal("request is not signed with the expected request key")
				}
				if userParam && binary.LittleEndian.Uint32(plain[len(plain)-8:len(plain)-4]) != 448 {
					t.Fatal("request is missing the configured user ID")
				}
				header, err := encodeAddress(dest)
				if err != nil {
					t.Fatal(err)
				}
				body := append(header, payload...)
				checkReply := func(key []byte, wantValid bool) {
					t.Helper()
					packet, err := cipher.EncryptPacket(append(append([]byte(nil), body...), sign(key, body)...))
					if err != nil {
						t.Fatal(err)
					}
					gotDest, got, err := codec.decode(packet)
					if !wantValid {
						if err == nil {
							t.Fatal("accepted reply signed with the wrong key")
						}
						return
					}
					if err != nil || gotDest.String() != dest.String() || !bytes.Equal(got, payload) {
						t.Fatalf("server-key reply rejected: destination=%v payload=%x err=%v", gotDest, got, err)
					}
				}
				checkReply(cipher.Key(), true)
				checkReply([]byte("wrong-server-key"), false)
				if userParam {
					checkReply(requestKey, false)
				}
			})
		}
	}
}
