// https://github.com/shadowsocksr-backup/shadowsocks-rss/blob/master/doc/auth_chain_a.md

package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"sort"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/proxy/shadowsocks/legacy"
	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/ssr"
	"github.com/xtls/xray-core/proxy/shadowsocksr/internal/tools"
)

func init() {
	register("auth_chain_a", NewAuthChainA)
}

type authChainA struct {
	ssr.ServerInfo
	randomClient tools.Shift128plusContext
	randomServer tools.Shift128plusContext
	recvInfo
	encryptor      cipher.Stream
	decryptor      cipher.Stream
	hasSentHeader  bool
	lastClientHash []byte
	lastServerHash []byte
	userKey        []byte
	userKeyLen     int
	uid            [4]byte
	salt           string
	data           *AuthData
	hmac           hmacMethod
	hashDigest     hashDigestMethod
	rnd            rndMethod
	dataSizeList   []int
	dataSizeList2  []int
	chunkID        uint32
	akarin         bool
	akarinSpec     bool
	sendTCPMSS     int
	recvTCPMSS     int
	sendBackCmd    uint16
}

func NewAuthChainA() IProtocol {
	a := &authChainA{
		salt:       "auth_chain_a",
		hmac:       tools.HmacMD5,
		hashDigest: tools.SHA1Sum,
		rnd:        authChainAGetRandLen,
		recvInfo: recvInfo{
			recvID: 1,
			buffer: new(bytes.Buffer),
		},
	}
	return a
}

func (a *authChainA) SetServerInfo(s *ssr.ServerInfo) {
	a.ServerInfo = *s
	switch a.salt {
	case "auth_chain_b":
		a.authChainBInitDataSize()
	case "auth_akarin_spec_a":
		a.authChainBInitDataSize()
	case "auth_chain_c":
		a.authChainCInitDataSize(false, nil)
	case "auth_chain_d", "auth_chain_e":
		a.authChainCInitDataSize(true, nil)
	case "auth_chain_f":
		interval := int64(86400)
		if parts := strings.SplitN(a.Param, "#", 2); len(parts) == 2 {
			if n, err := strconv.ParseInt(parts[1], 10, 64); err == nil && n > 0 {
				interval = n
			}
		}
		epochKey := make([]byte, 8)
		binary.BigEndian.PutUint64(epochKey, uint64(ssr.NowUnix(&a.ServerInfo)/interval))
		a.authChainCInitDataSize(true, epochKey)
	}
}

func (a *authChainA) authChainCInitDataSize(patch bool, xorPrefix []byte) {
	key := append([]byte(nil), a.Key...)
	for i := 0; i < len(xorPrefix) && i < len(key); i++ {
		key[i] ^= xorPrefix[i]
	}
	var random tools.Shift128plusContext
	random.InitFromBin(key)
	length := int(random.Next()%24 + 12)
	a.dataSizeList = make([]int, length)
	for i := range a.dataSizeList {
		a.dataSizeList[i] = int(random.Next() % 2340 % 2040 % 1440)
	}
	sort.Ints(a.dataSizeList)
	if patch {
		for len(a.dataSizeList) < 64 && a.dataSizeList[len(a.dataSizeList)-1] < 1300 {
			a.dataSizeList = append(a.dataSizeList, int(random.Next()%2340%2040%1440))
		}
	}
	sort.Ints(a.dataSizeList)
}

func (a *authChainA) GetServerInfo() (s *ssr.ServerInfo) {
	return &a.ServerInfo
}

func (a *authChainA) SetData(data interface{}) {
	if auth, ok := data.(*AuthData); ok {
		a.data = auth
	}
}

func (a *authChainA) GetData() interface{} {
	if a.data == nil {
		a.data = &AuthData{}
	}
	return a.data
}

func authChainAGetRandLen(dataLength int, random *tools.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int {
	if dataLength > 1440 {
		return 0
	}
	random.InitFromBinDatalen(lastHash[:16], dataLength)
	if dataLength > 1300 {
		return int(random.Next() % 31)
	}
	if dataLength > 900 {
		return int(random.Next() % 127)
	}
	if dataLength > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}

func getRandStartPos(random *tools.Shift128plusContext, randLength int) int {
	if randLength > 0 {
		return int(random.Next() % 8589934609 % uint64(randLength))
	}
	return 0
}

func (a *authChainA) getClientRandLen(dataLength int, overhead int) int {
	if a.akarin {
		if a.akarinSpec {
			return akarinSpecRandLen(dataLength, &a.randomClient, a.lastClientHash, a.dataSizeList, a.dataSizeList2, overhead)
		}
		return akarinRandLen(dataLength, a.sendTCPMSS, &a.randomClient, a.lastClientHash, overhead)
	}
	return a.rnd(dataLength, &a.randomClient, a.lastClientHash, a.dataSizeList, a.dataSizeList2, overhead)
}

func (a *authChainA) getServerRandLen(dataLength int, overhead int) int {
	if a.akarin {
		if a.akarinSpec {
			return akarinSpecRandLen(dataLength, &a.randomServer, a.lastServerHash, a.dataSizeList, a.dataSizeList2, overhead)
		}
		return akarinRandLen(dataLength, a.recvTCPMSS, &a.randomServer, a.lastServerHash, overhead)
	}
	return a.rnd(dataLength, &a.randomServer, a.lastServerHash, a.dataSizeList, a.dataSizeList2, overhead)
}

func akarinRandLen(dataLength, tcpMSS int, random *tools.Shift128plusContext, lastHash []byte, overhead int) int {
	if tcpMSS <= 0 {
		tcpMSS = 2000
	}
	if dataLength+overhead > tcpMSS {
		random.InitFromBinDatalenWithLoop(lastHash[:16], dataLength, 0)
		return int(random.Next() % 521)
	}
	if dataLength >= 1440 || dataLength+overhead == tcpMSS {
		return 0
	}
	random.InitFromBinDatalenWithLoop(lastHash[:16], dataLength, 0)
	if dataLength > 1300 {
		return int(random.Next() % 31)
	}
	if dataLength > 900 {
		return int(random.Next() % 127)
	}
	if dataLength > 400 {
		return int(random.Next() % 521)
	}
	limit := tcpMSS - dataLength - overhead
	if limit <= 0 {
		return 0
	}
	return int(random.Next() % uint64(limit))
}

func akarinSpecRandLen(dataLength int, random *tools.Shift128plusContext, lastHash []byte, sizes, sizes2 []int, overhead int) int {
	if dataLength > 1440 {
		return 0
	}
	random.InitFromBinDatalenWithLoop(lastHash[:16], dataLength, 0)
	otherSize := dataLength + overhead
	pos := sort.Search(len(sizes), func(i int) bool { return sizes[i] >= otherSize })
	finalPos := pos + int(random.Next()%uint64(len(sizes)))
	if finalPos < len(sizes) {
		return sizes[finalPos] - otherSize
	}
	pos = sort.Search(len(sizes2), func(i int) bool { return sizes2[i] >= otherSize })
	finalPos = pos + int(random.Next()%uint64(len(sizes2)))
	if finalPos < len(sizes2) {
		return sizes2[finalPos] - otherSize
	}
	if finalPos < pos+len(sizes2)-1 {
		return 0
	}
	if dataLength > 1300 {
		return int(random.Next() % 31)
	}
	if dataLength > 900 {
		return int(random.Next() % 127)
	}
	if dataLength > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}

func (a *authChainA) packedDataLen(data []byte) (chunkLength, randLength int) {
	dataLength := len(data)
	commandLength := 0
	if a.akarin && a.sendBackCmd != 0 {
		commandLength = 2
	}
	randLength = a.getClientRandLen(dataLength+commandLength, a.Overhead)
	chunkLength = randLength + dataLength + commandLength + 2 + 2
	return
}

func (a *authChainA) packData(outData []byte, data []byte, randLength int) {
	dataLength := len(data)
	startPos := 2
	outLength := randLength + dataLength + 2
	if a.akarin && a.sendBackCmd != 0 {
		outLength += 2
		startPos = 4
		a.sendTCPMSS = a.recvTCPMSS
		outData[0] = byte(a.sendBackCmd) ^ a.lastClientHash[14]
		outData[1] = byte(a.sendBackCmd>>8) ^ a.lastClientHash[15]
		outData[2] = byte(dataLength) ^ a.lastClientHash[12]
		outData[3] = byte(dataLength>>8) ^ a.lastClientHash[13]
		a.sendBackCmd = 0
	} else {
		outData[0] = byte(dataLength) ^ a.lastClientHash[14]
		outData[1] = byte(dataLength>>8) ^ a.lastClientHash[15]
	}

	{
		if dataLength > 0 {
			randPart1Length := getRandStartPos(&a.randomClient, randLength)
			if a.akarin {
				randPart1Length = 0
			}
			ssr.ReadRandom(&a.ServerInfo, outData[startPos:startPos+randPart1Length])
			a.encryptor.XORKeyStream(outData[startPos+randPart1Length:startPos+randPart1Length+dataLength], data)
			ssr.ReadRandom(&a.ServerInfo, outData[startPos+randPart1Length+dataLength:outLength])
		} else {
			ssr.ReadRandom(&a.ServerInfo, outData[startPos:startPos+randLength])
		}
	}

	keyLen := a.userKeyLen + 4
	key := make([]byte, keyLen)
	copy(key, a.userKey)
	a.chunkID++
	binary.LittleEndian.PutUint32(key[a.userKeyLen:], a.chunkID)
	a.lastClientHash = a.hmac(key, outData[:outLength])
	copy(outData[outLength:], a.lastClientHash[:2])
	return
}

const authheadLength = 4 + 8 + 4 + 16 + 4

func (a *authChainA) packAuthData(data []byte) (outData []byte) {
	outData = make([]byte, authheadLength, authheadLength+1500)
	a.data.connectionID++
	if a.data.connectionID > 0xFF000000 || a.data.clientID == nil {
		a.data.clientID = make([]byte, 4)
		ssr.ReadRandom(&a.ServerInfo, a.data.clientID)
		b := make([]byte, 4)
		ssr.ReadRandom(&a.ServerInfo, b)
		a.data.connectionID = binary.LittleEndian.Uint32(b) & 0xFFFFFF
	}
	key := make([]byte, a.IVLen+a.KeyLen)
	copy(key, a.IV)
	copy(key[a.IVLen:], a.Key)

	encrypt := make([]byte, 20)
	t := ssr.NowUnix(&a.ServerInfo)
	binary.LittleEndian.PutUint32(encrypt[:4], uint32(t))
	copy(encrypt[4:8], a.data.clientID)
	binary.LittleEndian.PutUint32(encrypt[8:], a.data.connectionID)
	binary.LittleEndian.PutUint16(encrypt[12:], uint16(a.Overhead))
	if a.akarin {
		a.sendTCPMSS = 1024
		a.recvTCPMSS = 1024
		binary.LittleEndian.PutUint16(encrypt[14:16], uint16(a.sendTCPMSS))
	} else {
		binary.LittleEndian.PutUint16(encrypt[14:16], 0)
	}

	// first 12 bytes
	{
		ssr.ReadRandom(&a.ServerInfo, outData[:4])
		a.lastClientHash = a.hmac(key, outData[:4])
		copy(outData[4:], a.lastClientHash[:8])
	}
	var base64UserKey string
	// uid & 16 bytes auth data
	{
		uid := make([]byte, 4)
		if a.userKey == nil {
			params := strings.SplitN(a.ServerInfo.Param, ":", 2)
			if len(params) >= 2 {
				if userID, err := strconv.Atoi(params[0]); err == nil {
					binary.LittleEndian.PutUint32(a.uid[:], uint32(userID))
					a.userKeyLen = len(params[1])
					a.userKey = []byte(params[1])
				}
			}
			if a.userKey == nil {
				ssr.ReadRandom(&a.ServerInfo, a.uid[:])

				a.userKeyLen = a.KeyLen
				a.userKey = make([]byte, a.KeyLen)
				copy(a.userKey, a.Key)
			}
		}
		for i := 0; i < 4; i++ {
			uid[i] = a.uid[i] ^ a.lastClientHash[8+i]
		}
		base64UserKey = base64.StdEncoding.EncodeToString(a.userKey)
		aesCipherKey := tools.EVPBytesToKey(base64UserKey+a.salt, 16)
		block, err := aes.NewCipher(aesCipherKey)
		if err != nil {
			return
		}
		encryptData := make([]byte, 16)
		iv := make([]byte, aes.BlockSize)
		cbc := cipher.NewCBCEncrypter(block, iv)
		cbc.CryptBlocks(encryptData, encrypt[:16])
		copy(encrypt[:4], uid[:])
		copy(encrypt[4:4+16], encryptData)
	}
	// final HMAC
	{
		a.lastServerHash = a.hmac(a.userKey, encrypt[0:20])

		copy(outData[12:], encrypt)
		copy(outData[12+20:], a.lastServerHash[:4])
	}

	// init cipher
	password := make([]byte, len(base64UserKey)+base64.StdEncoding.EncodedLen(16))
	copy(password, base64UserKey)
	base64.StdEncoding.Encode(password[len(base64UserKey):], a.lastClientHash[:16])
	innerMethod := "rc4"
	var innerIV []byte
	if a.akarin {
		innerMethod = "chacha20"
		innerIV = a.lastClientHash[:8]
	}
	innerCipher, err := legacy.New(innerMethod, string(password))
	if err != nil {
		return nil
	}
	a.encryptor, err = innerCipher.NewEncrypter(innerIV)
	if err != nil {
		return nil
	}
	if a.akarin {
		innerIV = a.lastServerHash[:8]
	}
	a.decryptor, err = innerCipher.NewDecrypter(innerIV)
	if err != nil {
		return nil
	}

	// data
	chunkLength, randLength := a.packedDataLen(data)
	if authheadLength+chunkLength <= cap(outData) {
		outData = outData[:authheadLength+chunkLength]
	} else {
		newOutData := make([]byte, authheadLength+chunkLength)
		copy(newOutData, outData[:authheadLength])
		outData = newOutData
	}
	a.packData(outData[authheadLength:], data, randLength)
	return outData
}

func (a *authChainA) PreEncrypt(plainData []byte) (outData []byte, err error) {
	a.buffer.Reset()
	dataLength := len(plainData)
	offset := 0
	if dataLength > 0 && !a.hasSentHeader {
		headSize := 1200
		if headSize > dataLength {
			headSize = dataLength
		}
		a.buffer.Write(a.packAuthData(plainData[:headSize]))
		offset += headSize
		dataLength -= headSize
		a.hasSentHeader = true
	}
	unitSize := a.TcpMss - a.Overhead
	for dataLength > unitSize {
		dataLen, randLength := a.packedDataLen(plainData[offset : offset+unitSize])
		b := make([]byte, dataLen)
		a.packData(b, plainData[offset:offset+unitSize], randLength)
		a.buffer.Write(b)
		dataLength -= unitSize
		offset += unitSize
	}
	if dataLength > 0 {
		dataLen, randLength := a.packedDataLen(plainData[offset:])
		b := make([]byte, dataLen)
		a.packData(b, plainData[offset:], randLength)
		a.buffer.Write(b)
	}
	if a.akarin && a.hasSentHeader && a.sendBackCmd != 0 && dataLength == 0 {
		dataLen, randLength := a.packedDataLen(nil)
		b := make([]byte, dataLen)
		a.packData(b, nil, randLength)
		a.buffer.Write(b)
	}
	return a.buffer.Bytes(), nil
}

func (a *authChainA) PostDecrypt(plainData []byte) (outData []byte, n int, err error) {
	a.buffer.Reset()
	key := make([]byte, len(a.userKey)+4)
	readlenth := 0
	copy(key, a.userKey)
	for len(plainData) > 4 {
		binary.LittleEndian.PutUint32(key[len(a.userKey):], a.recvID)
		dataLen := int((uint(plainData[1]^a.lastServerHash[15]) << 8) + uint(plainData[0]^a.lastServerHash[14]))
		randLen := a.getServerRandLen(dataLen, a.Overhead)
		length := randLen + dataLen
		if length >= 4096 {
			return nil, 0, ssr.ErrAuthChainDataLengthError
		}
		length += 4
		if length > len(plainData) {
			break
		}

		hash := a.hmac(key, plainData[:length-2])
		if !bytes.Equal(hash[:2], plainData[length-2:length]) {
			return nil, 0, ssr.ErrAuthChainIncorrectHMAC
		}
		var dataPos int
		if dataLen > 0 && randLen > 0 && !a.akarin {
			dataPos = 2 + getRandStartPos(&a.randomServer, randLen)
		} else {
			dataPos = 2
		}
		b := make([]byte, dataLen)
		a.decryptor.XORKeyStream(b, plainData[dataPos:dataPos+dataLen])
		a.buffer.Write(b)
		if a.recvID == 1 {
			mss := int(binary.LittleEndian.Uint16(a.buffer.Next(2)))
			a.TcpMss = mss
			if a.akarin {
				a.recvTCPMSS = mss
				a.sendBackCmd = 0xff00
			}
		}
		a.lastServerHash = hash
		a.recvID++
		plainData = plainData[length:]
		readlenth += length

	}
	return a.buffer.Bytes(), readlenth, nil
}

func (a *authChainA) GetOverhead() int {
	return 4
}

func (a *authChainA) initUDPUser() {
	if a.userKey != nil {
		return
	}
	if params := strings.SplitN(a.Param, ":", 2); len(params) == 2 {
		if userID, err := strconv.ParseUint(params[0], 10, 32); err == nil {
			binary.LittleEndian.PutUint32(a.uid[:], uint32(userID))
			a.userKey = []byte(params[1])
			a.userKeyLen = len(a.userKey)
		}
	}
	if a.userKey == nil {
		ssr.ReadRandom(&a.ServerInfo, a.uid[:])
		a.userKey = append([]byte(nil), a.Key...)
		a.userKeyLen = len(a.userKey)
	}
}

func (a *authChainA) udpRandLen(hash []byte, random *tools.Shift128plusContext) int {
	random.InitFromBin(hash)
	return int(random.Next() % 127)
}

func (a *authChainA) UDPPreEncrypt(data []byte) ([]byte, error) {
	a.initUDPUser()
	authData := make([]byte, 3)
	ssr.ReadRandom(&a.ServerInfo, authData)
	digest := a.hmac(a.Key, authData)
	randLen := a.udpRandLen(digest, &a.randomClient)
	password := base64.StdEncoding.EncodeToString(a.userKey) + base64.StdEncoding.EncodeToString(digest)
	innerMethod := "rc4"
	var iv []byte
	if a.akarin {
		innerMethod = "chacha20"
		iv = a.Key[:8]
	}
	inner, err := legacy.New(innerMethod, password)
	if err != nil {
		return nil, err
	}
	stream, err := inner.NewEncrypter(iv)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data), len(data)+randLen+8)
	stream.XORKeyStream(out, data)
	padding := make([]byte, randLen)
	ssr.ReadRandom(&a.ServerInfo, padding)
	out = append(out, padding...)
	out = append(out, authData...)
	maskedUID := binary.LittleEndian.Uint32(a.uid[:]) ^ binary.LittleEndian.Uint32(digest[:4])
	var uid [4]byte
	binary.LittleEndian.PutUint32(uid[:], maskedUID)
	out = append(out, uid[:]...)
	out = append(out, a.hmac(a.userKey, out)[0])
	return out, nil
}

func (a *authChainA) UDPPostDecrypt(data []byte) ([]byte, error) {
	a.initUDPUser()
	if len(data) <= 8 || !bytes.Equal(a.hmac(a.userKey, data[:len(data)-1])[:1], data[len(data)-1:]) {
		return nil, ssr.ErrAuthChainIncorrectHMAC
	}
	digest := a.hmac(a.Key, data[len(data)-8:len(data)-1])
	randLen := a.udpRandLen(digest, &a.randomServer)
	payloadLen := len(data) - 8 - randLen
	if payloadLen < 0 {
		return nil, ssr.ErrAuthChainDataLengthError
	}
	password := base64.StdEncoding.EncodeToString(a.userKey) + base64.StdEncoding.EncodeToString(digest)
	innerMethod := "rc4"
	var iv []byte
	if a.akarin {
		innerMethod = "chacha20"
		iv = a.Key[:8]
	}
	inner, err := legacy.New(innerMethod, password)
	if err != nil {
		return nil, err
	}
	stream, err := inner.NewDecrypter(iv)
	if err != nil {
		return nil, err
	}
	out := make([]byte, payloadLen)
	stream.XORKeyStream(out, data[:payloadLen])
	return out, nil
}
