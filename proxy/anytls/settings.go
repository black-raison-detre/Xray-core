package anytls

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/core"
)

func parseSettings(data []byte) (map[string]string, error) {
	m := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		p := strings.SplitN(line, "=", 2)
		if len(p) != 2 || p[0] == "" || p[1] == "" {
			return nil, ErrMalformedFrame
		}
		if _, ok := m[p[0]]; ok {
			return nil, ErrMalformedFrame
		}
		m[p[0]] = p[1]
	}
	return m, nil
}

func clientSettings(p *PaddingFactory) []byte {
	return []byte("v=2\nclient=xray-core/" + core.Version() + "\npadding-md5=" + p.MD5())
}

func validateClientSettings(data []byte) (map[string]string, error) {
	m, e := parseSettings(data)
	if e != nil {
		return nil, e
	}
	v, e := strconv.Atoi(m["v"])
	md5Value, md5Err := hex.DecodeString(m["padding-md5"])
	if e != nil || (v != 1 && v != 2) || m["client"] == "" || md5Err != nil || len(md5Value) != 16 {
		return nil, errors.New("anytls: invalid client settings")
	}
	return m, nil
}
