package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	transporttls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

func TestTLSAllowInsecure(t *testing.T) {
	parser := func(input string) (proto.Message, error) {
		config := new(TLSConfig)
		if err := json.Unmarshal([]byte(input), config); err != nil {
			return nil, err
		}
		return config.Build()
	}
	runMultiTestCase(t, []TestCase{
		{
			Input:  `{"allowInsecure":true,"serverName":"example.com"}`,
			Parser: parser,
			Output: &transporttls.Config{AllowInsecure: true, ServerName: "example.com"},
		},
		{
			Input:  `{}`,
			Parser: parser,
			Output: &transporttls.Config{},
		},
	})
}
