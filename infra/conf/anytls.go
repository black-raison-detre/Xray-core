package conf

import (
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"
	"github.com/xtls/xray-core/proxy/anytls"
	"google.golang.org/protobuf/proto"
)

// AnyTLSUserConfig is a user accepted by an AnyTLS inbound.
type AnyTLSUserConfig struct {
	Password string `json:"password"`
	Email    string `json:"email"`
	Level    uint32 `json:"level"`
}

// AnyTLSServerConfig is configuration for an AnyTLS inbound.
type AnyTLSServerConfig struct {
	Users         []*AnyTLSUserConfig `json:"users"`
	Clients       []*AnyTLSUserConfig `json:"clients"`
	PaddingScheme string              `json:"paddingScheme"`
}

// Build implements Buildable.
func (c *AnyTLSServerConfig) Build() (proto.Message, error) {
	if c.Clients != nil && c.Users != nil {
		return nil, errors.New("AnyTLS inbound cannot specify both users and clients")
	}
	if c.Clients != nil {
		c.Users = c.Clients
	}

	if len(c.Users) == 0 {
		return nil, errors.New("AnyTLS inbound requires at least one user")
	}
	if c.PaddingScheme != "" {
		if _, err := anytls.NewPaddingFactory([]byte(c.PaddingScheme)); err != nil {
			return nil, errors.New("AnyTLS paddingScheme is invalid").Base(err)
		}
	}
	passwords := make(map[string]struct{}, len(c.Users))
	emails := make(map[string]struct{}, len(c.Users))
	config := &anytls.ServerConfig{
		Users:         make([]*protocol.User, len(c.Users)),
		PaddingScheme: c.PaddingScheme,
	}
	for i, user := range c.Users {
		if user.Password == "" {
			return nil, errors.New("AnyTLS users: password is not specified")
		}
		if _, found := passwords[user.Password]; found {
			return nil, errors.New("AnyTLS users: duplicate password")
		}
		passwords[user.Password] = struct{}{}
		if user.Email != "" {
			email := strings.ToLower(user.Email)
			if _, found := emails[email]; found {
				return nil, errors.New("AnyTLS users: duplicate email")
			}
			emails[email] = struct{}{}
		}
		config.Users[i] = &protocol.User{
			Level: user.Level,
			Email: user.Email,
			Account: serial.ToTypedMessage(&anytls.Account{
				Password: user.Password,
			}),
		}
	}
	return config, nil
}

// AnyTLSClientConfig is configuration for an AnyTLS outbound.
type AnyTLSClientConfig struct {
	Address                  *Address          `json:"address"`
	Port                     uint16            `json:"port"`
	Password                 string            `json:"password"`
	Email                    string            `json:"email"`
	Level                    uint32            `json:"level"`
	IdleSessionCheckInterval duration.Duration `json:"idleSessionCheckInterval"`
	IdleSessionTimeout       duration.Duration `json:"idleSessionTimeout"`
	MinIdleSession           *uint32           `json:"minIdleSession"`
	DisableSessionReuse      bool              `json:"disableSessionReuse"`
}

// Build implements Buildable.
func (c *AnyTLSClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("AnyTLS server address is not set")
	}
	if c.Port == 0 {
		return nil, errors.New("AnyTLS server port is not set")
	}
	if c.Password == "" {
		return nil, errors.New("AnyTLS password is not specified")
	}

	checkInterval := time.Duration(c.IdleSessionCheckInterval)
	if checkInterval == 0 {
		checkInterval = 30 * time.Second
	}
	timeout := time.Duration(c.IdleSessionTimeout)
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if checkInterval <= 5*time.Second {
		return nil, errors.New("AnyTLS idleSessionCheckInterval must be greater than 5s")
	}
	if timeout <= 5*time.Second {
		return nil, errors.New("AnyTLS idleSessionTimeout must be greater than 5s")
	}

	minIdleSession := uint32(5)
	if c.MinIdleSession != nil {
		minIdleSession = *c.MinIdleSession
	}
	return &anytls.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
			User: &protocol.User{
				Level: c.Level,
				Email: c.Email,
				Account: serial.ToTypedMessage(&anytls.Account{
					Password: c.Password,
				}),
			},
		},
		IdleSessionCheckInterval: int64(checkInterval),
		IdleSessionTimeout:       int64(timeout),
		MinIdleSession:           &minIdleSession,
		DisableSessionReuse:      c.DisableSessionReuse,
	}, nil
}
