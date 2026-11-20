//go:build !windows

package egress

func platformSupported() bool { return false }

func collect(Options) (Observation, error) {
	return Observation{Unsupported: "automatic per-family egress selection is only available on Windows"}, nil
}

func registerNotifications(func()) (func(), error) {
	return func() {}, nil
}
