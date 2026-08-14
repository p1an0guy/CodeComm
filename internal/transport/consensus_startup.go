package transport

import (
	"errors"
	"os"
	"strings"
)

var (
	ErrExtendedConnectStartup = errors.New(
		"transport: RFC 8441 requires GODEBUG=http2xconnect=1 at process startup",
	)

	extendedConnectEnabledAtStartup = godebugSettingEnabled(
		os.Getenv("GODEBUG"),
		"http2xconnect",
	)
)

func requireExtendedConnectStartup() error {
	if !extendedConnectEnabledAtStartup {
		return ErrExtendedConnectStartup
	}
	return nil
}

func godebugSettingEnabled(settings string, name string) bool {
	enabled := false
	for _, setting := range strings.Split(settings, ",") {
		key, value, found := strings.Cut(setting, "=")
		if found && key == name {
			enabled = value == "1"
		}
	}
	return enabled
}
