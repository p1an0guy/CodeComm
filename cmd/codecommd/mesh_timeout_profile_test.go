package main

import (
	"fmt"
	"os"
	"testing"
	"time"
)

const (
	daemonMeshTimeoutProfileEnvironment  = "CODECOMM_TEST_TIMEOUT_PROFILE"
	daemonMeshTimeoutProfileInstrumented = "instrumented"
	daemonMeshChildWatchdogLead          = 30 * time.Second
)

type daemonMeshTimeoutProfile struct {
	convergence   time.Duration
	genericChild  time.Duration
	snapshotChild time.Duration
}

var daemonMeshTimeouts = mustDaemonMeshTimeoutProfile()

func mustDaemonMeshTimeoutProfile() daemonMeshTimeoutProfile {
	profile, err := newDaemonMeshTimeoutProfile(
		os.Getenv(daemonMeshTimeoutProfileEnvironment),
	)
	if err != nil {
		panic(err)
	}
	return profile
}

func newDaemonMeshTimeoutProfile(
	name string,
) (daemonMeshTimeoutProfile, error) {
	switch name {
	case "":
		return daemonMeshTimeoutProfile{
			convergence:   90 * time.Second,
			genericChild:  5 * time.Minute,
			snapshotChild: 10 * time.Minute,
		}, nil
	case daemonMeshTimeoutProfileInstrumented:
		return daemonMeshTimeoutProfile{
			convergence:   270 * time.Second,
			genericChild:  15 * time.Minute,
			snapshotChild: 30 * time.Minute,
		}, nil
	default:
		return daemonMeshTimeoutProfile{}, fmt.Errorf(
			"unsupported %s value %q",
			daemonMeshTimeoutProfileEnvironment,
			name,
		)
	}
}

func daemonMeshChildWatchdogArgument(processTimeout time.Duration) string {
	if processTimeout <= daemonMeshChildWatchdogLead {
		panic("daemon mesh child timeout does not leave a watchdog lead")
	}
	return "-test.timeout=" +
		(processTimeout - daemonMeshChildWatchdogLead).String()
}

func TestDaemonMeshTimeoutProfiles(t *testing.T) {
	tests := []struct {
		name string
		want daemonMeshTimeoutProfile
	}{
		{
			want: daemonMeshTimeoutProfile{
				convergence:   90 * time.Second,
				genericChild:  5 * time.Minute,
				snapshotChild: 10 * time.Minute,
			},
		},
		{
			name: daemonMeshTimeoutProfileInstrumented,
			want: daemonMeshTimeoutProfile{
				convergence:   270 * time.Second,
				genericChild:  15 * time.Minute,
				snapshotChild: 30 * time.Minute,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := newDaemonMeshTimeoutProfile(test.name)
			if err != nil {
				t.Fatalf("newDaemonMeshTimeoutProfile(): %v", err)
			}
			if got != test.want {
				t.Fatalf("timeout profile = %+v, want %+v", got, test.want)
			}
		})
	}
	if _, err := newDaemonMeshTimeoutProfile("slow"); err == nil {
		t.Fatal("unknown timeout profile was accepted")
	}
	if got := daemonMeshChildWatchdogArgument(5 * time.Minute); got !=
		"-test.timeout=4m30s" {
		t.Fatalf("child watchdog argument = %q", got)
	}
}
