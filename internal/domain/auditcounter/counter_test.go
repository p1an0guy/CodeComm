package auditcounter

import (
	"errors"
	"strings"
	"testing"

	"github.com/ijonahch/codecomm/internal/domain"
)

func TestCounterValidate(t *testing.T) {
	t.Parallel()

	valid := Counter{
		DeviceID:        domain.DeviceID("cc1" + strings.Repeat("1", 64)),
		CredentialEpoch: domain.MaxSafeInteger,
		AcceptedCount:   MaxAcceptedCount,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Counter.Validate() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Counter)
		want   error
	}{
		{
			name: "device",
			mutate: func(value *Counter) {
				value.DeviceID = ""
			},
			want: ErrInvalidDeviceID,
		},
		{
			name: "epoch",
			mutate: func(value *Counter) {
				value.CredentialEpoch = domain.MaxSafeInteger + 1
			},
			want: ErrInvalidCredentialEpoch,
		},
		{
			name: "count",
			mutate: func(value *Counter) {
				value.AcceptedCount = MaxAcceptedCount + 1
			},
			want: ErrInvalidAcceptedCount,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			value := valid
			test.mutate(&value)
			if err := value.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Counter.Validate() error = %v, want %v", err, test.want)
			}
		})
	}
}
