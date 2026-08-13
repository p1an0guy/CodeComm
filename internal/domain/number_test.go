package domain

import "testing"

func TestSafeIntegerBounds(t *testing.T) {
	t.Parallel()

	if MaxSafeInteger != 9_007_199_254_740_991 {
		t.Fatalf("MaxSafeInteger = %d", MaxSafeInteger)
	}
	if !ValidUnsignedInteger(0) || !ValidUnsignedInteger(MaxSafeInteger) {
		t.Fatal("ValidUnsignedInteger rejected an inclusive boundary")
	}
	if ValidUnsignedInteger(MaxSafeInteger + 1) {
		t.Fatal("ValidUnsignedInteger accepted one past MaxSafeInteger")
	}
}
