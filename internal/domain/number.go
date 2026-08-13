package domain

// MaxSafeInteger is the inclusive signed-JSON integer limit imposed by the
// protocol's RFC 8785 number profile.
const MaxSafeInteger = 1<<53 - 1

// MaxApplyLevel is the inclusive protocol capability/version ceiling.
const MaxApplyLevel = 1<<31 - 1

// ValidUnsignedInteger reports whether value can be represented by a
// CodeComm signed JSON integer without precision loss.
func ValidUnsignedInteger(value uint64) bool {
	return value <= MaxSafeInteger
}
