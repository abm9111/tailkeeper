package privacy

import "encoding/hex"

// Derived returns the pseudonym key and the digest key that Parse derives from
// master (64 hexadecimal characters), for tests that check neither is ever
// printed. A Key holds them in no field a test could read.
func Derived(master string) [][]byte {
	b, err := hex.DecodeString(master)
	if err != nil {
		panic(err)
	}
	return [][]byte{derive(b, pseudonymLabel), derive(b, digestLabel)}
}
