package securitypack

import (
	"bytes"
	"reflect"
	"testing"
)

func FuzzPackDecode(f *testing.F) {
	in := validPackInput()
	in.Sources = nil
	pack, err := newPack(in, nil)
	if err != nil {
		f.Fatal(err)
	}
	seed, err := Encode(pack)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("{}\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		// Dedicated boundary tests cover the full 16 MiB input cap; keep
		// fuzz mutations small enough for sustained sampling.
		if len(input) > 64<<10 {
			t.Skip()
		}
		pack, reading, err := Decode(input, nil)
		if err != nil {
			if !reflect.DeepEqual(pack, EvidencePack{}) || reading != (Reading{}) {
				t.Fatal("error returned partial data")
			}
			return
		}
		encoded, err := Encode(pack)
		if err != nil || !bytes.Equal(encoded, input) {
			t.Fatal("accepted input is not canonical")
		}
	})
}
