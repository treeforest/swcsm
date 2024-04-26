package swcsm

import (
	"bytes"
	"encoding/gob"
)

func GobEncode(o any) ([]byte, error) {
	w := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(w)
	if err := enc.Encode(o); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func GobDecode(b []byte, o any) error {
	dec := gob.NewDecoder(bytes.NewReader(b))
	return dec.Decode(o)
}
