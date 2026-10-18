package anytls

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
)

func TestAuthPreface(t *testing.T) {
	a := NewMemoryAccount("secret")
	var b bytes.Buffer
	if e := WriteAuthPreface(&b, a, 30); e != nil {
		t.Fatal(e)
	}
	v := new(Validator)
	if err := v.Add(&protocol.MemoryUser{Email: "user", Account: a}); err != nil {
		t.Fatal(err)
	}
	got, e := ReadAuthPreface(&b, v)
	if e != nil || got.Account != a || b.Len() != 0 {
		t.Fatalf("got %v %v remaining=%d", got, e, b.Len())
	}
}

func TestPaddingScheme(t *testing.T) {
	p, e := NewPaddingFactory([]byte(DefaultPaddingScheme))
	if e != nil {
		t.Fatal(e)
	}
	if p.Stop() != 8 || len(p.RecordSizes(2)) != 9 || p.MD5() == "" {
		t.Fatal("default scheme did not parse")
	}
}
