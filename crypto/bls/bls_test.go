package bls

import "testing"

func TestBLS(t *testing.T) {
	t.Run("test", func(t *testing.T) {
		err:= blsTest()
		if err != nil {
			t.Fatal("fatal")
		}
	})
}
