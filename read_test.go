/* go-pass
 *
 * Copyright (C) 2018  Franklin "Snaipe" Mathieu <me@snai.pe>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package pass

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/kr/pty"
)

func CheckPass(t *testing.T, r io.Reader, expected string) {
	var out [256]byte

	l, err := ReadTo(r, out[:])
	if err != nil {
		t.Fatal(err)
	}

	if l != len(expected) {
		t.Fatalf("Expected a password of length %v, got %v.", len(expected), l)
	}

	if expected != string(out[:l]) {
		t.Fatalf("Expected '%v', got '%v'.", expected, string(out[:l]))
	}
}

func CheckReadErr(t *testing.T, r io.Reader, expected error) {
	var out [256]byte

	_, err := ReadTo(r, out[:])
	if err != expected {
		t.Fatalf("Expected '%v', got '%v'.", expected, err)
	}
}

func TestRead(t *testing.T) {
	const pass = "this is a password"

	CheckPass(t, strings.NewReader(pass), pass)
}

type FakeTTY struct {
	*os.File
	pty *os.File
	r   io.Reader
}

func NewFakeTTY(r io.Reader) FakeTTY {
	p, t, err := pty.Open()
	if err != nil {
		panic(err)
	}
	return FakeTTY{t, p, r}
}

func (f FakeTTY) Read(b []byte) (int, error) {
	return f.r.Read(b)
}

func (f FakeTTY) Write(b []byte) (int, error) {
	panic("unsupported")
}

func (f FakeTTY) Close() (error) {
	f.File.Close()
	f.pty.Close()
	return nil
}

func TestControlChars(t *testing.T) {

	tty := NewFakeTTY(strings.NewReader("bad\b\b\bgood password"))
	defer tty.Close()

	CheckPass(t, tty, "good password")

	tty = NewFakeTTY(strings.NewReader("pass\x03word"))
	defer tty.Close()

	CheckReadErr(t, tty, ErrInterrupted)

	tty = NewFakeTTY(strings.NewReader("pass\x04word"))
	defer tty.Close()

	CheckPass(t, tty, "pass")

}
