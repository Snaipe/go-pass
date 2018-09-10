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
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

// Read reads a password from the passed reader until a newline or EOF is
// reached, and returns it in a secure buffer without the newline.
//
// If the reader is backed by a TTY, the following control characters are
// supported:
//
//   - Backspace (\b) and Delete (DEL) removes the last character from
//     the current input
//   - ^C (ETX) interrupts the input, and ErrInterrupted is returned
//   - ^D (EOT) acts like EOF.
//
// The maximum size of a password is one page, usually 4096 bytes.
func Read(rd io.Reader) (Password, error) {
	return ReadSize(rd, 0)
}

// ReadSize behaves like Read, except that the secure buffer is allocated with
// the specified size.
//
// If the size is zero, the allocated size will be one page, usually 4096 bytes.
func ReadSize(rd io.Reader, size int) (Password, error) {
	if size == 0 {
		size = os.Getpagesize()
	}

	pass, err := makePasswd(size)
	if err != nil {
		return nil, err
	}

	l, err := ReadTo(rd, pass)
	if err != nil {
		pass.Free()
		return nil, err
	}

	return pass[:l], nil
}

var (
	backspace = errors.New("backspace")

	// ErrInterrupted is returned when the password input has been interrupted
	// by ^C.
	ErrInterrupted = errors.New("Input interrupted")
)

const (
	asciiDEL = '\x7f' // Delete
	asciiETX = '\x03' // ^C
	asciiEOT = '\x04' // ^D
)

type fdBacked interface {
	Fd() uintptr
}

func getchTTY(out []byte, rd io.Reader) error {
	_, err := rd.Read(out)
	if err != nil {
		return err
	}
	switch out[0] {
	case asciiETX:
		return ErrInterrupted
	case '\b', asciiDEL:
		return backspace
	case asciiEOT, '\n', '\r':
		return io.EOF
	}
	return nil
}

func getchNormal(out []byte, rd io.Reader) error {
	_, err := rd.Read(out)
	if err != nil {
		return err
	}
	switch out[0] {
	case asciiEOT, '\n', '\r':
		return io.EOF
	}
	return nil
}

// ReadTo behaves like Read, except that the password is written to `out`
// rather than in an allocated secure buffer, and returns the number of
// bytes written to out.
//
// The byte count is returned even if an error occured.
//
// At most `len(out)` bytes are consumed from the reader and written to `out`.
// Consumers of this function should make sure that a slice of sufficient size
// is passed.
func ReadTo(rd io.Reader, out []byte) (int, error) {
	getch := getchNormal

	if rd, ok := rd.(fdBacked); ok && terminal.IsTerminal(int(rd.Fd())) {
		state, err := terminal.MakeRaw(int(rd.Fd()))
		if err != nil {
			return 0, err
		}
		getch = getchTTY
		defer func() {
			terminal.Restore(int(rd.Fd()), state)
		}()
	}

	i := 0
	for i < len(out) {
		err := getch(out[i:i+1], rd)
		if err == backspace {
			if i > 0 {
				i--
			}
			continue
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		i++
	}

	return i, nil
}
