// +build linux

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
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

const PR_SET_PTRACER_ANY = ^uintptr(0)

func coredump(file string) {
	_, _, errno := syscall.Syscall(syscall.SYS_PRCTL, syscall.PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0)
	if errno != 0 {
		panic(syscall.Errno(errno))
	}

	pid := fmt.Sprintf("%d", os.Getpid())

	proc := exec.Command("gdb", "-p", pid,
		"-ex", "set confirm off",
		"-ex", "generate-core-file "+file,
		"-ex", "quit")

	proc.Stdout = ioutil.Discard
	proc.Stderr = ioutil.Discard
	in, _ := proc.StdinPipe()
	in.Close()

	if err := proc.Run(); err != nil {
		panic(err)
	}
}

type NotReader struct {
	r io.Reader
}

func (r NotReader) Read(b []byte) (int, error) {
	l, err := r.r.Read(b)
	if err == nil {
		for i := 0; i < l; i++ {
			b[i] = ^b[i]
		}
	}
	return l, err
}

func FileContains(path string, pattern []byte) bool {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	return bytes.Contains(contents, pattern)
}

func TestSensitive(t *testing.T) {
	/* We use a very dumb bitwise "not" as cipher to unpack some fixed string
	   into memory as a searchable pattern. We can't search directly for a
	   pattern, as the pattern itself would have to be in memory. */
	notSecret := []byte("this very long string is unlikely to appear randomly")

	sensitive, err := Read(NotReader{bytes.NewReader(notSecret)})
	if err != nil {
		t.Fatal(err)
	}

	coredump("core.secret")

	sensitive.Wipe()
	coredump("core")

	actualSecret := make([]byte, len(notSecret))
	for i := range actualSecret {
		actualSecret[i] = ^notSecret[i]
	}

	/* sanity check */
	if !FileContains("core.secret", notSecret) || !FileContains("core", notSecret) {
		t.Fatal("Expected core files to contain ciphertext")
	}

	if !FileContains("core.secret", actualSecret) {
		t.Fatal("Expected pre-wipe core file to contain secret")
	}

	if FileContains("core", actualSecret) {
		t.Fatal("Expected post-wipe core file to NOT contain secret")
	}
}
