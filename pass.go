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
	"os"
	"reflect"
	"syscall"
	"unsafe"
)

// Password is a chunk of memory that lives outside of the Go garbage collector.
// The memory is locked to prevent it from leaking to swap, but note that this
// does not prevent the operating system from doing so during hibernation.
//
// It requires to be freed manually after its usage.
type Password []byte

func align2Up(v, p int) int {
	return ((v - 1) & ^(p - 1)) + p
}

func makePasswd(size int) (Password, error) {
	capacity := align2Up(size, os.Getpagesize())

	buf, err := syscall.Mmap(-1, 0, capacity, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return nil, err
	}

	err = syscall.Mlock(buf)
	if err != nil {
		syscall.Munmap(buf)
		return nil, err
	}

	return buf[:size], nil
}

// String returns a string view of the password buffer, not copying its contents.
func (p Password) String() (s string) {
	if p == nil {
		return ""
	}

	slice := (*reflect.SliceHeader)(unsafe.Pointer(&p))
	str := (*reflect.StringHeader)(unsafe.Pointer(&s))
	str.Data = slice.Data
	str.Len = slice.Len
	return
}

// Wipe zeroes out the entire password buffer.
func (p Password) Wipe() {
	if p == nil {
		return
	}

	p = p[:cap(p)]
	for i := range p {
		p[i] = 0
	}
}

// Free unmaps the slice from memory, wiping it beforehand.
func (p *Password) Free() {
	if *p == nil {
		return
	}

	p.Wipe()

	if err := syscall.Munmap((*p)[:cap(*p)]); err != nil {
		/* this can only happen due to a programming error on our part */
		panic(err)
	}
	*p = nil
}
