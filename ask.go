// go-pass
//
// Copyright (C) 2018  Franklin "Snaipe" Mathieu <me@snai.pe>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package pass

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
)

// Prompt is a convenience function that prints its parameter followed by a
// ": ", then reads a password from stdin.
//
// It returns the password as a secure buffer that needs to be manually freed.
func Prompt(prompt string) (Password, error) {
	return Ask(AskOptions{
		Prompt: prompt,
	})
}

type AskOptions struct {
	// If non-empty, will be printed to Out, followed by ": ".
	Prompt  string

	// If non-empty, will be executed and the password will be read from its stdout.
	Program string

	// The destination of the prompt string. If nil, means os.Stdout.
	Out     io.Writer

	// The allocated size of the secure password buffer.
	MaxSize int
}

// Ask is a convenience function that prompts the user for a password using the
// options passed as parameter.
//
// It returns the password as a secure buffer that needs to be manually freed.
func Ask(opts AskOptions) (Password, error) {
	var (
		err error
		src io.Reader = os.Stdin
		out io.Writer = os.Stdout
		cmd *exec.Cmd
	)

	if opts.Program != "" {
		cmd = exec.Command(opts.Program)
		cmd.Stderr = ioutil.Discard

		src, err = cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		cmd.Start()
	}

	if opts.Out != nil {
		out = opts.Out
	}

	if opts.Prompt != "" {
		out.Write([]byte(opts.Prompt + ": "))
	}

	pass, err := ReadSize(src, opts.MaxSize)

	if opts.Prompt != "" {
		/* the newline has been swallowed by the read, so re-output it here */
		fmt.Println()
	}

	if cmd != nil {
		cerr := cmd.Wait()

		/* most errors from Read are probably due to cmd failing --
		   so override it */
		if cerr != nil {
			err = cerr
		}
	}

	if pass != nil && err != nil {
		pass.Free()
		pass = nil
	}

	return pass, err
}
