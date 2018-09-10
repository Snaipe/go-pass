# go-pass

[![GoDoc](https://godoc.org/snai.pe/go-pass?status.svg)](https://godoc.org/snai.pe/go-pass)  

```
go get snai.pe/go-pass
```

go-pass is a small library providing functions to securely prompt users for their passwords.

It features the following:

* [x] **A secure Password slice type** that gets allocated out of the garbage collector,
      is locked in RAM, and providing functions to wipe, unmap, and create string views
      safely.
* [x] **Multiple Read functions** to retrieve the input from any reader and store it
      in a secure password slice, or a user-provided slice, if absolutely needed.
* [x] **Convenience functions** to display a prompt before requesting a password.

## Why?

Go is infamous for leaking secrets to uncontrollable memory when not careful. A slice allocated
by the garbage collector can and will get copied around, and the `string(slice)` construct copies
the content of `slice` to a new string, which makes usual idioms like zeroing out the password
after usage non-trivial to implement.

I evaluated a few of the existing solutions but consistently found that dumping the core
of my go process after wiping the password and grepping said password out of the core file
yielded positive matches, and I decided to roll my own library.

go-pass addresses this by allocating a secure buffer outside of the garbage collector to write
the password to, and locks the pages in RAM to prevent passwords leaking to swap (although be
warned that most operating systems will still copy RAM to swap during hibernation).
In addition, the secure password type provides a String() function that doesn't copy the buffer
to a GC-allocated string, but rather creates a string view of the underlying buffer.

Lastly, we have a unit test case that scans the core dump of the test process before and after
wiping the password to make sure we got you covered.
