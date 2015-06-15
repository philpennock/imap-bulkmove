# README for imap-bulkmove

This project is in the early days.  So far, it can connect, set up TLS and
authenticate using GSSAPI, but that's it.

The goal is to get towards doing routine administrative tasks such as moving
mails from a folder to a sub-folder based on a pattern extracted from the
message.  For instance, use the received-date and `%Y` to move them into
`2015/` as a sub-folder name.  Have constraints to only do this on certain
mails (eg, older than a certain age), and suddenly you have a system which has
smallish current folders being re-indexed and folders with older mail.

It's no enterprise message management system with hierarchical storage.  But
hey, it's free.

**Target audience**: postmasters and other people who really understand email
at a technical level.


## Build Notes

Early days, yet already, we have build notes.

### Dependencies

Run `go get -d -u -v -f`  
(download, update-existing, verbose, don't-whine-about-forks)

That should be it.  We're not doing anything fancy.

Version pinning: none at this time, but:

* First public release of Apcera's GSSAPI is known to work
* `code.google.com/p/go-imap` is untouched since `bf4993d7df21` in December 2013; that version works


### Building

Normally, `go build`

However, this uses cgo and gccgo; Golang _by default_ assumes that the system
compiler is gcc of a version which supports gccgo.  So golang just invokes `cc`.

On systems where `cc` is `clang` (ie, FreeBSD), the diagnostics indicating the problem are … "not intuitive".

Run:

```console
$ export CC=gcc48
$ go build
```

(amend exact gcc binary filename as appropriate for your system)
