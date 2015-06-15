# README for imap-bulkmove

This project is in the early days.  So far, it can connect, set up TLS and
authenticate using GSSAPI, but that's it.  We spew a lot of diagnostics to
stderr.

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


## Interop

Currently tested to work against Cyrus IMAP 2.4 series; specifically 2.4.17
running on FreeBSD.

Requires TLS.  Requires GSSAPI.  In future will support more authentication.
I wanted it to work for me, and I decided to use Apcera's GSSAPI library
adaptor for Golang (full disclosure: I'm involved in that project).  Patches
welcome, as long as passwords aren't passed on the command-line.  These days,
environ _is_ acceptable.

Note that TLS setup with modern ciphersuite specs led to TLS negotiation
failure when the old ciphersuites left in common were
`ECDHE-RSA-AES128-GCM-SHA256` and `ECDHE-ECDSA-AES128-GCM-SHA256`; I don't
know which side is at fault, I suspect "my side" and that I need to find a new
carved bone to shake over Cyrus's configuration to enable ECDHE in practice.
I have `AES256-SHA` 256/256 confirmed working between this code and Cyrus.

For TLS, client and server are both known to work with Heimdal 1.5.3 but I
have no reason to believe that there is any constraint either to a version of
Heimdal or to Heimdal instead of MIT.  Compatibility patches welcome.


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
