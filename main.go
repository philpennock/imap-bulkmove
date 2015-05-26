package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"code.google.com/p/go-imap/go1/imap"
	"github.com/apcera/gssapi"
)

const (
	maxGSSAPIStepIterations = 5
)

var flags struct {
	serverHostname string
	serverRealm    string
}

func init() {
	flag.StringVar(&flags.serverHostname, "server",
		os.Getenv("IMAP_SERVER"), "IMAP server hostname")
	flag.StringVar(&flags.serverRealm, "krb-realm",
		"", "IMAP server Kerberos realm")
}

var gssapiLoader struct {
	once    sync.Once
	lib     *gssapi.Lib
	options gssapi.Options
	err     error
}

func gssapiLoad() (*gssapi.Lib, error) {
	gssapiLoader.once.Do(func() {
		gssapiLoader.lib, gssapiLoader.err = gssapi.Load(&gssapiLoader.options)
	})
	// FIXME: wrap this better when there's no credentials cache file
	return gssapiLoader.lib, gssapiLoader.err
}

type gssapiAuth struct {
	realm            string
	hostname         string
	lib              *gssapi.Lib
	ctx              *gssapi.CtxId
	serverName       *gssapi.Name
	releaseNameStack []*gssapi.Name
	_                struct{}
}

// GSSAPIAuth is like the SASL constructions which the IMAP package uses, but
// we also return an error.
func GSSAPIAuth(serverName string) (imap.SASL, error) {
	gsslib, err := gssapiLoad()
	if err != nil {
		return nil, err
	}
	sasl := gssapiAuth{
		realm:            strings.ToUpper(flags.serverRealm),
		hostname:         serverName,
		lib:              gsslib,
		releaseNameStack: make([]*gssapi.Name, 0, 10),
	}

	var serverId string
	if sasl.realm != "" {
		// FIXME: escaping
		serverId = fmt.Sprintf("imap/%s@%s", sasl.hostname, sasl.realm)
	} else {
		serverId = fmt.Sprintf("imap/%s", sasl.hostname)
	}
	namebuf, err := gsslib.MakeBufferString(serverId)
	if err != nil {
		return nil, err
	}
	name, err := namebuf.Name(gsslib.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		return nil, err
	}
	sasl.serverName = name
	sasl.releaseNameStack = append(sasl.releaseNameStack, name)

	return sasl, nil
}

func (a gssapiAuth) Cleanup() {
	if a.ctx != nil {
		a.ctx.DeleteSecContext()
		a.ctx = nil
	}
	if a.releaseNameStack != nil {
		for i := len(a.releaseNameStack) - 1; i >= 0; i-- {
			a.releaseNameStack[i].Release()
		}
		a.releaseNameStack = nil
	}
}

func (a gssapiAuth) Start(s *imap.ServerInfo) (mech string, ir []byte, err error) {
	receiveToken := a.lib.GSS_C_NO_BUFFER
	defer receiveToken.Release()
	sendToken := a.lib.GSS_C_NO_BUFFER
	defer sendToken.Release()
	var retFlags uint32

	// comments here mostly come from Heimdal man-page (more so for input params)

	// ctxOut *CtxId, actualMechType *OID, outputToken *Buffer, retFlags uint32, timeRec time.Duration, err error) {

	// *CtxId: possibly a fresh context, if the input was nil
	// *OID: actual_mech_type the actual mech used, MUST NOT be freed since it
	//       pointing to static memory.
	// *Buffer: output_token if there is an output token, regardless of
	//          complete, continue_needed, or error it should be sent to the
	//          acceptor
	// uint32: ret_flags return what flags was negotitated, caller should check
	//         if they are accetable. For example, if GSS_C_MUTUAL_FLAG was
	//         negotiated with the acceptor or not.
	// time.Duration: time_rec amount of time this context is valid for
	// error: major/minor constructed error
	a.ctx, _, sendToken, retFlags, _, err =
		a.lib.InitSecContext(
			// initiator_cred_handle the credential to use when building the
			// context, if GSS_C_NO_CREDENTIAL is passed, the default
			// credential for the mechanism will be used
			a.lib.GSS_C_NO_CREDENTIAL,
			// context_handle a pointer to a context handle, will be returned
			// as long as there is not an error
			a.ctx,
			// target_name the target name of acceptor, created using
			// gss_import_name(). The name is can be of any name types the
			// mechanism supports, check supported name types with
			// gss_inquire_names_for_mech().
			a.serverName,
			// input_mech_type mechanism type to use, if GSS_C_NO_OID is used,
			// Kerberos (GSS_KRB5_MECHANISM) will be tried. Other available
			// mechanism are listed in the GSS-API mechanisms section.
			a.lib.GSS_C_NO_OID,
			// req_flags flags using when building the context, see Context
			// creation flags
			0,
			// time_req time requested this context should be valid in seconds,
			// common used value is GSS_C_INDEFINITE
			0,
			// input_chan_bindings Channel bindings used, if not expected
			// otherwise, use GSS_C_NO_CHANNEL_BINDINGS
			a.lib.GSS_C_NO_CHANNEL_BINDINGS,
			// input_token input token sent from the acceptor, for the initial
			// packet the buffer of { NULL, 0 } should be used.
			receiveToken)

	if err != nil {
		return "", []byte{}, err
	}
	fmt.Printf("retFlags: %x\n", retFlags)

	initialResponse := make([]byte, 0, sendToken.Length()*4/3)
	base64.StdEncoding.Encode(initialResponse, sendToken.Bytes())
	return "GSSAPI", initialResponse, nil
}

func (a gssapiAuth) Next(challenge []byte) (response []byte, err error) {
	// XXX: this says that auth is done
	panic("unimplemented")
	return nil, nil
}

var _ imap.SASL = &gssapiAuth{}

func main() {
	flag.Parse()

	defersChan := make(chan func())
	errorsChan := make(chan error)
	go setupIMAP(defersChan, errorsChan)
	for {
		d, ok := <-defersChan
		if !ok {
			break
		}
		defer d()
	}
	err := <-errorsChan
	if err != nil {
		fmt.Fprintf(os.Stderr, "FIXME: %s\n", err)
		os.Exit(1)
	}

	time.Sleep(time.Second)
}

func setupIMAP(defersChan chan<- func(), errorsChan chan<- error) {
	defer close(defersChan)
	defer close(errorsChan)

	imap.DefaultLogger = log.New(os.Stdout, "", 0)
	imap.DefaultLogMask = imap.LogConn | imap.LogRaw

	c, err := imap.Dial(flags.serverHostname)
	if err != nil {
		errorsChan <- err
		return
	}
	defersChan <- func() { ReportOK(c.Logout(30 * time.Second)) }

	ReportOK(c.Noop())

	tc := &tls.Config{
		ServerName: flags.serverHostname,
	}

	if c.Caps["STARTTLS"] {
		ReportOK(c.StartTLS(tc))
	}

	// Cyrus is buggy; if one listener gets an ID and then no auth, then a
	// later connection handled by the same listener will refuse to handle that
	// connection's ID, treating it as a second ID command in the same session.
	// So only issue ID after authentication.  Eww.

	if !c.Caps["AUTH=GSSAPI"] {
		errorsChan <- errors.New("Capability response missing AUTH=GSSAPI")
		return
	}
	sasl, err := GSSAPIAuth(flags.serverHostname)
	defersChan <- func() { sasl.(gssapiAuth).Cleanup() }
	if err != nil {
		errorsChan <- err
		return
	}
	ReportOK(c.Auth(sasl))

	if c.Caps["ID"] {
		ReportOK(c.ID("name", "imap-datesubdir-move"))
	}
	errorsChan <- nil
}

// ripped straight from imap-demo/demo1.go
func ReportOK(cmd *imap.Command, err error) *imap.Command {
	var rsp *imap.Response
	if cmd == nil {
		fmt.Printf("--- ??? ---\n%v\n\n", err)
		os.Exit(1)
	} else if err == nil {
		rsp, err = cmd.Result(imap.OK)
	}
	if err != nil {
		fmt.Printf("--- %s ---\n%v\n\n", cmd.Name(true), err)
		panic(err)
	}
	c := cmd.Client()
	fmt.Printf("--- %s ---\n"+
		"%d command response(s), %d unilateral response(s)\n"+
		"%s %s\n\n",
		cmd.Name(true), len(cmd.Data), len(c.Data), rsp.Status, rsp.Info)
	c.Data = nil
	return cmd
}
