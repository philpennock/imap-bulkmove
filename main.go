package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"code.google.com/p/go-imap/go1/imap"
	"github.com/apcera/gssapi"
)

// FIXME: use typed errors

const (
	maxGSSAPIStepIterations = 5
)

var flags struct {
	authzId        string
	serverHostname string
	serverRealm    string
}

func init() {
	flag.StringVar(&flags.authzId, "authz-id",
		"", "SASL authorization identity to request")
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

type Releaseable interface {
	Release() error
}

type gssapiAuth struct {
	realm            string
	authzId          string
	hostname         string
	lib              *gssapi.Lib
	ctx              *gssapi.CtxId
	serverName       *gssapi.Name
	releaseStack     []Releaseable
	clientMechanisms *gssapi.OIDSet
	requestMech      *gssapi.OID
	maxMessageLen    uint
	stepCount        int
}

// GSSAPIAuth is like the SASL constructions which the IMAP package uses, but
// we also return an error.
func GSSAPIAuth(serverName, authzId string) (imap.SASL, error) {
	gsslib, err := gssapiLoad()
	if err != nil {
		return nil, err
	}
	sasl := &gssapiAuth{
		realm:        strings.ToUpper(flags.serverRealm),
		authzId:      authzId,
		hostname:     serverName,
		lib:          gsslib,
		releaseStack: make([]Releaseable, 0, 10),
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
	sasl.releaseStack = append(sasl.releaseStack, name)

	err = sasl.CheckClientCredentials()
	if err != nil {
		return nil, err
	}

	return sasl, nil
}

func (a *gssapiAuth) Cleanup() {
	if a.ctx != nil {
		a.ctx.DeleteSecContext()
		a.ctx = nil
	}
	if a.releaseStack != nil && len(a.releaseStack) > 0 {
		for i := len(a.releaseStack) - 1; i >= 0; i-- {
			a.releaseStack[i].Release()
		}
		a.releaseStack = nil
	}
}

func (a *gssapiAuth) CheckClientCredentials() error {
	name, lifetime, credUsage, mechanisms, err := a.lib.InquireCred(a.lib.GSS_C_NO_CREDENTIAL)
	if err != nil {
		return err
	}
	defer func() {
		name.Release()
	}()

	fmt.Printf("Have client credentials for: %q\n", name)
	// should be checking lifetime against -1 or 2^32-1 (GSS_C_INDEFINITE) but the lifetime
	// in this wrapper is multiplying by time.Second ... huh?
	fmt.Printf("client credentials lifetime: %s\n", lifetime)
	if credUsage != gssapi.GSS_C_BOTH && credUsage != gssapi.GSS_C_INITIATE {
		return fmt.Errorf("GSSAPI credentials don't allow initiation: %d", credUsage)
	}
	fmt.Printf("mechanisms supported: %s\n", mechanisms.DebugString())

	a.clientMechanisms = mechanisms
	a.releaseStack = append(a.releaseStack, a.clientMechanisms)

	return nil
}

func (a *gssapiAuth) Start(s *imap.ServerInfo) (mech string, ir []byte, err error) {
	receiveToken := a.lib.GSS_C_NO_BUFFER
	defer receiveToken.Release()
	sendToken := a.lib.GSS_C_NO_BUFFER
	defer sendToken.Release()
	var (
		retFlags uint32
		mechUsed *gssapi.OID
	)

	if a.clientMechanisms.Contains(a.lib.GSS_MECH_SPNEGO) {
		a.requestMech = a.lib.GSS_MECH_SPNEGO
	} else {
		fmt.Fprintf(os.Stderr, "WARNING: client credentials do not support SPNEGO\n")
		a.requestMech = a.lib.GSS_C_NO_OID
	}

	a.stepCount += 1

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
	a.ctx, mechUsed, sendToken, retFlags, _, err =
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
			a.requestMech,
			// req_flags flags using when building the context, see Context
			// creation flags
			gssapi.GSS_C_MUTUAL_FLAG,
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
	fmt.Fprintf(os.Stderr, "selected mechanism: %s\n", mechUsed.DebugString())
	decodeGSSAPIContextFlags(os.Stdout, retFlags)

	//initialResponse := make([]byte, base64.StdEncoding.EncodedLen(sendToken.Length()))
	//base64.StdEncoding.Encode(initialResponse, sendToken.Bytes())
	//fmt.Fprintf(os.Stderr, "AUTH PARAM: %q\n", string(initialResponse))
	//return "GSSAPI", initialResponse, nil

	// The IMAP library does the base64 encoding for us
	return "GSSAPI", sendToken.Bytes(), nil
}

func (a *gssapiAuth) Next(challenge []byte) (response []byte, err error) {
	a.stepCount += 1

	receiveToken, err := a.lib.MakeBufferBytes(challenge)
	if err != nil {
		return nil, err
	}
	defer receiveToken.Release()

	// FIXME XXX GROSS HACK
	// We need to be checking GSS_S_COMPLETE from the previous pass, but the Go
	// bindings don't expose a way to get that?  So rely upon knowledge of
	// Kerberos flow to stop after the GSS bits are complete and extract the
	// SASL data instead.
	if a.stepCount > 2 {
		// SASL data, not GSS input

		// decoded (unwrapped) buffer, confState, QOPState, err
		decodedBuffer, _, _, err := a.ctx.Unwrap(receiveToken)
		if err != nil {
			return nil, err
		}
		defer decodedBuffer.Release()
		if decodedBuffer.Length() != 4 {
			// RFC 4752 §3.1: "If the resulting cleartext is not 4 octets long, the client fails the negotiation."
			return nil, fmt.Errorf("unwrapped SASL state length was %d, expected 4", decodedBuffer.Length())
		}
		decoded := decodedBuffer.Bytes()
		bitmask := decoded[0]
		a.maxMessageLen = ((uint(decoded[1])*256)+uint(decoded[2]))*256 + uint(decoded[3])

		// RFC 4752 §3.3
		fmt.Printf("offered security bitmask:")
		if bitmask&0x01 != 0 {
			fmt.Printf(" <none>")
		}
		if bitmask&0x02 != 0 {
			fmt.Printf(" <integrity>")
		}
		if bitmask&0x04 != 0 {
			fmt.Printf(" <confidentiality>")
		}
		fmt.Printf("\n")

		if bitmask&0x01 == 0 {
			return nil, fmt.Errorf("server demands GSSAPI security layers, which we don't implement: %d", bitmask)
		}

		// the authorization identifier is appended to a leading 4 octets, and
		// is UTF-8 encoded without trailing NUL.  Since our in-memory string
		// is already UTF-8, we're golden and can use len()
		response := make([]byte, 4+len(a.authzId))
		response[0] = 0x01 // select no security layer
		// response[1:4] left at 0, because no security layer
		if len(a.authzId) > 0 {
			copy(response[4:], a.authzId)
		}
		responseBuffer, err := a.lib.MakeBufferBytes(response)
		if err != nil {
			return nil, err
		}
		defer responseBuffer.Release()

		// confState bool, outputMessageBuffer *Buffer, err error
		_, encoded, err := a.ctx.Wrap(
			false, // no confidentiality
			0,     // no qop set (should derive from stats about TLS status)
			responseBuffer)
		if err != nil {
			return nil, err
		}
		defer encoded.Release()
		return encoded.Bytes(), nil
	}

	sendToken := a.lib.GSS_C_NO_BUFFER
	defer sendToken.Release()
	var retFlags uint32

	a.ctx, _, sendToken, retFlags, _, err =
		a.lib.InitSecContext(
			a.lib.GSS_C_NO_CREDENTIAL,
			a.ctx,
			a.serverName,
			a.requestMech,
			gssapi.GSS_C_MUTUAL_FLAG,
			0,
			a.lib.GSS_C_NO_CHANNEL_BINDINGS,
			receiveToken)
	if err != nil {
		return nil, err
	}
	decodeGSSAPIContextFlags(os.Stdout, retFlags)

	if sendToken != nil && sendToken.Length() > 0 {
		fmt.Fprintf(os.Stderr, "sending step %d, length %d\n", a.stepCount, sendToken.Length())
		return sendToken.Bytes(), nil
	}

	// XXX: how do we actually check that MajorStatus is GSS_S_COMPLETE ?

	return nil, nil
}

func decodeGSSAPIContextFlags(w io.Writer, flags uint32) {
	fmt.Fprintf(w, "GSSAPI Context flags (%d):", flags)
	if flags == uint32(0) {
		fmt.Fprintf(w, " <none>\n")
		return
	}
	if flags&gssapi.GSS_C_DELEG_FLAG != 0 {
		fmt.Fprintf(w, " <delegated-available>")
	}
	if flags&gssapi.GSS_C_MUTUAL_FLAG != 0 {
		fmt.Fprintf(w, " <mutual-requested>")
	}
	if flags&gssapi.GSS_C_REPLAY_FLAG != 0 {
		fmt.Fprintf(w, " <replay-detection-active>")
	}
	if flags&gssapi.GSS_C_SEQUENCE_FLAG != 0 {
		fmt.Fprintf(w, " <out-of-sequence-detection-active>")
	}
	if flags&gssapi.GSS_C_CONF_FLAG != 0 {
		fmt.Fprintf(w, " <confidentiality-available>")
	}
	if flags&gssapi.GSS_C_INTEG_FLAG != 0 {
		fmt.Fprintf(w, " <integrity-protection-available>")
	}
	if flags&gssapi.GSS_C_ANON_FLAG != 0 {
		fmt.Fprintf(w, " <anon-requested>")
	}
	if flags&gssapi.GSS_C_PROT_READY_FLAG != 0 {
		fmt.Fprintf(w, " <protection-during-handshake-available>")
	}
	if flags&gssapi.GSS_C_TRANS_FLAG != 0 {
		fmt.Fprintf(w, " <context-transferable>")
	}
	fmt.Fprintf(w, "\n")
}

var _ imap.SASL = &gssapiAuth{}

func main() {
	flag.Parse()

	defersChan := make(chan func())
	// must buffer errors: we don't check for them until after handling defers
	errorsChan := make(chan error, 1)
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
	sasl, err := GSSAPIAuth(flags.serverHostname, flags.authzId)
	defersChan <- func() { sasl.(*gssapiAuth).Cleanup() }
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
