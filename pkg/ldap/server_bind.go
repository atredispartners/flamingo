package ldap

import (
	"net"

	ber "github.com/atredispartners/flamingo/pkg/asn1-ber"
)

// HandleBindRequest handles a bind request and returns its result code. It is
// the pre-SASL entry point, kept for callers that have no way to send
// serverSaslCreds back: any credentials the handler produced are discarded.
func HandleBindRequest(req *ber.Packet, fns map[string]Binder, conn net.Conn) LDAPResultCode {
	resultCode, _ := HandleBindRequestSASL(req, fns, conn)
	return resultCode
}

// HandleBindRequestSASL handles a bind request and returns its result code
// together with the serverSaslCreds to place in the bind response, which is
// nil for every bind except an in-progress SASL exchange.
//
// flamingo change: SASL binds used to be refused unconditionally. They are now
// routed to the matching Binder when it also implements SASLBinder, so the
// handler can run a multi-round-trip mechanism (GSS-SPNEGO/NTLM, DIGEST-MD5)
// by answering LDAPResultSaslBindInProgress with its own serverSaslCreds. A
// Binder that does not implement SASLBinder keeps the old behaviour.
func HandleBindRequestSASL(req *ber.Packet, fns map[string]Binder, conn net.Conn) (resultCode LDAPResultCode, serverSaslCreds []byte) {
	defer func() {
		if r := recover(); r != nil {
			resultCode = LDAPResultOperationsError
			serverSaslCreds = nil
		}
	}()

	// BindRequest ::= [APPLICATION 0] SEQUENCE {
	//     version        INTEGER (1..127),
	//     name           LDAPDN,
	//     authentication AuthenticationChoice }
	if len(req.Children) < 3 {
		return LDAPResultProtocolError, nil
	}

	// we only support ldapv3
	ldapVersion, ok := req.Children[0].Value.(uint64)
	if !ok {
		return LDAPResultProtocolError, nil
	}
	if ldapVersion != 3 {
		// log.Debugf("Unsupported LDAP version: %d", ldapVersion)
		return LDAPResultInappropriateAuthentication, nil
	}

	// auth types
	bindDN, ok := req.Children[1].Value.(string)
	if !ok {
		return LDAPResultProtocolError, nil
	}
	bindAuth := req.Children[2]
	switch bindAuth.Tag {
	default:
		// log.Debug("Unknown LDAP authentication method")
		return LDAPResultInappropriateAuthentication, nil
	case LDAPBindAuthSimple:
		if len(req.Children) == 3 {
			fn := routeFunc(bindDN, binderNames(fns))
			resultCode, err := fns[fn].Bind(bindDN, bindAuth.Data.String(), conn)
			if err != nil {
				// log.Debugf("BindFn Error %s", err.Error())
				return LDAPResultOperationsError, nil
			}
			return resultCode, nil
		} else {
			// log.Debug("Simple bind request has wrong # children.  len(req.Children) != 3")
			return LDAPResultInappropriateAuthentication, nil
		}
	case LDAPBindAuthSASL:
		// SaslCredentials ::= SEQUENCE {
		//     mechanism   LDAPString,
		//     credentials OCTET STRING OPTIONAL }
		if len(bindAuth.Children) == 0 {
			return LDAPResultInappropriateAuthentication, nil
		}
		mechanism, ok := bindAuth.Children[0].Value.(string)
		if !ok {
			return LDAPResultProtocolError, nil
		}
		var credentials []byte
		if len(bindAuth.Children) > 1 {
			credentials = berContents(bindAuth.Children[1])
		}
		fn := routeFunc(bindDN, binderNames(fns))
		sasl, ok := fns[fn].(SASLBinder)
		if !ok {
			// log.Debug("SASL authentication is not supported")
			return LDAPResultInappropriateAuthentication, nil
		}
		code, creds, err := sasl.BindSASL(bindDN, mechanism, credentials, conn)
		if err != nil {
			// log.Debugf("BindSASL Error %s", err.Error())
			return LDAPResultOperationsError, nil
		}
		return code, creds
	}
}

// binderNames returns the base DNs the given bind handlers are registered
// under, for routeFunc to pick the most specific match from.
func binderNames(fns map[string]Binder) []string {
	names := make([]string, 0, len(fns))
	for k := range fns {
		names = append(names, k)
	}
	return names
}

// berContents returns the raw contents of a primitive BER packet, and nil when
// there are none.
func berContents(p *ber.Packet) []byte {
	if p == nil {
		return nil
	}
	if p.ByteValue != nil {
		return p.ByteValue
	}
	if p.Data != nil {
		return p.Data.Bytes()
	}
	return nil
}

// encodeBindResponse builds a bind response. flamingo change: serverSaslCreds
// is appended as the optional [7] field of BindResponse (RFC 4511 4.2.2) when
// the handler produced any, which is how the server half of a SASL exchange
// reaches the client.
func encodeBindResponse(messageID uint64, ldapResultCode LDAPResultCode, serverSaslCreds []byte) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	bindReponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
	bindReponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(ldapResultCode), "resultCode: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "errorMessage: "))
	if len(serverSaslCreds) > 0 {
		bindReponse.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, string(serverSaslCreds), "serverSaslCreds: "))
	}

	responsePacket.AppendChild(bindReponse)

	// ber.PrintPacket(responsePacket)
	return responsePacket
}
