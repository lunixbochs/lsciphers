package main

import (
    "bytes"
    "errors"
    "log"
    "net"
    "regexp"
    "time"
)

var xmppClientIdent string = `<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='%s' version='1.0'>\n`
var xmppServerPreamble string = `<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='%s' from='%s' version='1.0' xml:lang='en'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'></starttls></stream:features>\n`
var xmppClientStarttls string = `<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\n`
var xmppServerProceed string = `<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\n`

var tlsFeatureMatch *regexp.Regexp = regexp.MustCompile(`<starttls xmlns=['"]urn:ietf:params:xml:ns:xmpp-tls`)

func matchXmppTLS(conn net.Conn) bool {
    conn.SetDeadline(time.Now().Add(15 * time.Second))
    buf := make([]byte, 10240)
    pos := 0
    var err error
    var n int
    for tlsFeatureMatch.Find(buf) == nil {
        if err != nil {
            log.Println(err)
            return false
        }
        if pos > len(buf)-64 {
            return false
        }
        if bytes.Contains(buf, []byte("/stream:features>")) {
            return false
        }
        n, err = conn.Read(buf[pos:])
        pos += n
    }
    conn.SetDeadline(*new(time.Time))
    return true
}

func StartXmppTLS(conn net.Conn) (net.Conn, error) {
    if !matchXmppTLS(conn) {
        return nil, errors.New("Failed to starttls.")
    }
    _, err := conn.Write([]byte(xmppClientStarttls))
    if err != nil {
        return nil, err
    }
    buf := make([]byte, 1024)
    _, err = conn.Read(buf)
    if !bytes.Contains(buf, []byte("<proceed")) {
        return nil, errors.New("Server did not accept starttls.")
    }
    return conn, nil
}
