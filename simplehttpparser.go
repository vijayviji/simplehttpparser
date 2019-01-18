package simplehttpparser

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/textproto"
	"net/url"
	"time"
)

const (
	defaultReadBufferSize  = 4096
	defaultWriteBufferSize = 4096
)

// RequestHandler - Fn which handles all requests
type RequestHandler func(request *Request) *Response

// Session - A single session (or HTTP connection) where multiple requests can come in.
type Session struct {
	conn net.Conn

	tpReader *textproto.Reader
	bufR     *bufio.Reader
	bufW     *bufio.Writer

	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body.
	//
	// Because ReadTimeout does not let Handlers make per-request
	// decisions on each request body's acceptable deadline or
	// upload rate, most users will prefer to use
	// ReadHeaderTimeout. It is valid to use them both.
	ReadTimeout time.Duration

	// ReadHeaderTimeout is the amount of time allowed to read
	// request headers. The connection's read deadline is reset
	// after reading the headers and the Handler can decide what
	// is considered too slow for the body.
	ReadHeaderTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. It is reset whenever a new
	// request's header is read. Like ReadTimeout, it does not
	// let Handlers make decisions on a per-request basis.
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled. If IdleTimeout
	// is zero, the value of ReadTimeout is used. If both are
	// zero, ReadHeaderTimeout is used.
	IdleTimeout time.Duration

	closeConnection bool
}

// NewSession - Create a new session
func NewSession(conn net.Conn, readTimeout time.Duration, writeTimeout time.Duration, idleTimeout time.Duration) *Session {
	session := &Session{
		conn: conn,
	}

	//TODO: bufio reader, writer and textproto have to be recycled rather using sync.Pool
	session.bufR = bufio.NewReaderSize(session.conn, defaultReadBufferSize)
	session.bufW = bufio.NewWriterSize(session.conn, defaultWriteBufferSize)
	session.tpReader = textproto.NewReader(session.bufR)

	session.ReadHeaderTimeout = readTimeout
	session.WriteTimeout = writeTimeout

	return session
}

func (session *Session) close() error {
	return session.conn.Close()
}

// Returns true if we hit IdleTimeout.
func (session *Session) handleIdleTimeout() (timedOut bool) {
	// Let's set read dead line to IdleTimeout and try to peek for 4 bytes. If we don't get 4 bytes within
	// IdleTimeout, then timeout the connection (if we get 0 data, we'll get error from Peek().

	if d := session.IdleTimeout; d != 0 {
		session.conn.SetReadDeadline(time.Now().Add(d))
		if _, err := session.bufR.Peek(4); err != nil {
			return true
		}
	}

	// We've not timedout or IdleTimeout is 0. We've received some more data. Let's reset the read deadline
	session.conn.SetReadDeadline(time.Time{})
	return false
}

// Serve - Given a session, it reads all requests in that and calls reqHandler to get a response and writes it.
func (session *Session) Serve(reqHandler RequestHandler) {
	defer session.close()

	for {
		req, err := session.ReadRequest()
		fmt.Println("Request read. err=", err)
		if err != nil {
			const errorHeaders = "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"

			if isCommonNetReadError(err) {
				break // don't reply
			}

			publicErr := "400 Bad Request"
			if v, ok := err.(badRequestError); ok {
				publicErr = publicErr + ": " + string(v)
			}

			fmt.Fprintf(session.conn, "HTTP/1.1 "+publicErr+errorHeaders+publicErr)
			break
		}

		fmt.Println("Calling reqHandler")
		resp := reqHandler(req)
		fmt.Println("Writing resp")
		if err = session.WriteResponse(resp); err != nil {
			break
		}
		fmt.Println("Response written")

		if session.handleIdleTimeout() {
			// we've timed out.
			break
		}

		if session.closeConnection {
			break
		}
	}
}

func (header *Header) Write(w *bufio.Writer) {
	if header.date != nil {
		w.Write(headerDate)
		w.Write(header.date)
		w.Write(strCRLF)
	}
	if header.contentLength != nil {
		w.Write(headerContentLength)
		w.Write(header.contentLength)
		w.Write(strCRLF)
	}
	for i, v := range []string{header.contentType, header.connection, header.transferEncoding} {
		if v != "" {
			w.Write(extraHeaderKeys[i])
			w.Write(strColonSpace)
			w.Write([]byte(v))
			w.Write(strCRLF)
		}
	}
}

// WriteResponse - Write a response to the connection/session
func (session *Session) WriteResponse(resp *Response) error {
	var (
		err error
	)

	if d := session.WriteTimeout; d != 0 {
		session.conn.SetWriteDeadline(time.Now().Add(session.WriteTimeout))
	}

	writeStatusLine(session.bufW, resp, resp.StatusCode, nil)
	resp.Header.Write(session.bufW)
	if _, err = session.bufW.Write(strCRLF); err != nil {
		return err
	}

	if len(resp.Body) > 0 {
		if _, err = session.bufW.Write(resp.Body); err != nil {
			return err
		}
	}

	if err = session.bufW.Flush(); err != nil {
		return err
	}

	return nil
}

func (session *Session) readHeaderTimeout() time.Duration {
	if session.ReadHeaderTimeout != 0 {
		return session.ReadHeaderTimeout
	}
	return session.ReadTimeout
}

// ReadRequest - Read a request from the connection/session
func (session *Session) ReadRequest() (*Request, error) {
	var (
		s string
		err error
		ok bool
		mimeHeader textproto.MIMEHeader
	)

	// Right now we're reading only headers
	if d := session.readHeaderTimeout(); d != 0 {
		session.conn.SetReadDeadline(time.Now().Add(d))
	}

	if s, err = session.tpReader.ReadLine(); err != nil {
		return nil, err
	}

	request := newRequest()

	// First line: GET /index.html HTTP/1.0
	request.Method, request.RequestURI, request.Proto, _ = parseRequestLine(s)

	if request.Proto, request.ProtoMajor, request.ProtoMinor, ok = parseHTTPVersion(request.Proto); !ok {
		return nil, &badStringError{"malformed HTTP version", request.Proto}
	}

	if !http1ServerSupportsRequest(request) {
		return nil, badRequestError("unsupported protocol version")
	}

	// read Headers here
	if mimeHeader, err = session.tpReader.ReadMIMEHeader(); err != nil {
		return nil, err
	}
	request.Header = Header(mimeHeader)
	session.closeConnection = shouldClose(request.ProtoMajor, request.ProtoMinor, request.Header, false)

	// TODO: Read Body of the request

	return request, nil
}

// Request - A request object
type Request struct {
	RequestURI string
	Proto      string
	ProtoMajor int
	ProtoMinor int

	Method string
	Header Header
	Form   url.Values
}

func newRequest() *Request {
	return &Request{}
}

// Response - A response object
type Response struct {
	req *Request

	Proto      string
	ProtoMajor int
	ProtoMinor int

	Header ResponseHeader

	Body          []byte
}

// NewResponse - Create a new response object
func NewResponse(req *Request) *Response {
	return &Response{
		req: req,

		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Proto:      req.Proto,
	}
}


// SetSuccess - Make the response to fill up with default values for a succcess response.
func (resp *Response) SetSuccess(contentType string, body []byte) {
	resp.StatusCode = 200
	resp.Body = body
}

// SetError - Make the response to fill up with default values for a error response.
func (resp *Response) SetError(statusCode int) {
	resp.StatusCode = statusCode
}



type argsKV struct {
	key     []byte
	value   []byte
	noValue bool
}

// ResponseHeader represents HTTP response header.
// ResponseHeader instance MUST NOT be used from concurrently running
// goroutines.
type ResponseHeader struct {
	connectionClose      bool

	statusCode         int
	contentLength      int
	contentLengthBytes []byte

	contentType []byte
	server      []byte

	// rest of the headers
	others []argsKV
}

func appendHeaderLine(dst, key, value []byte) []byte {
	dst = append(dst, key...)
	dst = append(dst, strColonSpace...)
	dst = append(dst, value...)
	return append(dst, strCRLF...)
}

// ContentType returns Content-Type header value.
func (h *ResponseHeader) ContentType() []byte {
	if len(h.contentType) == 0 {
		return defaultContentType
	}
	return h.contentType
}

// Server returns Server header value.
func (h *ResponseHeader) Server() []byte {
	if (len(h.server) == 0) {
		return defaultServerName
	}

	return h.server
}

func (h *ResponseHeader) AppendBytes(dst []byte) []byte {
	statusCode := h.statusCode
	if statusCode < 0 {
		statusCode = 200
	}
	dst = append(dst, statusLine(statusCode)...)

	server := []byte(h.Server())
	if len(server) != 0 {
		dst = appendHeaderLine(dst, strServer, server)
	}
	dst = appendHeaderLine(dst, strDate, []byte(time.Now().Format(timeFormat)))

	// Append Content-Type only for non-zero responses
	// or if it is explicitly set.
	// See https://github.com/valyala/fasthttp/issues/28 .
	if h.contentLength != 0 || len(h.contentType) > 0 {
		dst = appendHeaderLine(dst, strContentType, h.ContentType())
	}

	if len(h.contentLengthBytes) > 0 {
		dst = appendHeaderLine(dst, strContentLength, h.contentLengthBytes)
	}

	for i, n := 0, len(h.others); i < n; i++ {
		kv := &h.others[i]
		if !bytes.Equal(kv.key, strDate) {
			dst = appendHeaderLine(dst, kv.key, kv.value)
		}
	}

	if h.connectionClose {
		dst = appendHeaderLine(dst, strConnection, strClose)
	}

	return append(dst, strCRLF...)
}

// Header - Represents the headers in http request
type Header map[string][]string

func (h Header) get(key string) string {
	if v := h[key]; len(v) > 0 {
		return v[0]
	}

	return ""
}

func (h Header) set(key string, value string) {
	h[key] = []string{value}
}
