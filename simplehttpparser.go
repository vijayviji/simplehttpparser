package SimpleHttpParser

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"net/url"
	"time"
)

type extraHeader struct {
	contentType      string
	connection       string
	transferEncoding string
	date             []byte // written if not nil
	contentLength    []byte // written if not nil
}

type RequestHandler func (request *Request) *Response

type Session struct {
	conn net.Conn

	tpReader *textproto.Reader
	bufR *bufio.Reader
	bufW *bufio.Writer

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

func NewSession(conn net.Conn, readTimeout time.Duration, writeTimeout time.Duration) *Session {
	session := &Session {
		conn: conn,
	}

	//TODO: bufio reader, writer and textproto have to recycled rather using sync.Pool
	session.bufR = bufio.NewReader(session)
	session.bufW = bufio.NewWriter(session)
	session.tpReader = textproto.NewReader(session.bufR)

	session.ReadHeaderTimeout = readTimeout
	session.WriteTimeout = writeTimeout

	return session
}

func (session *Session) Read(p []byte) (n int, err error) {
	n, err = session.conn.Read(p)

	return n, err
}

func (session *Session) Write(p []byte) (n int, err error) {
	n, err = session.conn.Write(p)
	
	return n, err
}

func (session *Session) close() error {
	return session.conn.Close()
}

func (session *Session) Serve(reqHandler RequestHandler) {
	for {
		req, err := session.ReadRequest()
		if err != nil {
			const errorHeaders = "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"

			if isCommonNetReadError(err) {
				return // don't reply
			}

			publicErr := "400 Bad Request"
			if v, ok := err.(badRequestError); ok {
				publicErr = publicErr + ": " + string(v)
			}

			fmt.Fprintf(session.conn, "HTTP/1.1 "+publicErr+errorHeaders+publicErr)
			return
		}

		resp := reqHandler(req)
		session.WriteResponse(resp)

		if session.closeConnection {
			session.close()
			return
		}
	}
}

func (session *Session) writeExtraHeader(header *extraHeader) {
	if header.date != nil {
		session.Write(headerDate)
		session.Write(header.date)
		session.Write(crlf)
	}
	if header.contentLength != nil {
		session.Write(headerContentLength)
		session.Write(header.contentLength)
		session.Write(crlf)
	}
	for i, v := range []string{header.contentType, header.connection, header.transferEncoding} {
		if v != "" {
			session.Write(extraHeaderKeys[i])
			session.Write(colonSpace)
			session.Write([]byte(v))
			session.Write(crlf)
		}
	}
}

func (session *Session) WriteResponse(resp *Response) error {
	var (
		err error
	)

	is11 := false

	if resp.Proto == "HTTP" && resp.ProtoMajor == 1 && resp.ProtoMinor == 1 {
		is11 = true
	}

	session.conn.SetWriteDeadline(time.Now().Add(session.WriteTimeout))

	writeStatusLine(session.bufW, is11, resp.StatusCode, nil)
	session.writeExtraHeader(resp.extraHeader)

	_, err = session.Write(crlf)
	if err != nil {
		return err
	}

	_, err = session.Write(resp.Body)
	if err != nil {
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

func (session *Session) ReadRequest() (*Request, error) {
	var s string

	// Right now we're reading only headers
	session.conn.SetReadDeadline(time.Now().Add(session.readHeaderTimeout()))
	s, err := session.tpReader.ReadLine()
	if err != nil {
		return nil, err
	}

	request := newRequest()

	// First line: GET /index.html HTTP/1.0
	request.Method, request.RequestURI, request.Proto, _ = parseRequestLine(s)

	var ok bool
	if request.ProtoMajor, request.ProtoMinor, ok = parseHTTPVersion(request.Proto); !ok {
		return nil, &badStringError{"malformed HTTP version", request.Proto}
	}

	if !http1ServerSupportsRequest(request) {
		return nil, badRequestError("unsupported protocol version")
	}

	// read Headers here
	mimeHeader, err := session.tpReader.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	request.Header = Header(mimeHeader)

	session.closeConnection = shouldClose(request.ProtoMajor, request.ProtoMinor, request.Header, false)

	// TODO: Read Body of the request

	return  request, nil
}


type Request struct {
	RequestURI string
	Proto string
	ProtoMajor int
	ProtoMinor int

	Method string
	Header Header
	Form url.Values
}

func newRequest() *Request {
	return &Request{}
}


type Response struct {
	req *Request

	Proto string
	ProtoMajor int
	ProtoMinor int

	StatusCode    int
	extraHeader   *extraHeader
	Header        Header
	ContentLength int64
	Body          []byte
}

func NewResponse(req *Request) *Response {
	return &Response{
		req: req,

		ProtoMajor:req.ProtoMajor,
		ProtoMinor:req.ProtoMinor,
		Proto:req.Proto,
	}
}

func newExtraHeader(contentType string, req *Request) *extraHeader {
	return & extraHeader{
		contentType: contentType,
		date: []byte(time.Now().Format(TimeFormat)),
		connection:req.Header.get("connection"),
	}
}

func (resp *Response) SetSuccess(contentType string, body []byte) {
	resp.StatusCode = 200
	resp.Body = body
	resp.extraHeader = newExtraHeader(contentType, resp.req)
}

func (resp *Response) SetError(statusCode int) {
	resp.StatusCode = statusCode
	resp.extraHeader = newExtraHeader("text/html", resp.req)
}


type Header map[string][]string

// get is like Get, but key must already be in CanonicalHeaderKey form.
func (h Header) get(key string) string {
	if v := h[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}
