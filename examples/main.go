package main

import (
	"fmt"
	"github.com/valyala/fasthttp"
	"github.com/vijayviji/simplehttpparser"
	"net"
	"os"
)

func requestHandlerFastHTTP(ctx *fasthttp.RequestCtx) {
	ctx.SuccessString("text/plain", "adsf")
}

func requestHandler(req *simplehttpparser.Request) *simplehttpparser.Response {
	fmt.Println("Inside requestHandler")
	resp := simplehttpparser.NewResponse(req)
	resp.SetSuccess("text/html", nil)
	fmt.Println("Returning resp")
	return resp
}

func handleConnection(conn net.Conn) {
	session := simplehttpparser.NewSession(conn, 0, 0, 0)

	fmt.Println("Trying to serve")
	session.Serve(requestHandler)
}

func handleConnectionFastHTTP(conn net.Conn) {
	fasthttp.ServeConn(conn, requestHandlerFastHTTP)
}

func main() {
	l, err := net.Listen("tcp", ":4080")
	if err != nil {
		fmt.Println("Error listening=", err.Error())
		os.Exit(1)
	}

	defer l.Close()

	for {
		conn, err := l.Accept()
		// log error and continue to accept new connections
		if err != nil {
			fmt.Println("Error accepting client connection ", err.Error())
			continue
		}

		//go handleConnection(conn)
		go handleConnectionFastHTTP(conn)
	}
}
