package SimpleHttpParser

import (
	"SimpleHttpParser"
	"fmt"
	"net"
	"os"
)

func requestHandler(req *SimpleHttpParser.Request) *SimpleHttpParser.Response {
	resp := SimpleHttpParser.NewResponse(req)
	resp.SetSuccess("text/html", nil)

	return resp
}

func handleConnection(conn net.Conn) {
	session := SimpleHttpParser.NewSession(conn, 0, 0)
	session.Serve(requestHandler)
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

		go handleConnection(conn)
	}
}

