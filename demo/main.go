package main

import (
	"google.golang.org/grpc"
	"net"
)

func perror(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	server := grpc.NewServer()

	{
		lis, err := net.Listen("tcp", ":7532")
		perror(err)
		perror(server.Serve(lis))
	}
}
