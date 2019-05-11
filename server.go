package main

import (
	"context"
	"fmt"
	"log"
	"net"


	
	"google.golang.org/grpc"

	"google.golang.org/grpc/reflection"
)

type server struct{}

func FatalOnError(message string, err error) {
	if err != nil {
		log.Println(message)
		log.Println(err)
	}
}

func (*server) Signup(context context.Context, req *SignupRequest) (*SignupResponse, error) {

	return nil, nil

}

func main() {

	fmt.Println("Starting gRPC Server")

	lis, err := net.Listen("tcp", "0.0.0.0:50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	service.RegisterEcommerceServer(s, &server{})

	reflection.Register(s)

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

	// mux := http.NewServeMux()

	// mux.HandleFunc("/", home)
	// mux.HandleFunc("/login", login)
	// mux.HandleFunc("/signup", signup)
	// mux.HandleFunc("/editUser", editUser)
	// mux.HandleFunc("/cart", cart)
	// mux.HandleFunc("/checkout", checkout)
	// mux.HandleFunc("/pay", pay)

	// log.Println("Server listening at public web port (:80)")
	// err01 := http.ListenAndServe(":8000", nil)
	// if err01 != nil {
	// 	FatalOnError("Failed to start server.", err01)
	// }

}
