package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"strconv"
	"text/template"

	"go.mongodb.org/mongo-driver/bson"

	uuid "github.com/satori/go.uuid"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"

	"google.golang.org/grpc/reflection"

	"github.com/DevManavSethi/EcommerceWebsite/service"
)

var tpl *template.Template
var mongoDBclient *mongo.Client

func init() {
	var err001 error

	err001 = nil

	//------------------------------------------------------------------------

	tpl, err001 = template.ParseGlob("/templates/*")
	if err001 != nil {
		FatalOnError("Error parsing glob templates", err001)
		return
	}

	//-------------------------------------------------------------------

	log.Println("Starting gRPC Server")

	lis, err := net.Listen("tcp", "0.0.0.0:50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	service.RegisterEcommerceServer(s, &server{})

	reflection.Register(s)

	log.Println("gRPC server started!")

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

type server struct{}

func FatalOnError(message string, err error) {
	if err != nil {
		log.Println(message)
		log.Println(err)

	}
}

func (*server) Signup(ctx context.Context, req *service.SignupRequest) (*service.SignupResponse, error) {

	user := req.GetUser()

	pass := user.GetPassword()

	EncryptedPass, err00 := bcrypt.GenerateFromPassword([]byte(pass), 10)

	user.Password = string(EncryptedPass)

	uuid, err000 := uuid.NewV4()
	FatalOnError("Error ", err000)
	user.ID = uuid.String()

	mongoDBclient, err01 := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
	FatalOnError("Error connecting to mongoDB.", err01)

	_, err02 := mongoDBclient.Database("ecommerce").Collection("users").InsertOne(context.TODO(), user)
	if err02 != nil {
		FatalOnError("error insering in mongodb", err02)
		return nil, err02
	}
	return &service.SignupResponse{
		User: user,
	}, nil

}
func (*server) Login(ctx context.Context, req *service.LoginRequest) (*service.LoginResponse, error) {
	email := req.Email
	pass := req.Password
	KeepLoggedIn := req.ToKeepLoggedIn

	mongoDBclient, err01 := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
	FatalOnError("Error connecting to mongoDB.", err01)

	EncryptedPass, err00 := bcrypt.GenerateFromPassword([]byte(pass), 10)

	result := mongoDBclient.Database("ecommerce").Collection("users").FindOne(context.TODO(), bson.M{"email": email, "password": string(EncryptedPass)})

	var user service.User

	result.Decode(&user)

	error001 := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pass))

	if user.Email != email || error001 != nil {
		return nil, error001
	}

	//search mongo

	return &service.LoginResponse{
		User: &user,
	}, nil

}
func (*server) Logout(ctx context.Context, req *service.LogoutRequest) (*service.LogoutResponse, error) {

	//erase cookie

	return &service.LogoutResponse{
		Success: true,
	}, nil

}
func (*server) AddToCart(ctx context.Context, req *service.AddToCartRequest) (*service.AddToCartResponse, error) {
	return nil, nil
}
func (*server) ReadCart(ctx context.Context, req *service.ReadCartRequest) (*service.ReadCartResponse, error) {
	return nil, nil
}
func (*server) UpdateCart(ctx context.Context, req *service.UpdateCartRequest) (*service.UpdateCartResponse, error) {
	return nil, nil
}
func (*server) EmptyCart(ctx context.Context, req *service.EmptyCartRequest) (*service.EmptyCartResponse, error) {
	return nil, nil
}
func (*server) Checkout(ctx context.Context, req *service.CheckoutRequest) (*service.CheckoutResponse, error) {
	return nil, nil
}
func (*server) EditUser(ctx context.Context, req *service.EditUserRequest) (*service.EditUserResponse, error) {

	// userBefore := req.GetUserBefore()
	// userAfter := req.GetUserAfter()

	return nil, nil
}
func (*server) Pay(ctx context.Context, req *service.PayRequest) (*service.PayResponse, error) {
	return nil, nil
}

func main() {

	mux := http.NewServeMux()

	mux.HandleFunc("/", home)
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/signup", signup)
	mux.HandleFunc("/editUser", editUser)
	mux.HandleFunc("/cart", cart)
	mux.HandleFunc("/checkout", checkout)
	mux.HandleFunc("/pay", pay)

	log.Println("Werb Server listening at public web port (:80)")
	err01 := http.ListenAndServe(":8000", mux)
	if err01 != nil {
		FatalOnError("Failed to start server.", err01)
	}

}

func home(w http.ResponseWriter, r *http.Request) {

	cookie, err01 := r.Cookie("ecommerce_user")
	if err01 == http.ErrNoCookie {

		//prompt to login
	} else if err01 != nil {
		//prompt to login
	} else {

		mongoDBclient, err001 := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
		if err001 != nil {
			FatalOnError("Cannot connect to MongoDBclient", err001)
			return
		}

		result := mongoDBclient.Database("ecommerce").Collection("users").FindOne(context.TODO(), bson.M{"id": cookie.Value})

		var user service.User

		er01 := result.Decode(&user)

		FatalOnError("Error finding user from database", er01)

		err02 := tpl.ExecuteTemplate(w, "home.html", user)

		if err02 != nil {
			FatalOnError("Error executing template", err02)
			http.Redirect(w, r, "/", http.StatusNotFound)
		}
	}

}
func login(w http.ResponseWriter, r *http.Request) {

	if r.Response.StatusCode == http.StatusNonAuthoritativeInfo {
		// write wrong email or password
	}
	//--------------------------------------------------------------------

	if r.Method == http.MethodPost {

		cc, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
		if err != nil {
			log.Fatalf("could not connect: %v", err)
		}
		defer cc.Close()

		c := service.NewEcommerceClient(cc)

		//-----------------------------------------------------------------------

		err01 := r.ParseForm()
		FatalOnError("Error parsing form. ", err01)

		//---------------------------------------------------------------------

		req := &service.LoginRequest{
			Email:          r.FormValue("email"),
			Password:       r.FormValue("password"),
			ToKeepLoggedIn: r.FormValue("keepLoggedIn") == "on",
		}

		res, err02 := c.Login(context.TODO(), req)
		if err02 != nil {
			FatalOnError("Error logging in: ", err02)
			http.Redirect(w, r, "/login", http.StatusNonAuthoritativeInfo)
		}

		//-----------------------------------------------------------------------

		user := res.GetUser()

		http.SetCookie(w, &http.Cookie{
			Name:  "ecommerce_user",
			Value: user.ID,
		})

		http.Redirect(w, r, "/", http.StatusAccepted)
	}

	err01 := tpl.ExecuteTemplate(w, "login.html", nil)
	if err01 != nil {
		FatalOnError("Error parsing template login.html", err01)

	}

}
func signup(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodPost {

		cc, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
		if err != nil {
			log.Fatalf("could not connect: %v", err)
		}
		defer cc.Close()

		c := service.NewEcommerceClient(cc)

		//-----------------------------------------------------------------------

		err01 := r.ParseForm()
		FatalOnError("Error parsing form. ", err01)

		//---------------------------------------------------------------------

		phone := r.FormValue("phone")
		phone_int, _ := strconv.Atoi(phone)

		pin := r.FormValue("pin")
		pin_int, _ := strconv.Atoi(pin)

		req := &service.SignupRequest{
			User: &service.User{
				FirstName: r.FormValue("fname"),
				LastName:  r.FormValue("lname"),
				Phone:     int64(phone_int),
				Email:     r.FormValue("email"),
				Address1:  r.FormValue("add1"),
				Address2:  r.FormValue("add2"),
				City:      r.FormValue("city"),
				State:     r.FormValue("state"),
				Country:   r.FormValue("country"),
				Pincode:   pin_int,
				Cart:      nil,
				Funds:     0,
				Member:    false,
				Password:  r.FormValue("pass"),
			},
		}

		res, err02 := c.Signup(context.TODO(), req)
		if err02 != nil {

			FatalOnError("Error signup ", err02)
			http.Redirect(w, r, "/signup", http.StatusNotImplemented)

		}
		http.SetCookie(w, &http.Cookie{
			Name:  "ecommerce_user",
			Value: res.GetUser().GetID(),
		})
		http.Redirect(w, r, "/", http.StatusCreated)

	}

	err01 := tpl.ExecuteTemplate(w, "signup.html", nil)
	if err01 != nil {
		FatalOnError("Error excute template signup", err01)
	}

}
func editUser(w http.ResponseWriter, r *http.Request) {

}
func cart(w http.ResponseWriter, r *http.Request) {

}
func checkout(w http.ResponseWriter, r *http.Request) {

}
func pay(w http.ResponseWriter, r *http.Request) {

}
