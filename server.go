package main

//--go_out=plugins=grpc:.
import (
	"context"
	"errors"
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

type ProductToSend struct {
	Product      *service.VariantProduct
	SuperProduct *service.Product
}

func init() {
	var err001 error

	err001 = nil

	//------------------------------------------------------------------------

	tpl, err001 = template.ParseGlob("./templates/*")
	if err001 != nil {
		FatalOnError("Error parsing glob templates", err001)
		return
	}

	//-------------------------------------------------------------------

	go func() {
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
	}()
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

	//--------------------------------
	EncryptedPass, err00 := bcrypt.GenerateFromPassword([]byte(pass), 10)
	if err00 != nil {
		FatalOnError("Error encrypting password", err00)
	}
	user.Password = string(EncryptedPass)
	//-------------------------------
	uuid, err000 := uuid.NewV4()
	FatalOnError("Error ", err000)
	user.ID = uuid.String()

	//---------------------------------------------------------------------------------

	mongoDBclient, err01 := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
	FatalOnError("Error connecting to mongoDB.", err01)

	_, err02 := mongoDBclient.Database("ecommerce").Collection("users").InsertOne(context.TODO(), user)
	if err02 != nil {
		FatalOnError("error insering in mongodb", err02)
		return nil, err02
	}

	//------------------------------------------------------------------------------------
	return &service.SignupResponse{
		User: user,
	}, nil

}
func (*server) Login(ctx context.Context, req *service.LoginRequest) (*service.LoginResponse, error) {
	email := req.GetEmail()
	pass := req.GetPassword()
	//KeepLoggedIn := req.ToKeepLoggedIn

	mongoDBclient, err01 := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
	FatalOnError("Error connecting to mongoDB.", err01)

	//EncryptedPass, err00 := bcrypt.GenerateFromPassword([]byte(pass), 10)

	//FatalOnError("Error encrypting password", err00)

	result := mongoDBclient.Database("ecommerce").Collection("users").FindOne(context.TODO(), bson.M{"email": email})
	if result == nil {

		return nil, errors.New("User not found")

	}
	var user *service.User

	err02 := result.Decode(&user)
	if err02 != nil {
		FatalOnError("Error finding from mongo", err02)
		return nil, err02

	}

	error001 := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pass))

	if user.Email != email || error001 != nil {
		return nil, error001
	}

	return &service.LoginResponse{
		User: user,
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
	mux.HandleFunc("/product", product)
	mux.HandleFunc("/cart", cart)
	mux.HandleFunc("/checkout", checkout)
	mux.HandleFunc("/pay", pay)
	mux.Handle("/favicon.ico", http.NotFoundHandler())

	log.Println("Werb Server listening at public web port (:80)")
	err01 := http.ListenAndServe(":8000", mux)
	if err01 != nil {
		FatalOnError("Failed to start server.", err01)
	}

}

func product(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodPost {

		err01 := r.ParseForm()
		if err01 != nil {

		}

		id := r.FormValue("id")
		quantity := r.FormValue("quantity")
		comment := r.FormValue("comment")

		cookie, err02 := r.Cookie("ecommerce_cart")
		if err02 != nil || err02 == http.ErrNoCookie {

			http.SetCookie(w, &http.Cookie{
				Name:  "ecommerce_cart",
				Value: id + ":" + quantity + ":" + comment + "|",
			})
		} else {
			cookie.Value = cookie.Value + id + ":" + quantity + ":" + comment + "|"
			http.SetCookie(w, cookie)
		}

	}

	keys, ok := r.URL.Query()["id"]

	if !ok || len(keys[0]) < 1 {
		log.Println("Url Param 'key' is missing")
		return
	}

	id := keys[0]
	id_int, _ := strconv.Atoi(id)

	mongoDBclient, err001 := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
	if err001 != nil {
		FatalOnError("Cannot connect to MongoDBclient", err001)
		return
	}

	result := mongoDBclient.Database("ecommerce").Collection("products").FindOne(context.TODO(), bson.M{"id": id_int})

	var product *service.VariantProduct

	er01 := result.Decode(&product)

	if product == nil || er01 != nil {
		FatalOnError("Error finding user from database", er01)
	} else {

		MainProductName := product.GetMainProductName()
		result := mongoDBclient.Database("ecommerce").Collection("main_products").FindOne(context.TODO(), bson.M{"name": MainProductName})

		var MainProduct *service.Product

		er01 := result.Decode(&MainProduct)

		if MainProduct == nil || er01 != nil {
			FatalOnError("Error finding user from database", er01)
		} else {

			var ProductToSend ProductToSend
			ProductToSend.Product = product
			ProductToSend.SuperProduct = MainProduct

			err02 := tpl.ExecuteTemplate(w, "product.html", ProductToSend)
			if err02 != nil {

			}

		}

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

		var user *service.User

		er01 := result.Decode(&user)

		FatalOnError("Error finding user from database", er01)

		if user == nil {

			err02 := tpl.ExecuteTemplate(w, "home.html", nil)

			if err02 != nil {
				FatalOnError("Error executing template", err02)
				http.Redirect(w, r, "/", http.StatusNotFound)
			}

		}

		err02 := tpl.ExecuteTemplate(w, "home.html", user)

		if err02 != nil {
			FatalOnError("Error executing template", err02)
			http.Redirect(w, r, "/", http.StatusNotFound)
		}
	}

}
func login(w http.ResponseWriter, r *http.Request) {

	// if r.Response.StatusCode == http.StatusNonAuthoritativeInfo {
	// 	// write wrong email or password
	// }
	//--------------------------------------------------------------------

	cookie, err0001 := r.Cookie("ecommerce_user")
	if err0001 != nil || err0001 == http.ErrNoCookie {
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
				ToKeepLoggedIn: true,
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
				Value: user.GetID(),
			})

			http.Redirect(w, r, "/", http.StatusAccepted)
		} else {

			err01 := tpl.ExecuteTemplate(w, "login.html", nil)
			if err01 != nil {
				FatalOnError("Error parsing template login.html", err01)

			}
		}

	} else {

		mongoDBclient, err001 := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
		if err001 != nil {
			FatalOnError("Cannot connect to MongoDBclient", err001)
			return
		}

		result := mongoDBclient.Database("ecommerce").Collection("users").FindOne(context.TODO(), bson.M{"id": cookie.Value})

		var user *service.User

		er01 := result.Decode(&user)

		FatalOnError("Error finding user from database", er01)

		err01 := tpl.ExecuteTemplate(w, "login_user_already_logged_in.html", *user)
		if err01 != nil {
			FatalOnError("Error parsing template login.html", err01)

		}
	}

}
func signup(w http.ResponseWriter, r *http.Request) {

	cookie, err1 := r.Cookie("ecommerce_user")

	if err1 != nil || err1 == http.ErrNoCookie {

		if r.Method == http.MethodPost {

			cc, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
			if err != nil {
				log.Fatalf("could not connect grpc server: %v", err)
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
					Pincode:   int64(pin_int),
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

			user := res.GetUser()

			err03 := tpl.ExecuteTemplate(w, "signup.html", *user)
			if err03 != nil {
				FatalOnError("Error execute template signup.html", err01)
			}

		} else {

			err01 := tpl.ExecuteTemplate(w, "signup.html", nil)
			if err01 != nil {
				FatalOnError("Error execute template signup.html", err01)
			}
		}

	} else {

		mongoDBclient, err001 := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
		if err001 != nil {
			FatalOnError("Cannot connect to MongoDBclient", err001)
			return
		}

		result := mongoDBclient.Database("ecommerce").Collection("users").FindOne(context.TODO(), bson.M{"id": cookie.Value})

		var user *service.User

		er01 := result.Decode(&user)

		FatalOnError("Error finding user from database", er01)

		err01 := tpl.ExecuteTemplate(w, "signup_user_already_logged_in.html", *user)
		if err01 != nil {
			FatalOnError("Error execute template signup.html", err01)
		}
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

//{"name": "Rajdhani Besan", "variants": [{"name": "Rajdhani Besan 500 grams", "categoryid":1, "id":1, "imagepaths":["/images/rajdhanibesan500_1.jpg","/images/rajdhanibesan500_2.jpg","/images/rajdhanibesan500_3.jpg", "/images/rajdhanibesan500_4.jpg", "/images/rajdhanibesan500_5.jpg"],"unitprice":45, "mrp": 55, "cashback":0, "unit": "Kg","size":0.5,"memberprice":43,"mainproductname":"Rajdhani Besan", "xxx_nounkeyedliteral":{}, "xxx_unrecognized": null, "xxx_sizecache":0},{"name": "Rajdhani Besan 1 Kg", "categoryid":1, "id":2, "imagepaths":["/images/rajdhanibesan1000_1.jpg","/images/rajdhanibesan1000_2.jpg","/images/rajdhanibesan1000_3.jpg", "/images/rajdhanibesan1000_4.jpg", "/images/rajdhanibesan1000_5.jpg"],"unitprice":80, "mrp": 105, "cashback":0, "unit": "Kg","size":1,"memberprice":85,"mainproductname":"Rajdhani Besan", "xxx_nounkeyedliteral":{}, "xxx_unrecognized": null, "xxx_sizecache":0}], "xxx_nounkeyedliteral":{}, "xxx_unrecognized": null, "xxx_sizecache":0}
