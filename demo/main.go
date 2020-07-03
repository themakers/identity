package main

import (
	"context"
	"fmt"
	"github.com/themakers/identity/backend_mongo"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_email"
	"github.com/themakers/identity/verifier_password"
	"github.com/themakers/identity_svc_http"
	"net/http"
	"strings"
)
const (
	cookiePrefix = "Session "
	cookieName = "cookie"
	)

func main() {
	//STEP 1
	// At the first step we preparing mongodb storer for identities
	// by providing name of database,
	// collection prefix - there will be creating 2 collections(users and authentications) with provided prefix
	// uri for connecting to db

	idenBackend, err := backend_mongo.New(backend_mongo.Options{
		DBName:           "test",
		CollectionPrefix: "idn_",
		URI:              "mongodb://localhost:27017",
	})
	if err != nil {
		panic(err)
	}



	//STEP 2
	// Create service by providing  storer from first step, string key for cookie object from context,
	// list of identities - there only email identity object
	// list of verifiers - there password verifier for realizing classical email-password mechanism
	idenSvc, err := identity_svc_http.New(idenBackend, cookieName, []identity.Identity{
		identity_email.New(),
	},
		[]identity.Verifier{
			verifier_password.New(),
		})
	if err != nil {
		panic(err)
	}

	// STEP 3
	// by calling Register method we get the multiplexer handle all of identity enpoints

	publicIdentityMux, _ := idenSvc.Register()

	// STEP 4
	// we create middleware for converting http auth cookie to Cookie object that realize Cookie interface
	// for having way to improve it with some capabilities like cryptografy, onCookie data etc.
	var chain = onCookieMiddleware(publicIdentityMux, cookieName)

	// STEP 5
	// creating the root multiplexer for chaining out identity. sometimes we need some other activities, isn't it?
	apiMux := http.NewServeMux()

	// connecting the identity multiplexer with root multiplexer
	apiMux.Handle("/identity/", http.StripPrefix("/identity", publicIdentityMux))

	// STEP 6
	// SERVE INCOMING CONNECTIONS
	server := &http.Server{
		Handler: chain,
		Addr: ":8080",
	}

	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}

// Middleware function for get auth token from cookie, create cookie object and put into context
// to throw it into identity service
func onCookieMiddleware(next http.Handler, cookieKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {

		val := ""

		if coo, err := q.Cookie(cookieKey); err == nil {
			val = coo.Value
		}

		if strings.HasPrefix(val, cookiePrefix) {
			val = strings.TrimPrefix(val, cookiePrefix)
		}

		cookie := New(val, w)

		next.ServeHTTP(w, q.WithContext(context.WithValue(q.Context(), cookieKey, cookie)))


	})
}

// Simple Cookie type realizing Cookie interface. Without any amazing things. Just unmarshal cookie from http.cookie
//  and marshal it and set it into response writer

type Cookie struct {
	userID, sessionID string
	w http.ResponseWriter
}

func New(val string, w http.ResponseWriter) *Cookie {
	cookiePair := strings.Split(val,":")

	if len(cookiePair) == 2 {
		return &Cookie{
			userID: "",
			sessionID: "",
		}

	}
	return &Cookie{
		userID: cookiePair[0],
		sessionID: cookiePair[1],
		w: w,
	}
}
func (c *Cookie) setCookie() {
	http.SetCookie(c.w, &http.Cookie{
		Name:     cookieName,
		Value:    fmt.Sprintf("%s%s", cookiePrefix, fmt.Sprintf("%s:%s", c.userID , c.sessionID)),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60, //one month
	})
}

func (c *Cookie) Init() {
	c.userID = "uid"
	c.sessionID = "sid"
}

func (c *Cookie) SetUserID(id string) {
	c.userID = id
	c.setCookie()
}

func (c *Cookie) SetSessionID(id string) {
	c.sessionID = id
	c.setCookie()
}

func (c *Cookie) GetUserID() string {
	return c.userID
}

func (c *Cookie) GetSessionID() string {
	return c.sessionID
}

