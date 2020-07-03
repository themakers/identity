# identity


TheMakers.Identity package provide a both inline and standalone service solution for user authorization with a wide range  of authoriaztion paths, like static login-password, regular code-by-sms, or totp and oauth.

  ## Requrements
  
  - golang =>1.10
  - mongodb =>4.0
  - github.com/themakers/identity_svc_http - by default grpc
  
  ## Install
  
  Just pull sources to your library
  
  ```
    go get github.com/themakers/identity
  ```
  
  And import it 
  
  ```
  import "github.com/themakers/identity"
  ```
  
  ## QuickStart
  
  First of all identity was developed for grpc, but http is most commonly used.
  
  First step is preparing storage for identity data. Next we creating identity service by providing storage, cookieKey, list of identity agents and list of verifiers for them. And at the last step we providing the root path '/identity' for our IdentityService and start listening. 
  
  ``` 
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
  	//STEP ONE
  	idenBackend, err := backend_mongo.New(backend_mongo.Options{ // At the first step we preparing mongodb storer for identities
  		DBName:           "test",                                   // by providing name of database,
  		CollectionPrefix: "idn_",                                   // collection prefix - there will be creating 2 collections(users and authentications) with provided prefix
  		URI:              "mongodb://localhost:27017",              // uri for connecting to db
  	})
  	if err != nil {
  		panic(err)
  	}
  
  
  
  	//STEP TWO
  	idenSvc, err := identity_svc_http.New(idenBackend, cookieName, []identity.Identity{ // Create service by providing  storer from first step, string key for cookie object from context,
  		identity_email.New(),                                                                         // list of identities - there only email identity object
  	},
  		[]identity.Verifier{
  			verifier_password.New(),                                                                     // list of verifiers - there password verifier for realizing classical email-password mechanism
  		})
  	if err != nil {
  		panic(err)
  	}
  	// STEP THREE
  	publicIdentityMux, _ := idenSvc.Register() // by calling Register method we get the multiplexer with handling all of identity enpoints
  
  	var chain = onCookieMiddleware(publicIdentityMux, cookieName)
  
  	apiMux := http.NewServeMux() // creating the root multiplexer
  
  	apiMux.Handle("/identity/", http.StripPrefix("/identity", publicIdentityMux)) // connecting the identity multiplexer with root multiplexer
  
  	server := &http.Server{
  		Handler: chain,
  		Addr: ":8080",
  	}
  
  	if err := server.ListenAndServe(); err != nil {
  		panic(err)
  	}
  }
  
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
  		defer cookie.SetCookie()
  
  		next.ServeHTTP(w, q.WithContext(context.WithValue(q.Context(), cookieKey, cookie)))
  
  
  	})
  }
  
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
  func (c *Cookie) SetCookie() {
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
  }
  
  func (c *Cookie) SetSessionID(id string) {
  	c.sessionID = id
  }
  
  func (c *Cookie) GetUserID() string {
  	return c.userID
  }
  
  func (c *Cookie) GetSessionID() string {
  	return c.sessionID
  }
  

  

  ```
  
  Now you can send your auth requests  to the endpoint   localhost:8080/identity/. For example http://localhost:8080/ListSupportedIdentitiesAndVerifiers
  
  ## API
  
  You could use https://github.com/themakers/identity_svc_grpc/blob/master/identity_svc_test.go  as an example.