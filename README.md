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
   "github.com/themakers/identity/backend_mongo"
   "github.com/themakers/identity/identity"
   "github.com/themakers/identity/identity_email"
   "github.com/themakers/identity/verifier_password"
   "github.com/themakers/identity_svc_http"
   "net/http"
  )
  
  func main() {
     idenBackend, err := backend_mongo.New(backend_mongo.Options{
      DBName:           "test",
      CollectionPrefix: "idn_",
      URI:              "mongodb://localhost:27017",
     })
     if err != nil {
      panic(err)
     }
  
  
     idenSvc, err := identity_svc_http.New(idenBackend, "pancake", []identity.Identity{
      identity_email.New(),
     },
      []identity.Verifier{
       verifier_password.New(),
      })
     if err != nil {
      panic(err)
     }
  
     publicIdentityMux, _ := idenSvc.Register()
  
     apiMux := http.NewServeMux()
  
      apiMux.Handle("/identity/", http.StripPrefix("/identity", publicIdentityMux))
  
      server := &http.Server{
          Handler: apiMux,
          Addr: ":8080",
      }
  
      if err := server.ListenAndServe(); err != nil {
          panic(err)
      }

  ```
  
  Now you can send your auth requests  to the endpoint   localhost:8080/identity/. For example localhost:8080/identity/ListSupportedIdentitiesAndVerifiers
  
  ## API