package identity_svc_http

type VerifierDetailsResp struct {
	IdentitiyNames []string           `json:"IdentitiyNames"`
	Verifiers      []*VerifierDetails `json:"Verifiers"`
}

type VerifierDetails struct {
	Name           string `json:"Name"`
	IdentityName   string `json:"IdentityName"`
	SupportRegular bool   `json:"SupportRegular"`
	SupportReverse bool   `json:"SupportReverse"`
	SupportOAuth2  bool   `json:"SupportOAuth2"`
	SupportStatic  bool   `json:"SupportStatic"`
}

type Status struct {
	Token string `json:"Token"`

	Authenticating *StatusAuthenticating `json:"Authenticating"`
	Authenticated  *StatusAuthenticated  `json:"Authenticating"`
}
type StatusAuthenticating struct {
	Objective        string  `json:"Objective"`
	RemainingFactors int                      `json:"RemainingFactors"`
	CompletedFactors []StatusCompletedFactors `json:"CompletedFactors"`
}
type StatusCompletedFactors struct {
	VerifierName string `json:"VerifierName"`
	IdentityName string `json:"IdentityName"`
	Identity     string `json:"Identity"`
}

type StatusAuthenticated struct {
	User string `json:"User"`
}

type ListMyIdentitiesAndVerifiersResp struct {
	Identities           []*IdentityData `json:"Identities"`
	Verifiers            []string        `json:"Verifiers"`
}

type IdentityData struct {
	Name                 string   `json:"Name"`
	Identity             string   `json:"Identity"`
}

type StartResp struct {
	Directions           map[string]string `json:"Directions"`
}

type StartReq struct {
	VerifierName         string            `json:"VerifierName"`
	IdentityName         string            `json:"IdentityName"`
	Identity             string            `json:"Identity"`
	Args                 map[string]string `json:"Args"`
	Values               map[string]string `json:"Values"`
}

type VerifyReq struct {
	VerifierName         string   `json:"VerifierName"`
	VerificationCode     string   `json:"VerificationCode"`
	IdentityName         string   `json:"IdentityName"`
	Identity             string   `json:"Identity"`
}

type LoginAsReq struct {
	User                 string   `json:"User"`
}

type LoginAsResp struct {
	Session              string   `json:"Session"`
	User                 string   `json:"User"`
	Error                string   `json:"Error"`
}