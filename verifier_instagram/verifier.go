package verifier_instagram

import (
	"context"
	"encoding/json"
	"github.com/themakers/identity/identity"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/instagram"
	"io/ioutil"
	"net/http"
	"net/url"
)

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

var _ identity.OAuth2Verification = new(Verifier)

type Verifier struct {
	oacfg *oauth2.Config
}

func New(cfg Config) *Verifier {
	cfg.Scopes = ensureContains(cfg.Scopes, "basic")
	prov := &Verifier{
		oacfg: &oauth2.Config{
			RedirectURL:  cfg.RedirectURL,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Scopes:       cfg.Scopes,
			Endpoint:     instagram.Endpoint,
		},
	}

	return prov
}

func (prov *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{
		Name: "instagram",
	}
}

func (prov *Verifier) NormalizeIdentity(idn string) string {
	return idn
}

func (prov *Verifier) GetOAuth2URL(state string) string {
	return prov.oacfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (prov *Verifier) HandleOAuth2Callback(ctx context.Context, code string) (token *oauth2.Token, err error) {
	token, err = prov.oacfg.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (prov *Verifier) GetOAuth2Identity(ctx context.Context, accessToken string) (iden *identity.IdentityData, err error) {
	u, err := url.Parse("https://api.instagram.com/v1/users/self/")
	if err != nil {
		return nil, err
	}
	query := url.Values{
		"access_token": {accessToken},
	}
	u.RawQuery = query.Encode()

	client := &http.Client{}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var user UserInfo
	var data_wrapper data_wrapper
	if err := json.Unmarshal(data, &data_wrapper); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(data_wrapper.Data), &user); err != nil {
		return nil, err
	}

	return &identity.IdentityData{}, nil
}

type data_wrapper struct {
	Data string `json:"data"`
}

type UserInfo struct {
	ID             int    `json:"id"`
	Username       string `json:"username"`
	FullName       string `json:"full_name"`
	ProfilePicture string `json:"profile_picture"`
	Bio            string `json:"bio"`
	Website        string `json:"website"`
	IsBusiness     bool   `json:"is_business"`
	Counts         struct {
		Media      int `json:"media"`
		Follows    int `json:"follows"`
		FollowedBy int `json:"followed_by"`
	} `json:"counts"`
}

func ensureContains(scopes []string, requireed ...string) []string {
	for _, req := range requireed {
		found := false
		for _, scope := range scopes {
			if scope == req {
				found = true
				break
			}
		}
		if !found {
			scopes = append(scopes, req)
		}
	}
	return scopes
}
