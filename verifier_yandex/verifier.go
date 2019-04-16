package verifier_yandex

import (
	"context"
	"encoding/json"
	"github.com/themakers/identity/identity"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/yandex"
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
	prov := &Verifier{
		oacfg: &oauth2.Config{
			RedirectURL:  cfg.RedirectURL,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Scopes:       cfg.Scopes,
			Endpoint:     yandex.Endpoint,
		},
	}

	return prov
}

func (prov *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{
		Name: "yandex",
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
	u, err := url.Parse("https://login.yandex.ru/info")
	if err != nil {
		return nil, err
	}
	query := url.Values{
		"format": {"json"},
	}
	u.RawQuery = query.Encode()

	client := &http.Client{}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", `W/"OAuth "`+accessToken)
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
	//todo: validate service answer
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}

	return &identity.IdentityData{}, nil
}

type UserInfo struct {
	Login             string   `json:"login"`
	ID                string   `json:"id"`
	ClientId          string   `json:"client_id"`
	OpenidIdentities  []string `json:"openid_identities"`
	OldSocialLogin    string   `json:"old_social_login"`
	DefaultEmail      string   `json:"default_email"`
	Emails            []string `json:"emails"`
	IsAvatarEmpty     bool     `json:"is_avatar_empty"`
	DefaultAvatarId   string   `json:"default_avatar_id"`
	Birthday          string   `json:"birthday"`
	FirstName         string   `json:"first_name"`
	LastName          string   `json:"last_name"`
	DisplayName       string   `json:"display_name"`
	ReposURL          string   `json:"repos_url"`
	EventsURL         string   `json:"events_url"`
	ReceivedEventsURL string   `json:"received_events_url"`
	RealName          string   `json:"real_name"`
	Sex               string   `json:"sex"`
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
