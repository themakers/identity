package provider_github

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/themakers/identity/identity"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

var _ identity.OAuth2Provider = new(Provider)

type Provider struct {
	oacfg *oauth2.Config
}

func New(cfg Config) *Provider {
	cfg.Scopes = ensureContains(cfg.Scopes, "read:user", "user:email")
	prov := &Provider{
		oacfg: &oauth2.Config{
			RedirectURL:  cfg.RedirectURL,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Scopes:       cfg.Scopes,
			Endpoint:     github.Endpoint,
		},
	}

	return prov
}

func (prov *Provider) Info() identity.ProviderInfo {
	return identity.ProviderInfo{
		Name: "github",
	}
}

func (prov *Provider) NormalizeIdentity(idn string) string {
	return idn
}

func (prov *Provider) GetOAuth2URL(state string) string {
	return prov.oacfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (prov *Provider) HandleOAuth2Callback(ctx context.Context, code string) (token *oauth2.Token, err error) {
	token, err = prov.oacfg.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (prov *Provider) GetOAuth2Identity(ctx context.Context, accessToken string) (iden *identity.Identity, err error) {
	u, err := url.Parse("https://api.github.com/user")
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

	if err := json.Unmarshal(data, user); err != nil {
		return nil, err
	}

	return &identity.Identity{
		Provider: prov.Info().Name,
		ID:       fmt.Sprint(user.ID),
		Fields: identity.IdentityFields{
			"login":  user.Login,
			"email":  user.Email,
			"name":   user.Name,
			"avatar": user.AvatarURL,
		},
	}, nil
}

type UserInfo struct {
	Login                   string    `json:"login"`
	ID                      int       `json:"id"`
	NodeID                  string    `json:"node_id"`
	AvatarURL               string    `json:"avatar_url"`
	GravatarID              string    `json:"gravatar_id"`
	URL                     string    `json:"url"`
	HTMLURL                 string    `json:"html_url"`
	FollowersURL            string    `json:"followers_url"`
	FollowingURL            string    `json:"following_url"`
	GistsURL                string    `json:"gists_url"`
	StarredURL              string    `json:"starred_url"`
	SubscriptionsURL        string    `json:"subscriptions_url"`
	OrganizationsURL        string    `json:"organizations_url"`
	ReposURL                string    `json:"repos_url"`
	EventsURL               string    `json:"events_url"`
	ReceivedEventsURL       string    `json:"received_events_url"`
	Type                    string    `json:"type"`
	SiteAdmin               bool      `json:"site_admin"`
	Name                    string    `json:"name"`
	Company                 string    `json:"company"`
	Blog                    string    `json:"blog"`
	Location                string    `json:"location"`
	Email                   string    `json:"email"`
	Hireable                bool      `json:"hireable"`
	Bio                     string    `json:"bio"`
	PublicRepos             int       `json:"public_repos"`
	PublicGists             int       `json:"public_gists"`
	Followers               int       `json:"followers"`
	Following               int       `json:"following"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
	TotalPrivateRepos       int       `json:"total_private_repos"`
	OwnedPrivateRepos       int       `json:"owned_private_repos"`
	PrivateGists            int       `json:"private_gists"`
	DiskUsage               int       `json:"disk_usage"`
	Collaborators           int       `json:"collaborators"`
	TwoFactorAuthentication bool      `json:"two_factor_authentication"`
	Plan                    struct {
		Name          string `json:"name"`
		Space         int    `json:"space"`
		PrivateRepos  int    `json:"private_repos"`
		Collaborators int    `json:"collaborators"`
	} `json:"plan"`
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
