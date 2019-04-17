package verifier_google

import (
	"context"
	"encoding/json"
	"github.com/themakers/identity/identity"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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

const fields = "addresses,ageRanges,biographies,birthdays,braggingRights,coverPhotos,emailAddresses,events,genders,imClients,interests,locales,memberships,metadata,names,nicknames,occupations,organizations,phoneNumbers,photos,relations,relationshipInterests,relationshipStatuses,residences,sipAddresses,skills,taglines,urls"

type Verifier struct {
	oacfg *oauth2.Config
}

func New(cfg Config) *Verifier {
	cfg.Scopes = ensureContains(cfg.Scopes, "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/user.phonenumbers.read", "https://www.googleapis.com/auth/user.birthday.read", "https://www.googleapis.com/auth/user.addresses.read", "https://www.googleapis.com/auth/user.emails.read")
	prov := &Verifier{
		oacfg: &oauth2.Config{
			RedirectURL:  cfg.RedirectURL,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Scopes:       cfg.Scopes,
			Endpoint:     google.Endpoint,
		},
	}

	return prov
}

func (prov *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{
		Name: "google",
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
	u, err := url.Parse("https://people.googleapis.com/v1/people/me")
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
	//todo: validate service answer
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}

	return &identity.IdentityData{}, nil
}

type Source struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

type Metadata struct {
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
	Source   Source `json:"source"`
}

type UserInfo struct {
	ResourceName string `json:"resourceName"`
	Etag         string `json:"etag"`
	Metadata     struct {
		Sources []struct {
			Type            string `json:"type"`
			Id              string `json:"id"`
			Etag            string `json:"etag"`
			ProfileMetadata struct {
				ObjectType string   `json:"objectType"`
				UserTypes  []string `json:"userTypes"`
			} `json:"profileMetadata"`
		} `json:"sources"`
		ObjectType string `json:"objectType"`
	} `json:"metadata"`
	Locales []struct {
		Metadata Metadata `json:"metadata"`
		Value    string   `json:"value"`
	} `json:"locales"`
	Names struct {
		Metadata             Metadata `json:"metadata"`
		DisplayName          string   `json:"displayName"`
		FamilyName           string   `json:"familyName"`
		GivenName            string   `json:"givenName"`
		DisplayNameLastFirst string   `json:"displayNameLastFirst"`
	} `json:"names"`
	CoverPhotos []struct {
		Metadata Metadata `json:"metadata"`
		Url      string   `json:"url"`
		Default  bool     `json:"default"`
	} `json:"coverPhotos"`
	Photos []struct {
		Metadata Metadata `json:"metadata"`
		Url      string   `json:"url"`
	} `json:"photos"`
	Birthdays []struct {
		Metadata Metadata `json:"metadata"`
		Date     []struct {
			Year  int `json:"year"`
			Month int `json:"month"`
			Day   int `json:"day"`
		} `json:"date"`
	} `json:"birthdays"`
	EmailAddresses []struct {
		Metadata Metadata `json:"metadata"`
		Value    string   `json:"value"`
	} `json:"emailAddresses"`
	Urls []struct {
		Metadata      Metadata `json:"metadata"`
		Value         string   `json:"value"`
		Type          string   `json:"type"`
		FormattedType string   `json:"formattedType"`
	} `json:"urls"`
	Organizations []struct {
		Metadata      Metadata `json:"metadata"`
		Type          string   `json:"type"`
		FormattedType string   `json:"formattedType"`
		EndDate       struct {
			Year  int `json:"year"`
			Month int `json:"month"`
			Day   int `json:"day"`
		} `json:"endDate"`
		Current bool   `json:"current"`
		Name    string `json:"name"`
	} `json:"organizations"`
	AgeRanges []struct {
		Metadata Metadata `json:"metadata"`
		AgeRange string   `json:"ageRange"`
	} `json:"ageRanges"`
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