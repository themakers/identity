package verifier_facebook

import (
	"context"
	"encoding/json"
	"github.com/themakers/identity/identity"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
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

const fields = "id,address,age_range,birthday,context,email,employee_number,favorite_athletes,favorite_teams,first_name,gender,hometown,inspirational_people,installed,is_shared_login,languages,last_name,location,meeting_for,middle_name,name,name_format,profile_pic,public_key,quotes,sports"

type Verifier struct {
	oacfg *oauth2.Config
}

func New(cfg Config) *Verifier {
	cfg.Scopes = ensureContains(cfg.Scopes, "default", "email", "user_age_range", "user_birthday", "user_gender", "user_hometown", "user_link", "user_link")
	prov := &Verifier{
		oacfg: &oauth2.Config{
			RedirectURL:  cfg.RedirectURL,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Scopes:       cfg.Scopes,
			Endpoint:     facebook.Endpoint,
		},
	}

	return prov
}

func (prov *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{
		Name: "facebook",
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
	u, err := url.Parse("https://graph.facebook.com/me")
	if err != nil {
		return nil, err
	}
	query := url.Values{
		"fields":       {fields},
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

type UserInfo struct {
	Id      int `json:"id"`
	Address struct {
		City        string  `json:"city"`
		CityId      uint32  `json:"city_id"`
		Country     string  `json:"country"`
		CountryCode string  `json:"country_code"`
		Latitude    float32 `json:"latitude"`
		LocatedIn   int     `json:"located_in"`
		Name        string  `json:"name"`
		Region      string  `json:"region"`
		RegionId    uint32  `json:"region_id"`
		State       string  `json:"state"`
		Street      string  `json:"street"`
		Zip         string  `json:"zip"`
	} `json:"address"`
	Age_range struct {
		Max uint32 `json:"max"`
		Min uint32 `json:"min"`
	} `json:"age_range"`
	Birthday string `json:"birthday"`
	Context  struct {
		Context string `json:"context"`
	} `json:"context"`
	Email            string `json:"email"`
	EmployeeNumber   string `json:"employee_number"`
	FavoriteAthletes []struct {
		Id          string `json:"id"`
		Description string `json:"description"`
		Name        string `json:"name"`
	} `json:"favorite_athletes"`
	FavoriteTeams []struct {
		Id          string `json:"id"`
		Description string `json:"description"`
		Name        string `json:"name"`
	} `json:"favorite_teams"`
	FirstName string `json:"first_name"`
	Gender    string `json:"gender"`
	Hometown  []struct {
		Id    string `json:"id"`
		About string `json:"about"`
		Name  string `json:"name"`
	} `json:"hometown"`
	InspirationalPeople []struct {
		Id          string `json:"id"`
		Description string `json:"description"`
		Name        string `json:"name"`
	} `json:"inspirational_people"`
	Installed     bool     `json:"installed"`
	InterestedIn  []string `json:"interested_in"`
	IsSharedLogin bool     `json:"is_shared_login"`
	LastName      string   `json:"last_name"`
	Location      struct {
		Id    string `json:"id"`
		About string `json:"about"`
		Name  string `json:"name"`
	} `json:"location"`
	MeetingFor []string `json:"meeting_for"`
	MiddleName string   `json:"middle_name"`
	Name       string   `json:"name"`
	NameFormat string   `json:"name_format"`
	ProfilePic string   `json:"profile_pic"`
	PublicKey  string   `json:"public_key"`
	Quotes     string   `json:"quotes"`
	Sports     []struct {
		Id          string `json:"id"`
		Description string `json:"description"`
		Name        string `json:"name"`
	} `json:"sports"`
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
