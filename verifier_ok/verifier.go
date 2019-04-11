package verifier_github

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"github.com/themakers/identity/identity"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/odnoklassniki"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

const application_key = "application_key"
const fields = "UID,LOCALE,FIRST_NAME,LAST_NAME,NAME,GENDER,AGE,BIRTHDAY,HAS_EMAIL,CURRENT_STATUS,CURRENT_STATUS_ID,CURRENT_STATUS_DATE,PHOTO_ID,PIC1024X768,EMAIL,LOCATION,INTERNAL_PIC_ALLOW_EMPTY,PIC_FULL,PIC_BASE,VIP,HAS_PHONE,PREMIUM,URL_PROFILE,URL_PROFILE_MOBILE"

var _ identity.OAuth2Verification = new(Verifier)

type Verifier struct {
	oacfg *oauth2.Config
}

func New(cfg Config) *Verifier {
	cfg.Scopes = ensureContains(cfg.Scopes, "read:user", "user:email")
	prov := &Verifier{
		oacfg: &oauth2.Config{
			RedirectURL:  cfg.RedirectURL,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Scopes:       cfg.Scopes,
			Endpoint:     odnoklassniki.Endpoint,
		},
	}

	return prov
}

func (prov *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{
		Name: "odnoklassniki",
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

func strMD5(str string) string {
	tstr := md5.Sum([]byte(str))
	return hex.EncodeToString(tstr[:])
}

func (prov *Verifier) GetOAuth2Identity(ctx context.Context, accessToken string) (iden *identity.IdentityData, err error) {
	//get access token
	u, err := url.Parse("https://api.ok.ru/fb.do")
	if err != nil {
		return nil, err
	}
	var session_secret_key = strMD5(accessToken + application_key)
	string4sig := strMD5("application_key=" + application_key + "fields=" + fields + "format=jsonmethod=users.getCurrentUser" + session_secret_key)
	query := url.Values{
		"application_key": {application_key},
		"fields":          {fields},
		"format":          {"json"},
		"method":          {"users.getCurrentUser"},
		"sig": {
			strings.ToLower(
				string4sig,
			),
		},
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
	var response response
	//todo: validate service answer
	if err := json.Unmarshal(data, response); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(response.Response), user); err != nil {
		return nil, err
	}

	return &identity.IdentityData{}, nil
}

type response struct {
	Response string `json:"response"`
}

type UserInfo struct {
	Accessible                        bool   `json:"accessible"`
	Age                               int    `json:"age"`
	Allow_add_to_friend               bool   `json:"allow_add_to_friend"`
	Allows_anonym_access              bool   `json:"allows_anonym_access"`
	Allows_messaging_only_for_friends bool   `json:"allows_messaging_only_for_friends"`
	Birthday                          string `json:"birthday"`
	BirthdaySet                       bool   `json:"birthdaySet"`
	Blocked                           bool   `json:"blocked"`
	Blocks                            bool   `json:"blocks"`
	Can_use_referral_invite           bool   `json:"can_use_referral_invite"`
	Can_vcall                         bool   `json:"can_vcall"`
	Can_vmail                         bool   `json:"can_vmail"`
	Capabilities                      string `json:"capabilities"`
	City_of_birth                     string `json:"city_of_birth"`
	Common_friends_count              int    `json:"common_friends_count"`
	Current_location                  struct {
		Altitude  float32 `json:"altitude"`
		CellId    int     `json:"cellId"`
		City      string  `json:"city"`
		Country   string  `json:"country"`
		IpAddress string  `json:"ipAddress"`
		Latitude  float32 `json:"altitude"`
		Longitude float32 `json:"longitude"`
	} `json:"current_location"`
	Current_status        string `json:"current_status"`
	Email                 string `json:"email"`
	Executor              bool   `json:"executor"`
	Feed_subscription     bool   `json:"feed_subscription"`
	First_name            string `json:"first_name"`
	Forbids_mentioning    bool   `json:"forbids_mentioning"`
	Friend                bool   `json:"friend"`
	Friend_invitation     bool   `json:"friend_invitation"`
	Gender                string `json:"gender"`
	Has_email             bool   `json:"has_email"`
	Has_phone             bool   `json:"has_phone"`
	Has_service_invisible bool   `json:"has_service_invisible"`
	Invited_by_friend     bool   `json:"invited_by_friend"`
	Last_name             string `json:"last_name"`
	Locale                string `json:"locale"`
	Location              struct {
		City        string `json:"city"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		CountryName string `json:"countryName"`
	} `json:"location"`
	Location_of_birth struct {
		City        string `json:"city"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		CountryName string `json:"countryName"`
	}
	Login                      string    `json:"login"`
	Mobile                     string    `json:"mobile"`
	Name                       string    `json:"name"`
	Notifications_subscription bool      `json:"notifications_subscription"`
	Pic1024x768                string    `json:"pic1024x768"`
	Premium                    bool      `json:"premium"`
	Private                    bool      `json:"private"`
	Registered_date            time.Time `json:"registered_date"`
	Uid                        string    `json:"uid"`
	Url_chat                   string    `json:"url_chat"`
	Url_chat_mobile            string    `json:"url_chat_mobile"`
	Url_profile                string    `json:"url_profile"`
	Url_profile_mobile         string    `json:"url_profile_mobile"`
	Vip                        string    `json:"vip"`
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
