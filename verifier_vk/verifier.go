package verifier_github

import (
	"context"
	"encoding/json"
	"github.com/themakers/identity/identity"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/vk"
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

const fields = "verified, sex, bdate, city, country, home_town, has_photo, photo_max_orig, domain, has_mobile, contacts, site, education, universities, schools, status, followers_count, common_count, occupation, nickname, relatives, relation, personal, connections, exports, activities, interests, music, movies, tv, books, games, about, quotes, can_post, can_see_all_posts, can_see_audio, can_write_private_message, can_send_friend_request, is_favorite, is_hidden_from_feed, timezone, screen_name, is_friend, friend_status, career, military, blacklisted, blacklisted_by_me"

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
			Endpoint:     vk.Endpoint,
		},
	}

	return prov
}

func (prov *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{
		Name: "vk",
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

	u, err := url.Parse("https://api.vk.com/method/users.get")
	if err != nil {
		return nil, err
	}
	query := url.Values{
		"fields":       {fields},
		"access_token": {accessToken},
		"v":            {"5.92"},
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
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var user UserInfo

	if err := json.Unmarshal(data, user); err != nil {
		return nil, err
	}

	return &identity.IdentityData{}, nil
}

type UserInfo struct {
	ID                        int    `json:"id"`
	First_name                string `json:"first_name"`
	Last_name                 string `json:"last_name"`
	Deactivated               string `json:"deactivated"`
	Is_closed                 bool   `json:"is_closed"`
	Can_access_closed         bool   `json:"can_access_closed"`
	About                     string `json:"about"`
	Activities                string `json:"activities"`
	Bdate                     string `json:"bdate"`
	Blacklisted               int    `json:"blacklisted"`
	Blacklisted_by_me         int    `json:"blacklisted_by_me"`
	Books                     string `json:"books"`
	Can_post                  int    `json:"can_post"`
	Can_see_all_posts         int    `json:"can_see_all_posts"`
	Can_see_audio             int    `json:"can_see_audio"`
	Can_send_friend_request   int    `json:"can_send_friend_request"`
	Can_write_private_message int    `json:"can_write_private_message"`
	Career                    []struct {
		Group_id   int    `json:"group_id"`
		Company    string `json:"company"`
		Country_id int    `json:"country_id"`
		City_id    int    `json:"city_id"`
		City_name  string `json:"city_name"`
		From       int    `json:"from"`
		Until      int    `json:"until"`
		Position   int    `json:"position"`
	} `json:"career"`
	City struct {
		Id    int    `json:"id"`
		Title string `json:"title"`
	} `json:"city"`
	Common_count int    `json:"common_count"`
	Skype        string `json:"skype"`
	Facebook     string `json:"facebook"`
	Twitter      string `json:"twitter"`
	Livejournal  string `json:"livejournal"`
	Instagram    string `json:"instagram"`
	Mobile_phone string `json:"mobile_phone"`
	Home_phone   string `json:"home_phone"`
	Counters     struct {
		Albums         int `json:"albums"`
		Videos         int `json:"videos"`
		Audios         int `json:"audios"`
		Photos         int `json:"photos"`
		Notes          int `json:"notes"`
		Friends        int `json:"friends"`
		Groups         int `json:"groups"`
		Online_friends int `json:"online_friends"`
		Mutual_friends int `json:"mutual_friends"`
		User_videos    int `json:"user_videos"`
		Followers      int `json:"followers"`
		Pages          int `json:"pages"`
	} `json:"counters"`
	Country struct {
		Id    int `json:"id"`
		Title int `json:"title"`
	} `json:"country"`
	Domain              string `json:"domain"`
	University          int    `json:"university"`
	University_name     string `json:"university_name"`
	Faculty             int    `json:"faculty"`
	Faculty_name        string `json:"faculty_name"`
	Graduation          int    `json:"graduation"`
	First_name_nom      string `json:"first_name_nom"`
	First_name_gen      string `json:"first_name_gen"`
	First_name_dat      string `json:"first_name_dat"`
	First_name_acc      string `json:"first_name_acc"`
	First_name_ins      string `json:"first_name_ins"`
	First_name_abl      string `json:"first_name_abl "`
	Followers_count     int    `json:"followers_count"`
	Friend_status       int    `json:"friend_status"`
	Games               string `json:"games"`
	Has_mobile          int    `json:"has_mobile"`
	Has_photo           int    `json:"has_photo"`
	Home_town           string `json:"home_town"`
	Interests           string `json:"interests"`
	Is_favorite         int    `json:"is_favorite"`
	Is_friend           int    `json:"is_friend"`
	Is_hidden_from_feed int    `json:"is_hidden_from_feed"`
	Last_name_nom       string `json:"last_name_nom"`
	Last_name_gen       string `json:"last_name_gen"`
	Last_name_dat       string `json:"last_name_dat"`
	Last_name_acc       string `json:"last_name_acc"`
	Last_name_ins       string `json:"last_name_ins"`
	Last_name_abl       string `json:"last_name_abl"`
	Military            struct {
		Unit       string `json:"unit"`
		Unit_id    int    `json:"unit_id"`
		Country_id int    `json:"country_id"`
		From       int    `json:"from"`
		Until      int    `json:"until"`
	} `json:"military"`
	Movies     string `json:"movies "`
	Nickname   string `json:"nickname "`
	Occupation struct {
		Type string `json:"type "`
		Id   int    `json:"id"`
		Name string `json:"name"`
	} `json:"occupation "`
	Personal struct {
		Political   int      `json:"political"`
		Langs       []string `json:"langs"`
		Religion    string   `json:"religion"`
		Inspired_by string   `json:"inspired_by"`
		People_main int      `json:"people_main"`
		Life_main   int      `json:"life_main"`
		Smoking     int      `json:"smoking"`
		Alcohol     int      `json:"alcohol"`
	} `json:"personal"`
	Photo_max_orig   string `json:"photo_max_orig"`
	Quotes           string `json:"quotes"`
	Relation         int    `json:"relation"`
	Relation_partner struct {
		Id   int    `json:"id"`
		Name string `json:"name"`
	} `json:"relation_partner"`
	Relatives []struct {
		Id   int    `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"relatives"`
	Schools []struct {
		Id             int    `json:"id"`
		Name           string `json:"name"`
		Country        int    `json:"country"`
		City           int    `json:"city"`
		Year_from      int    `json:"year_from"`
		Year_to        int    `json:"year_to"`
		Year_graduated int    `json:"year_graduated"`
		Class          string `json:"class"`
		Speciality     string `json:"speciality"`
		Type           int    `json:"type"`
		Type_str       string `json:"type_str"`
	} `json:"schools"`
	Screen_name  string `json:"screen_name"`
	Sex          int    `json:"sex"`
	Site         string `json:"site"`
	Status       string `json:"status"`
	Timezone     int    `json:"timezone"`
	Trending     int    `json:"trending"`
	Tv           string `json:"tv"`
	Universities struct {
		Id               int    `json:"id"`
		Country          int    `json:"country"`
		City             int    `json:"city"`
		Name             string `json:"name"`
		Faculty          int    `json:"faculty"`
		Faculty_name     string `json:"faculty_name"`
		Chair            int    `json:"chair"`
		Chair_name       string `json:"chair_name"`
		Graduation       int    `json:"graduation"`
		Education_form   string `json:"education_form"`
		Education_status string `json:"education_status"`
	} `json:"universities"`
	Verified     int    `json:"verified"`
	Wall_default string `json:"wall_default"`
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
