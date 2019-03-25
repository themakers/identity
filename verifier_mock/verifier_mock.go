package verifier_mock

import (
	"math/rand"
	"strconv"
)

type MockVerifier interface {
	RegularVerification() string
	ReverseVerification() string
	OAuth2Verification() string
	ReverseVerfification() string
}

type SmsVerifier struct {
	ver MockVerifier
}

func (sms SmsVerifier) ReturnSecurityCode() string {
	code := 1000 + rand.Intn(8999)
	return strconv.Itoa(code)

}
