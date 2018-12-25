package provider_sms

import (
	"context"
	"crypto/rand"
	"fmt"
	"github.com/themakers/identity/identity"
	"github.com/themakers/smsg/smsg"
	"log"
	"unicode"
)

type Config struct {
	ServiceID   string
	AccessToken string
}

var _ identity.Type1Provider = new(Provider)
var _ identity.Type2Provider = new(Provider)

type Provider struct {
	smsg *smsg.Client
}

func New(cfg Config) *Provider {
	prov := &Provider{
		smsg: &smsg.Client{
			ServiceID:   cfg.ServiceID,
			AccessToken: cfg.AccessToken,
		},
	}

	return prov
}

func (prov *Provider) Info() identity.ProviderInfo {
	return identity.ProviderInfo{
		Name: "sms",
	}
}

func (prov *Provider) NormalizeIdentity(idn string) string {
	return NormalizePhone(idn)
}

func NormalizePhone(phone string) (result string) {
	for _, c := range phone {
		if unicode.IsDigit(c) {
			result += string(rune(c))
		}
	}
	if len(result) == 11 && result[0] == '8' {
		result = string(rune('7')) + result[1:]
	} else if len(result) == 10 && result[0] == '9' {
		result = string(rune('7')) + result[:]
	}

	return
}

////////////////////////////////////////////////////////////////
//// Type 1
////

func (prov *Provider) StartType1Verification(ctx context.Context) (target, securityCode string, err error) {
	target = "4947"
	securityCode = newSecurityCode(6)
	return
}

func (prov *Provider) StartType1Worker(ctx context.Context, event chan<- identity.Type1Event) (err error) {
	prov.smsg.StartWorker(ctx)

	// TODO

	return nil
}

////////////////////////////////////////////////////////////////
//// Type 2
////

func (prov *Provider) StartType2Verification(ctx context.Context, idn string) (securityCode string, iden *identity.Identity, err error) {
	idn = NormalizePhone(idn)
	sc := newSecurityCode(6)

	smc, err := prov.smsg.SendMessage(ctx, idn, sc, false)
	if err != nil {
		log.Println("ERROR", idn, sc, err)
		return "", nil, err
	}
	log.Println("OK", idn, sc, err)

	switch accepted := <-smc.Accepted; accepted := accepted.(type) {
	case error:
		return "", nil, accepted
	case string:
		log.Println("Message accepted:", accepted)
	}

	switch sent := <-smc.Sent; sent := sent.(type) {
	case error:
		return "", nil, sent
	case bool:
		log.Println("Message sent:", sent)
	}

	switch delivered := <-smc.Delivered; delivered := delivered.(type) {
	case error:
		log.Println("Message NOT delivered:", delivered)
	case bool:
		log.Println("Message delivered:", delivered)
	}

	return sc, &identity.Identity{
		Provider: prov.Info().Name,
		ID:       idn,
		// TODO fields
	}, nil
}

func newSecurityCode(l int) (code string) {
	b := [1]byte{}
	for i := 0; i < l; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		code += fmt.Sprint(int(b[0] % 10))
	}
	return
}
