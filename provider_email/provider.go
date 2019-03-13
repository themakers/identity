package provider_email

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"strings"

	sendgrid "github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/themakers/identity/identity"
)

const (
	emailCodeLength = 6
)

// EmailSender can send email
type EmailSender interface {
	SendMessage(ctx context.Context, address, code string) error
}

// CodeGenerator can generate security codes with given length
type CodeGenerator interface {
	Generate(codeLength int) string
}

// Provider allow make two types of verifications throught email
type Provider struct {
	sender        EmailSender
	codeGenerator CodeGenerator
}

// Info implements Provider method
func (prov *Provider) Info() identity.ProviderInfo {
	return identity.ProviderInfo{
		Name: "email",
	}
}

// NormalizeIdentity implements Provider method
func (prov *Provider) NormalizeIdentity(idn string) string {
	return idn
}

func (prov *Provider) StartRegularVerification(ctx context.Context, idn string) (string, *identity.Identity, error) {
	idn = prov.NormalizeIdentity(idn)
	sc := prov.codeGenerator.Generate(emailCodeLength)

	if err := prov.sender.SendMessage(ctx, idn, sc); err != nil {
		log.Println("ERROR", idn, sc, err)
		return "", nil, err
	}
	log.Println("OK", idn, sc)

	return sc, &identity.Identity{
		Provider: prov.Info().Name,
		ID:       idn,
		// TODO fields
	}, nil
}

// func (prov *Provider) StartType2Verification(ctx context.Context) (target, securityCode string, err error) {
// 	target = "4947"
// 	securityCode = newSecurityCode(6)
// 	return
// }

// func (prov *Provider) StartType1Worker(ctx context.Context, event chan<- identity.Type1Event) (err error) {
// 	prov.smsg.StartWorker(ctx)

// 	// TODO

// 	return nil
// }

// AlphabetCodeGenerator generates alphabetical codes implements CodeGenerator
type AlphabetCodeGenerator struct{}

// Genarate implements Generate from CodeGenerator
func (g AlphabetCodeGenerator) Generate(codeLength int) string {
	return strings.Repeat("a", codeLength)
}

// NumericCodeGenerator generates numeric codes implements CodeGenerator
type NumericCodeGenerator struct{}

// Generate implements Generate from CodeGenerator
func (g NumericCodeGenerator) Generate(codeLength int) string {
	code := ""
	b := [1]byte{}
	for i := 0; i < codeLength; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		code += fmt.Sprint(int(b[0] % 10))
	}
	return code
}

type SendGridSender struct {
	From            *mail.Email
	Subj            string
	MessageTemplate string
	APIKey          string
}

func (s SendGridSender) SendMessage(ctx context.Context, address, code string) error {
	to := mail.NewEmail("", address)
	msg := mail.NewSingleEmail(s.From, s.Subj, to, fmt.Sprintf(s.MessageTemplate, code), fmt.Sprintf("<strong>%s</strong>", code))
	cli := sendgrid.NewSendClient(s.APIKey)
	resp, err := cli.Send(msg)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("error sending message. status %d text:%s", resp.StatusCode, resp.Body) // TODO: error handling
	}
	log.Println("send email status:", resp.StatusCode)
	return nil
}
