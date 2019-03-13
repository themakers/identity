package provider_email

import (
	"context"
	"testing"

	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/stretchr/testify/require"
)

func TestSendMessage(t *testing.T) {
	prov := Provider{
		codeGenerator: AlphabetCodeGenerator{},
		sender: SendGridSender{
			APIKey:          "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",
			From:            mail.NewEmail("noreply", "noreply@storemood.com"),
			MessageTemplate: "Your code: %s\n",
			Subj:            "verification code",
		},
	}

	testAddress := "losaped@gmail.com"
	code, idn, err := prov.StartRegularVerification(context.Background(), testAddress)
	require.NoError(t, err)
	require.Equal(t, "aaaaaa", code)
	require.Equal(t, idn.Provider, "email")
	require.Equal(t, idn.ID, testAddress)
}
