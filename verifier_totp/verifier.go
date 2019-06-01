package verifier_totp

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/pquerna/otp/totp"
	"github.com/themakers/identity/identity"
	"image/png"
)

var _ identity.Verifier = new(Verifier)
var _ identity.StaticVerifier = new(Verifier)

type Verifier struct {
}

func (v *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{
		Name:         "totp",
		IdentityName: "",
	}
}

func New() *Verifier {
	v := &Verifier{}
	return v
}

func (v *Verifier) InitStaticVerifier(ctx context.Context, verifierData *identity.VerifierData, args identity.M) (res identity.M, err error) {
	key, err := totp.Generate(totp.GenerateOpts{})
	if err != nil {
		return nil, err
	}

	pngB64, err := (func() (string, error) {
		var buf bytes.Buffer
		img, err := key.Image(200, 200)
		if err != nil {
			panic(err)
		}
		if err := png.Encode(&buf, img); err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
	})()

	verifierData.AuthenticationData = map[string][]byte{
		"secret": []byte(key.String()),
	}

	return identity.M{
		"secret": key.String(),
		"image": pngB64,
	}, nil
}

func (v *Verifier) StaticVerify(ctx context.Context, verifierData identity.VerifierData, inputCode string) (bool, error) {
	secret := verifierData.AuthenticationData["secret"]

	if totp.Validate(inputCode, string(secret)) {
		return true, nil
	} else {
		return false, nil
	}
}
