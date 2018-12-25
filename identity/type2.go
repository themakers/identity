package identity

import (
	"context"
	"log"
)

func (sess *Session) StartType2Verification(ctx context.Context, prov, idn string) (verificationID string, err error) {
	p := sess.manager.prov[prov].internal.type2Ref

	log.Println("PROVIDER", sess.manager.prov[prov], p, p.Info().Name)

	securityCode, identity, err := p.StartType2Verification(ctx, p.NormalizeIdentity(idn))
	if err != nil {
		return "", err
	}
	log.Println("StartType2Verification", securityCode, identity, err)

	if von, err := sess.manager.backend.CreateVerification(identity, securityCode); err != nil {
		return "", err
	} else {
		return von.VerificationID, nil
	}
}

func (sess *Session) Type2Verify(ctx context.Context, verificationID, securityCode string) (err error) {
	von, err := sess.manager.backend.GetVerification(verificationID)
	if err != nil {
		return err
	}

	if von.SecurityCode != securityCode {
		return ErrSecurityCodeMismatch
	}

	if err := sess.handleIncomingIdentity(ctx, &von.Identity); err != nil {
		return err
	}

	return nil
}
