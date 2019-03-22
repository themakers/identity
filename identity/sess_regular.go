package identity

import (
	"context"
	"log"
)

func (sess *Session) StartRegularVerification(ctx context.Context, ver, idn string) (verificationID string, err error) {
	p := sess.manager.ver[ver].internal.regularRef

	log.Println("VERIFIER", sess.manager.ver[ver], p, p.Info().Name)

	securityCode, identity, err := p.StartRegularVerification(ctx, idn)
	if err != nil {
		return "", err
	}
	log.Println("StartRegularVerification", securityCode, identity, err)

	if von, err := sess.manager.backend.CreateVerification(identity, securityCode); err != nil {
		return "", err
	} else {
		return von.VerificationID, nil
	}
}

func (sess *Session) RegularVerify(ctx context.Context, verificationID, securityCode string) (err error) {
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
