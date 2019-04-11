package identity

import (
	"context"
	"log"
)

func (sess *Session) StartRegularVerification(ctx context.Context, vername, idn string, vd []VerifierData) (verificationID string, err error) {
	p := sess.manager.ver[vername].internal.regularRef

	log.Println("VERIFIER", sess.manager.ver[vername], p, p.Info().Name)

	// TODO Make check of absolutely new user

	idn, err = sess.manager.idn[p.Info().IdentityName].NormalizeAndValidateData(idn)

	// TODO Obtain verifier data from backend
	// TODO realise search by two parameters
	// TODO modificate starting function

	securitycode, err := p.StartRegularVerification(ctx, idn, vd)
	/*
		securityCode, eruser, err := sess.manager.backend.GetUserByIdentity(idn)
		verifierData := user.Verifiers
		resp, err := p.StartRegularVerification(ctx, idn, verifierData)
		if err != nil {
			return "", err
		}
		log.Println("StartRegularVerification", securityCode, idn, err)

		if von, err := sess.manager.backend.CreateVerification(identity, securityCode); err != nil {
			return "", err
		} else {
			return von.VerificationID, nil
		}*/
	return
}

func (sess *Session) RegularVerify(ctx context.Context, verificationID, securityCode string) (err error) {
	von, err := sess.manager.backend.GetVerification(verificationID)
	if err != nil {
		return err
	}
	// todo modificate regular verification
	von.SessionToken = "asflkas"
	/*
		if von.SecurityCode != securityCode {
			return ErrSecurityCodeMismatch
		}

		if err := sess.handleIncomingIdentity(ctx, &von.Identity); err != nil {
			return err
		}
	*/
	return nil
}
