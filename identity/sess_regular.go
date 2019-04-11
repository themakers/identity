package identity

import (
	"context"
	"google.golang.org/grpc/metadata"
	"log"
)

func (sess *Session) StartRegularVerification(ctx context.Context, vername, idn string, vd []VerifierData) (AuthenticationID string, err error) {
	//log.Println(ctx)
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		panic(ok)
	}
	AID := md[SessionTokenName][0]
	p := sess.manager.ver[vername].internal.regularRef
	log.Println("Regular VERIFIER", sess.manager.ver[vername], p, p.Info().Name)

	idn, err = sess.manager.idn[p.Info().IdentityName].NormalizeAndValidateData(idn)

	_ = sess.handleIncomingIdentity(ctx, &IdentityData{Identity: idn, Name: p.Info().IdentityName})
	securitycode, err := p.StartRegularVerification(ctx, idn, vd)
	if err != nil {
		panic(err)
	}
	log.Println(securitycode)

	user, err := sess.manager.backend.GetUserByIdentity(idn)
	if err != nil {
		panic(err)
	}
	log.Println(user)
	/*
		user.Verifiers = append(user.Verifiers, VerifierData{map[string]string{p.Info().Name:securitycode}, map[string]string{}})


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
	return AID, err
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
