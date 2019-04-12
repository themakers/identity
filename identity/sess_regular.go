package identity

import (
	"context"
	"google.golang.org/grpc/metadata"
	"log"
)

func (sess *Session) StartRegularVerification(ctx context.Context, vername, idn string, vd []VerifierData) (AuthenticationID string, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		panic(ok)
	}
	AID := md[SessionTokenName][0]
	p := sess.manager.ver[vername].internal.regularRef
	log.Println("Regular VERIFIER", sess.manager.ver[vername], p, p.Info().Name)

	idn, err = sess.manager.idn[p.Info().IdentityName].NormalizeAndValidateData(idn)

	_ = sess.handleIncomingIdentity(ctx, &IdentityData{Identity: idn, Name: p.Info().IdentityName})
	user, err := sess.manager.backend.GetUserByIdentity(idn)
	if err != nil {
		panic(err)
	}
	securitycode, err := p.StartRegularVerification(ctx, idn, vd)
	if err != nil {
		panic(err)
	}
	// todo add securitycode to verifier data
	log.Println(securitycode)
	log.Println(idn)

	//auth, err := sess.manager.backend.GetAuthenticationBySessionToken(AID)
	//log.Println(auth)

	log.Println(user)

	// todo add user to auth by AID
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

func (sess *Session) RegularVerify(ctx context.Context, AuthenticationID, securityCode string) (err error) {
	auth, err := sess.manager.backend.GetAuthenticationBySessionToken(AuthenticationID)
	if err != nil {
		panic(err)
	}
	user, err := sess.manager.backend.GetUserByID(auth.UserID)
	dem := user.Verifiers[1].AuthenticationData["backend"]
	log.Println(dem)

	/*	von, err := sess.manager.backend.GetVerification(verificationID)
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
