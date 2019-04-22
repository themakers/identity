package identity

import (
	"context"
	"google.golang.org/grpc/metadata"
	"log"
)

func (sess *Session) StartRegularVerification(ctx context.Context, idn string, vd VerifierData) (AuthenticationID string, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		panic(ok)
	}
	AID := md[SessionTokenName][0]
	v := sess.manager.ver[vd.VerifierName].internal.regularRef
	log.Println("Regular VERIFIER", sess.manager.ver[vd.VerifierName], v, v.Info().Name)

	idn, err = sess.manager.idn[v.Info().IdentityName].NormalizeAndValidateData(idn)

	err = sess.handleIncomingIdentity(ctx, &IdentityData{Identity: idn, Name: v.Info().IdentityName}, &vd)
	if err != nil {
		panic(err)
	}
	user, err := sess.manager.backend.GetUserByIdentity(idn)
	if err != nil {
		panic(err)
	}
	securitycode, err := v.StartRegularVerification(ctx, idn, vd)
	if err != nil {
		panic(err)
	}
	_, err = sess.manager.backend.AddTempAuthDataToAuth(AID, map[string]map[string]string{vd.VerifierName: {idn: securitycode}})
	if err != nil {
		panic(err)
	}
	_, err = sess.manager.backend.AddUserToAuthentication(AID, user.ID)
	if err != nil {
		panic(err)
	}

	return AID, err
}

func (sess *Session) RegularVerify(ctx context.Context, AuthenticationID, securityCode, vername, idn string) (err error) {
	// todo make check aid from context and authenticationid as value
	auth, err := sess.manager.backend.GetAuthenticationBySessionToken(AuthenticationID)
	if err != nil {
		panic(err)
	}
	for key, value := range auth.TempAuthenticationData {
		if key == vername {
			for inkey, invalue := range value {
				if inkey == idn && invalue == securityCode {
					data := VerifierData{VerifierName: vername, AuthenticationData: map[string]string{}, AdditionalData: map[string]string{}}
					_, err = sess.manager.backend.AddUserAuthenticationData(auth.UserID, &data)
					err = sess.manager.backend.UpdateFactorStatus(AuthenticationID, vername)
					return nil
				}
			}

		}
	}
	return ErrSecurityCodeMismatch
}
