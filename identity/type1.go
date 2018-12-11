package identity

import "context"

func (sess *Session) StartType1Verification(ctx context.Context, prov, identity string) (verificationID, target, securityCode string, err error) {
	p := sess.manager.prov[prov].internal.type1Ref

	target, securityCode, err = p.StartType1Verification(ctx)
	if err != nil {
		return "", "", "", err
	}

	// TODO Register verification ID

	return "", "", "", nil
}

func (sess *Session) AwaitType1Result(ctx context.Context, verificationID string) (err error) {
	// TODO // sess.manager.backend.AwaitVerification
	return nil
}
