package identity

import "context"

func (sess *Session) StartReverseVerification(ctx context.Context, ver, identity string) (verificationID, target, securityCode string, err error) {
	p := sess.manager.ver[ver].internal.reverseRef

	target, securityCode, err = p.StartReverseVerification(ctx)
	if err != nil {
		return "", "", "", err
	}

	// TODO Register verification ID

	return "", "", "", nil
}

func (sess *Session) ReverseResult(ctx context.Context, verificationID string) (err error) {
	// TODO // sess.manager.backend.AwaitVerification
	return nil
}
