package identity

import "context"

func (sess *Session) reverseStart(ctx context.Context, ver VerifierSummary, auth *Authentication, args M, identityName, identity string) (M, error) {
	panic("not implemented")
}

func (sess *Session) reverseVerify(ctx context.Context, ver VerifierSummary, auth *Authentication, inputCode, identityName, identity string) (bool, error) {
	panic("not implemented")
}
