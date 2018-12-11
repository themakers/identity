package identity

import "context"

func (sess *Session) handleIncomingIdentity(ctx context.Context, identity *Identity) (err error) {
	userID, err := sess.sess.GetUser()
	if err != nil {
		return err
	}

	user, err := sess.manager.backend.GetUserByIdentity(identity.Provider, identity.ID)
	if err != nil {
		return err
	}

	switch {
	case userID == "" && user == nil: // Empty session AND new identity => create user
		user, err = sess.manager.backend.CreateUser(identity)
		if err != nil {
			return err
		}
	case userID == "" && user != nil: // Empty session AND existing identity => own new session
		// OK
	case userID != "" && user == nil: // Authenticated session AND new identity => add user identity OR reauthenticate // FIXME
		user, err = sess.manager.backend.PutUserIdentity(userID, identity)
		if err != nil {
			return err
		}
	case userID != "" && user != nil && userID != user.ID: // Different authenticated user and identity owner => reown session OR offer user merge // FIXME
		// FIXME Now reown session
	case userID != "" && user != nil && userID == user.ID: // Same user => do nothing // FIXME report duplicate identity
		// OK
	default:
		panic("something went wrong")
	}

	if err := sess.sess.SetUser(user.ID); err != nil {
		return err
	}

	return nil
}
