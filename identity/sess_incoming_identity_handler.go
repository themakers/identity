package identity

import (
	"context"
	"log"
)

func (sess *Session) handleIncomingIdentity(ctx context.Context, identity *IdentityData, data *VerifierData) (err error) {
	userID, err := sess.sess.GetUser()
	if err != nil {
		return err
	}

	user, err := sess.manager.backend.GetUserByIdentity(identity.Identity)
	if err != nil {
		return err
	}
	log.Println(identity.Identity)
	log.Println(user)

	switch {
	case userID == "" && user == nil: // Empty session AND new identity => create user
		log.Println("Empty session AND new identity => create user")
		user, err = sess.manager.backend.CreateUser(identity, data)
		if err != nil {
			return err
		}
	case userID == "" && user != nil: // Empty session AND existing identity => own new session
		log.Println("Empty session AND existing identity => own new session")
		// OK
	case userID != "" && user == nil: // Authenticated session AND user adding new identity => add user identity OR reauthenticate // FIXME
		log.Println("Authenticated session AND new identity")
		user, err = sess.manager.backend.AddUserIdentity(userID, identity)
		if err != nil {
			return err
		}
	case userID != "" && user != nil && userID != user.ID: // Different authenticated user and identity owner => reown session OR offer user merge // FIXME
		log.Println("Different authenticated user and identity owner")
		// FIXME Now reown session
	case userID != "" && user != nil && userID == user.ID: // Same user => do nothing // FIXME report duplicate identity
		log.Println("Same user => do nothing")
		// OK
	default:
		panic("something went wrong")
	}

	if err := sess.sess.SetUser(user.ID); err != nil {
		return err
	}

	return nil
}
