package identity

func (sess *Session) LoginAs(uid string) (sid string, err error) {
	if err := sess.sess.SetUser(uid); err != nil {
		return "", err
	}

	// FIXME
	sess.user = uid
	//sess.become(uid)

	return sess.sess.GetID()
}
