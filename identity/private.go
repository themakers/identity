package identity

func (sess *Session) LoginAs(uid string) (sid string, err error) {
	if err := sess.sess.SetUser(uid); err != nil {
		return "", err
	}

	return sess.sess.GetID()
}
