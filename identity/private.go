package identity

func (sess *Session) LoginAs(uid string) (sid string, err error) {
	// FIXME
	sess.cookie.SetUserID(uid)
	//sess.become(uid)

	return sess.cookie.GetUserID(), nil
}
