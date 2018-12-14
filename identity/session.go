package identity

import "github.com/themakers/session"

type Session struct {
	manager *Manager

	sess *session.Session
}

func (sess *Session) Info() (sid, uid string, err error) {
	sid, err = sess.sess.GetID()
	if err != nil {
		return "", "", err
	}
	uid, err = sess.sess.GetUser()
	if err != nil {
		return "", "", err
	}

	return
}


func (sess *Session) Dispose() {
	sess.sess.Dispose()
}
