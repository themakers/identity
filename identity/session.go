package identity

import (
	"github.com/themakers/identity/cookie"
)

type Session struct {
	cookie cookie.Cookie

	manager *Manager
}

func (mgr *Manager) Session(cookie cookie.Cookie) *Session {
	sess := &Session{
		cookie:  cookie,
		manager: mgr,
	}
	return sess
}

func (sess *Session) Info() (sid, uid string) {
	return sess.cookie.GetSessionID(), sess.cookie.GetUserID()

	// FIXME:
	//sid, err = sess.sess.GetID()
	//if err != nil {
	//	return "", "", err
	//}
	//uid, err = sess.sess.GetUser()
	//if err != nil {
	//	return "", "", err
	//}
	//return
}
