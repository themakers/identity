package identity

import (
	"github.com/themakers/session"
	"time"
)

type Session struct {
	token string
	user  string

	manager *Manager

	sess *session.Session
}


func (mgr *Manager) Session(token string) *Session {
	sess := &Session{
		manager: mgr,
		token: token,
	}

	if s, err := mgr.sessMgr.Session(token); err != nil {
		panic(err)
	} else {
		// FIXME Make configurable
		if err := s.SetTTL(7 * 24 * time.Hour); err != nil {
			panic(err)
		}

		if user, err := s.GetUser(); err != nil {
			panic(err)
		} else {
			sess.become(user)
		}

		sess.sess = s
	}
	return sess
}

func (sess *Session) become(user string) {
	sess.user = user
}

func (sess *Session) Dispose() {
	sess.sess.Dispose()
}


func (sess *Session) Info() (sid, uid string, err error) {
	return sess.token, sess.user, nil

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
