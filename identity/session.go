package identity

import "github.com/themakers/session"

type Session struct {
	manager *Manager

	sess *session.Session
}

func (sess *Session) Dispose() {
	sess.sess.Dispose()
}
