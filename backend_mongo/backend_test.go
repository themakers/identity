package backend_mongo

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func initdb() Backend {
	var back Backend
	back.mgo.db = "identity_test"
	back.mgo.collPrefix = "idn"
	back.mgo.addr = "127.0.0.1"
	back.mgo.port = 27017
	return back
}

func TestBackend_GetUserByIdentity(t *testing.T) {
	back := initdb()
	Convey("test find user by identity", t, func() {
		user, _ := back.GetUserByIdentity("79991112233")
		So(user.ID, ShouldNotEqual, "")
	})
}

func TestBackend_GetUserByID(t *testing.T) {
	back := initdb()
	Convey("test find user by id", t, func() {
		user, _ := back.GetUserByID("bj0mtfnvu4hpvpmilh30")
		So(user.ID, ShouldNotEqual, "")
	})

}

func TestBackend_GetUserByLogin(t *testing.T) {
	back := initdb()
	Convey("test get user by login", t, func() {
		user, _ := back.GetUserByLogin("micresh", "Login")
		So(user.ID, ShouldNotEqual, "")
	})
}
