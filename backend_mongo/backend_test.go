package backend_mongo

import (
	"context"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/themakers/identity/identity"
	"testing"
	"time"
)

func Test_Backend(t *testing.T) {
	back, err := New(Options{
		URI:              "mongodb://localhost:27017/?replicaSet=rs0",
		DBName:           "test_identity_backend",
		CollectionPrefix: "",
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	Convey("Start testing by cleaning up a database", t, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		err := back.Clear(ctx)
		So(err, ShouldBeNil)

		Convey("Should not find non-existing user", func() {
			user, err := back.GetUser(ctx, "nouser")
			So(err, ShouldBeNil)
			So(user, ShouldBeNil)
		})

		Convey("Then create a user", func() {
			userID := "uid1"
			user := &identity.User{
				ID: userID,
			}

			user, err := back.CreateUser(ctx, user)
			So(err, ShouldBeNil)
			So(user.Version, ShouldEqual, 1)

			Convey("User now should exists", func() {
				user, err := back.GetUser(ctx, userID)
				So(err, ShouldBeNil)
				So(user, ShouldNotBeNil)
				So(user.ID, ShouldEqual, userID)
				So(user.Version, ShouldEqual, 1)

				Convey("Then update user", func() {
					idn1 := identity.IdentityData{
						Name:     "N1",
						Identity: "I1",
					}
					idn2 := identity.IdentityData{
						Name:     "N2",
						Identity: "I2",
					}
					user.Identities = append(user.Identities, idn1, idn2)
					user, err := back.SaveUser(ctx, user)
					So(err, ShouldBeNil)
					So(user, ShouldNotBeNil)
					So(user.Version, ShouldEqual, 2)

					Convey("And try to find it by identity", func() {
						user, err := back.GetUserByIdentity(ctx, idn1.Name, idn1.Identity)
						So(err, ShouldBeNil)
						So(user, ShouldNotBeNil)
						So(user.Version, ShouldEqual, 2)
					})

					Convey("And try to find it by WRONG identity", func() {
						user, err := back.GetUserByIdentity(ctx, idn1.Name, idn2.Identity)
						So(err, ShouldBeNil)
						So(user, ShouldBeNil)
					})

					Convey("Then try to update user with wrong version", func() {
						user.AuthFactorsNumber = 3
						user.Version--
						user, err := back.SaveUser(ctx, user)
						So(err, ShouldNotBeNil)
						So(user, ShouldBeNil)
					})
				})
			})
		})

		Convey("Should not find non-existing authentication", func() {
			auth, err := back.GetAuthentication(ctx, "noauth")
			So(err, ShouldBeNil)
			So(auth, ShouldBeNil)
		})

		Convey("Then create an authentication", func() {
			authID := "aid1"
			userID := "uid1"
			auth, err := back.CreateAuthentication(ctx, authID, identity.ObjectiveSignIn, userID)
			So(err, ShouldBeNil)
			So(auth.ID, ShouldEqual, authID)
			So(auth.Objective, ShouldEqual, identity.ObjectiveSignIn)
			So(auth.UserID, ShouldEqual, userID)
			So(auth.Version, ShouldEqual, 1)

			Convey("Authentication now should exists", func() {
				auth, err := back.GetAuthentication(ctx, authID)
				So(err, ShouldBeNil)
				So(auth.ID, ShouldEqual, authID)
				So(auth.Objective, ShouldEqual, identity.ObjectiveSignIn)
				So(auth.UserID, ShouldEqual, userID)
				So(auth.Version, ShouldEqual, 1)

				Convey("Then update authentication", func() {
					auth.RequiredFactorsCount = 2
					auth, err := back.SaveAuthentication(ctx, auth)
					So(err, ShouldBeNil)
					So(auth.RequiredFactorsCount, ShouldEqual, 2)
					So(auth.Version, ShouldEqual, 2)

					Convey("Then try to update authentication with wrong version", func() {
						auth.RequiredFactorsCount = 3
						auth.Version--
						auth, err := back.SaveAuthentication(ctx, auth)
						So(err, ShouldNotBeNil)
						So(auth, ShouldBeNil)
					})
				})
			})
		})
	})
}
