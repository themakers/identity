package identity_email

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestIdentity_NormalizeAndValidateData(t *testing.T) {
	Convey("Normalize and Validate tests", t, func() {
		var idn Identity
		So(idn.Info().Name, ShouldEqual, "email")
		res, _ := idn.NormalizeAndValidateData("TeSt@Email.com")
		So(res, ShouldEqual, "test@email.com")
		res, err := idn.NormalizeAndValidateData("test-mail.com")
		So(err, ShouldEqual, ErrEmailNotValid)
		So(res, ShouldEqual, "")
	})
}
