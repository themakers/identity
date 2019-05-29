package identity_phone

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestIdentity_NormalizeAndValidateData(t *testing.T) {
	var idn Identity
	Convey("test phone number normalize and validate", t, func() {
		So(idn.Info().Name, ShouldEqual, "phone")
		_, err := idn.NormalizeAndValidateIdentity("779121122556")
		So(err, ShouldEqual, ErrPhoneNumberNotValid)
		_, err = idn.NormalizeAndValidateIdentity("799121d22556")
		So(err, ShouldEqual, ErrPhoneNumberNotValid)
		res, err := idn.NormalizeAndValidateIdentity("89991112233")
		So(res, ShouldEqual, "79991112233")
		res, err = idn.NormalizeAndValidateIdentity("9992233444")
		So(res, ShouldEqual, "79992233444")
	})
}

func TestIdentity_Info(t *testing.T) {
	var idn Identity
	Convey("test phone info", t, func() {
		So(idn.Info().Name, ShouldEqual, "phone")
	})
}
