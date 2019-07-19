package identity

var (
	ErrAlreadyRegistered = ErrInvalidArgument("i000001 - identity already registered")
	ErrAlreadyExists = ErrInvalidArgument("i000002 - user with such identity already exists")
	// svc_place
	ErrInvalidPassword = ErrInvalidArgument("i000003 - Invalid password")
	ErrCouldNotCombine            = ErrInvalidArgument("000004 - could not combine static verifier and non-standalone identity in same stage")
	ErrNotAuthenticated = NewErrUnauthenticated("i000005 - not authenticated")
	ErrUserNotFound = ErrInvalidArgument("i000006 - user not found")
	ErrNoVerifierData = ErrInvalidArgument("i000007 - no verifier data for this verifier and user")
	ErrVerificationCodeMismatch = ErrInvalidArgument("i000008 - verification code mismatch")
	ErrIdentityNotRegistered = ErrInvalidArgument("i000009 - identity not registered")
	ErrAlreadyAttached = ErrInvalidArgument("i000010 - already attached")
	ErrNotImplemented = NewErrUnimplemented("i000011 - not implemented")
)

type ErrPermissionDenied struct {
	Message string
	error
}
func (e *ErrPermissionDenied) Error() string {
	return e.Message
}

func NewErrPermissionDenied(t string) error {
	return &ErrPermissionDenied{Message: t}
}

type ErrUnauthenticated struct {
	Message string
	error
}
func (e *ErrUnauthenticated) Error() string {
	return e.Message
}

func NewErrUnauthenticated(t string) error {
	return &ErrUnauthenticated{Message: t}
}

type ErrUnimplemented struct {
	Message string
	error
}
func (e *ErrUnimplemented) Error() string {
	return e.Message
}

func NewErrUnimplemented(t string) error {
	return &ErrUnimplemented{Message: t}
}


func ErrInvalidArgument(msg string) error {
	return &InvalidArgumentErr{Message: msg}
}
func (e *InvalidArgumentErr) Error() string {
	return e.Message
}

type InvalidArgumentErr struct {
	Message string
	error
}