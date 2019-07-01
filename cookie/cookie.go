package cookie

type Cookie interface {
	Init()
	SetUserID(id string)
	GetUserID() string
	GetSessionID() string
	SetSessionID(id string)
}
