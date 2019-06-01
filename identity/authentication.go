package identity

type AuthenticationObjective string

const (
	ObjectiveSignIn AuthenticationObjective = "sign_in"
	ObjectiveSignUp AuthenticationObjective = "sign_up"
	ObjectiveAttach AuthenticationObjective = "attach"
)

type AuthenticationStage struct {
	Completed bool `bson:"Completed" json:"Completed"`

	UserID string `bson:"UserID" json:"UserID"`

	VerifierName string `bson:"Name" json:"Name"`
	IdentityName string `bson:"Identity" json:"Identity"`
	Identity     string `bson:"Identity" json:"Identity"`

	StoredSecurityCode string `bson:"StoredSecurityCode" json:"StoredSecurityCode"`
	InputSecurityCode  string `bson:"InputSecurityCode" json:"InputSecurityCode"`

	OAuth2State string `bson:"OAuth2State" json:"OAuth2State"`

	VerifierData *VerifierData `bson:"VerifierData" json:"VerifierData"`
}

type Authentication struct {
	ID        string                  `bson:"_id" json:"SessionToken"`
	Objective AuthenticationObjective `bson:"Objective" json:"Objective"`

	Completed bool `bson:"Completed" json:"Completed"`

	//> Filled if user is authenticated and going to add new identity/verifier (AuthenticationObjective)
	//  or if user completed one of the factors
	UserID string `bson:"UserID" json:"UserID"`

	RequiredFactorsCount int `bson:"RequiredFactorsCount" json:"RequiredFactorsCount"`

	Stages []*AuthenticationStage `bson:"Stages" json:"Stages"`

	CreationTime int64 `bson:"CreationTime" json:"CreationTime"`

	Version int `bson:"Version" json:"Version"`
}

func (auth *Authentication) findStage(verifierName, identity string) *AuthenticationStage {
	for _, stage := range auth.Stages {
		if stage.VerifierName == verifierName {
			if identity != "" {
				if stage.Identity == identity {
					return stage
				}
			} else {
				return stage
			}
		}
	}
	return nil
}


func (auth *Authentication) status() *StatusAuthenticating {
	status := &StatusAuthenticating{
		Objective:        auth.Objective,
		RemainingFactors: auth.RequiredFactorsCount, // FIXME !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	}

	for _, stage := range auth.Stages {
		if stage.Completed {
			status.RemainingFactors--
			status.CompletedFactors = append(status.CompletedFactors, StatusCompletedFactors{
				VerifierName: stage.VerifierName,
				IdentityName: stage.IdentityName,
				Identity:     stage.Identity,
			})
		}
	}

	return status
}
