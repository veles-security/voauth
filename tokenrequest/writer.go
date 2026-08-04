package tokenrequest

import (
	"github.com/veles-security/vapi"
	"github.com/veles-security/voauth/clientcredentials"
	"github.com/veles-security/voauth/token"
)

type Writer[RT, AT, CT token.AnyToken, RTO, ATO, CTO any] struct {
	tokenEncoder             *token.Encoder
	assertionTokenEncoder    vapi.Encoder[AT, ATO]
	clientCredentialsEncoder clientcredentials.Writer[CT, CTO]
}
