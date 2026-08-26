package identitysdk

import "context"

type requestIdentityContextKey struct{}

func WithRequestIdentity(ctx context.Context, identity RequestIdentity) context.Context {
	return context.WithValue(ctx, requestIdentityContextKey{}, identity)
}

func RequestIdentityFromContext(ctx context.Context) (RequestIdentity, bool) {
	if ctx == nil {
		return RequestIdentity{}, false
	}
	identity, ok := ctx.Value(requestIdentityContextKey{}).(RequestIdentity)
	return identity, ok && identity.Principal.Known
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	identity, ok := RequestIdentityFromContext(ctx)
	return identity.Principal, ok
}
