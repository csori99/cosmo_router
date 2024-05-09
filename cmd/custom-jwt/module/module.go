package module

import (
	"context"
	"fmt"
	"net/http"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/wundergraph/cosmo/router/core"
	"go.uber.org/zap"
	"google.golang.org/api/option"
)

func init() {
	core.RegisterModule(&FirebaseAuthModule{})
}

const (
	ModuleID       = "com.example.firebase-auth"
	authContextKey = "firebase-auth-token"
)

type FirebaseAuthModule struct {
	FirebaseAuth *auth.Client
	Logger       *zap.Logger
}

func (m *FirebaseAuthModule) Provision(ctx *core.ModuleContext) error {
	// Provide the path to the Firebase admin SDK json file
	app, err := firebase.NewApp(context.Background(), nil, option.WithCredentialsFile("path/to/ourStagewoodKey.json"))
	if err != nil {
		return fmt.Errorf("error initializing Firebase app: %v", err)
	}

	m.FirebaseAuth, err = app.Auth(context.Background())
	if err != nil {
		return fmt.Errorf("failed to initialize Firebase Auth client: %v", err)
	}

	// Assign the logger to the module
	m.Logger = ctx.Logger

	return nil
}

func (m *FirebaseAuthModule) Middleware(ctx core.RequestContext, next http.Handler) {
	authHeader := ctx.Request().Header.Get("Authorization")
	if authHeader == "" {
		core.WriteResponseError(ctx, fmt.Errorf("authorization header is required"))
		return
	}

	idToken := authHeader[len("Bearer "):]
	token, err := m.FirebaseAuth.VerifyIDToken(context.Background(), idToken)
	if err != nil {
		core.WriteResponseError(ctx, fmt.Errorf("error verifying Firebase ID token: %w", err))
		return
	}

	ctx.Set(authContextKey, token.Claims)
	next.ServeHTTP(ctx.ResponseWriter(), ctx.Request())
}

func (m *FirebaseAuthModule) OnOriginRequest(request *http.Request, ctx core.RequestContext) (*http.Request, *http.Response) {
	if claims, ok := ctx.Get(authContextKey); ok {
		if claimsMap, ok := claims.(map[string]interface{}); ok {
			// Now you can safely use claimsMap
			// Example: Accessing user_id from claims
			if userID, ok := claimsMap["user_id"].(string); ok {
				request.Header.Add("X-User-ID", userID)
			}
		}
	}
	return request, nil
}

func (m *FirebaseAuthModule) Module() core.ModuleInfo {
	return core.ModuleInfo{
		ID: ModuleID,
		New: func() core.Module {
			return &FirebaseAuthModule{}
		},
	}
}

var _ interface {
	core.EnginePreOriginHandler
	core.RouterMiddlewareHandler
	core.Provisioner
} = (*FirebaseAuthModule)(nil)
