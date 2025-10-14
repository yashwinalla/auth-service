package handlers

import (
	"github.com/hivemindd/auth-service/config"
	"github.com/hivemindd/auth-service/internal/auth"
	"github.com/hivemindd/auth-service/internal/store"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
)

// Service struct holds all variables common to all handlers.
// That is why members have to be safe for concurrent use and do not cause race conditions!
type Service struct {
	ServiceName    string
	Config         *config.Config
	AuthService    *auth.AuthClient
	Logger         *zap.Logger
	Db             *store.PostgresStore
	TracerProvider *trace.TracerProvider
}
