package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	firebase "firebase.google.com/go"
	firebaseAuth "firebase.google.com/go/auth"

	"github.com/gin-gonic/gin"
	"github.com/hivemindd/auth-service/config"
	"github.com/hivemindd/auth-service/handlers"
	"github.com/hivemindd/auth-service/internal/auth"
	"github.com/hivemindd/auth-service/internal/email"
	"github.com/hivemindd/auth-service/internal/store"
	"github.com/hivemindd/expert-service/pkg/expertgrpc"
	"github.com/hivemindd/kit/env"
	"github.com/hivemindd/kit/queue"
	"github.com/hivemindd/kit/sentry"
	"github.com/hivemindd/kit/zaplog"

	"go.uber.org/zap"

	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const serviceName = "auth-service"

func main() {
	// Default environment variable ENV has to be set via Makefile with values: dev, stg, prod.
	environ := os.Getenv("ENV")
	if environ == "" {
		panic("Failed to get environment variable ENV. Make sure it is set.")
	}
	// Used only when local env needs to load secrets from GCP Secret Manager
	env.SetProjectID(os.Getenv("PROJECT_ID"))
	env.SetCredentialsFile(os.Getenv("SECRET_CREDENTIALS_PATH"))

	var conf config.Config
	if err := env.Load(&conf); err != nil {
		panic("Failed to load environment variables:" + err.Error())
	}
	conf.DatabaseURI = strings.Trim(conf.DatabaseURI, "'")
	if !strings.HasPrefix(conf.ServerPort, ":") {
		conf.ServerPort = ":" + conf.ServerPort
	}

	lg := zaplog.Setup(serviceName)
	logger := sentry.AttachLogger(lg, conf.SentryDSN, serviceName)
	defer logger.Sync()

	startService(&conf, logger)
}

func startService(conf *config.Config, logger *zap.Logger) {
	logger.Info("Starting", zap.String("service", serviceName), zap.String("env", string(env.Get())))

	psqlConn, err := connectPostgres(conf.DatabaseURI)
	if err != nil {
		logger.Fatal("Failed to connect to postgres", zap.String("databaseuri", conf.DatabaseURI), zap.Error(err))
	}
	postgresStore := store.NewPostgresStore(psqlConn)

	tp, shutdown := newTracerProvider(serviceName, logger)
	defer shutdown()

	// Initialize Firebase
	var authClient *firebaseAuth.Client
	opt := option.WithCredentialsJSON([]byte(conf.Firebase.PrivateKey))
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		logger.Fatal("error initializing Firebase app: ", zap.Error(err))
	}
	authClient, err = app.Auth(context.Background())
	if err != nil {
		logger.Fatal("error initializing Firebase Auth: ", zap.Error(err))
	}

	q := queue.Connect(conf.Rabbit.URI)

	sender := email.NewSender(q, conf.Rabbit.EMAIL_QUEUE)

	expertCtx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	expertConn, err := grpc.DialContext(expertCtx, conf.ExpertServiceGRPCAddr, grpc.WithBlock(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logger.Panic("failed to dial to expert", zap.Error(err), zap.String("addr", conf.ExpertServiceGRPCAddr))
	}
	expertClient := expertgrpc.NewExpertClient(expertConn)

	authService := auth.NewAuthService(postgresStore, logger, authClient, sender, conf.WebAppURL, expertClient)

	srv := &handlers.Service{
		ServiceName:    serviceName,
		Config:         conf,
		Logger:         logger,
		TracerProvider: tp,
		Db:             postgresStore,
		AuthService:    authService,
	}

	router, err := handlers.SetupRouter(srv)
	if err != nil {
		logger.Panic("Failed to setup router", zap.Error(err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)

	go func() {
		errCh <- listenAndServe(ctx, router, conf.ServerPort, logger)
	}()

	err = <-errCh
	if err != nil {
		logger.Error("Server exited with error", zap.Error(err))
	} else {
		logger.Info("Server exited gracefully")
	}
}

func listenAndServe(ctx context.Context, router *gin.Engine, serverPort string, logger *zap.Logger) error {
	srv := &http.Server{
		Addr:    serverPort,
		Handler: router,
	}

	serverErrCh := make(chan error, 1)

	go func() {
		logger.Info("Listening on address", zap.String("port", serverPort))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("Shutting down gracefully")

		ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctxShutDown); err != nil {
			return err
		}

		return nil
	case err := <-serverErrCh:
		return err
	}
}
