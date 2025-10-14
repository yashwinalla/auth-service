package handlers

import (
	"net/http"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-contrib/requestid"
	"github.com/gin-gonic/gin"
	"github.com/hivemindd/kit/auth"
	cors "github.com/itsjamie/gin-cors"
)

func SetupRouter(svr *Service) (*gin.Engine, error) {
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(sentrygin.New(sentrygin.Options{Repanic: true}))
	router.Use(requestid.New())
	router.Use(cors.Middleware(cors.Config{
		Origins:         "*", // TODO
		Methods:         "GET, PUT, POST, DELETE, HEAD, PATCH",
		RequestHeaders:  "Origin, Authorization, Content-Type, Content-Length",
		ExposedHeaders:  "Correlation-Id",
		MaxAge:          12 * time.Hour,
		Credentials:     false,
		ValidateHeaders: false,
	}))

	router.GET("/service/api/auth/v1/health", svr.Health)
	spec, err := GetSwagger()
	if err != nil {
		return nil, err
	}

	// oapi doesn't provide ability to check security and inject data in ctx, so we should do this in separate middlewares
	validator := auth.OAPIMiddleware(svr.Config.Firebase.ProjectID, spec)
	router.Use(validator, auth.InjectUserInfoInCtx(svr.Config.Firebase.ProjectID), svr.checkTokenInvalidated)
	RegisterHandlers(router, svr)
	openapi3filter.RegisterBodyDecoder("multipart/form-data", openapi3filter.FileBodyDecoder)

	return router, nil
}

func (s *Service) checkTokenInvalidated(c *gin.Context) {
	t := c.Request.Header.Get("Authorization")
	if t == "" || t == "Bearer" {
		return
	}

	token, _, err := auth.VerifyToken(c.Request, s.Config.Firebase.ProjectID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalidated token"})
	}
}
