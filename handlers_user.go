package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"github.com/hivemindd/auth-service/internal/model"
	"github.com/hivemindd/kit/auth"
	"github.com/hivemindd/kit/errorsx"
	"github.com/hivemindd/kit/ginutil"
	"github.com/hivemindd/kit/optional"
	"go.uber.org/zap"
)

func (s *Service) Health(c *gin.Context) {
	ginutil.JSON(c, nil, "Success")
}

func (s *Service) SignUp(c *gin.Context) {
	ctx := c.Request.Context()

	var req SignUpRequest
	err := c.BindJSON(&req)
	if err != nil {
		errMsg := "failed to decode sign-up request"
		s.Logger.Error(errMsg, zap.Error(err))
		ginutil.JSONError(c, http.StatusBadRequest, nil, errMsg+": %v", err)
		return
	}

	err = validateEmail(req.Email)
	if err != nil {
		ginutil.JSONError(c, http.StatusBadRequest, nil, "%v", err.Error())
		return
	}

	err = s.AuthService.SignUp(ctx, model.SignUpArgs{
		Email: req.Email,
		Tnc:   req.Tnc,
	})
	if err != nil {
		errMsg := "failed to do sign-up"
		s.Logger.Error(errMsg, zap.Error(err))
		errorsx.HandleError(c, err)
		return
	}

	ginutil.JSON(c, nil, "User created successfully. Please check your inbox to verify your email and set your password.")
}

func validateEmail(email string) error {
	return validation.Validate(
		email,
		validation.Required.Error("email is required"),
		is.Email.Error("valid email is required"))
}

func (s *Service) ForgotPassword(c *gin.Context) {
	ctx := c.Request.Context()

	var req ForgotPasswordRequest
	err := c.BindJSON(&req)
	if err != nil {
		errMsg := "failed to decode forgot-password request"
		s.Logger.Error(errMsg, zap.Error(err))
		ginutil.JSONError(c, http.StatusBadRequest, nil, errMsg+": %v", err)
		return
	}

	err = validateEmail(req.Email)
	if err != nil {
		ginutil.JSONError(c, http.StatusBadRequest, nil, "%v", err.Error())
		return
	}

	err = s.AuthService.ForgotPassword(ctx, &model.ForgotPasswordArgs{
		Email: req.Email,
	})
	if err != nil {
		errMsg := "failed to do forgot-password"
		s.Logger.Error(errMsg, zap.Error(err))
		errorsx.HandleError(c, err)
		return
	}

	ginutil.JSON(c, nil, "Password reset link sent. Please check your inbox.")
}

func (s *Service) SocialSignUp(c *gin.Context) {
	ctx := c.Request.Context()

	var req SocialSignUpRequest
	err := c.BindJSON(&req)
	if err != nil {
		errMsg := "failed to decode social sign-up request"
		s.Logger.Error(errMsg, zap.Error(err))
		ginutil.JSONError(c, http.StatusBadRequest, nil, errMsg+": %v", err)
		return
	}

	err = validateEmail(req.Email)
	if err != nil {
		ginutil.JSONError(c, http.StatusBadRequest, nil, "%v", err.Error())
		return
	}

	created, err := s.AuthService.SocialSignUp(ctx, model.SocialSignUpArgs{
		Email:          req.Email,
		FirebaseUserID: req.FirebaseUserID,
		Tnc:            req.Tnc,
	})
	if err != nil {
		errMsg := "failed to do social sign-up"
		s.Logger.Error(errMsg, zap.Error(err))
		errorsx.HandleError(c, err)
		return
	}

	if created {
		ginutil.JSON(c, nil, "User created successfully.")
	} else {
		ginutil.JSON(c, nil, "Success")
	}
}

func (s *Service) LogUserLogin(c *gin.Context) {
	ctx := c.Request.Context()

	var req LoginLogsRequest
	err := c.BindJSON(&req)
	if err != nil {
		errMsg := "failed to decode login logs request"
		s.Logger.Error(errMsg, zap.Error(err))
		ginutil.JSONError(c, http.StatusBadRequest, nil, errMsg+": %v", err)
		return
	}

	claims := auth.GetClaims(c)
	var userDocID optional.Optional[string]
	if claims != nil {
		userDocID = optional.NewOptional(claims.UserID)
	}

	// clientIP := c.ClientIP()
	clientIP := "8.8.8.8" // Google's public DNS IP, just for dev

	loginFailureCount, err := s.AuthService.LogUserLogin(ctx, &model.LoginLogArgs{
		Email:     req.Email,
		UserDocID: userDocID,
		IpAddress: clientIP,
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		errMsg := "failed to login user log"
		s.Logger.Error(errMsg, zap.Error(err))
		ginutil.JSONError(c, http.StatusBadRequest, nil, errMsg+": %v", err)
		return
	}

	accountLockStatus := false

	if loginFailureCount == 3 {
		accountLockStatus = true
	}

	ginutil.JSON(c, &AccountLockStatusResponse{IsAccountLocked: accountLockStatus, LoginFailureCount: loginFailureCount}, "Success")
}

func (s *Service) CheckAccountLockStatus(c *gin.Context, params CheckAccountLockStatusParams) {
	ctx := c.Request.Context()

	accountLockStatus, err := s.AuthService.CheckAccountLockStatus(ctx, params.Email)
	if err != nil {
		errMsg := "failed to get account lock status"
		s.Logger.Error(errMsg, zap.Error(err))
		ginutil.JSONError(c, http.StatusBadRequest, nil, errMsg+": %v", err)
		return
	}

	if accountLockStatus == nil {
		ginutil.JSON(c, &AccountLockStatusResponse{IsAccountLocked: false, LoginFailureCount: 0}, "Success")
		return
	}

	ginutil.JSON(c, &AccountLockStatusResponse{IsAccountLocked: accountLockStatus.IsAccountLocked, LoginFailureCount: 0}, "Success")
}

func (s *Service) UnlockAccount(c *gin.Context, params UnlockAccountParams) {
	ctx := c.Request.Context()

	err := s.Db.UpdateAccountLockedUntil(ctx, params.Email, nil)
	if err != nil {
		errMsg := "failed to unlock account"
		s.Logger.Error(errMsg, zap.Error(err))
		ginutil.JSONError(c, http.StatusBadRequest, nil, errMsg+": %v", err)
		return
	}

	ginutil.JSON(c, nil, "Success")
}

func (s *Service) ResendPasswordResetLink(c *gin.Context) {
	ctx := c.Request.Context()

	var req ResendPasswordResetLinkRequest
	err := c.BindJSON(&req)
	if err != nil {
		errMsg := "failed to decode resend password reset link request"
		s.Logger.Error(errMsg, zap.Error(err))
		ginutil.JSONError(c, http.StatusBadRequest, nil, "%v", err)
		return
	}

	err = validateEmail(req.Email)
	if err != nil {
		ginutil.JSONError(c, http.StatusBadRequest, nil, "%v", err.Error())
		return
	}

	err = s.AuthService.ResendPasswordResetLink(ctx, &model.ResendPasswordResetLinkArgs{
		Email: req.Email,
	})
	if err != nil {
		errMsg := "failed to resend password reset link"
		s.Logger.Error(errMsg, zap.Error(err))
		errorsx.HandleError(c, err)
		return
	}

	ginutil.JSON(c, nil, "Password reset link sent. Please check your inbox.")
}

func (s *Service) ValidatePasswordResetToken(c *gin.Context, params ValidatePasswordResetTokenParams) {
	ctx := c.Request.Context()

	if params.Token == "" {
		ginutil.JSONError(c, http.StatusBadRequest, nil, "token is required")
		return
	}

	err := s.AuthService.ValidatePasswordResetToken(ctx, params.Token)
	if err != nil {
		errMsg := "failed to validate password reset token"
		s.Logger.Error(errMsg, zap.Error(err))
		errorsx.HandleError(c, err)
		return
	}

	ginutil.JSON(c, nil, "Token is valid.")
}

func (s *Service) ResetPasswordSubmit(c *gin.Context, params ResetPasswordSubmitParams) {
	ctx := c.Request.Context()

	if params.Token == "" {
		ginutil.JSONError(c, http.StatusBadRequest, nil, "token is required")
		return
	}

	err := s.AuthService.ResetPasswordSubmit(ctx, params.Token)
	if err != nil {
		errMsg := "failed to reset password"
		s.Logger.Error(errMsg, zap.Error(err))
		errorsx.HandleError(c, err)
		return
	}

	ginutil.JSON(c, nil, "Password has been successfully reset.")
}

func (s *Service) DeleteFacebookUserData(c *gin.Context) {
	ctx := c.Request.Context()

	url, err := s.AuthService.DeleteFacebookUserData(ctx, c.PostForm("signed_request"))
	if err != nil {
		errMsg := "failed to delete facebook user data"
		s.Logger.Error(errMsg, zap.Error(err))
		ginutil.JSONError(c, http.StatusBadRequest, nil, errMsg+": %v", err)
		return
	}

	ginutil.JSON(c, &DeleteFacebookUserDataResponse{Url: url}, "Success")
}

func (s *Service) GetFacebookUserDataDeletionStatus(c *gin.Context, params GetFacebookUserDataDeletionStatusParams) {
	ctx := c.Request.Context()

	err := s.AuthService.GetFacebookUserDataDeletionStatus(ctx, params.UserId)
	if err != nil {
		errMsg := "failed to get facebook user data deletion status"
		s.Logger.Error(errMsg, zap.Error(err))
		ginutil.JSONError(c, http.StatusBadRequest, nil, errMsg+": %v", err)
		return
	}

	ginutil.JSON(
		c,
		&FacebookUserDataDeletionStatusResponse{
			UserId:  params.UserId,
			Status:  "deleted",
			Message: "User data deleted successfully.",
		}, "Success")
}
