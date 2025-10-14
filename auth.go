package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	firebaseAuth "firebase.google.com/go/auth"

	"github.com/hivemindd/auth-service/internal/model"
	expertgrpc "github.com/hivemindd/expert-service/pkg/expertgrpc"
	"github.com/hivemindd/kit/docid"
	"github.com/hivemindd/kit/errorsx"
	"github.com/mssola/user_agent"

	"go.uber.org/zap"
)

const (
	ErrResetPasswordLinkExpired = "The link has expired. Try new reset link or request for a new password reset link."
)

var httpGet = http.Get

type FirebaseClient interface {
	CreateUser(ctx context.Context, params *firebaseAuth.UserToCreate) (*firebaseAuth.UserRecord, error)
	SetCustomUserClaims(ctx context.Context, uid string, claims map[string]interface{}) error
	PasswordResetLink(ctx context.Context, email string) (string, error)
}

type EmailSender interface {
	SendResetPasswordEmail(ctx context.Context, emailType model.EmailType, email string, link string) error
	SendAccountLockEmail(ctx context.Context, emailType model.EmailType, email string, link string, loginLog *model.LoginLog) error
}

type AuthClient struct {
	store        AggregateStoreTx
	logger       *zap.Logger
	authClient   FirebaseClient
	emailSender  EmailSender
	webAppURL    string
	expertClient expertgrpc.ExpertClient
}

func NewAuthService(
	store AggregateStoreTx,
	logger *zap.Logger,
	authClient FirebaseClient,
	emailSender EmailSender,
	webAppURL string,
	expertClient expertgrpc.ExpertClient,
) *AuthClient {
	return &AuthClient{
		store:        store,
		logger:       logger,
		authClient:   authClient,
		emailSender:  emailSender,
		webAppURL:    webAppURL,
		expertClient: expertClient,
	}
}

func (a *AuthClient) SignUp(ctx context.Context, args model.SignUpArgs) error {
	params := (&firebaseAuth.UserToCreate{}).Email(args.Email).Password(generatePassword())
	firebaseUser, err := a.authClient.CreateUser(ctx, params)
	if err != nil {
		mappedErr := mapFirebaseError(err)
		a.logger.Error("failed to create user in firebase: ", zap.Error(mappedErr))
		return mappedErr
	}

	documentID := docid.New()
	err = a.store.SignUp(ctx, &model.User{
		DocumentID:     documentID,
		Email:          args.Email,
		FirebaseUserID: firebaseUser.UID,
		Tnc:            args.Tnc,
	})
	if err != nil {
		a.logger.Error("failed to do sign-up: ", zap.Error(err))
		return err
	}

	claims := map[string]interface{}{
		"user_document_id": documentID,
	}
	err = a.authClient.SetCustomUserClaims(ctx, firebaseUser.UID, claims)
	if err != nil {
		a.logger.Error("failed to set custom claims: ", zap.Error(err))
		return err
	}

	return a.ResendPasswordResetLink(ctx, &model.ResendPasswordResetLinkArgs{
		Email: args.Email,
	})
}

func generatePassword() string {
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower := "abcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"
	special := "!@#$%^&*()_+{}[]<>?"

	all := upper + lower + digits + special

	rand.Seed(time.Now().UnixNano())

	password := make([]byte, 10)
	password[0] = upper[rand.Intn(len(upper))]
	password[1] = lower[rand.Intn(len(lower))]
	password[2] = digits[rand.Intn(len(digits))]
	password[3] = special[rand.Intn(len(special))]

	for i := 4; i < 10; i++ {
		password[i] = all[rand.Intn(len(all))]
	}

	rand.Shuffle(len(password), func(i, j int) {
		password[i], password[j] = password[j], password[i]
	})

	return string(password)
}

func mapFirebaseError(err error) error {
	if strings.Contains(err.Error(), "EMAIL_EXISTS") {
		return errorsx.NewBadRequestError(errors.New("an account with this email already exists in firebase"))
	}
	return err
}

func (a *AuthClient) ForgotPassword(ctx context.Context, args *model.ForgotPasswordArgs) error {
	_, token, err := a.createPasswordResetLog(ctx, args.Email)
	if err != nil {
		a.logger.Error("failed to create password reset log: ", zap.Error(err))
		return err
	}
	link := fmt.Sprintf("%s/reset-password?email=%s&email_type=%s&token=%s", a.webAppURL, args.Email, model.ForgotPasswordEmailType, token)
	return a.emailSender.SendResetPasswordEmail(ctx, model.ForgotPasswordEmailType, args.Email, link)
}

func (a *AuthClient) SocialSignUp(ctx context.Context, args model.SocialSignUpArgs) (bool, error) {
	count, err := a.store.CheckIfEmailExists(ctx, args.Email)
	if err != nil {
		a.logger.Error("failed to do social sign-up: ", zap.Error(err))
		return false, err
	}

	if count == 0 {
		documentID := docid.New()
		err = a.store.SignUp(ctx, &model.User{
			DocumentID:     documentID,
			Email:          args.Email,
			FirebaseUserID: args.FirebaseUserID,
			Tnc:            args.Tnc,
		})
		if err != nil {
			a.logger.Error("failed to do social sign-up: ", zap.Error(err))
			return false, err
		}

		claims := map[string]interface{}{
			"user_document_id": documentID,
		}

		err = a.authClient.SetCustomUserClaims(ctx, args.FirebaseUserID, claims)
		if err != nil {
			a.logger.Error("failed to set custom claims: ", zap.Error(err))
			return false, err
		}

		err = a.updateExpertBranding(ctx, args.Email, args.FirebaseUserID, documentID)
		if err != nil {
			a.logger.Error("failed to create expert with username", zap.Error(err))
			return false, err
		}

		return true, nil
	}

	return false, nil
}

func (a *AuthClient) LogUserLogin(ctx context.Context, args *model.LoginLogArgs) (int64, error) {
	var userID *uint
	var status string
	var loginFailureCount int64

	if args.UserDocID.IsValid() && args.UserDocID.ShouldGet() != "" {
		user, err := a.store.GetUser(ctx, args.UserDocID.ShouldGet())
		if err != nil {
			a.logger.Error("failed to get user", zap.Error(err))
			return loginFailureCount, err
		}
		if args.UserDocID.ShouldGet() == user.DocumentID {
			userID = &user.ID
			status = "success"
		}
	}

	ipAPIResponse, err := getLocationFromIP(args.IpAddress)
	if err != nil {
		a.logger.Error("", zap.Error(err))
		return loginFailureCount, err
	}
	location := ipAPIResponse.City
	if ipAPIResponse.Country != "" {
		location = fmt.Sprintf("%s, %s", ipAPIResponse.City, ipAPIResponse.Country)
	}

	userAgentInfo := parseUserAgentInfo(args.UserAgent)
	device := userAgentInfo.Browser
	if userAgentInfo.OS != "" {
		device = fmt.Sprintf("%s, %s", userAgentInfo.Browser, userAgentInfo.OS)
	}

	loginLog := &model.LoginLog{
		DocumentID: docid.New(),
		Email:      args.Email,
		UserID:     userID,
		IpAddress:  args.IpAddress,
		Location:   location,
		UserAgent:  args.UserAgent,
		Device:     device,
		Status:     status,
	}

	err = a.store.CreateLoginLog(ctx, loginLog)
	if err != nil {
		a.logger.Error("failed to log user login: ", zap.Error(err))
		return loginFailureCount, err
	}

	loginFailureCount, err = a.store.HasConsecutiveLoginFailures(ctx, args.Email)
	if err != nil {
		a.logger.Error("failed to get consecutive login failures count: ", zap.Error(err))
		return loginFailureCount, err
	}

	if loginFailureCount == 3 {
		emailExists, err := a.store.CheckIfEmailExists(ctx, args.Email)
		if err != nil {
			a.logger.Error("failed to check if email exists: ", zap.Error(err))
			return loginFailureCount, err
		}

		if emailExists == 1 {
			accountLockedUntil := time.Now().Add(30 * time.Minute)
			err := a.store.UpdateAccountLockedUntil(ctx, args.Email, &accountLockedUntil)
			if err != nil {
				a.logger.Error("failed to update user account locked until time: ", zap.Error(err))
				return loginFailureCount, err
			}

			_, token, err := a.createPasswordResetLog(ctx, args.Email)
			if err != nil {
				a.logger.Error("failed to create password reset log: ", zap.Error(err))
				return loginFailureCount, err
			}

			link := fmt.Sprintf("%s/reset-password?email=%s&email_type=%s&token=%s", a.webAppURL, args.Email, model.AccountLockEmailType, token)

			return loginFailureCount, a.emailSender.SendAccountLockEmail(ctx, model.AccountLockEmailType, args.Email, link, loginLog)
		}
	}

	return loginFailureCount, nil
}

type IPAPIResponse struct {
	Status     string  `json:"status"`
	Country    string  `json:"country"`
	RegionName string  `json:"regionName"`
	City       string  `json:"city"`
	Zip        string  `json:"zip"`
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
	Timezone   string  `json:"timezone"`
	Query      string  `json:"query"`
	Message    string  `json:"message"`
}

func getLocationFromIP(ip string) (*IPAPIResponse, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip)
	resp, err := httpGet(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IP location: %w", err)
	}
	defer resp.Body.Close()

	var data IPAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if data.Status != "success" {
		return nil, fmt.Errorf("ip-api error: %s", data.Message)
	}

	return &data, nil
}

type UserAgentInfo struct {
	DeviceType string // "mobile", "tablet", "desktop", etc.
	Browser    string
	BrowserVer string
	OS         string
}

func parseUserAgentInfo(userAgent string) UserAgentInfo {
	ua := user_agent.New(userAgent)

	browserName, browserVersion := ua.Browser()

	deviceType := "desktop"
	if ua.Mobile() {
		deviceType = "mobile"
	}

	return UserAgentInfo{
		DeviceType: deviceType,
		Browser:    browserName,
		BrowserVer: browserVersion,
		OS:         ua.OS(),
	}
}

func (a *AuthClient) CheckAccountLockStatus(ctx context.Context, email string) (*model.AccountLockStatus, error) {
	accountLockeStatus, err := a.store.CheckAccountLockStatus(ctx, email)
	if err != nil {
		a.logger.Error("failed to get account lock status: ", zap.Error(err))
		return nil, err
	}

	return accountLockeStatus, nil
}

func (a *AuthClient) ResendPasswordResetLink(ctx context.Context, args *model.ResendPasswordResetLinkArgs) error {
	fuid, token, err := a.createPasswordResetLog(ctx, args.Email)
	if err != nil {
		a.logger.Error("failed to create password reset log:", zap.Error(err))
		return err
	}
	link := fmt.Sprintf("%s/reset-password?email=%s&email_type=%s&fuid=%s&token=%s", a.webAppURL, args.Email, model.SetPasswordEmailType, fuid, token)
	return a.emailSender.SendResetPasswordEmail(ctx, model.SetPasswordEmailType, args.Email, link)
}

func (a *AuthClient) createPasswordResetLog(ctx context.Context, email string) (string, string, error) {
	user, err := a.store.GetUserByEmail(ctx, email)
	if err != nil {
		a.logger.Error("failed to get user:", zap.Error(err))
		return "", "", err
	}

	dailyCount, err := a.store.GetPasswordResetLogsCountByUserIDInLast24Hours(ctx, user.ID)
	if err != nil {
		a.logger.Error("failed to get daily password reset count:", zap.Error(err))
		return "", "", err
	}
	if dailyCount >= 5 {
		return "", "", errorsx.NewBadRequestError(errors.New("You've reached the maximum number of password reset attempts for today. Please try again tomorrow."))
	}

	latestLog, err := a.store.GetLatestPasswordResetLogByUserID(ctx, user.ID)
	if err != nil {
		a.logger.Error("failed to get latest password reset log:", zap.Error(err))
		return "", "", err
	}
	if latestLog != nil {
		timeSinceLastRequest := time.Since(latestLog.CreatedAt)
		if timeSinceLastRequest < 5*time.Minute {
			remainingTime := 5*time.Minute - timeSinceLastRequest
			return "", "", errorsx.NewBadRequestError(fmt.Errorf("Please wait %v before requesting another password reset", remainingTime.Round(time.Second)))
		}
	}

	err = a.store.InvalidatePasswordResetLogsByUserID(ctx, user.ID)
	if err != nil {
		a.logger.Error("failed to invalidate previous password reset logs:", zap.Error(err))
		return "", "", err
	}

	token, err := a.generateSecureToken(ctx, email)
	if err != nil {
		a.logger.Error("failed to generate secure token(oobCode):", zap.Error(err))
		return "", "", err
	}

	err = a.store.CreatePasswordResetLog(ctx, &model.PasswordResetLog{
		UserID:      user.ID,
		Token:       token,
		Used:        false,
		Invalidated: false,
	})
	if err != nil {
		a.logger.Error("failed to create password reset log:", zap.Error(err))
		return "", "", err
	}

	return user.FirebaseUserID, token, nil
}

func (a *AuthClient) ValidatePasswordResetToken(ctx context.Context, token string) error {
	passwordResetLog, err := a.store.GetPasswordResetLog(ctx, token)
	if err != nil ||
		passwordResetLog == nil ||
		passwordResetLog.Used ||
		passwordResetLog.Invalidated ||
		time.Since(passwordResetLog.CreatedAt) > 30*time.Minute {
		a.logger.Error("failed to get password reset log:", zap.Error(err))
		return errorsx.NewBadRequestError(errors.New(ErrResetPasswordLinkExpired))
	}

	return nil
}

func (a *AuthClient) generateSecureToken(ctx context.Context, email string) (string, error) {
	resetPasswordlink, err := a.authClient.PasswordResetLink(ctx, email)
	if err != nil {
		return "", fmt.Errorf("failed to generate link: %w", err)
	}

	parsedResetPasswordLink, err := url.Parse(resetPasswordlink)
	if err != nil {
		return "", fmt.Errorf("failed to parse link: %w", err)
	}

	oobCode := parsedResetPasswordLink.Query().Get("oobCode")
	if oobCode == "" {
		return "", fmt.Errorf("oobCode not found in link: %w", err)
	}

	return oobCode, nil
}

func (a *AuthClient) ResetPasswordSubmit(ctx context.Context, token string) error {
	err := a.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		a.logger.Error("failed to validate password reset token:", zap.Error(err))
		return err
	}

	passwordResetLog, err := a.store.GetPasswordResetLog(ctx, token)
	if err != nil {
		a.logger.Error("failed to get password reset log:", zap.Error(err))
		return errorsx.NewBadRequestError(errors.New(ErrResetPasswordLinkExpired))
	}
	if passwordResetLog == nil {
		return errorsx.NewBadRequestError(errors.New(ErrResetPasswordLinkExpired))
	}

	passwordResetLog.Used = true
	err = a.store.UpdatePasswordResetLog(ctx, token, passwordResetLog)
	if err != nil {
		a.logger.Error("failed to mark password reset token as used:", zap.Error(err))
		return err
	}

	user, err := a.store.GetUserByID(ctx, passwordResetLog.UserID)
	if err != nil {
		a.logger.Error("failed to get user:", zap.Error(err))
		return err
	}

	err = a.store.UpdateAccountLockedUntil(ctx, user.Email, nil)
	if err != nil {
		a.logger.Error("failed to update account locked until:", zap.Error(err))
		return err
	}

	err = a.updateExpertBranding(ctx, user.Email, user.FirebaseUserID, user.DocumentID)
	if err != nil {
		a.logger.Error("failed to create expert with username", zap.Error(err))
		return err
	}

	return nil
}

func (a *AuthClient) updateExpertBranding(ctx context.Context, email, firebaseUserID, userID string) error {
	username, _, found := strings.Cut(email, "@")
	if !found || username == "" {
		errMsg := "failed to get username from email"
		a.logger.Error(errMsg)
		return errorsx.NewBadRequestError(errors.New(errMsg))
	}

	_, err := a.expertClient.UpdateExpertBranding(ctx, &expertgrpc.UpdateExpertBrandingRequest{
		FirebaseUserID: firebaseUserID,
		UserID:         userID,
		Username:       username,
	})
	if err != nil {
		a.logger.Error("failed to create expert with username", zap.Error(err))
		return err
	}

	return nil
}

func (a *AuthClient) DeleteFacebookUserData(ctx context.Context, signedRequest string) (string, error) {
	var data map[string]interface{}
	var userID string

	parts := strings.Split(signedRequest, ".")
	if len(parts) != 2 {
		return userID, errorsx.NewBadRequestError(errors.New("malformed signed_request: expected '<signature>.<payload>' format"))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return userID, errorsx.NewBadRequestError(errors.New("invalid signed_request payload: base64 decoding failed"))
	}

	if err := json.Unmarshal(payload, &data); err != nil {
		return userID, errorsx.NewBadRequestError(errors.New("invalid signed_request payload: JSON unmarshal failed"))
	}

	userIDValue, exists := data["user_id"]
	if !exists {
		return userID, errorsx.NewBadRequestError(errors.New("signed_request missing required field: 'user_id'"))
	}

	userID, ok := userIDValue.(string)
	if !ok {
		return userID, errorsx.NewBadRequestError(errors.New("invalid signed_request: 'user_id' is not a string"))
	}

	// TODO: for later - delete user data

	return fmt.Sprintf("%s/service/api/auth/v1/facebook/user-data-deletion-status?userId=%s", a.webAppURL, userID), nil
}

func (a *AuthClient) GetFacebookUserDataDeletionStatus(ctx context.Context, userID string) error {
	// TODO: for later - return user data deletion status
	return nil
}
