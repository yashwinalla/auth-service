package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/hivemindd/auth-service/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	firebaseAuth "firebase.google.com/go/auth"
	expertgrpc "github.com/hivemindd/expert-service/pkg/expertgrpc"
	"github.com/hivemindd/kit/optional"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// --- Mock Expert Client ---
type MockExpertClient struct {
	mock.Mock
}

// Add any methods that ExpertClient interface requires
func (m *MockExpertClient) GetExpertProfile(ctx context.Context, req *expertgrpc.GetExpertProfileRequest, opts ...grpc.CallOption) (*expertgrpc.ExpertProfileResponse, error) {
	args := m.Called(ctx, req, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*expertgrpc.ExpertProfileResponse), args.Error(1)
}

func (m *MockExpertClient) UpdateExpertBranding(ctx context.Context, req *expertgrpc.UpdateExpertBrandingRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	args := m.Called(ctx, req, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*emptypb.Empty), args.Error(1)
}

// --- Mock Firebase Client ---
type MockFirebaseClient struct {
	mock.Mock
}

func (m *MockFirebaseClient) CreateUser(ctx context.Context, params *firebaseAuth.UserToCreate) (*firebaseAuth.UserRecord, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*firebaseAuth.UserRecord), args.Error(1)
}

func (m *MockFirebaseClient) SetCustomUserClaims(ctx context.Context, uid string, claims map[string]interface{}) error {
	args := m.Called(ctx, uid, claims)
	return args.Error(0)
}

// Add PasswordResetLink to satisfy FirebaseClient interface
func (m *MockFirebaseClient) PasswordResetLink(ctx context.Context, email string) (string, error) {
	args := m.Called(ctx, email)
	return args.String(0), args.Error(1)
}

// --- Mock Store ---
type MockStore struct {
	mock.Mock
}

func (m *MockStore) SignUp(ctx context.Context, user *model.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockStore) CheckIfEmailExists(ctx context.Context, email string) (int64, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStore) CheckAccountLockStatus(ctx context.Context, email string) (*model.AccountLockStatus, error) {
	args := m.Called(ctx, email)
	status, _ := args.Get(0).(*model.AccountLockStatus)
	return status, args.Error(1)
}

func (m *MockStore) CreateLoginLog(ctx context.Context, log *model.LoginLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockStore) GetUser(ctx context.Context, email string) (*model.User, error) {
	args := m.Called(ctx, email)
	user, _ := args.Get(0).(*model.User)
	return user, args.Error(1)
}

func (m *MockStore) HasConsecutiveLoginFailures(ctx context.Context, email string) (int64, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStore) UpdateAccountLockedUntil(ctx context.Context, email string, until *time.Time) error {
	args := m.Called(ctx, email, until)
	return args.Error(0)
}

func (m *MockStore) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	args := m.Called(ctx, email)
	user, _ := args.Get(0).(*model.User)
	return user, args.Error(1)
}

func (m *MockStore) GetUserByID(ctx context.Context, id uint) (*model.User, error) {
	args := m.Called(ctx, id)
	user, _ := args.Get(0).(*model.User)
	return user, args.Error(1)
}

func (m *MockStore) CreatePasswordResetLog(ctx context.Context, passwordResetLog *model.PasswordResetLog) error {
	args := m.Called(ctx, passwordResetLog)
	return args.Error(0)
}

func (m *MockStore) GetPasswordResetLog(ctx context.Context, token string) (*model.PasswordResetLog, error) {
	args := m.Called(ctx, token)
	log, _ := args.Get(0).(*model.PasswordResetLog)
	return log, args.Error(1)
}

func (m *MockStore) UpdatePasswordResetLog(ctx context.Context, token string, passwordResetLog *model.PasswordResetLog) error {
	args := m.Called(ctx, token, passwordResetLog)
	return args.Error(0)
}

func (m *MockStore) GetPasswordResetLogsByUserID(ctx context.Context, userID uint) ([]*model.PasswordResetLog, error) {
	args := m.Called(ctx, userID)
	logs, _ := args.Get(0).([]*model.PasswordResetLog)
	return logs, args.Error(1)
}

func (m *MockStore) InvalidatePasswordResetLogsByUserID(ctx context.Context, userID uint) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockStore) GetPasswordResetLogsCountByUserIDInLast24Hours(ctx context.Context, userID uint) (int64, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockStore) GetLatestPasswordResetLogByUserID(ctx context.Context, userID uint) (*model.PasswordResetLog, error) {
	args := m.Called(ctx, userID)
	log, _ := args.Get(0).(*model.PasswordResetLog)
	return log, args.Error(1)
}

// Add InTx to satisfy AggregateStoreTx
func (m *MockStore) InTx(ctx context.Context, f TxF) error {
	return f(ctx, m)
}

// --- Mock Email Sender ---
type MockEmailSender struct {
	mock.Mock
}

func (m *MockEmailSender) SendResetPasswordEmail(ctx context.Context, emailType model.EmailType, email string, link string) error {
	args := m.Called(ctx, emailType, email, link)
	return args.Error(0)
}

func (m *MockEmailSender) SendAccountLockEmail(ctx context.Context, emailType model.EmailType, email string, link string, log *model.LoginLog) error {
	args := m.Called(ctx, emailType, email, link, log)
	return args.Error(0)
}

func TestAuthClient_SignUp_Success(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockFirebase := new(MockFirebaseClient)
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)
	mockExpert := new(MockExpertClient)

	// Fake inputs
	email := "email@example.com"
	token := "generated_token"
	firebaseUser := &firebaseAuth.UserRecord{UserInfo: &firebaseAuth.UserInfo{UID: "firebase_user_id"}}
	expectedLink := "http://localhost:9001/reset-password?email=" + email + "&email_type=set_password&fuid=" + firebaseUser.UserInfo.UID + "&token=" + token

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase, // pass the mock
		mockEmail,
		"http://localhost:9001",
		mockExpert,
	)

	// Mock user for GetUserByEmail call
	user := &model.User{
		Model:          gorm.Model{ID: 1},
		Email:          email,
		FirebaseUserID: firebaseUser.UserInfo.UID,
	}

	// Expectations
	mockFirebase.On("CreateUser", mock.Anything, mock.Anything).Return(firebaseUser, nil)
	mockStore.On("SignUp", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return u.Email == email && u.FirebaseUserID == firebaseUser.UserInfo.UID
	})).Return(nil)
	mockFirebase.On("SetCustomUserClaims", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
	mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), nil)
	mockStore.On("GetLatestPasswordResetLogByUserID", mock.Anything, uint(1)).Return(nil, nil)
	mockStore.On("InvalidatePasswordResetLogsByUserID", mock.Anything, uint(1)).Return(nil)
	mockStore.On("CreatePasswordResetLog", mock.Anything, mock.Anything).Return(nil)
	mockFirebase.On("PasswordResetLink", mock.Anything, email).Return("https://example.com/reset?oobCode="+token, nil)
	mockEmail.On("SendResetPasswordEmail", mock.Anything, model.SetPasswordEmailType, email, expectedLink).Return(nil)

	// Run
	err := authClient.SignUp(ctx, model.SignUpArgs{Email: email, Tnc: true})

	// Assert
	assert.NoError(t, err)
	mockFirebase.AssertExpectations(t)
	mockEmail.AssertExpectations(t)
	mockStore.AssertExpectations(t)
}

func TestAuthClient_SignUp_FirebaseCreateUserFails(t *testing.T) {
	ctx := context.Background()

	mockFirebase := new(MockFirebaseClient)
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)

	email := "email@example.com"
	firebaseErr := errors.New("EMAIL_EXISTS: The email address is already in use by another account.")

	mockFirebase.On("CreateUser", mock.Anything, mock.Anything).Return((*firebaseAuth.UserRecord)(nil), firebaseErr)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	err := authClient.SignUp(ctx, model.SignUpArgs{Email: email, Tnc: true})

	require.Error(t, err)
	require.Contains(t, err.Error(), "an account with this email already exists in firebase")

	// Ensure no DB or email actions were performed
	mockStore.AssertNotCalled(t, "SignUp", mock.Anything, mock.Anything)
	mockEmail.AssertNotCalled(t, "SendResetPasswordEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	mockFirebase.AssertExpectations(t)
}

func TestAuthClient_SignUp_StoreFails(t *testing.T) {
	ctx := context.Background()

	mockFirebase := new(MockFirebaseClient)
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)

	email := "email@example.com"
	firebaseUser := &firebaseAuth.UserRecord{UserInfo: &firebaseAuth.UserInfo{UID: "firebase_user_id"}}
	storeErr := errors.New("db failure")

	mockFirebase.On("CreateUser", mock.Anything, mock.Anything).Return(firebaseUser, nil)
	mockStore.On("SignUp", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return u.Email == email && u.FirebaseUserID == firebaseUser.UserInfo.UID
	})).Return(storeErr)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	err := authClient.SignUp(ctx, model.SignUpArgs{Email: email, Tnc: true})

	require.Error(t, err)
	require.Contains(t, err.Error(), "db failure")

	// Ensure email is not sent
	mockEmail.AssertNotCalled(t, "SendResetPasswordEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	mockFirebase.AssertExpectations(t)
	mockStore.AssertExpectations(t)
}

func TestAuthClient_SignUp_SetCustomUserClaimsFails(t *testing.T) {
	ctx := context.Background()
	mockFirebase := new(MockFirebaseClient)
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)

	email := "email@example.com"
	firebaseUser := &firebaseAuth.UserRecord{UserInfo: &firebaseAuth.UserInfo{UID: "firebase_user_id"}}

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	mockFirebase.On("CreateUser", mock.Anything, mock.Anything).Return(firebaseUser, nil)
	mockStore.On("SignUp", mock.Anything, mock.Anything).Return(nil)
	mockFirebase.On("SetCustomUserClaims", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("claims error"))

	err := authClient.SignUp(ctx, model.SignUpArgs{Email: email, Tnc: true})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "claims error")
	mockFirebase.AssertExpectations(t)
	mockStore.AssertExpectations(t)
}

func TestAuthClient_SocialSignUp_Success(t *testing.T) {
	ctx := context.Background()

	mockFirebase := new(MockFirebaseClient)
	mockStore := new(MockStore)
	mockExpert := new(MockExpertClient)

	// Fake inputs
	email := "email@example.com"
	firebaseUserID := "firebase_user_id"

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		nil,
		"",
		mockExpert,
	)

	// Expectations
	mockStore.On("CheckIfEmailExists", mock.Anything, email).Return(int64(0), nil)
	mockStore.On("SignUp", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return u.Email == email && u.FirebaseUserID == firebaseUserID
	})).Return(nil)
	mockFirebase.On("SetCustomUserClaims", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockExpert.On("UpdateExpertBranding", mock.Anything, mock.Anything, mock.Anything).Return(&emptypb.Empty{}, nil)

	// Run
	_, err := authClient.SocialSignUp(ctx, model.SocialSignUpArgs{Email: email, FirebaseUserID: firebaseUserID, Tnc: true})

	// Assert
	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
	mockFirebase.AssertExpectations(t)
	mockExpert.AssertExpectations(t)
}

func TestAuthClient_SocialSignUp_SetCustomUserClaimsFails(t *testing.T) {
	ctx := context.Background()
	mockFirebase := new(MockFirebaseClient)
	mockStore := new(MockStore)
	mockExpert := new(MockExpertClient)

	email := "email@example.com"
	firebaseUserID := "firebase_user_id"

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		nil,
		"",
		mockExpert,
	)

	mockStore.On("CheckIfEmailExists", mock.Anything, email).Return(int64(0), nil)
	mockStore.On("SignUp", mock.Anything, mock.Anything).Return(nil)
	mockFirebase.On("SetCustomUserClaims", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("claims error"))

	_, err := authClient.SocialSignUp(ctx, model.SocialSignUpArgs{Email: email, FirebaseUserID: firebaseUserID, Tnc: true})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "claims error")
	mockFirebase.AssertExpectations(t)
	mockStore.AssertExpectations(t)
}

func TestAuthClient_ForgotPassword_Success(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	// Fake inputs
	email := "email@example.com"
	token := "generated_token"
	expectedLink := "http://localhost:9001/reset-password?email=" + email + "&email_type=forgot_password&token=" + token

	// Mock user for GetUserByEmail call
	user := &model.User{
		Model: gorm.Model{ID: 1},
		Email: email,
	}

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Expectations
	mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
	mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), nil)
	mockStore.On("GetLatestPasswordResetLogByUserID", mock.Anything, uint(1)).Return(nil, nil)
	mockStore.On("InvalidatePasswordResetLogsByUserID", mock.Anything, uint(1)).Return(nil)
	mockStore.On("CreatePasswordResetLog", mock.Anything, mock.Anything).Return(nil)
	mockFirebase.On("PasswordResetLink", mock.Anything, email).Return("https://example.com/reset?oobCode="+token, nil)
	mockEmail.On("SendResetPasswordEmail", mock.Anything, model.ForgotPasswordEmailType, email, expectedLink).Return(nil)

	// Run
	err := authClient.ForgotPassword(ctx, &model.ForgotPasswordArgs{Email: email})

	// Assert
	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
	mockFirebase.AssertExpectations(t)
	mockEmail.AssertExpectations(t)
}

func TestGeneratePassword_Success(t *testing.T) {
	const iterations = 20 // Run multiple times to check randomness and constraints

	for i := 0; i < iterations; i++ {
		password := generatePassword()
		println(password)
	}
}

func TestMapFirebaseError_EmailExists(t *testing.T) {
	origErr := errors.New("something: EMAIL_EXISTS: already exists")
	err := mapFirebaseError(origErr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "an account with this email already exists in firebase")
}

func TestMapFirebaseError_OtherError(t *testing.T) {
	origErr := errors.New("some other firebase error")
	err := mapFirebaseError(origErr)
	require.Equal(t, origErr, err)
}

func TestAuthClient_CreatePasswordResetLog_SecurityChecks(t *testing.T) {
	ctx := context.Background()

	email := "test@example.com"
	user := &model.User{
		Model:          gorm.Model{ID: 1},
		Email:          email,
		FirebaseUserID: "test_firebase_user_id",
	}

	// Test daily limit exceeded
	t.Run("DailyLimitExceeded", func(t *testing.T) {
		mockStore := new(MockStore)
		mockFirebase := new(MockFirebaseClient)
		mockEmail := new(MockEmailSender)

		authClient := NewAuthService(
			mockStore,
			zap.NewNop(),
			mockFirebase,
			mockEmail,
			"http://localhost:9001",
			nil,
		)

		mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
		mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(5), nil)

		_, _, err := authClient.createPasswordResetLog(ctx, email)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "You've reached the maximum number of password reset attempts for today. Please try again tomorrow.")

		mockStore.AssertExpectations(t)
	})

	// Test cooldown period
	t.Run("CooldownPeriod", func(t *testing.T) {
		mockStore := new(MockStore)
		mockFirebase := new(MockFirebaseClient)
		mockEmail := new(MockEmailSender)

		authClient := NewAuthService(
			mockStore,
			zap.NewNop(),
			mockFirebase,
			mockEmail,
			"http://localhost:9001",
			nil,
		)

		latestLog := &model.PasswordResetLog{
			Model: gorm.Model{CreatedAt: time.Now().Add(-2 * time.Minute)}, // 2 minutes ago
		}

		mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
		mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), nil)
		mockStore.On("GetLatestPasswordResetLogByUserID", mock.Anything, uint(1)).Return(latestLog, nil)

		_, _, err := authClient.createPasswordResetLog(ctx, email)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Please wait")

		mockStore.AssertExpectations(t)
	})

	// Test successful creation
	t.Run("SuccessfulCreation", func(t *testing.T) {
		mockStore := new(MockStore)
		mockFirebase := new(MockFirebaseClient)
		mockEmail := new(MockEmailSender)

		authClient := NewAuthService(
			mockStore,
			zap.NewNop(),
			mockFirebase,
			mockEmail,
			"http://localhost:9001",
			nil,
		)

		mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
		mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), nil)
		mockStore.On("GetLatestPasswordResetLogByUserID", mock.Anything, uint(1)).Return(nil, nil)
		mockStore.On("InvalidatePasswordResetLogsByUserID", mock.Anything, uint(1)).Return(nil)
		mockStore.On("CreatePasswordResetLog", mock.Anything, mock.Anything).Return(nil)
		mockFirebase.On("PasswordResetLink", mock.Anything, email).Return("https://example.com/reset?oobCode=test_token", nil)

		firebaseUserID, token, err := authClient.createPasswordResetLog(ctx, email)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.NotEmpty(t, firebaseUserID)

		mockStore.AssertExpectations(t)
		mockFirebase.AssertExpectations(t)
	})
}

func TestAuthClient_LogUserLogin_Success(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)
	logger := zap.NewNop()

	userDocID := "user-doc-id"
	email := "user@example.com"
	ip := "1.2.3.4"
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

	args := &model.LoginLogArgs{
		Email:     email,
		UserDocID: optional.NewOptional(userDocID),
		IpAddress: ip,
		UserAgent: userAgent,
	}

	mockStore.On("GetUser", mock.Anything, userDocID).Return(&model.User{DocumentID: userDocID, Email: email}, nil)
	mockStore.On("CreateLoginLog", mock.Anything, mock.MatchedBy(func(log *model.LoginLog) bool {
		return log.Email == email && log.IpAddress == ip && log.UserAgent == userAgent && log.Status == "success" && log.UserID != nil
	})).Return(nil)
	mockStore.On("HasConsecutiveLoginFailures", mock.Anything, email).Return(int64(0), nil)

	authClient := NewAuthService(mockStore, logger, nil, mockEmail, "http://localhost:9001", nil)

	_, err := authClient.LogUserLogin(ctx, args)
	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
}

func TestAuthClient_LogUserLogin_Fail_GetUser(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)
	logger := zap.NewNop()

	userDocID := "user-doc-id"
	email := "user@example.com"
	ip := "1.2.3.4"
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

	args := &model.LoginLogArgs{
		Email:     email,
		UserDocID: optional.NewOptional(userDocID),
		IpAddress: ip,
		UserAgent: userAgent,
	}

	mockStore.On("GetUser", mock.Anything, userDocID).Return(nil, errors.New("db error"))

	authClient := NewAuthService(mockStore, logger, nil, mockEmail, "http://localhost:9001", nil)

	_, err := authClient.LogUserLogin(ctx, args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db error")
	mockStore.AssertExpectations(t)
}

func TestGetLocationFromIP_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"city":    "TestCity",
			"country": "TestCountry",
		})
	}))
	defer ts.Close()

	// Patch http.Get
	origGet := httpGet
	httpGet = func(url string) (*http.Response, error) {
		return http.Get(strings.Replace(url, "http://ip-api.com/json/", ts.URL+"/", 1))
	}
	defer func() { httpGet = origGet }()

	resp, err := getLocationFromIP("1.2.3.4")
	assert.NoError(t, err)
	assert.Equal(t, "TestCity", resp.City)
	assert.Equal(t, "TestCountry", resp.Country)
	assert.Equal(t, "success", resp.Status)
}

func TestGetLocationFromIP_HTTPError(t *testing.T) {
	origGet := httpGet
	httpGet = func(url string) (*http.Response, error) {
		return nil, io.EOF
	}
	defer func() { httpGet = origGet }()

	resp, err := getLocationFromIP("1.2.3.4")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to fetch IP location")
}

func TestGetLocationFromIP_DecodeError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer ts.Close()

	origGet := httpGet
	httpGet = func(url string) (*http.Response, error) {
		return http.Get(strings.Replace(url, "http://ip-api.com/json/", ts.URL+"/", 1))
	}
	defer func() { httpGet = origGet }()

	resp, err := getLocationFromIP("1.2.3.4")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to decode response")
}

func TestGetLocationFromIP_APIFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "fail",
			"message": "bad ip",
		})
	}))
	defer ts.Close()

	origGet := httpGet
	httpGet = func(url string) (*http.Response, error) {
		return http.Get(strings.Replace(url, "http://ip-api.com/json/", ts.URL+"/", 1))
	}
	defer func() { httpGet = origGet }()

	resp, err := getLocationFromIP("1.2.3.4")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "ip-api error")
}

func TestParseUserAgentInfo(t *testing.T) {
	tests := []struct {
		name       string
		ua         string
		deviceType string
		browser    string
		os         string
	}{
		{
			name:       "Chrome on Mac",
			ua:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
			deviceType: "desktop",
			browser:    "Chrome",
			os:         "Intel Mac OS X 10_15_7",
		},
		{
			name:       "Safari on iPhone",
			ua:         "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
			deviceType: "mobile",
			browser:    "Safari",
			os:         "CPU iPhone OS 15_0 like Mac OS X",
		},
		{
			name:       "Firefox on Linux",
			ua:         "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0",
			deviceType: "desktop",
			browser:    "Firefox",
			os:         "Ubuntu",
		},
		{
			name:       "Edge on Windows",
			ua:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64",
			deviceType: "desktop",
			browser:    "Edge",
			os:         "Windows 10",
		},
		{
			name:       "Empty user agent",
			ua:         "",
			deviceType: "desktop",
			browser:    "",
			os:         "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info := parseUserAgentInfo(tc.ua)
			assert.Equal(t, tc.deviceType, info.DeviceType)
			assert.Equal(t, tc.browser, info.Browser)
			assert.Equal(t, tc.os, info.OS)
		})
	}
}

func TestAuthClient_CheckAccountLockStatus_Success(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStore)
	logger := zap.NewNop()
	email := "user@example.com"

	lockedStatus := &model.AccountLockStatus{IsAccountLocked: true}
	mockStore.On("CheckAccountLockStatus", mock.Anything, email).Return(lockedStatus, nil)
	authClient := NewAuthService(mockStore, logger, nil, nil, "", nil)

	status, err := authClient.CheckAccountLockStatus(ctx, email)
	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.True(t, status.IsAccountLocked)
	mockStore.AssertExpectations(t)
}

func TestAuthClient_CheckAccountLockStatus_Unlocked(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStore)
	logger := zap.NewNop()
	email := "user@example.com"

	unlockedStatus := &model.AccountLockStatus{IsAccountLocked: false}
	mockStore.On("CheckAccountLockStatus", mock.Anything, email).Return(unlockedStatus, nil)
	authClient := NewAuthService(mockStore, logger, nil, nil, "", nil)

	status, err := authClient.CheckAccountLockStatus(ctx, email)
	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.False(t, status.IsAccountLocked)
	mockStore.AssertExpectations(t)
}

func TestAuthClient_CheckAccountLockStatus_Error(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStore)
	logger := zap.NewNop()
	email := "user@example.com"

	mockStore.On("CheckAccountLockStatus", mock.Anything, email).Return((*model.AccountLockStatus)(nil), errors.New("db error"))
	authClient := NewAuthService(mockStore, logger, nil, nil, "", nil)

	status, err := authClient.CheckAccountLockStatus(ctx, email)
	assert.Error(t, err)
	assert.Nil(t, status)
	mockStore.AssertExpectations(t)
}

func TestAuthClient_LogUserLogin_Lockout_UpdateAccountLockedUntilError(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)
	logger := zap.NewNop()

	email := "user@example.com"
	ip := "1.2.3.4"
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
	userDocID := "user-doc-id"

	args := &model.LoginLogArgs{
		Email:     email,
		UserDocID: optional.NewOptional(userDocID),
		IpAddress: ip,
		UserAgent: userAgent,
	}

	mockStore.On("GetUser", mock.Anything, userDocID).Return(&model.User{DocumentID: userDocID, Email: email}, nil)
	mockStore.On("CreateLoginLog", mock.Anything, mock.Anything).Return(nil)
	mockStore.On("HasConsecutiveLoginFailures", mock.Anything, email).Return(int64(3), nil)
	mockStore.On("CheckIfEmailExists", mock.Anything, email).Return(int64(1), nil)
	mockStore.On("UpdateAccountLockedUntil", mock.Anything, email, mock.Anything).Return(errors.New("lock error"))

	authClient := NewAuthService(mockStore, logger, nil, mockEmail, "http://localhost:9001", nil)

	_, err := authClient.LogUserLogin(ctx, args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lock error")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_LogUserLogin_Lockout_SendAccountLockEmailError(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)
	mockFirebase := new(MockFirebaseClient)
	logger := zap.NewNop()

	email := "user@example.com"
	ip := "1.2.3.4"
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
	userDocID := "user-doc-id"

	args := &model.LoginLogArgs{
		Email:     email,
		UserDocID: optional.NewOptional(userDocID),
		IpAddress: ip,
		UserAgent: userAgent,
	}

	// Mock user for GetUserByEmail call
	user := &model.User{
		Model: gorm.Model{ID: 1},
		Email: email,
	}

	mockStore.On("GetUser", mock.Anything, userDocID).Return(&model.User{DocumentID: userDocID, Email: email}, nil)
	mockStore.On("CreateLoginLog", mock.Anything, mock.Anything).Return(nil)
	mockStore.On("HasConsecutiveLoginFailures", mock.Anything, email).Return(int64(3), nil)
	mockStore.On("CheckIfEmailExists", mock.Anything, email).Return(int64(1), nil)
	mockStore.On("UpdateAccountLockedUntil", mock.Anything, email, mock.Anything).Return(nil)
	mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
	mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), nil)
	mockStore.On("GetLatestPasswordResetLogByUserID", mock.Anything, uint(1)).Return(nil, nil)
	mockStore.On("InvalidatePasswordResetLogsByUserID", mock.Anything, uint(1)).Return(nil)
	mockStore.On("CreatePasswordResetLog", mock.Anything, mock.Anything).Return(nil)
	mockFirebase.On("PasswordResetLink", mock.Anything, email).Return("https://example.com/reset?oobCode=oob_code", nil)
	mockEmail.On("SendAccountLockEmail", mock.Anything, model.AccountLockEmailType, email, mock.Anything, mock.Anything).Return(errors.New("email error"))

	authClient := NewAuthService(mockStore, logger, mockFirebase, mockEmail, "http://localhost:9001", nil)

	_, err := authClient.LogUserLogin(ctx, args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email error")
	mockStore.AssertExpectations(t)
	mockFirebase.AssertExpectations(t)
	mockEmail.AssertExpectations(t)
}

func TestAuthClient_ValidatePasswordResetToken_AcceptanceCriteria(t *testing.T) {
	ctx := context.Background()
	token := "test_token"

	// Test 1: Valid token
	t.Run("ValidToken", func(t *testing.T) {
		mockStore := new(MockStore)
		mockFirebase := new(MockFirebaseClient)
		mockEmail := new(MockEmailSender)

		authClient := NewAuthService(
			mockStore,
			zap.NewNop(),
			mockFirebase,
			mockEmail,
			"http://localhost:9001",
			nil,
		)

		validLog := &model.PasswordResetLog{
			Model:       gorm.Model{CreatedAt: time.Now().Add(-10 * time.Minute)},
			Used:        false,
			Invalidated: false,
		}
		mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(validLog, nil)

		err := authClient.ValidatePasswordResetToken(ctx, token)
		assert.NoError(t, err)

		mockStore.AssertExpectations(t)
	})

	// Test 2: Used token
	t.Run("UsedToken", func(t *testing.T) {
		mockStore := new(MockStore)
		mockFirebase := new(MockFirebaseClient)
		mockEmail := new(MockEmailSender)

		authClient := NewAuthService(
			mockStore,
			zap.NewNop(),
			mockFirebase,
			mockEmail,
			"http://localhost:9001",
			nil,
		)

		usedLog := &model.PasswordResetLog{
			Model:       gorm.Model{CreatedAt: time.Now().Add(-10 * time.Minute)},
			Used:        true,
			Invalidated: false,
		}
		mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(usedLog, nil)

		err := authClient.ValidatePasswordResetToken(ctx, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "The link has expired. Try new reset link or request for a new password reset link")

		mockStore.AssertExpectations(t)
	})

	// Test 3: Invalidated token
	t.Run("InvalidatedToken", func(t *testing.T) {
		mockStore := new(MockStore)
		mockFirebase := new(MockFirebaseClient)
		mockEmail := new(MockEmailSender)

		authClient := NewAuthService(
			mockStore,
			zap.NewNop(),
			mockFirebase,
			mockEmail,
			"http://localhost:9001",
			nil,
		)

		invalidatedLog := &model.PasswordResetLog{
			Model:       gorm.Model{CreatedAt: time.Now().Add(-10 * time.Minute)},
			Used:        false,
			Invalidated: true,
		}
		mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(invalidatedLog, nil)

		err := authClient.ValidatePasswordResetToken(ctx, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "The link has expired. Try new reset link or request for a new password reset link")

		mockStore.AssertExpectations(t)
	})

	// Test 4: Expired token (older than 30 minutes)
	t.Run("ExpiredToken", func(t *testing.T) {
		mockStore := new(MockStore)
		mockFirebase := new(MockFirebaseClient)
		mockEmail := new(MockEmailSender)

		authClient := NewAuthService(
			mockStore,
			zap.NewNop(),
			mockFirebase,
			mockEmail,
			"http://localhost:9001",
			nil,
		)

		expiredLog := &model.PasswordResetLog{
			Model:       gorm.Model{CreatedAt: time.Now().Add(-35 * time.Minute)},
			Used:        false,
			Invalidated: false,
		}
		mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(expiredLog, nil)

		err := authClient.ValidatePasswordResetToken(ctx, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "The link has expired. Try new reset link or request for a new password reset link")

		mockStore.AssertExpectations(t)
	})

	// Test 5: Non-existent token
	t.Run("NonExistentToken", func(t *testing.T) {
		mockStore := new(MockStore)
		mockFirebase := new(MockFirebaseClient)
		mockEmail := new(MockEmailSender)

		authClient := NewAuthService(
			mockStore,
			zap.NewNop(),
			mockFirebase,
			mockEmail,
			"http://localhost:9001",
			nil,
		)

		mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(nil, nil)

		err := authClient.ValidatePasswordResetToken(ctx, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "The link has expired. Try new reset link or request for a new password reset link")

		mockStore.AssertExpectations(t)
	})
}

func TestAuthClient_CreatePasswordResetLog_AcceptanceCriteria(t *testing.T) {
	ctx := context.Background()
	email := "test@example.com"
	user := &model.User{
		Model:          gorm.Model{ID: 1},
		Email:          email,
		FirebaseUserID: "test_firebase_user_id",
	}

	// Test 1: Daily limit exceeded (5 attempts)
	t.Run("DailyLimitExceeded", func(t *testing.T) {
		mockStore := new(MockStore)
		mockFirebase := new(MockFirebaseClient)
		mockEmail := new(MockEmailSender)

		authClient := NewAuthService(
			mockStore,
			zap.NewNop(),
			mockFirebase,
			mockEmail,
			"http://localhost:9001",
			nil,
		)

		mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
		mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(5), nil)

		_, _, err := authClient.createPasswordResetLog(ctx, email)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "You've reached the maximum number of password reset attempts for today. Please try again tomorrow.")

		mockStore.AssertExpectations(t)
	})

	// Test 2: Cooldown period not met (less than 5 minutes)
	t.Run("CooldownPeriod", func(t *testing.T) {
		mockStore := new(MockStore)
		mockFirebase := new(MockFirebaseClient)
		mockEmail := new(MockEmailSender)

		authClient := NewAuthService(
			mockStore,
			zap.NewNop(),
			mockFirebase,
			mockEmail,
			"http://localhost:9001",
			nil,
		)

		recentLog := &model.PasswordResetLog{
			Model: gorm.Model{CreatedAt: time.Now().Add(-2 * time.Minute)}, // 2 minutes ago
		}

		mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
		mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), nil)
		mockStore.On("GetLatestPasswordResetLogByUserID", mock.Anything, uint(1)).Return(recentLog, nil)

		_, _, err := authClient.createPasswordResetLog(ctx, email)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Please wait")

		mockStore.AssertExpectations(t)
	})

	// Test 3: Successful creation with token invalidation
	t.Run("SuccessfulCreation", func(t *testing.T) {
		mockStore := new(MockStore)
		mockFirebase := new(MockFirebaseClient)
		mockEmail := new(MockEmailSender)

		authClient := NewAuthService(
			mockStore,
			zap.NewNop(),
			mockFirebase,
			mockEmail,
			"http://localhost:9001",
			nil,
		)

		mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
		mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), nil)
		mockStore.On("GetLatestPasswordResetLogByUserID", mock.Anything, uint(1)).Return(nil, nil)
		mockStore.On("InvalidatePasswordResetLogsByUserID", mock.Anything, uint(1)).Return(nil)
		mockStore.On("CreatePasswordResetLog", mock.Anything, mock.Anything).Return(nil)
		mockFirebase.On("PasswordResetLink", mock.Anything, email).Return("https://example.com/reset?oobCode=test_token", nil)

		firebaseUserID, token, err := authClient.createPasswordResetLog(ctx, email)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.NotEmpty(t, firebaseUserID)

		mockStore.AssertExpectations(t)
		mockFirebase.AssertExpectations(t)
	})
}

func TestAuthClient_ResetPasswordSubmit_Success(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)
	mockExpert := new(MockExpertClient)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		mockExpert,
	)

	token := "valid_token"

	// Mock password reset log
	passwordResetLog := &model.PasswordResetLog{
		Model:       gorm.Model{CreatedAt: time.Now().Add(-10 * time.Minute)},
		UserID:      1,
		Token:       token,
		Used:        false,
		Invalidated: false,
	}

	// Mock user for GetUserByID call
	user := &model.User{
		Model: gorm.Model{ID: 1},
		Email: "test@example.com",
	}

	// Expectations
	mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(passwordResetLog, nil)
	mockStore.On("UpdatePasswordResetLog", mock.Anything, token, mock.Anything).Return(nil)
	mockStore.On("GetUserByID", mock.Anything, uint(1)).Return(user, nil)
	mockStore.On("UpdateAccountLockedUntil", mock.Anything, user.Email, mock.Anything).Return(nil)
	mockExpert.On("UpdateExpertBranding", mock.Anything, mock.Anything, mock.Anything).Return(&emptypb.Empty{}, nil)

	// Run
	err := authClient.ResetPasswordSubmit(ctx, token)

	// Assert
	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
	mockFirebase.AssertExpectations(t)
	mockExpert.AssertExpectations(t)
}

func TestAuthClient_ResetPasswordSubmit_InvalidToken(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	token := "invalid_token"

	// Mock non-existent password reset log
	mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(nil, nil)

	// Run
	err := authClient.ResetPasswordSubmit(ctx, token)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "The link has expired. Try new reset link or request for a new password reset link")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_ResetPasswordSubmit_UsedToken(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	token := "used_token"

	// Mock used password reset log
	passwordResetLog := &model.PasswordResetLog{
		Model:       gorm.Model{CreatedAt: time.Now().Add(-10 * time.Minute)},
		UserID:      1,
		Token:       token,
		Used:        true,
		Invalidated: false,
	}

	// Expectations
	mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(passwordResetLog, nil)

	// Run
	err := authClient.ResetPasswordSubmit(ctx, token)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "The link has expired. Try new reset link or request for a new password reset link")
	mockStore.AssertExpectations(t)
}

// New tests to increase coverage

func TestAuthClient_ForgotPassword_Error(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	email := "test@example.com"
	user := &model.User{
		Model: gorm.Model{ID: 1},
		Email: email,
	}

	// Mock createPasswordResetLog to return error
	mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
	mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(5), nil)

	args := &model.ForgotPasswordArgs{Email: email}
	err := authClient.ForgotPassword(ctx, args)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "You've reached the maximum number of password reset attempts for today")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_ResendPasswordResetLink_Success(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	email := "test@example.com"
	firebaseUserID := "firebase_user_id"
	user := &model.User{
		Model: gorm.Model{ID: 1},
		Email: email,
	}

	args := &model.ResendPasswordResetLinkArgs{
		Email:          email,
		FirebaseUserID: firebaseUserID,
	}

	// Mock successful password reset log creation
	mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
	mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), nil)
	mockStore.On("GetLatestPasswordResetLogByUserID", mock.Anything, uint(1)).Return(nil, nil)
	mockStore.On("InvalidatePasswordResetLogsByUserID", mock.Anything, uint(1)).Return(nil)
	mockStore.On("CreatePasswordResetLog", mock.Anything, mock.Anything).Return(nil)
	mockFirebase.On("PasswordResetLink", mock.Anything, email).Return("https://example.com/reset?oobCode=test_token", nil)
	mockEmail.On("SendResetPasswordEmail", mock.Anything, model.SetPasswordEmailType, email, mock.Anything).Return(nil)

	err := authClient.ResendPasswordResetLink(ctx, args)

	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
	mockFirebase.AssertExpectations(t)
	mockEmail.AssertExpectations(t)
}

func TestAuthClient_ResendPasswordResetLink_Error(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	email := "test@example.com"
	firebaseUserID := "firebase_user_id"
	user := &model.User{
		Model: gorm.Model{ID: 1},
		Email: email,
	}

	args := &model.ResendPasswordResetLinkArgs{
		Email:          email,
		FirebaseUserID: firebaseUserID,
	}

	// Mock error in createPasswordResetLog
	mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
	mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(5), nil)

	err := authClient.ResendPasswordResetLink(ctx, args)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "You've reached the maximum number of password reset attempts for today")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_LogUserLogin_GetUserError(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)
	logger := zap.NewNop()

	userDocID := "user-doc-id"
	email := "user@example.com"
	ip := "1.2.3.4"
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

	args := &model.LoginLogArgs{
		Email:     email,
		UserDocID: optional.NewOptional(userDocID),
		IpAddress: ip,
		UserAgent: userAgent,
	}

	mockStore.On("GetUser", mock.Anything, userDocID).Return(nil, errors.New("db error"))

	authClient := NewAuthService(mockStore, logger, nil, mockEmail, "http://localhost:9001", nil)

	_, err := authClient.LogUserLogin(ctx, args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db error")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_LogUserLogin_CreateLoginLogError(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)
	logger := zap.NewNop()

	userDocID := "user-doc-id"
	email := "user@example.com"
	ip := "1.2.3.4"
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

	args := &model.LoginLogArgs{
		Email:     email,
		UserDocID: optional.NewOptional(userDocID),
		IpAddress: ip,
		UserAgent: userAgent,
	}

	mockStore.On("GetUser", mock.Anything, userDocID).Return(&model.User{DocumentID: userDocID, Email: email}, nil)
	mockStore.On("CreateLoginLog", mock.Anything, mock.Anything).Return(errors.New("log error"))

	authClient := NewAuthService(mockStore, logger, nil, mockEmail, "http://localhost:9001", nil)

	_, err := authClient.LogUserLogin(ctx, args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "log error")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_LogUserLogin_HasConsecutiveLoginFailuresError(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)
	logger := zap.NewNop()

	userDocID := "user-doc-id"
	email := "user@example.com"
	ip := "1.2.3.4"
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

	args := &model.LoginLogArgs{
		Email:     email,
		UserDocID: optional.NewOptional(userDocID),
		IpAddress: ip,
		UserAgent: userAgent,
	}

	mockStore.On("GetUser", mock.Anything, userDocID).Return(&model.User{DocumentID: userDocID, Email: email}, nil)
	mockStore.On("CreateLoginLog", mock.Anything, mock.Anything).Return(nil)
	mockStore.On("HasConsecutiveLoginFailures", mock.Anything, email).Return(int64(0), errors.New("failure count error"))

	authClient := NewAuthService(mockStore, logger, nil, mockEmail, "http://localhost:9001", nil)

	_, err := authClient.LogUserLogin(ctx, args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failure count error")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_LogUserLogin_CheckIfEmailExistsError(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)
	logger := zap.NewNop()

	userDocID := "user-doc-id"
	email := "user@example.com"
	ip := "1.2.3.4"
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

	args := &model.LoginLogArgs{
		Email:     email,
		UserDocID: optional.NewOptional(userDocID),
		IpAddress: ip,
		UserAgent: userAgent,
	}

	mockStore.On("GetUser", mock.Anything, userDocID).Return(&model.User{DocumentID: userDocID, Email: email}, nil)
	mockStore.On("CreateLoginLog", mock.Anything, mock.Anything).Return(nil)
	mockStore.On("HasConsecutiveLoginFailures", mock.Anything, email).Return(int64(3), nil)
	mockStore.On("CheckIfEmailExists", mock.Anything, email).Return(int64(0), errors.New("email check error"))

	authClient := NewAuthService(mockStore, logger, nil, mockEmail, "http://localhost:9001", nil)

	_, err := authClient.LogUserLogin(ctx, args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email check error")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_LogUserLogin_UpdateAccountLockedUntilError(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStore)
	mockEmail := new(MockEmailSender)
	logger := zap.NewNop()

	userDocID := "user-doc-id"
	email := "user@example.com"
	ip := "1.2.3.4"
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

	args := &model.LoginLogArgs{
		Email:     email,
		UserDocID: optional.NewOptional(userDocID),
		IpAddress: ip,
		UserAgent: userAgent,
	}

	mockStore.On("GetUser", mock.Anything, userDocID).Return(&model.User{DocumentID: userDocID, Email: email}, nil)
	mockStore.On("CreateLoginLog", mock.Anything, mock.Anything).Return(nil)
	mockStore.On("HasConsecutiveLoginFailures", mock.Anything, email).Return(int64(3), nil)
	mockStore.On("CheckIfEmailExists", mock.Anything, email).Return(int64(1), nil)
	mockStore.On("UpdateAccountLockedUntil", mock.Anything, email, mock.Anything).Return(errors.New("lock error"))

	authClient := NewAuthService(mockStore, logger, nil, mockEmail, "http://localhost:9001", nil)

	_, err := authClient.LogUserLogin(ctx, args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lock error")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_CreatePasswordResetLog_GetUserByEmailError(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	email := "test@example.com"

	// Mock GetUserByEmail to return error
	mockStore.On("GetUserByEmail", mock.Anything, email).Return(nil, errors.New("user not found"))

	_, _, err := authClient.createPasswordResetLog(ctx, email)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_CreatePasswordResetLog_GetDailyCountError(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	email := "test@example.com"
	user := &model.User{
		Model: gorm.Model{ID: 1},
		Email: email,
	}

	// Mock GetUserByEmail to succeed but GetPasswordResetLogsCountByUserIDInLast24Hours to fail
	mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
	mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), errors.New("db error"))

	_, _, err := authClient.createPasswordResetLog(ctx, email)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db error")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_CreatePasswordResetLog_GetLatestLogError(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	email := "test@example.com"
	user := &model.User{
		Model: gorm.Model{ID: 1},
		Email: email,
	}

	// Mock GetUserByEmail and GetPasswordResetLogsCountByUserIDInLast24Hours to succeed but GetLatestPasswordResetLogByUserID to fail
	mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
	mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), nil)
	mockStore.On("GetLatestPasswordResetLogByUserID", mock.Anything, uint(1)).Return(nil, errors.New("latest log error"))

	_, _, err := authClient.createPasswordResetLog(ctx, email)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "latest log error")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_CreatePasswordResetLog_InvalidateLogsError(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	email := "test@example.com"
	user := &model.User{
		Model: gorm.Model{ID: 1},
		Email: email,
	}

	// Mock all previous calls to succeed but InvalidatePasswordResetLogsByUserID to fail
	mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
	mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), nil)
	mockStore.On("GetLatestPasswordResetLogByUserID", mock.Anything, uint(1)).Return(nil, nil)
	mockStore.On("InvalidatePasswordResetLogsByUserID", mock.Anything, uint(1)).Return(errors.New("invalidate error"))

	_, _, err := authClient.createPasswordResetLog(ctx, email)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalidate error")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_CreatePasswordResetLog_GenerateTokenError(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	email := "test@example.com"
	user := &model.User{
		Model: gorm.Model{ID: 1},
		Email: email,
	}

	// Mock all previous calls to succeed but PasswordResetLink to fail
	mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
	mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), nil)
	mockStore.On("GetLatestPasswordResetLogByUserID", mock.Anything, uint(1)).Return(nil, nil)
	mockStore.On("InvalidatePasswordResetLogsByUserID", mock.Anything, uint(1)).Return(nil)
	mockFirebase.On("PasswordResetLink", mock.Anything, email).Return("", errors.New("firebase error"))

	_, _, err := authClient.createPasswordResetLog(ctx, email)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "firebase error")
	mockStore.AssertExpectations(t)
	mockFirebase.AssertExpectations(t)
}

func TestAuthClient_CreatePasswordResetLog_CreateLogError(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	email := "test@example.com"
	user := &model.User{
		Model: gorm.Model{ID: 1},
		Email: email,
	}

	// Mock all previous calls to succeed but CreatePasswordResetLog to fail
	mockStore.On("GetUserByEmail", mock.Anything, email).Return(user, nil)
	mockStore.On("GetPasswordResetLogsCountByUserIDInLast24Hours", mock.Anything, uint(1)).Return(int64(0), nil)
	mockStore.On("GetLatestPasswordResetLogByUserID", mock.Anything, uint(1)).Return(nil, nil)
	mockStore.On("InvalidatePasswordResetLogsByUserID", mock.Anything, uint(1)).Return(nil)
	mockFirebase.On("PasswordResetLink", mock.Anything, email).Return("https://example.com/reset?oobCode=test_token", nil)
	mockStore.On("CreatePasswordResetLog", mock.Anything, mock.Anything).Return(errors.New("create log error"))

	_, _, err := authClient.createPasswordResetLog(ctx, email)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create log error")
	mockStore.AssertExpectations(t)
	mockFirebase.AssertExpectations(t)
}

func TestAuthClient_ResetPasswordSubmit_GetLogError(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	token := "test_token"

	// Mock GetPasswordResetLog to return error
	mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(nil, errors.New("get log error"))

	err := authClient.ResetPasswordSubmit(ctx, token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "The link has expired. Try new reset link or request for a new password reset link")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_ResetPasswordSubmit_UpdateLogError(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	token := "test_token"
	passwordResetLog := &model.PasswordResetLog{
		Model:       gorm.Model{CreatedAt: time.Now().Add(-10 * time.Minute)},
		UserID:      1,
		Token:       token,
		Used:        false,
		Invalidated: false,
	}

	// Mock GetPasswordResetLog to succeed but UpdatePasswordResetLog to fail
	mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(passwordResetLog, nil)
	mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(passwordResetLog, nil) // Called twice in ResetPasswordSubmit
	mockStore.On("UpdatePasswordResetLog", mock.Anything, token, mock.Anything).Return(errors.New("update log error"))

	err := authClient.ResetPasswordSubmit(ctx, token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "update log error")
	mockStore.AssertExpectations(t)
}

func TestAuthClient_ResetPasswordSubmit_MarkAsUsedError(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	token := "test_token"
	passwordResetLog := &model.PasswordResetLog{
		Model:       gorm.Model{CreatedAt: time.Now().Add(-10 * time.Minute)},
		UserID:      1,
		Token:       token,
		Used:        false,
		Invalidated: false,
	}

	// Mock GetPasswordResetLog to succeed but MarkPasswordResetTokenAsUsed to fail
	mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(passwordResetLog, nil)
	mockStore.On("GetPasswordResetLog", mock.Anything, token).Return(passwordResetLog, nil) // Called twice in ResetPasswordSubmit
	mockStore.On("UpdatePasswordResetLog", mock.Anything, token, mock.Anything).Return(errors.New("mark as used error"))

	err := authClient.ResetPasswordSubmit(ctx, token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mark as used error")
	mockStore.AssertExpectations(t)
}

// Test cases for DeleteFacebookUserData function
func TestAuthClient_DeleteFacebookUserData_Success(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Create a valid signed request
	userID := "facebook_user_123"
	payload := map[string]interface{}{
		"user_id": userID,
	}
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signedRequest := "signature." + encodedPayload

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:9001/service/api/auth/v1/facebook/user-data-deletion-status?userId=facebook_user_123", redirectURL)
}

func TestAuthClient_DeleteFacebookUserData_InvalidSignedRequest_TooFewParts(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Test with invalid signed request (only one part)
	signedRequest := "invalid_signed_request"

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed signed_request: expected '<signature>.<payload>' format")
	assert.Empty(t, redirectURL)
}

func TestAuthClient_DeleteFacebookUserData_InvalidSignedRequest_TooManyParts(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Test with invalid signed request (three parts)
	userID := "facebook_user_123"
	payload := map[string]interface{}{
		"user_id": userID,
	}
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signedRequest := "signature." + encodedPayload + ".extra"

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed signed_request: expected '<signature>.<payload>' format")
	assert.Empty(t, redirectURL)
}

func TestAuthClient_DeleteFacebookUserData_InvalidBase64Encoding(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Test with invalid base64 encoding
	signedRequest := "signature.invalid_base64_encoding!"

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signed_request payload: base64 decoding failed")
	assert.Empty(t, redirectURL)
}

func TestAuthClient_DeleteFacebookUserData_InvalidJSONPayload(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Test with invalid JSON payload
	invalidJSON := "invalid json payload"
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(invalidJSON))
	signedRequest := "signature." + encodedPayload

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signed_request payload: JSON unmarshal failed")
	assert.Empty(t, redirectURL)
}

func TestAuthClient_DeleteFacebookUserData_MissingUserID(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Test with payload missing user_id
	payload := map[string]interface{}{
		"other_field": "some_value",
	}
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signedRequest := "signature." + encodedPayload

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signed_request missing required field: 'user_id'")
	assert.Empty(t, redirectURL)
}

func TestAuthClient_DeleteFacebookUserData_EmptyUserID(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Test with empty user_id
	payload := map[string]interface{}{
		"user_id": "",
	}
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signedRequest := "signature." + encodedPayload

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert - this should work fine with empty string
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:9001/service/api/auth/v1/facebook/user-data-deletion-status?userId=", redirectURL)
}

func TestAuthClient_DeleteFacebookUserData_NonStringUserID(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Test with non-string user_id
	payload := map[string]interface{}{
		"user_id": 12345,
	}
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signedRequest := "signature." + encodedPayload

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signed_request: 'user_id' is not a string")
	assert.Empty(t, redirectURL)
}

func TestAuthClient_DeleteFacebookUserData_DifferentWebAppURL(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	// Test with different web app URL
	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"https://myapp.com",
		nil,
	)

	// Create a valid signed request
	userID := "facebook_user_456"
	payload := map[string]interface{}{
		"user_id": userID,
	}
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signedRequest := "signature." + encodedPayload

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "https://myapp.com/service/api/auth/v1/facebook/user-data-deletion-status?userId=facebook_user_456", redirectURL)
}

func TestAuthClient_DeleteFacebookUserData_ComplexUserID(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Test with complex user ID containing special characters
	userID := "facebook_user_123-abc_456.def"
	payload := map[string]interface{}{
		"user_id": userID,
	}
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signedRequest := "signature." + encodedPayload

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:9001/service/api/auth/v1/facebook/user-data-deletion-status?userId=facebook_user_123-abc_456.def", redirectURL)
}

func TestAuthClient_DeleteFacebookUserData_EmptySignedRequest(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Test with empty signed request
	signedRequest := ""

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed signed_request: expected '<signature>.<payload>' format")
	assert.Empty(t, redirectURL)
}

func TestAuthClient_DeleteFacebookUserData_OnlySignature(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Test with only signature (no payload)
	signedRequest := "signature"

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed signed_request: expected '<signature>.<payload>' format")
	assert.Empty(t, redirectURL)
}

func TestAuthClient_DeleteFacebookUserData_OnlyPayload(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	mockStore := new(MockStore)
	mockFirebase := new(MockFirebaseClient)
	mockEmail := new(MockEmailSender)

	authClient := NewAuthService(
		mockStore,
		zap.NewNop(),
		mockFirebase,
		mockEmail,
		"http://localhost:9001",
		nil,
	)

	// Test with only payload (no signature)
	userID := "facebook_user_123"
	payload := map[string]interface{}{
		"user_id": userID,
	}
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signedRequest := encodedPayload

	// Run
	redirectURL, err := authClient.DeleteFacebookUserData(ctx, signedRequest)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed signed_request: expected '<signature>.<payload>' format")
	assert.Empty(t, redirectURL)
}
