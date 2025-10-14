package auth

import (
	"context"
	"time"

	"github.com/hivemindd/auth-service/internal/model"
)

type AggregateStoreTx interface {
	AggregateRepository
	Transactional
}

// AggregateRepository aggregates repos.
type AggregateRepository interface {
	AuthStore
}

// Transactional defines transaction methods.
type Transactional interface {
	InTx(context.Context, TxF) error
}
type TxF func(ctx context.Context, repo AggregateStoreTx) error

// AuthStore defines methods for auth entity.
type AuthStore interface {
	SignUp(ctx context.Context, user *model.User) error
	CheckIfEmailExists(ctx context.Context, email string) (int64, error)
	GetUser(ctx context.Context, id string) (*model.User, error)
	GetUserByID(ctx context.Context, id uint) (*model.User, error)
	CreateLoginLog(ctx context.Context, loginLog *model.LoginLog) error
	HasConsecutiveLoginFailures(ctx context.Context, email string) (int64, error)
	UpdateAccountLockedUntil(ctx context.Context, email string, loginLockExpiresAt *time.Time) error
	CheckAccountLockStatus(ctx context.Context, email string) (*model.AccountLockStatus, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	CreatePasswordResetLog(ctx context.Context, passwordResetLog *model.PasswordResetLog) error
	GetPasswordResetLog(ctx context.Context, token string) (*model.PasswordResetLog, error)
	UpdatePasswordResetLog(ctx context.Context, token string, passwordResetLog *model.PasswordResetLog) error
	GetPasswordResetLogsByUserID(ctx context.Context, userID uint) ([]*model.PasswordResetLog, error)
	InvalidatePasswordResetLogsByUserID(ctx context.Context, userID uint) error
	GetPasswordResetLogsCountByUserIDInLast24Hours(ctx context.Context, userID uint) (int64, error)
	GetLatestPasswordResetLogByUserID(ctx context.Context, userID uint) (*model.PasswordResetLog, error)
}
