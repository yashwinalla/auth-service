package store

import (
	"context"
	"errors"
	"time"

	"github.com/hivemindd/auth-service/internal/model"
	"github.com/hivemindd/kit/errorsx"
)

func (p *PostgresStore) SignUp(ctx context.Context, user *model.User) error {
	err := p.db.WithContext(ctx).Create(&user).Error
	if err != nil {
		if err.Error() == "duplicated key not allowed" { // TODO: optimize checking
			return errorsx.NewBadRequestError(errors.New("an account with this email already exists in db"))
		}
		return err
	}

	return nil
}

func (p *PostgresStore) CheckIfEmailExists(ctx context.Context, email string) (int64, error) {
	var count int64

	err := p.db.WithContext(ctx).Model(&model.User{}).Where("email = ?", email).Count(&count).Error
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (p *PostgresStore) GetUser(ctx context.Context, id string) (*model.User, error) {
	var user *model.User

	err := p.db.WithContext(ctx).Model(&model.User{}).Where("document_id = ?", id).Find(&user).Error
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (p *PostgresStore) CreateLoginLog(ctx context.Context, loginLog *model.LoginLog) error {
	err := p.db.WithContext(ctx).Create(&loginLog).Error
	if err != nil {
		return err
	}

	return nil
}

func (p *PostgresStore) HasConsecutiveLoginFailures(ctx context.Context, email string) (int64, error) {
	var count int64

	err := p.db.WithContext(ctx).Raw(`
		SELECT COUNT(*)
		FROM (
  			SELECT status
  			FROM login_logs
  			WHERE email = ?
    		AND created_at >= NOW() - INTERVAL '15 minutes'
  			ORDER BY created_at DESC
  			LIMIT 3
		) AS last_3
		WHERE status = 'failure';
		`, email).Scan(&count).Error
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (p *PostgresStore) UpdateAccountLockedUntil(ctx context.Context, email string, accountLockedUntil *time.Time) error {
	err := p.db.WithContext(ctx).Model(&model.User{}).Where("email = ?", email).Update("account_locked_until", accountLockedUntil).Error
	if err != nil {
		return err
	}

	return nil
}

func (p *PostgresStore) CheckAccountLockStatus(ctx context.Context, email string) (*model.AccountLockStatus, error) {
	var accountLockStatus *model.AccountLockStatus

	err := p.db.WithContext(ctx).Raw(`
  		SELECT
			CASE
        		WHEN account_locked_until IS NOT NULL AND account_locked_until > NOW() THEN true
        		ELSE false
        	END AS is_account_locked
  		FROM users
  		WHERE email = ?
	`, email).Scan(&accountLockStatus).Error
	if err != nil {
		return nil, err
	}

	return accountLockStatus, nil
}

func (p *PostgresStore) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	var user *model.User

	err := p.db.WithContext(ctx).Model(&model.User{}).Where("email = ?", email).Find(&user).Error
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (p *PostgresStore) GetUserByID(ctx context.Context, id uint) (*model.User, error) {
	var user *model.User

	err := p.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", id).First(&user).Error
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (p *PostgresStore) CreatePasswordResetLog(ctx context.Context, passwordResetLog *model.PasswordResetLog) error {
	err := p.db.WithContext(ctx).Create(&passwordResetLog).Error
	if err != nil {
		return err
	}

	return nil
}

func (p *PostgresStore) GetPasswordResetLog(ctx context.Context, token string) (*model.PasswordResetLog, error) {
	var passwordResetLog *model.PasswordResetLog

	err := p.db.WithContext(ctx).Model(&model.PasswordResetLog{}).Where("token = ?", token).Find(&passwordResetLog).Error
	if err != nil {
		return nil, err
	}

	return passwordResetLog, nil
}

func (p *PostgresStore) UpdatePasswordResetLog(ctx context.Context, token string, passwordResetLog *model.PasswordResetLog) error {
	err := p.db.WithContext(ctx).Model(&model.PasswordResetLog{}).Where("token = ?", token).Updates(&passwordResetLog).Error
	if err != nil {
		return err
	}

	return nil
}

func (p *PostgresStore) GetPasswordResetLogsByUserID(ctx context.Context, userID uint) ([]*model.PasswordResetLog, error) {
	var passwordResetLogs []*model.PasswordResetLog

	err := p.db.WithContext(ctx).Model(&model.PasswordResetLog{}).Where("user_id = ?", userID).Find(&passwordResetLogs).Error
	if err != nil {
		return nil, err
	}

	return passwordResetLogs, nil
}

func (p *PostgresStore) InvalidatePasswordResetLogsByUserID(ctx context.Context, userID uint) error {
	err := p.db.WithContext(ctx).Model(&model.PasswordResetLog{}).Where("user_id = ?", userID).Update("invalidated", true).Error
	if err != nil {
		return err
	}

	return nil
}

func (p *PostgresStore) GetPasswordResetLogsCountByUserIDInLast24Hours(ctx context.Context, userID uint) (int64, error) {
	var count int64

	err := p.db.WithContext(ctx).Model(&model.PasswordResetLog{}).Where("user_id = ? AND created_at >= NOW() - INTERVAL '24 hours'", userID).Count(&count).Error
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (p *PostgresStore) GetLatestPasswordResetLogByUserID(ctx context.Context, userID uint) (*model.PasswordResetLog, error) {
	var passwordResetLog *model.PasswordResetLog

	err := p.db.WithContext(ctx).Model(&model.PasswordResetLog{}).Where("user_id = ? and used = false", userID).Order("created_at DESC").First(&passwordResetLog).Error
	if err != nil {
		// If no records found, return nil instead of error
		if err.Error() == "record not found" {
			return nil, nil
		}
		return nil, err
	}

	return passwordResetLog, nil
}
