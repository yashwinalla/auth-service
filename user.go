package model

import (
	"time"

	"github.com/hivemindd/kit/optional"
	"gorm.io/gorm"
)

type EmailType string

const (
	SetPasswordEmailType    EmailType = "set_password"
	ForgotPasswordEmailType EmailType = "forgot_password"
	AccountLockEmailType    EmailType = "account_lock"
)

type User struct {
	gorm.Model
	DocumentID         string                       `gorm:"unique;not null"`
	Email              string                       `gorm:"unique;not null"`
	FirebaseUserID     string                       `gorm:"not null"`
	Tnc                bool                         `gorm:"default:false"`
	AccountLockedUntil optional.Optional[time.Time] `gorm:"null"`
}

type SignUpArgs struct {
	Email string
	Tnc   bool
}

type ForgotPasswordArgs struct {
	Email string
}

type SocialSignUpArgs struct {
	Email          string
	FirebaseUserID string
	Tnc            bool
}

type AccountLockStatus struct {
	IsAccountLocked bool
}

type ResendPasswordResetLinkArgs struct {
	Email          string
	FirebaseUserID string
}
