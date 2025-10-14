package model

import (
	"github.com/hivemindd/kit/optional"
	"gorm.io/gorm"
)

type LoginLog struct {
	gorm.Model
	DocumentID string `gorm:"unique;not null"`
	Email      string `gorm:"not null"`
	UserID     *uint  `gorm:""`
	IpAddress  string `gorm:"not null"`
	Location   string `gorm:"not null"`
	UserAgent  string `gorm:"not null"`
	Device     string `gorm:"not null"`
	Status     string `gorm:"not null;default:failure"`
}

type LoginLogArgs struct {
	Email     string
	UserDocID optional.Optional[string]
	IpAddress string
	UserAgent string
}
