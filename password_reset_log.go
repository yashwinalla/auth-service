package model

import (
	"gorm.io/gorm"
)

type PasswordResetLog struct {
	gorm.Model
	UserID      uint   `gorm:"index;not null"`
	Token       string `gorm:"unique;not null"`
	Used        bool   `gorm:"default:false"`
	Invalidated bool   `gorm:"default:false"`
}
