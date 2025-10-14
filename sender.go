package email

import (
	"context"

	"github.com/hivemindd/auth-service/internal/model"
	"github.com/hivemindd/kit/queue"
)

type emailFormat struct {
	To   string  `json:"to"`
	Type string  `json:"type"`
	Name string  `json:"name"`
	Url  *string `json:"url"`

	// Data holds extra email data
	Data map[string]string `json:"data"`
}

type Sender struct {
	queue     queue.Queue
	queueName string
}

func NewSender(queue queue.Queue, queueName string) *Sender {
	return &Sender{
		queue:     queue,
		queueName: queueName,
	}
}

func (s *Sender) SendResetPasswordEmail(_ context.Context, emailType model.EmailType, email string, link string) error {
	emailMsg := &emailFormat{
		To:   email,
		Type: convertToTypeOfEmail(emailType),
		Name: "",
		Url:  &link,
		Data: nil,
	}
	return s.queue.PublishJSON("", s.queueName, true, emailMsg)
}

func (s *Sender) SendAccountLockEmail(_ context.Context, emailType model.EmailType, email string, link string, loginLog *model.LoginLog) error {
	emailMsg := &emailFormat{
		To:   email,
		Type: convertToTypeOfEmail(emailType),
		Name: "",
		Url:  &link,
		Data: map[string]string{
			"LoginRequestDate": loginLog.CreatedAt.Format("January 2, 2006 at 3:04 PM"),
			"Device":           loginLog.Device,
			"Location":         loginLog.Location,
		},
	}
	return s.queue.PublishJSON("", s.queueName, true, emailMsg)
}

func convertToTypeOfEmail(emailType model.EmailType) string {
	switch emailType {
	case model.SetPasswordEmailType:
		return "set_password"
	case model.ForgotPasswordEmailType:
		return "forgot_password"
	case model.AccountLockEmailType:
		return "account_lock"
	}
	return ""
}
