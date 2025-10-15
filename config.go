package config

type Config struct {
	DatabaseURI           string   `envconfig:"DATABASE_URI" required:"true"`
	ExpertServiceGRPCAddr string   `envconfig:"EXPERT_SERVICE_GRPC_ADDR" required:"true"`
	Firebase              Firebase `envconfig:"FIREBASE" required:"true"`
	Rabbit                Rabbit   `envconfig:"RABBIT" required:"true"`
	SentryDSN             string   `envconfig:"SENTRY_DSN" required:"true"`
	ServerPort            string   `envconfig:"AUTH_SERVICE_SERVER_PORT" required:"true"`
	WebAppURL             string   `envconfig:"WEB_APP_URL" required:"true"`
}
type Firebase struct {
	PrivateKey string `envconfig:"PRIVATE_KEY" required:"true"`
	ProjectID  string `envconfig:"PROJECT_ID" required:"true"`
}

type Rabbit struct {
	URI         string `envconfig:"URI" required:"true"`
	EMAIL_QUEUE string `envconfig:"EMAIL_QUEUE" required:"true"`
}
