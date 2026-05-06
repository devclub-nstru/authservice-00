package ques

import (
	"fmt"

	"kael/internal/config"

	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
)

const (
	QueueCritical = "critical"
	QueueDefault  = "default"
	QueueLow      = "low"
)

const (
	TaskEmailVerification = "email:verification"
	TaskPasswordReset     = "email:password_reset"
	TaskEmailOTP          = "email:otp"
)

func RedisClientOpt(cfg *config.Config) (asynq.RedisClientOpt, error) {
	if cfg.RedisURL != "" {
		opts, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			return asynq.RedisClientOpt{}, fmt.Errorf("failed to parse REDIS_URL: %w", err)
		}
		return asynq.RedisClientOpt{
			Addr:      opts.Addr,
			Password:  opts.Password,
			DB:        opts.DB,
			TLSConfig: opts.TLSConfig,
		}, nil
	}

	return asynq.RedisClientOpt{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	}, nil
}

func NewClient(cfg *config.Config) (*asynq.Client, error) {
	opt, err := RedisClientOpt(cfg)
	if err != nil {
		return nil, err
	}

	return asynq.NewClient(opt), nil
}

func NewServer(cfg *config.Config) (*asynq.Server, error) {
	opt, err := RedisClientOpt(cfg)
	if err != nil {
		return nil, err
	}

	return asynq.NewServer(opt, asynq.Config{
		Concurrency: cfg.AsynqWorkerConcurrency,
		Queues: map[string]int{
			QueueCritical: 6,
			QueueDefault:  3,
			QueueLow:      1,
		},
	}), nil
}
