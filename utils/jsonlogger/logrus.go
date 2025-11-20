package jsonlogger

import (
	"github.com/sirupsen/logrus"
)

func EnableLogger() *logrus.Logger {
	log := logrus.New()

	log.SetFormatter(&logrus.JSONFormatter{})

	return log
}
