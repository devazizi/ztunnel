package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

func LoadYAMLConfig[T any](path string, out *T) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, out)
}
