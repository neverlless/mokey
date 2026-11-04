package cmd

import (
	"fmt"
	"io"
	golog "log"
	"log/slog"
	"os"
	"strings"

	"github.com/neverlless/mokey/v2/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile     string
	cfgFileUsed string
	logLevel    string

	Root = &cobra.Command{
		Use:     "mokey",
		Version: server.Version,
		Short:   "FreeIPA self-service account management tool",
		Long:    ``,
	}
)

func Execute() {
	if err := Root.Execute(); err != nil {
		fatal(err.Error())
	}
}

func init() {
	// set before initConfig so its fatal errors are formatted and redacted too
	slog.SetDefault(slog.New(server.NewLogHandler(os.Stderr)))
	cobra.OnInitialize(initConfig)

	Root.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
	Root.PersistentFlags().StringVar(&logLevel, "loglevel", "info", "Set log level")

	Root.PersistentPreRunE = func(command *cobra.Command, args []string) error {
		return SetupLogging()
	}
}

func SetupLogging() error {
	switch logLevel {
	// slog has no trace level; nothing logs below debug anyway
	case "trace", "debug":
		server.LogLevel.Set(slog.LevelDebug)
	case "info":
		server.LogLevel.Set(slog.LevelInfo)
	case "warn":
		server.LogLevel.Set(slog.LevelWarn)
	case "error":
		server.LogLevel.Set(slog.LevelError)
	default:
		return fmt.Errorf("Unknown log level: %s", logLevel)
	}

	golog.SetOutput(io.Discard)

	if cfgFileUsed != "" {
		slog.Info("Using config file", "path", cfgFileUsed)
	}

	Root.SilenceUsage = true
	Root.SilenceErrors = true

	return nil
}

func initConfig() {
	viper.SetConfigType("toml")
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			fatal(err.Error())
		}

		viper.AddConfigPath("/etc/mokey/")
		viper.AddConfigPath(cwd)
		viper.SetConfigName("mokey.toml")
	}

	server.SetDefaults()
	viper.AutomaticEnv()
	viper.SetEnvPrefix("mokey")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fatal("Failed parsing config file", "path", viper.ConfigFileUsed(), "err", err)
		}
	} else {
		cfgFileUsed = viper.ConfigFileUsed()
	}

	if !viper.IsSet("email.token_secret") {
		secret, err := server.GenerateSecret(32)
		if err != nil {
			fatal(err.Error())
		}

		viper.Set("email.token_secret", secret)
	}

	if !viper.IsSet("server.csrf_secret") {
		secret, err := server.GenerateSecretString(16)
		if err != nil {
			fatal(err.Error())
		}

		viper.Set("server.csrf_secret", secret)
	}

	if !viper.IsSet("site.keytab") {
		fatal("Please provide path to keytab file")
	}

	if viper.IsSet("accounts.otp_hash_algorithm") {
		algo := viper.GetString("accounts.otp_hash_algorithm")
		validAlgo := false
		for _, a := range []string{"sha1", "sha256", "sha512"} {
			if algo == a {
				validAlgo = true
				break
			}
		}

		if !validAlgo {
			fatal("Invalid otp hash algorithm", "algorithm", algo)
		}
	}
}

func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
