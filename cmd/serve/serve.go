package serve

import (
	"context"
	"os"
	"os/signal"
	"time"

	"github.com/neverlless/mokey/v2/cmd"
	"github.com/neverlless/mokey/v2/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Run server",
		Long:  `Run server`,
		RunE: func(command *cobra.Command, args []string) error {
			return serve()
		},
	}
)

func init() {
	serveCmd.Flags().String("keytab", "", "path to keytab file")
	cobra.CheckErr(viper.BindPFlag("site.keytab", serveCmd.Flags().Lookup("keytab")))

	serveCmd.Flags().String("listen", "0.0.0.0:8866", "address to listen on")
	cobra.CheckErr(viper.BindPFlag("server.listen", serveCmd.Flags().Lookup("listen")))
	serveCmd.Flags().String("cert", "", "path to ssl cert")
	cobra.CheckErr(viper.BindPFlag("server.ssl_cert", serveCmd.Flags().Lookup("cert")))
	serveCmd.Flags().String("key", "", "path to ssl key")
	cobra.CheckErr(viper.BindPFlag("server.ssl_key", serveCmd.Flags().Lookup("key")))
	serveCmd.Flags().String("dbpath", "", "path to mokey database")
	cobra.CheckErr(viper.BindPFlag("storage.sqlite3.dbpath", serveCmd.Flags().Lookup("dbpath")))

	serveCmd.Flags().String("smtp-host", "localhost", "smtp host")
	cobra.CheckErr(viper.BindPFlag("email.smtp_host", serveCmd.Flags().Lookup("smtp-host")))

	serveCmd.Flags().Int("smtp-port", 25, "smtp port")
	cobra.CheckErr(viper.BindPFlag("email.smtp_port", serveCmd.Flags().Lookup("smtp-port")))

	serveCmd.Flags().String("email-from", "", "from email address")
	cobra.CheckErr(viper.BindPFlag("email.from", serveCmd.Flags().Lookup("email-from")))

	cmd.Root.AddCommand(serveCmd)
}

func serve() error {
	srv, err := server.NewServer(viper.GetString("server.listen"))
	if err != nil {
		return err
	}

	srv.KeyFile = viper.GetString("server.ssl_key")
	srv.CertFile = viper.GetString("server.ssl_cert")

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt)
		<-quit
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		logrus.Debug("Shutting down server")
		if err := srv.Shutdown(ctx); err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("Server shutdown failed")
		}
	}()

	return srv.Serve()
}
