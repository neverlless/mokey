package server

import (
	"log/slog"
	"strconv"
	"time"

	"github.com/slack-go/slack"
	"github.com/spf13/viper"
)

type SlackNotifier struct {
	client *slack.Client
}

func NewSlackNotifier() *SlackNotifier {
	token := viper.GetString("slack.token")
	if token == "" {
		return nil
	}
	return &SlackNotifier{
		client: slack.New(token),
	}
}

func (s *SlackNotifier) SendSlackMessage(email, message string) error {
	user, err := s.client.GetUserByEmail(email)
	if err != nil {
		return err
	}

	channelID, timestamp, err := s.client.PostMessage(
		user.ID,
		slack.MsgOptionText(message, false),
		slack.MsgOptionDisableLinkUnfurl(),
		slack.MsgOptionDisableMediaUnfurl(),
	)
	if err != nil {
		return err
	}

	slog.Info("Message successfully sent", "channel", channelID, "sent_at", slackTime(timestamp))
	return nil
}

// slackTime turns a Slack message ts ("1794851016.779229", seconds since
// the epoch) into a readable UTC time; anything else is returned as is.
func slackTime(ts string) string {
	sec, err := strconv.ParseFloat(ts, 64)
	if err != nil {
		return ts
	}
	return time.UnixMilli(int64(sec * 1000)).UTC().Format(time.RFC3339Nano)
}
