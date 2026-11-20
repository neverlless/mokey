package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/spf13/viper"
)

const syncHookFlush = 30 * time.Second

// RunSync is `mokey sync`: one pass without HTTP or background loops. Exit
// codes: 0 ok, 1 errors or another run holds the claim, 2 held by the brake.
func RunSync(ctx context.Context, dryRun bool, out io.Writer) (int, error) {
	// a per-process store cannot see the lock or the held plan of serve
	if viper.GetString("storage.driver") != "redis" {
		return 1, errors.New("mokey sync needs storage.driver = \"redis\" to share state with serve; with another driver set sync.interval and let serve run it")
	}
	storage, err := newStorage()
	if err != nil {
		return 1, err
	}
	defer func() {
		if err := storage.Close(); err != nil {
			slog.Warn("Failed to close storage", "err", err)
		}
	}()
	r, err := NewRouter(storage)
	if err != nil {
		return 1, err
	}
	return r.runSync(ctx, dryRun, out)
}

func (r *Router) runSync(ctx context.Context, dryRun bool, out io.Writer) (int, error) {
	// the process exits next: let the webhook queues drain first
	defer func() {
		if !r.hooks.flush(syncHookFlush) {
			slog.Warn("Webhook events of the sync run not delivered before exit", "timeout", syncHookFlush)
		}
	}()
	if !r.sync.on() {
		return 1, errors.New("directory sync is not enabled: set sync.enabled = true")
	}
	res, ran, err := r.syncRunLocked(ctx, time.Now(), "", dryRun)
	if !ran {
		if err == nil {
			err = errors.New("another sync run is in progress")
		}
		return 1, err
	}
	if res != nil {
		printSyncResult(out, res)
	}
	switch {
	case err != nil || (res != nil && len(res.Errors) > 0):
		return 1, err
	case res != nil && res.Held:
		return 2, nil
	}
	return 0, nil
}

func printSyncResult(w io.Writer, res *syncRunResult) {
	p := res.Plan
	mode := "applied"
	if res.DryRun {
		mode = "dry run"
	}
	fmt.Fprintf(w, "sync %s: create %d, update %d, enable %d, disable %d, delete %d, adopt %d\n",
		mode, len(p.Create), len(p.Update), len(p.Enable), len(p.Disable), len(p.Delete), len(p.Adopt))
	if res.Held {
		fmt.Fprintf(w, "held by the brake: %d locks, deletes and accounts losing groups, apply them from the admin Sync page\n", res.HeldCount)
	}
	for _, k := range slices.Sorted(maps.Keys(res.Applied)) {
		fmt.Fprintf(w, "applied %s: %d\n", k, res.Applied[k])
	}
	for _, s := range res.SkipReasons {
		fmt.Fprintf(w, "skipped: %s\n", s)
	}
	for _, e := range res.Errors {
		fmt.Fprintf(w, "error: %s\n", e)
	}
}
