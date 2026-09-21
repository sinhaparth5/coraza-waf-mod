package blocklist

import (
	"context"
	"log"

	"github.com/redis/go-redis/v9"

	"coraza-waf-mod/internal/storage"
)

// clusterChannel is the Redis pub/sub channel every node in a cluster
// publishes to and subscribes on. Before this (issue #77), IPBlocklist was
// purely in-memory and only ever reloaded from a *local* trigger (a UI save,
// SIGHUP, or autoban's own ban on that same process) — so a ban written by
// one node's autoban left every other node still proxying that IP until an
// operator manually restarted or SIGHUP'd it.
const clusterChannel = "coraza:ipblocklist:reload"

// EnableClusterSync connects to Redis and makes every future Reload/
// ReloadIntel call broadcast to, and every broadcast from, every other node
// pointed at the same Redis instance. It deliberately reuses the Redis
// address/password already configured for clustered rate limiting
// (ratelimit.RedisBackend) rather than adding a second on/off toggle —
// a configured Redis instance is already this project's existing signal for
// "this is a multi-node deployment".
func (bl *IPBlocklist) EnableClusterSync(ctx context.Context, addr, password string, db *storage.DB) error {
	client := redis.NewClient(&redis.Options{Addr: addr, Password: password})
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return err
	}

	sub := client.Subscribe(ctx, clusterChannel)
	if _, err := sub.Receive(ctx); err != nil {
		sub.Close()
		client.Close()
		return err
	}

	bl.clusterPub = client
	bl.clusterSub = sub

	go func() {
		for msg := range sub.Channel() {
			var err error
			if msg.Payload == "intel" {
				err = bl.reloadIntelLocal(db)
			} else {
				err = bl.reloadLocal(db)
			}
			if err != nil {
				log.Printf("blocklist: cluster-triggered reload failed: %v", err)
			}
		}
	}()

	return nil
}

// publish is a no-op when cluster sync was never enabled.
func (bl *IPBlocklist) publish(payload string) {
	if bl.clusterPub == nil {
		return
	}
	if err := bl.clusterPub.Publish(context.Background(), clusterChannel, payload).Err(); err != nil {
		log.Printf("blocklist: cluster broadcast failed: %v", err)
	}
}

// Close shuts down the cluster-sync connection. Safe to call even when
// EnableClusterSync was never called.
func (bl *IPBlocklist) Close() {
	if bl.clusterSub != nil {
		_ = bl.clusterSub.Close()
	}
	if bl.clusterPub != nil {
		_ = bl.clusterPub.Close()
	}
}
