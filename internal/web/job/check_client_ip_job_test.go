package job

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/dbtest"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestMergeClientIps_EvictsStaleOldEntries(t *testing.T) {
	// #4077: after a ban expires, a single IP that reconnects used to get
	// banned again immediately because a long-disconnected IP stayed in the
	// DB with an ancient timestamp and kept "protecting" itself against
	// eviction. Guard against that regression here.
	old := []model.ClientIpEntry{
		{IP: "1.1.1.1", Timestamp: 100},  // stale — client disconnected long ago
		{IP: "2.2.2.2", Timestamp: 1900}, // fresh — still connecting
	}
	new := []model.ClientIpEntry{
		{IP: "2.2.2.2", Timestamp: 2000}, // same IP, newer log line
	}

	got := mergeClientIps(old, new, 1000, false)

	want := map[string]int64{"2.2.2.2": 2000}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stale 1.1.1.1 should have been dropped\ngot:  %v\nwant: %v", got, want)
	}
}

func TestMergeClientIps_KeepsFreshOldEntriesUnchanged(t *testing.T) {
	// Backwards-compat: entries that aren't stale are still carried forward,
	// so enforcement survives access-log rotation.
	old := []model.ClientIpEntry{
		{IP: "1.1.1.1", Timestamp: 1500},
	}
	got := mergeClientIps(old, nil, 1000, false)

	want := map[string]int64{"1.1.1.1": 1500}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fresh old IP should have been retained\ngot:  %v\nwant: %v", got, want)
	}
}

func TestMergeClientIps_PrefersLaterTimestampForSameIp(t *testing.T) {
	old := []model.ClientIpEntry{{IP: "1.1.1.1", Timestamp: 1500}}
	new := []model.ClientIpEntry{{IP: "1.1.1.1", Timestamp: 1700}}

	got := mergeClientIps(old, new, 1000, false)

	if got["1.1.1.1"] != 1700 {
		t.Fatalf("expected latest timestamp 1700, got %d", got["1.1.1.1"])
	}
}

func TestMergeClientIps_DropsStaleNewEntries(t *testing.T) {
	// A log line with a clock-skewed old timestamp must not resurrect a
	// stale IP past the cutoff.
	new := []model.ClientIpEntry{{IP: "1.1.1.1", Timestamp: 500}}
	got := mergeClientIps(nil, new, 1000, false)

	if len(got) != 0 {
		t.Fatalf("stale new IP should have been dropped, got %v", got)
	}
}

func TestMergeClientIps_NoStaleCutoffStillWorks(t *testing.T) {
	// Defensive: a zero cutoff (e.g. during very first run on a fresh
	// install) must not over-evict.
	old := []model.ClientIpEntry{{IP: "1.1.1.1", Timestamp: 100}}
	new := []model.ClientIpEntry{{IP: "2.2.2.2", Timestamp: 200}}

	got := mergeClientIps(old, new, 0, false)

	want := map[string]int64{"1.1.1.1": 100, "2.2.2.2": 200}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("zero cutoff should keep everything\ngot:  %v\nwant: %v", got, want)
	}
}

func TestMergeClientIps_LiveObservationsBypassStaleCutoff(t *testing.T) {
	// online-API mode: lastSeen is set when the connection was dispatched, so
	// a connection held open for hours has an "old" timestamp while being live
	// by definition. It must survive the stale cutoff.
	new := []model.ClientIpEntry{{IP: "1.1.1.1", Timestamp: 500}} // opened long ago, still connected
	got := mergeClientIps(nil, new, 1000, true)

	want := map[string]int64{"1.1.1.1": 500}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("live observation must bypass the stale cutoff\ngot:  %v\nwant: %v", got, want)
	}
}

func TestMergeClientIps_LiveModeStillEvictsStaleOldEntries(t *testing.T) {
	// the bypass applies only to this scan's observations — persisted entries
	// from past scans still age out as before.
	old := []model.ClientIpEntry{{IP: "2.2.2.2", Timestamp: 100}}
	new := []model.ClientIpEntry{{IP: "1.1.1.1", Timestamp: 2000}}
	got := mergeClientIps(old, new, 1000, true)

	want := map[string]int64{"1.1.1.1": 2000}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stale db entry must still be evicted in live mode\ngot:  %v\nwant: %v", got, want)
	}
}

func TestInboundLimitBansKickOldest(t *testing.T) {
	inbound := &model.Inbound{Id: 1, Tag: "in-a", LimitIP: 1, LimitAction: "kick_oldest"}
	attached := map[string][]*model.Inbound{
		"a@example.test": {inbound},
		"b@example.test": {inbound},
	}
	observed := map[string]map[string]int64{
		"a@example.test": {"1.1.1.1": 100, "2.2.2.2": 300},
		"b@example.test": {"1.1.1.1": 150},
	}

	bans := (&CheckClientIpJob{}).inboundLimitBans(observed, attached)

	if len(bans) != 2 {
		t.Fatalf("bans = %d, want one per email using the oldest IP", len(bans))
	}
	for _, ban := range bans {
		if len(ban.candidates) != 1 || ban.candidates[0].IP != "1.1.1.1" {
			t.Fatalf("banned candidates = %+v, want 1.1.1.1", ban.candidates)
		}
		if ban.keptLive != 1 {
			t.Fatalf("keptLive = %d, want 1", ban.keptLive)
		}
	}
}

func TestInboundLimitBansRejectNewKeepsOldest(t *testing.T) {
	inbound := &model.Inbound{Id: 2, Tag: "in-b", LimitIP: 1, LimitAction: "reject_new"}
	attached := map[string][]*model.Inbound{"a@example.test": {inbound}}
	observed := map[string]map[string]int64{
		"a@example.test": {"1.1.1.1": 100, "2.2.2.2": 300},
	}

	bans := (&CheckClientIpJob{}).inboundLimitBans(observed, attached)

	if len(bans) != 1 || bans[0].candidates[0].IP != "2.2.2.2" {
		t.Fatalf("bans = %+v, want the newest IP rejected", bans)
	}
}

func TestInboundLimitBansCountsSharedIpOnce(t *testing.T) {
	inbound := &model.Inbound{Id: 3, Tag: "in-c", LimitIP: 1, LimitAction: "kick_oldest"}
	attached := map[string][]*model.Inbound{
		"a@example.test": {inbound},
		"b@example.test": {inbound},
	}
	observed := map[string]map[string]int64{
		"a@example.test": {"9.9.9.9": 100},
		"b@example.test": {"9.9.9.9": 200},
	}

	if bans := (&CheckClientIpJob{}).inboundLimitBans(observed, attached); len(bans) != 0 {
		t.Fatalf("a shared IP must occupy one slot, got bans %+v", bans)
	}
}

func TestInboundLimitBansApplyPerInbound(t *testing.T) {
	first := &model.Inbound{Id: 4, Tag: "in-1", LimitIP: 1, LimitAction: "kick_oldest"}
	second := &model.Inbound{Id: 5, Tag: "in-2", LimitIP: 5, LimitAction: "kick_oldest"}
	attached := map[string][]*model.Inbound{"a@example.test": {first, second}}
	observed := map[string]map[string]int64{
		"a@example.test": {"1.1.1.1": 100, "2.2.2.2": 300},
	}

	bans := (&CheckClientIpJob{}).inboundLimitBans(observed, attached)

	if len(bans) != 1 || bans[0].inbound.Id != first.Id {
		t.Fatalf("bans = %+v, want only the strict inbound to ban", bans)
	}
}

func TestInboundLimitBansRespectsAllowlist(t *testing.T) {
	inbound := &model.Inbound{Id: 6, Tag: "in-allow", LimitIP: 1, LimitAction: "kick_oldest"}
	job := &CheckClientIpJob{allowlist: parseIpLimitAllowlist("1.1.1.1")}
	attached := map[string][]*model.Inbound{"a@example.test": {inbound}}
	observed := map[string]map[string]int64{
		"a@example.test": {"1.1.1.1": 100, "2.2.2.2": 300},
	}

	if bans := job.inboundLimitBans(observed, attached); len(bans) != 0 {
		t.Fatalf("an allowlisted IP must not consume a slot, got %+v", bans)
	}
}

func TestGetInboundByEmailFallbackIgnoresProtocolScalarFields(t *testing.T) {
	dbDir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dbDir)
	dbtest.InitDB(t, filepath.Join(dbDir, "x-ui.db"))

	inbound := &model.Inbound{
		UserId:   1,
		Tag:      "vless-limit-fallback",
		Enable:   true,
		Port:     43002,
		Protocol: model.VLESS,
		Settings: `{
			"clients": [{"email": "alice@example.test", "id": "11111111-1111-1111-1111-111111111111", "limitIp": 2}],
			"decryption": "none",
			"encryption": "none",
			"fallbacks": []
		}`,
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	got, err := (&CheckClientIpJob{}).getInboundByEmail("alice@example.test")
	if err != nil {
		t.Fatalf("getInboundByEmail: %v", err)
	}
	if got.Id != inbound.Id {
		t.Fatalf("inbound id = %d, want %d", got.Id, inbound.Id)
	}
}

func TestCheckFail2BanInstalled_DisabledEnvSkipsClientProbe(t *testing.T) {
	t.Setenv("XUI_ENABLE_FAIL2BAN", "false")
	marker := fakeFail2BanClient(t)

	if (&CheckClientIpJob{}).checkFail2BanInstalled() {
		t.Fatal("fail2ban should be unavailable when XUI_ENABLE_FAIL2BAN=false")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("fail2ban-client should not have been executed, stat error: %v", err)
	}
}

func TestCheckFail2BanInstalled_EmptyEnvSkipsClientProbe(t *testing.T) {
	t.Setenv("XUI_ENABLE_FAIL2BAN", "")
	marker := fakeFail2BanClient(t)

	if (&CheckClientIpJob{}).checkFail2BanInstalled() {
		t.Fatal("fail2ban should be unavailable when XUI_ENABLE_FAIL2BAN is empty")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("fail2ban-client should not have been executed, stat error: %v", err)
	}
}

func TestIsFail2BanEnabled_DefaultsToEnabledWhenUnset(t *testing.T) {
	value, ok := os.LookupEnv("XUI_ENABLE_FAIL2BAN")
	os.Unsetenv("XUI_ENABLE_FAIL2BAN")
	t.Cleanup(func() {
		if ok {
			os.Setenv("XUI_ENABLE_FAIL2BAN", value)
		} else {
			os.Unsetenv("XUI_ENABLE_FAIL2BAN")
		}
	})

	if !isFail2BanEnabled() {
		t.Fatal("fail2ban should default to enabled when XUI_ENABLE_FAIL2BAN is unset")
	}
}

func TestCheckFail2BanInstalled_EnabledEnvProbesClient(t *testing.T) {
	t.Setenv("XUI_ENABLE_FAIL2BAN", "true")
	marker := fakeFail2BanClient(t)

	if !(&CheckClientIpJob{}).checkFail2BanInstalled() {
		t.Fatal("fail2ban should be available when the client probe succeeds")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("fail2ban-client should have been executed: %v", err)
	}
}

func fakeFail2BanClient(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	marker := filepath.Join(dir, "probe-called")
	fakeClient := filepath.Join(dir, "fail2ban-client")
	script := "#!/bin/sh\n: > \"$FAIL2BAN_PROBE_MARKER\"\nexit 0\n"
	if runtime.GOOS == "windows" {
		fakeClient += ".bat"
		script = "@echo off\ntype nul > \"%FAIL2BAN_PROBE_MARKER%\"\nexit /b 0\n"
	}
	if err := os.WriteFile(fakeClient, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake fail2ban-client: %v", err)
	}

	t.Setenv("FAIL2BAN_PROBE_MARKER", marker)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return marker
}

// resolveEnforce is platform-pure (the caller supplies needsBinary), so this
// table pins every branch — the Windows carve-out included — statically.
func TestResolveEnforce(t *testing.T) {
	cases := []struct {
		name         string
		f2bEnabled   bool
		hasLimit     bool
		f2bInstalled bool
		needsBinary  bool
		want         bool
	}{
		{"disabled env with fail2ban present never enforces", false, true, true, true, false},
		{"disabled env without fail2ban never enforces", false, true, false, true, false},
		{"enabled with fail2ban and a limit enforces", true, true, true, true, true},
		{"enabled, binary needed but absent, cannot enforce", true, true, false, true, false},
		{"enabled, no binary needed (windows), enforces without fail2ban", true, true, false, false, true},
		{"no limit never enforces even fully installed", true, false, true, true, false},
	}
	j := NewCheckClientIpJob()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := j.resolveEnforce(tc.f2bEnabled, tc.hasLimit, tc.f2bInstalled, tc.needsBinary); got != tc.want {
				t.Fatalf("resolveEnforce(%v, %v, %v, %v) = %v, want %v", tc.f2bEnabled, tc.hasLimit, tc.f2bInstalled, tc.needsBinary, got, tc.want)
			}
		})
	}
}
