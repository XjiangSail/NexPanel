package service

import (
	"strconv"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestRecordClientIpHistoryKeepsEarliestAndLatest(t *testing.T) {
	initClientHwidTestDB(t)
	svc := &InboundService{}
	base := time.Now().Add(-time.Hour).Unix()

	if err := svc.RecordClientIpHistory(map[string][]model.ClientIpEntry{
		"history@example.com": {
			{IP: "1.1.1.1", Timestamp: base},
			{IP: "2.2.2.2", Timestamp: base},
		},
	}); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if err := svc.RecordClientIpHistory(map[string][]model.ClientIpEntry{
		"history@example.com": {{IP: "1.1.1.1", Timestamp: base + clientIpHistoryRefreshSeconds}},
	}); err != nil {
		t.Fatalf("second record: %v", err)
	}

	var rows []model.ClientIpHistory
	if err := database.GetDB().Where("email = ?", "history@example.com").Find(&rows).Error; err != nil {
		t.Fatalf("read rows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("history rows = %d, want 2 (one per unique IP)", len(rows))
	}
	for _, row := range rows {
		if row.IP != "1.1.1.1" {
			continue
		}
		if row.FirstSeen != base {
			t.Fatalf("firstSeen = %d, want %d", row.FirstSeen, base)
		}
		if row.LastSeen != base+clientIpHistoryRefreshSeconds {
			t.Fatalf("lastSeen = %d, want %d", row.LastSeen, base+clientIpHistoryRefreshSeconds)
		}
		return
	}
	t.Fatal("history is missing 1.1.1.1")
}

func TestRecordClientIpHistoryDeduplicatesInput(t *testing.T) {
	initClientHwidTestDB(t)
	svc := &InboundService{}
	base := time.Now().Add(-time.Hour).Unix()

	if err := svc.RecordClientIpHistory(map[string][]model.ClientIpEntry{
		"dup@example.com": {
			{IP: "4.4.4.4", Timestamp: base},
			{IP: "4.4.4.4", Timestamp: base - 30},
		},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	var rows []model.ClientIpHistory
	if err := database.GetDB().Where("email = ?", "dup@example.com").Find(&rows).Error; err != nil {
		t.Fatalf("read rows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("history rows = %d, want 1 for a repeated IP", len(rows))
	}
	if rows[0].FirstSeen != base-30 || rows[0].LastSeen != base {
		t.Fatalf("first/last = %d/%d, want %d/%d", rows[0].FirstSeen, rows[0].LastSeen, base-30, base)
	}
}

func TestRecordClientIpHistorySkipsFrequentLastSeenRefresh(t *testing.T) {
	initClientHwidTestDB(t)
	svc := &InboundService{}
	base := time.Now().Add(-time.Hour).Unix()

	if err := svc.RecordClientIpHistory(map[string][]model.ClientIpEntry{
		"refresh@example.com": {{IP: "3.3.3.3", Timestamp: base}},
	}); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if err := svc.RecordClientIpHistory(map[string][]model.ClientIpEntry{
		"refresh@example.com": {{IP: "3.3.3.3", Timestamp: base + 10}},
	}); err != nil {
		t.Fatalf("second record: %v", err)
	}
	if err := svc.RecordClientIpHistory(map[string][]model.ClientIpEntry{
		"refresh@example.com": {{IP: "3.3.3.3", Timestamp: base - 100}},
	}); err != nil {
		t.Fatalf("third record: %v", err)
	}

	var row model.ClientIpHistory
	if err := database.GetDB().Where("email = ? AND ip = ?", "refresh@example.com", "3.3.3.3").First(&row).Error; err != nil {
		t.Fatalf("read row: %v", err)
	}
	if row.LastSeen != base {
		t.Fatalf("lastSeen = %d, want %d (under the refresh interval)", row.LastSeen, base)
	}
	if row.FirstSeen != base-100 {
		t.Fatalf("firstSeen = %d, want %d (an older start must still be recorded)", row.FirstSeen, base-100)
	}
}

func TestGetClientIpHistoryOrdersByLastSeen(t *testing.T) {
	initClientHwidTestDB(t)
	svc := &InboundService{}
	now := time.Now().Unix()

	if err := svc.RecordClientIpHistory(map[string][]model.ClientIpEntry{
		"order@example.com": {
			{IP: "9.9.9.9", Timestamp: now - 120},
			{IP: "8.8.8.8", Timestamp: now - 60},
		},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	history, err := svc.GetClientIpHistory("order@example.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(history) != 2 || history[0].IP != "8.8.8.8" {
		t.Fatalf("history = %+v, want 8.8.8.8 first", history)
	}
	if history[0].FirstSeen == "" || history[0].LastSeen == "" {
		t.Fatalf("history timestamps are not formatted: %+v", history[0])
	}
}

func TestClearClientIpsAlsoClearsHistory(t *testing.T) {
	initClientHwidTestDB(t)
	svc := &InboundService{}
	now := time.Now().Unix()

	if err := database.GetDB().Create(&model.InboundClientIps{
		ClientEmail: "clear@example.com",
		Ips:         `[{"ip":"7.7.7.7","timestamp":` + strconv.FormatInt(now, 10) + `}]`,
	}).Error; err != nil {
		t.Fatalf("seed live IPs: %v", err)
	}
	if err := svc.RecordClientIpHistory(map[string][]model.ClientIpEntry{
		"clear@example.com": {{IP: "7.7.7.7", Timestamp: now}},
	}); err != nil {
		t.Fatalf("record history: %v", err)
	}

	if err := svc.ClearClientIps("clear@example.com"); err != nil {
		t.Fatalf("clear: %v", err)
	}

	var history int64
	if err := database.GetDB().Model(&model.ClientIpHistory{}).Where("email = ?", "clear@example.com").Count(&history).Error; err != nil {
		t.Fatalf("count history: %v", err)
	}
	if history != 0 {
		t.Fatalf("history rows after clear = %d, want 0", history)
	}
}

func TestPruneClientIpHistoryHonorsRetention(t *testing.T) {
	initClientHwidTestDB(t)
	svc := &InboundService{}
	now := time.Now().Unix()

	if err := svc.RecordClientIpHistory(map[string][]model.ClientIpEntry{
		"prune@example.com": {
			{IP: "6.6.6.6", Timestamp: now - clientIpHistoryRetentionSeconds - 60},
			{IP: "5.5.5.5", Timestamp: now},
		},
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := svc.PruneClientIpHistory(); err != nil {
		t.Fatalf("prune: %v", err)
	}

	history, err := svc.GetClientIpHistory("prune@example.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(history) != 1 || history[0].IP != "5.5.5.5" {
		t.Fatalf("history after prune = %+v, want only 5.5.5.5", history)
	}
}
