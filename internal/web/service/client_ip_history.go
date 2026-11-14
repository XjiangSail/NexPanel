package service

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	// clientIpHistoryRetentionSeconds keeps six months of source addresses; one
	// row per (email, ip) bounds growth without a configurable knob.
	clientIpHistoryRetentionSeconds = int64(180 * 24 * 60 * 60)
	clientIpHistoryRefreshSeconds   = int64(5 * 60)
	clientIpHistoryInsertBatch      = 100
)

// ClientIpHistoryInfo is one long-term IP entry rendered in the panel.
type ClientIpHistoryInfo struct {
	IP        string `json:"ip"`
	FirstSeen string `json:"firstSeen"`
	LastSeen  string `json:"lastSeen"`
}

// RecordClientIpHistory upserts observed addresses, preserving the earliest
// first_seen and the latest last_seen for each (email, ip) pair.
func (s *InboundService) RecordClientIpHistory(observed map[string][]model.ClientIpEntry) error {
	now := time.Now().Unix()
	type historyKey struct{ email, ip string }
	seen := make(map[historyKey]int)
	rows := make([]model.ClientIpHistory, 0, len(observed))
	for email, entries := range observed {
		email = strings.TrimSpace(email)
		if email == "" {
			continue
		}
		for _, entry := range entries {
			if entry.IP == "" {
				continue
			}
			ts := entry.Timestamp
			if ts <= 0 {
				ts = now
			}
			ts = min(ts, now)
			key := historyKey{email: email, ip: entry.IP}
			if idx, ok := seen[key]; ok {
				// One statement cannot touch the same key twice (PostgreSQL).
				if ts < rows[idx].FirstSeen {
					rows[idx].FirstSeen = ts
				}
				if ts > rows[idx].LastSeen {
					rows[idx].LastSeen = ts
				}
				continue
			}
			seen[key] = len(rows)
			rows = append(rows, model.ClientIpHistory{Email: email, IP: entry.IP, FirstSeen: ts, LastSeen: ts})
		}
	}
	if len(rows) == 0 {
		return nil
	}

	db := database.GetDB()
	for start := 0; start < len(rows); start += clientIpHistoryInsertBatch {
		end := min(start+clientIpHistoryInsertBatch, len(rows))
		if err := db.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "email"}, {Name: "ip"}},
			DoUpdates: clause.Assignments(map[string]any{
				"first_seen": gorm.Expr("CASE WHEN excluded.first_seen < client_ip_history.first_seen THEN excluded.first_seen ELSE client_ip_history.first_seen END"),
				"last_seen":  gorm.Expr("CASE WHEN excluded.last_seen > client_ip_history.last_seen THEN excluded.last_seen ELSE client_ip_history.last_seen END"),
			}),
			// Scans run every 5-10s; only refresh a row when a window or an older start arrives.
			Where: clause.Where{Exprs: []clause.Expression{
				gorm.Expr("excluded.last_seen >= client_ip_history.last_seen + ? OR excluded.first_seen < client_ip_history.first_seen", clientIpHistoryRefreshSeconds),
			}},
		}).Create(rows[start:end]).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *InboundService) GetClientIpHistory(email string) ([]ClientIpHistoryInfo, error) {
	var rows []model.ClientIpHistory
	if err := database.GetDB().
		Where("email = ?", email).
		Order("last_seen DESC").
		Order("id DESC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]ClientIpHistoryInfo, 0, len(rows))
	for _, row := range rows {
		out = append(out, ClientIpHistoryInfo{
			IP:        row.IP,
			FirstSeen: formatClientIpHistoryTime(row.FirstSeen),
			LastSeen:  formatClientIpHistoryTime(row.LastSeen),
		})
	}
	return out, nil
}

func (s *InboundService) ClearClientIpHistory(email string) error {
	return database.GetDB().Where("email = ?", email).Delete(&model.ClientIpHistory{}).Error
}

// PruneClientIpHistory enforces the retention window. The last_seen index keeps
// the recurring sweep cheap when nothing has expired.
func (s *InboundService) PruneClientIpHistory() error {
	cutoff := time.Now().Unix() - clientIpHistoryRetentionSeconds
	return database.GetDB().Where("last_seen < ?", cutoff).Delete(&model.ClientIpHistory{}).Error
}

func formatClientIpHistoryTime(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).Local().Format("2006-01-02 15:04:05")
}

func clientIpHistoryFromRows(rows []model.InboundClientIps) map[string][]model.ClientIpEntry {
	observed := make(map[string][]model.ClientIpEntry, len(rows))
	for _, row := range rows {
		if row.ClientEmail == "" || row.Ips == "" {
			continue
		}
		var entries []model.ClientIpEntry
		if err := json.Unmarshal([]byte(row.Ips), &entries); err != nil {
			continue
		}
		if len(entries) > 0 {
			observed[row.ClientEmail] = append(observed[row.ClientEmail], entries...)
		}
	}
	return observed
}
