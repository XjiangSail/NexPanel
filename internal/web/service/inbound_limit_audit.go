package service

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

type InboundLimitClientAudit struct {
	Email     string                `json:"email"`
	SubID     string                `json:"subId"`
	OnlineIPs []ClientIpInfo        `json:"onlineIps"`
	History   []ClientIpHistoryInfo `json:"history"`
	Devices   []ClientHwidInfo      `json:"devices"`
}

type InboundLimitAudit struct {
	InboundID     int                        `json:"inboundId"`
	Tag           string                     `json:"tag"`
	Remark        string                     `json:"remark"`
	LimitIP       int                        `json:"limitIp"`
	LimitAction   string                     `json:"limitAction"`
	OnlineIPCount int                        `json:"onlineIpCount"`
	Remote        bool                       `json:"remote"`
	Clients       []InboundLimitClientAudit  `json:"clients"`
	Rejections    []model.InboundIpRejection `json:"rejections"`
}

// nonNilSlice keeps JSON output stable: nil slices marshal to null, which the
// panel UI renders as a crash instead of an empty list.
func nonNilSlice[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

// GetInboundLimitAudit aggregates every attached client's live IPs, IP history,
// devices and over-limit events for one inbound (node-level view).
func (s *InboundService) GetInboundLimitAudit(inboundID int) (*InboundLimitAudit, error) {
	inbound, err := s.GetInbound(inboundID)
	if err != nil {
		return nil, err
	}

	type attachedClient struct {
		Email string
		SubID string
	}
	var attached []attachedClient
	if err := database.GetDB().Table("clients").
		Select("clients.email AS email, clients.sub_id AS sub_id").
		Joins("JOIN client_inbounds ON client_inbounds.client_id = clients.id").
		Where("client_inbounds.inbound_id = ?", inboundID).
		Scan(&attached).Error; err != nil {
		return nil, err
	}
	sort.Slice(attached, func(i, j int) bool { return attached[i].Email < attached[j].Email })

	emails := make([]string, 0, len(attached))
	subIDs := make([]string, 0, len(attached))
	for _, row := range attached {
		if row.Email != "" {
			emails = append(emails, row.Email)
		}
		if row.SubID != "" {
			subIDs = append(subIDs, row.SubID)
		}
	}

	onlineByEmail, _ := s.inboundOnlineIps(inbound, emails)
	historyByEmail := s.clientIpHistoryByEmail(emails)
	devicesBySubID := s.clientHwidsBySubID(subIDs)

	clients := make([]InboundLimitClientAudit, 0, len(attached))
	uniqueIPs := make(map[string]struct{})
	for _, row := range attached {
		online := onlineByEmail[row.Email]
		for _, entry := range online {
			if entry.IP != "" {
				uniqueIPs[entry.IP] = struct{}{}
			}
		}
		clients = append(clients, InboundLimitClientAudit{
			Email:     row.Email,
			SubID:     row.SubID,
			OnlineIPs: nonNilSlice(online),
			History:   nonNilSlice(historyByEmail[row.Email]),
			Devices:   nonNilSlice(devicesBySubID[row.SubID]),
		})
	}
	inbound.OnlineIPCount = len(uniqueIPs)

	var rejections []model.InboundIpRejection
	if err := database.GetDB().Where("inbound_id = ?", inboundID).
		Order("created_at DESC").Order("id DESC").Limit(200).Find(&rejections).Error; err != nil {
		logger.Debug("read inbound ip rejections failed:", err)
	}
	if rejections == nil {
		rejections = []model.InboundIpRejection{}
	}

	return &InboundLimitAudit{
		InboundID:     inbound.Id,
		Tag:           inbound.Tag,
		Remark:        inbound.Remark,
		LimitIP:       inbound.LimitIP,
		LimitAction:   inbound.LimitAction,
		OnlineIPCount: inbound.OnlineIPCount,
		Remote:        inbound.NodeID != nil,
		Clients:       clients,
		Rejections:    rejections,
	}, nil
}

// inboundOnlineIps prefers the running core's live view. A remote inbound (or a
// stopped core) falls back to the scanner's last observations from the DB.
func (s *InboundService) inboundOnlineIps(inbound *model.Inbound, emails []string) (map[string][]ClientIpInfo, string) {
	out := make(map[string][]ClientIpInfo, len(emails))
	if inbound.NodeID == nil {
		if users, ok, err := (&XrayService{}).GetOnlineUsers(); err == nil && ok {
			byEmail := make(map[string][]xray.OnlineIP, len(users))
			for _, user := range users {
				byEmail[user.Email] = user.IPs
			}
			for _, email := range emails {
				out[email] = onlineIPsToInfo(byEmail[email])
			}
			return out, "xray"
		}
	}
	return s.cachedClientIps(emails), "cache"
}

func onlineIPsToInfo(ips []xray.OnlineIP) []ClientIpInfo {
	out := make([]ClientIpInfo, 0, len(ips))
	for _, entry := range ips {
		if entry.IP == "" {
			continue
		}
		info := ClientIpInfo{IP: entry.IP}
		if entry.LastSeen > 0 {
			info.Time = formatClientIpHistoryTime(entry.LastSeen)
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func (s *InboundService) cachedClientIps(emails []string) map[string][]ClientIpInfo {
	out := make(map[string][]ClientIpInfo, len(emails))
	db := database.GetDB()
	cutoff := time.Now().Unix() - clientIpStaleAfterSeconds
	for _, batch := range chunkStrings(emails, sqlInChunk) {
		var rows []model.InboundClientIps
		if err := db.Where("client_email IN ?", batch).Find(&rows).Error; err != nil {
			continue
		}
		for _, row := range rows {
			var entries []model.ClientIpEntry
			if row.Ips == "" || json.Unmarshal([]byte(row.Ips), &entries) != nil {
				continue
			}
			infos := make([]ClientIpInfo, 0, len(entries))
			for _, entry := range entries {
				if entry.IP == "" || entry.Timestamp < cutoff {
					continue
				}
				infos = append(infos, ClientIpInfo{IP: entry.IP, Time: formatClientIpHistoryTime(entry.Timestamp)})
			}
			sort.Slice(infos, func(i, j int) bool { return infos[i].IP < infos[j].IP })
			out[row.ClientEmail] = infos
		}
	}
	return out
}

func (s *InboundService) clientIpHistoryByEmail(emails []string) map[string][]ClientIpHistoryInfo {
	out := make(map[string][]ClientIpHistoryInfo, len(emails))
	db := database.GetDB()
	for _, batch := range chunkStrings(emails, sqlInChunk) {
		var rows []model.ClientIpHistory
		if err := db.Where("email IN ?", batch).Order("last_seen DESC").Find(&rows).Error; err != nil {
			continue
		}
		for _, row := range rows {
			out[row.Email] = append(out[row.Email], ClientIpHistoryInfo{
				IP:        row.IP,
				FirstSeen: formatClientIpHistoryTime(row.FirstSeen),
				LastSeen:  formatClientIpHistoryTime(row.LastSeen),
			})
		}
	}
	return out
}

func (s *InboundService) clientHwidsBySubID(subIDs []string) map[string][]ClientHwidInfo {
	out := make(map[string][]ClientHwidInfo, len(subIDs))
	db := database.GetDB()
	for _, batch := range chunkStrings(subIDs, sqlInChunk) {
		var rows []model.ClientHwid
		if err := db.Where("sub_id IN ?", batch).Order("last_seen DESC").Find(&rows).Error; err != nil {
			continue
		}
		for _, row := range rows {
			out[row.SubID] = append(out[row.SubID], clientHwidInfoFromRow(row))
		}
	}
	return out
}

func (s *InboundService) RecordInboundIpRejections(rows []model.InboundIpRejection) error {
	if len(rows) == 0 {
		return nil
	}
	db := database.GetDB()
	const batch = 100
	for start := 0; start < len(rows); start += batch {
		end := min(start+batch, len(rows))
		if err := db.Create(rows[start:end]).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *InboundService) PruneInboundIpRejections() error {
	cutoff := time.Now().AddDate(0, 0, -90).UnixMilli()
	return database.GetDB().Where("created_at < ?", cutoff).Delete(&model.InboundIpRejection{}).Error
}
