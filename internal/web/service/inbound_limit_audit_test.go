package service

import (
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestGetInboundLimitAuditAggregatesAttachedClients(t *testing.T) {
	initClientHwidTestDB(t)
	db := database.GetDB()

	inbound := &model.Inbound{
		Tag: "audit-in", Remark: "audit", Enable: true, Protocol: model.VLESS, Port: 44001,
		Settings: `{"clients":[]}`, LimitIP: 2, LimitAction: "kick_oldest",
	}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	client := &model.ClientRecord{Email: "audit@example.com", SubID: "sub-audit", UUID: "11111111-2222-4333-8444-555555555555", Enable: true}
	if err := db.Create(client).Error; err != nil {
		t.Fatalf("seed client: %v", err)
	}
	if err := db.Create(&model.ClientInbound{ClientId: client.Id, InboundId: inbound.Id}).Error; err != nil {
		t.Fatalf("seed link: %v", err)
	}

	now := time.Now().Unix()
	if err := db.Create(&model.InboundClientIps{
		ClientEmail: client.Email,
		Ips:         `[{"ip":"203.0.113.9","timestamp":` + itoa(now) + `}]`,
	}).Error; err != nil {
		t.Fatalf("seed live ips: %v", err)
	}
	if err := (&InboundService{}).RecordClientIpHistory(map[string][]model.ClientIpEntry{
		client.Email: {{IP: "198.51.100.7", Timestamp: now - 60}},
	}); err != nil {
		t.Fatalf("seed history: %v", err)
	}
	if err := upsertClientHwid(db, client.SubID, HwidRequest{
		Hwid: "audit-device-1", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	}); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := (&InboundService{}).RecordInboundIpRejections([]model.InboundIpRejection{
		{InboundID: inbound.Id, Tag: inbound.Tag, Email: client.Email, IP: "192.0.2.44", Action: "kick_oldest"},
	}); err != nil {
		t.Fatalf("seed rejection: %v", err)
	}

	audit, err := (&InboundService{}).GetInboundLimitAudit(inbound.Id)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.LimitIP != 2 || audit.LimitAction != "kick_oldest" || audit.OnlineIPCount != 1 {
		t.Fatalf("audit summary = %+v", audit)
	}
	if len(audit.Clients) != 1 {
		t.Fatalf("clients = %d, want 1", len(audit.Clients))
	}
	got := audit.Clients[0]
	if len(got.OnlineIPs) != 1 || got.OnlineIPs[0].IP != "203.0.113.9" {
		t.Fatalf("online ips = %+v", got.OnlineIPs)
	}
	if len(got.History) != 1 || got.History[0].IP != "198.51.100.7" {
		t.Fatalf("history = %+v", got.History)
	}
	if len(got.Devices) != 1 || got.Devices[0].DeviceOS != "Windows" {
		t.Fatalf("devices = %+v", got.Devices)
	}
	if len(audit.Rejections) != 1 || audit.Rejections[0].IP != "192.0.2.44" {
		t.Fatalf("rejections = %+v", audit.Rejections)
	}
}

func itoa(v int64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	buf := make([]byte, 0, 20)
	for v > 0 {
		buf = append([]byte{digits[v%10]}, buf...)
		v /= 10
	}
	return string(buf)
}
