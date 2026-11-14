package model

import (
	"cmp"
	"encoding/json"
	"slices"
)

// ClientIpEntry records an observed client IP and its last-seen Unix timestamp.
type ClientIpEntry struct {
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"`
}

func SortClientIpEntries(entries []ClientIpEntry) {
	slices.SortFunc(entries, func(a, b ClientIpEntry) int {
		if order := cmp.Compare(a.Timestamp, b.Timestamp); order != 0 {
			return order
		}
		return cmp.Compare(a.IP, b.IP)
	})
}

func MarshalClientIpEntries(entries []ClientIpEntry) (string, error) {
	if len(entries) == 0 {
		return "[]", nil
	}
	SortClientIpEntries(entries)
	encoded, err := json.Marshal(entries)
	return string(encoded), err
}

// NodeClientIp records which panel (identified by its stable panelGuid) observed
// a client's IPs on its own Xray. Unlike InboundClientIps (a flattened,
// cluster-wide union used for IP-limit counting and that is pushed back to every
// node), this table preserves attribution: it never mixes in IPs a parent pushed
// down, so the master can tell exactly which node a given IP is connecting to.
//
// Rows under the local panel's own panelGuid are written by check_client_ip_job
// from local Xray observations; rows under remote guids are merged in by the node
// sync job from each node's clientIpsByGuid report (its own panelGuid subtree plus
// any descendants), so attribution survives across a chain of nodes.
type NodeClientIp struct {
	Id       int    `json:"id" gorm:"primaryKey;autoIncrement"`
	NodeGuid string `json:"nodeGuid" gorm:"uniqueIndex:idx_nodeip_guid_email,priority:1;not null"`
	Email    string `json:"email" gorm:"uniqueIndex:idx_nodeip_guid_email,priority:2;not null"`
	Ips      string `json:"ips"`
}

// ClientIpHistory keeps one row per client email and source IP, retaining
// addresses after they leave the live inbound_client_ips window.
type ClientIpHistory struct {
	Id        int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Email     string `json:"email" gorm:"uniqueIndex:idx_client_ip_history_email_ip,priority:1;not null"`
	IP        string `json:"ip" gorm:"size:64;uniqueIndex:idx_client_ip_history_email_ip,priority:2;not null"`
	FirstSeen int64  `json:"firstSeen" gorm:"not null"`
	LastSeen  int64  `json:"lastSeen" gorm:"not null;index"`
}

func (ClientIpHistory) TableName() string { return "client_ip_history" }

// InboundIpRejection is one over-limit enforcement event, kept per inbound so
// the panel can show what was blocked without parsing rotated log files.
type InboundIpRejection struct {
	Id        int    `json:"id" gorm:"primaryKey;autoIncrement"`
	InboundID int    `json:"inboundId" gorm:"column:inbound_id;not null;index"`
	Tag       string `json:"tag" gorm:"column:tag"`
	Email     string `json:"email" gorm:"not null;index"`
	IP        string `json:"ip" gorm:"size:64;not null"`
	Action    string `json:"action" gorm:"not null"`
	CreatedAt int64  `json:"createdAt" gorm:"autoCreateTime:milli;index"`
}

func (InboundIpRejection) TableName() string { return "inbound_ip_rejections" }
