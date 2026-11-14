package service

import (
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// populateInboundOnlineIPCounts labels local inbounds with the number of distinct
// live source IPs their clients use. Remote inbounds are counted by their node.
func (s *InboundService) populateInboundOnlineIPCounts(inbounds []*model.Inbound) {
	local := make([]*model.Inbound, 0, len(inbounds))
	ids := make([]int, 0, len(inbounds))
	for _, inbound := range inbounds {
		if inbound == nil || inbound.NodeID != nil {
			continue
		}
		local = append(local, inbound)
		ids = append(ids, inbound.Id)
	}
	if len(ids) == 0 {
		return
	}

	type attachedClient struct {
		Email     string
		InboundID int
	}
	var pairs []attachedClient
	for _, batch := range chunkInts(ids, sqlInChunk) {
		var page []attachedClient
		if err := database.GetDB().Table("clients").
			Select("clients.email AS email, client_inbounds.inbound_id AS inbound_id").
			Joins("JOIN client_inbounds ON client_inbounds.client_id = clients.id").
			Where("client_inbounds.inbound_id IN ?", batch).
			Scan(&page).Error; err != nil {
			return
		}
		pairs = append(pairs, page...)
	}
	if len(pairs) == 0 {
		return
	}

	users, ok, err := (&XrayService{}).GetOnlineUsers()
	if err != nil || !ok {
		return
	}
	ipsByEmail := make(map[string]map[string]struct{}, len(users))
	for _, user := range users {
		if user.Email == "" {
			continue
		}
		set := ipsByEmail[user.Email]
		if set == nil {
			set = make(map[string]struct{}, len(user.IPs))
			ipsByEmail[user.Email] = set
		}
		for _, entry := range user.IPs {
			if entry.IP != "" {
				set[entry.IP] = struct{}{}
			}
		}
	}

	ipsByInbound := make(map[int]map[string]struct{}, len(local))
	for _, pair := range pairs {
		ips := ipsByEmail[pair.Email]
		if len(ips) == 0 {
			continue
		}
		set := ipsByInbound[pair.InboundID]
		if set == nil {
			set = make(map[string]struct{}, len(ips))
			ipsByInbound[pair.InboundID] = set
		}
		for ip := range ips {
			set[ip] = struct{}{}
		}
	}
	for _, inbound := range local {
		inbound.OnlineIPCount = len(ipsByInbound[inbound.Id])
	}
}
