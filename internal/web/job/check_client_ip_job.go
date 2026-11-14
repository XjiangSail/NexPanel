package job

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawgkern"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// onlineUsersSource is the one service.XrayService method the scan needs, so
// tests can drive Run end to end without a live xray core.
type onlineUsersSource interface {
	GetOnlineUsers() ([]xray.OnlineUser, bool, error)
}

// CheckClientIpJob monitors client IP addresses and manages IP blocking based
// on configured limits. The per-client IPs come from the core's online-stats
// API; no access log is involved. On a core too old to expose that API the job
// simply skips the run (the bundled core always supports it).
type CheckClientIpJob struct {
	bannedSeen  map[string]int64
	onlineUsers onlineUsersSource
	allowlist   ipLimitAllowlist
	lastIpPrune int64
}

const defaultXrayAPIPort = 62789

const ipStaleAfterSeconds = int64(30 * 60)

// pruneStaleIpRows cadence; the scan itself cannot prune offline clients' rows.
const ipPruneIntervalSeconds = int64(5 * 60)

// NewCheckClientIpJob creates a new client IP monitoring job instance.
func NewCheckClientIpJob() *CheckClientIpJob {
	return &CheckClientIpJob{onlineUsers: &service.XrayService{}}
}

func (j *CheckClientIpJob) Run() {
	j.pruneStaleIpRows()
	observed, apiMode := j.collectFromOnlineAPI()
	// Kernel-mode AmneziaWG peers never reach Xray, so its online users cannot
	// see them; their connect locations come from the kernel interface instead.
	kernelIPs := amneziawgkern.GetCollector().ClientIPs()
	if len(kernelIPs) > 0 {
		if observed == nil {
			observed = make(map[string]map[string]int64, len(kernelIPs))
		}
		for email, ips := range kernelIPs {
			if _, ok := observed[email]; !ok {
				observed[email] = make(map[string]int64, len(ips))
			}
			for ip, ts := range ips {
				if prev, seen := observed[email][ip]; !seen || ts > prev {
					observed[email][ip] = ts
				}
			}
		}
	}
	if !apiMode && len(kernelIPs) == 0 {
		// xray is down or predates the online-stats API. There is no access-log
		// fallback anymore, so there is nothing to do this run.
		logger.Debug("[LimitIP] online-stats API unavailable this run; skipping")
		return
	}

	// XUI_ENABLE_FAIL2BAN=false disables enforcement, not tracking (#6722):
	// the scan still records IPs so the panel keeps showing them.
	hasLimit := j.hasInboundLimitIp()
	f2bInstalled := false
	if hasLimit {
		f2bInstalled = j.checkFail2BanInstalled()
	}
	// Windows enforces through disconnects and never needs the fail2ban binary.
	needsBinary := runtime.GOOS != "windows"
	enforce := j.resolveEnforce(isFail2BanEnabled(), hasLimit, f2bInstalled, needsBinary)
	// Read only when the limit is actually applied: this runs every 10s and
	// most panels carry no IP limit at all.
	if enforce {
		j.allowlist = j.loadAllowlist()
	}
	j.processObserved(observed, enforce, true)
}

// resolveEnforce decides whether limits can actually be enforced this run: a
// disabled fail2ban gates every platform, a missing binary the ones needing it.
func (j *CheckClientIpJob) resolveEnforce(f2bEnabled, hasLimit, f2bInstalled, needsBinary bool) bool {
	if !f2bEnabled {
		return false
	}
	if hasLimit && needsBinary && !f2bInstalled {
		return false
	}
	return hasLimit
}

// collectFromOnlineAPI builds per-email IP observations (email -> ip ->
// last-seen unix seconds) from the core's online-stats API. ok=false means the
// API is unavailable — xray not running, an older core, or a transient gRPC
// failure — and the caller skips the run (there is no access-log fallback).
func (j *CheckClientIpJob) collectFromOnlineAPI() (map[string]map[string]int64, bool) {
	onlineUsers, ok, err := j.onlineUsers.GetOnlineUsers()
	if err != nil {
		logger.Debug("[LimitIP] online-stats API unavailable this run:", err)
		return nil, false
	}
	if !ok {
		return nil, false
	}
	now := time.Now().Unix()
	observed := make(map[string]map[string]int64, len(onlineUsers))
	for _, user := range onlineUsers {
		for _, entry := range user.IPs {
			// No localhost guard needed here: the core's OnlineMap.AddIP drops
			// 127.0.0.1/[::1] itself, so they never reach this list.
			ts := entry.LastSeen
			if ts <= 0 {
				ts = now
			}
			if _, exists := observed[user.Email]; !exists {
				observed[user.Email] = make(map[string]int64)
			}
			if existing, seen := observed[user.Email][entry.IP]; !seen || ts > existing {
				observed[user.Email][entry.IP] = ts
			}
		}
	}
	return observed, true
}

// hasInboundLimitIp reports whether any locally hosted inbound carries an IP
// limit. Remote inbounds are enforced by the node that runs them.
func (j *CheckClientIpJob) hasInboundLimitIp() bool {
	db := database.GetDB()
	var probe int64
	err := db.Model(&model.Inbound{}).
		Where("limit_ip > 0 AND enable = ? AND node_id IS NULL", true).
		Limit(1).Count(&probe).Error
	return err == nil && probe > 0
}

// loadAllowlist reads the operator's trusted addresses once per scan; a bad
// read leaves the list empty, which enforces the limit as before rather than
// silently exempting everyone.
func (j *CheckClientIpJob) loadAllowlist() ipLimitAllowlist {
	raw, err := (&service.SettingService{}).GetIpLimitAllowlist()
	if err != nil {
		logger.Warning("[LimitIP] could not read the allowlist, enforcing without it:", err)
		return ipLimitAllowlist{}
	}
	return parseIpLimitAllowlist(raw)
}

const ipScanChunk = 400

func chunkEmails(s []string, size int) [][]string {
	if len(s) == 0 {
		return nil
	}
	chunks := make([][]string, 0, (len(s)+size-1)/size)
	for size < len(s) {
		s, chunks = s[size:], append(chunks, s[:size])
	}
	return append(chunks, s)
}

// loadAttachedLimitInbounds maps each observed email to every local enabled
// inbound enforcing an IP cap. A client attached to several inbounds counts
// toward each, matching the per-inbound view.
func (j *CheckClientIpJob) loadAttachedLimitInbounds(emails []string) map[string][]*model.Inbound {
	db := database.GetDB()
	idsByEmail := make(map[string][]int, len(emails))
	idSet := make(map[int]struct{})
	for _, batch := range chunkEmails(emails, ipScanChunk) {
		var pairs []struct {
			Email     string
			InboundID int
		}
		if err := db.Table("client_inbounds").
			Select("clients.email AS email, client_inbounds.inbound_id AS inbound_id").
			Joins("JOIN clients ON clients.id = client_inbounds.client_id").
			Where("clients.email IN ?", batch).
			Scan(&pairs).Error; err != nil {
			j.checkError(err)
			continue
		}
		for _, p := range pairs {
			idsByEmail[p.Email] = append(idsByEmail[p.Email], p.InboundID)
			idSet[p.InboundID] = struct{}{}
		}
	}
	if len(idSet) == 0 {
		return nil
	}

	ids := make([]int, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	inboundsByID := make(map[int]*model.Inbound, len(ids))
	for lo := 0; lo < len(ids); lo += ipScanChunk {
		hi := min(lo+ipScanChunk, len(ids))
		var page []*model.Inbound
		if err := db.Model(&model.Inbound{}).
			Where("id IN ? AND limit_ip > 0 AND enable = ? AND node_id IS NULL", ids[lo:hi], true).
			Find(&page).Error; err != nil {
			j.checkError(err)
			return nil
		}
		for _, ib := range page {
			inboundsByID[ib.Id] = ib
		}
	}

	out := make(map[string][]*model.Inbound, len(idsByEmail))
	for email, inboundIDs := range idsByEmail {
		seen := make(map[int]struct{}, len(inboundIDs))
		for _, id := range inboundIDs {
			ib, ok := inboundsByID[id]
			if !ok {
				continue
			}
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			out[email] = append(out[email], ib)
		}
	}
	return out
}

// loadInboundsByEmails resolves each email's owning inbound through the
// clients/client_inbounds relation in chunked queries. Like the old per-email
// First() it keeps the lowest inbound id when a client spans several inbounds.
func (j *CheckClientIpJob) loadInboundsByEmails(emails []string) map[string]*model.Inbound {
	db := database.GetDB()
	minInboundByEmail := make(map[string]int, len(emails))
	for _, batch := range chunkEmails(emails, ipScanChunk) {
		var pairs []struct {
			Email     string
			InboundId int
		}
		if err := db.Table("client_inbounds").
			Select("clients.email AS email, client_inbounds.inbound_id AS inbound_id").
			Joins("JOIN clients ON clients.id = client_inbounds.client_id").
			Where("clients.email IN ?", batch).
			Scan(&pairs).Error; err != nil {
			j.checkError(err)
			return nil
		}
		for _, p := range pairs {
			if cur, ok := minInboundByEmail[p.Email]; !ok || p.InboundId < cur {
				minInboundByEmail[p.Email] = p.InboundId
			}
		}
	}
	if len(minInboundByEmail) == 0 {
		return nil
	}

	idSet := make(map[int]struct{}, len(minInboundByEmail))
	ids := make([]int, 0, len(minInboundByEmail))
	for _, id := range minInboundByEmail {
		if _, seen := idSet[id]; !seen {
			idSet[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	inboundsById := make(map[int]*model.Inbound, len(ids))
	for lo := 0; lo < len(ids); lo += ipScanChunk {
		hi := min(lo+ipScanChunk, len(ids))
		var page []*model.Inbound
		if err := db.Model(&model.Inbound{}).Where("id IN ?", ids[lo:hi]).Find(&page).Error; err != nil {
			j.checkError(err)
			return nil
		}
		for _, ib := range page {
			inboundsById[ib.Id] = ib
		}
	}

	out := make(map[string]*model.Inbound, len(minInboundByEmail))
	for email, id := range minInboundByEmail {
		if ib, ok := inboundsById[id]; ok {
			out[email] = ib
		}
	}
	return out
}

func (j *CheckClientIpJob) loadClientIpRows(emails []string) map[string]*model.InboundClientIps {
	db := database.GetDB()
	out := make(map[string]*model.InboundClientIps, len(emails))
	for _, batch := range chunkEmails(emails, ipScanChunk) {
		var rows []model.InboundClientIps
		if err := db.Where("client_email IN ?", batch).Find(&rows).Error; err != nil {
			j.checkError(err)
			continue
		}
		for i := range rows {
			out[rows[i].ClientEmail] = &rows[i]
		}
	}
	return out
}

// processObserved runs collection + enforcement for one scan's observations
// (email -> ip -> last-seen unix seconds). observedAreLive marks the
// observations as live connections, which bypass the stale cutoff: a connection
// that opened hours ago is still live even though its timestamp is old. The
// online-stats API always reports live connections, so the job passes true.
// Lookups are batched up front and all inbound_client_ips writes share one
// transaction, so a scan costs a handful of queries and one fsync instead of
// several per observed email.
func (j *CheckClientIpJob) processObserved(observed map[string]map[string]int64, enforce, observedAreLive bool) bool {
	shouldCleanLog := false
	now := time.Now().Unix()

	emails := make([]string, 0, len(observed))
	for email := range observed {
		emails = append(emails, email)
	}
	sort.Strings(emails)

	inboundByEmail := j.loadInboundsByEmails(emails)
	attachedInbounds := j.loadAttachedLimitInbounds(emails)
	ipRowByEmail := j.loadClientIpRows(emails)

	// attribution accumulates this scan's local observations per email so they can
	// be recorded under this panel's own guid for cross-node IP attribution.
	attribution := make(map[string][]model.ClientIpEntry, len(observed))

	db := database.GetDB()
	tx := db.Begin()
	if tx.Error != nil {
		j.checkError(tx.Error)
		return false
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	for _, email := range emails {
		ipTimestamps := observed[email]

		// The observations can still reference a client that was just renamed
		// or deleted; its email no longer matches any inbound. Skip it (and
		// drop any orphaned tracking row) instead of recreating a row and
		// logging an ERROR every run (#4963). The batch map resolves through
		// the clients relation; the per-email fallback keeps its settings LIKE
		// net for clients not yet present there.
		inbound, ok := inboundByEmail[email]
		if !ok {
			var err error
			inbound, err = j.getInboundByEmail(email)
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					logger.Debugf("[LimitIP] skipping stale observed email %q (renamed or deleted)", email)
					j.delInboundClientIps(tx, email)
				} else {
					j.checkError(err)
				}
				continue
			}
		}

		ipsWithTime := make([]model.ClientIpEntry, 0, len(ipTimestamps))
		attrEntries := make([]model.ClientIpEntry, 0, len(ipTimestamps))
		for ip, timestamp := range ipTimestamps {
			ipsWithTime = append(ipsWithTime, model.ClientIpEntry{IP: ip, Timestamp: timestamp})
			// A live connection's lastSeen may be its old start time.
			// Stamp attribution now so retention cannot evict a connected IP.
			attrTs := timestamp
			if observedAreLive {
				attrTs = now
			}
			attrEntries = append(attrEntries, model.ClientIpEntry{IP: ip, Timestamp: attrTs})
		}
		if len(attrEntries) > 0 {
			attribution[email] = attrEntries
		}

		clientIpsRecord, ok := ipRowByEmail[email]
		if !ok {
			jsonIps, err := model.MarshalClientIpEntries(ipsWithTime)
			if err != nil {
				j.checkError(err)
				continue
			}
			clientIpsRecord = &model.InboundClientIps{ClientEmail: email, Ips: jsonIps}
			result := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "client_email"}},
				DoNothing: true,
			}).Create(clientIpsRecord)
			if result.Error != nil {
				j.checkError(result.Error)
				continue
			}
			if result.RowsAffected > 0 {
				continue
			}
			if err := tx.Where("client_email = ?", email).First(clientIpsRecord).Error; err != nil {
				j.checkError(err)
				continue
			}
		}

		j.updateInboundClientIps(tx, clientIpsRecord, inbound, email, ipsWithTime, observedAreLive)
	}

	if err := tx.Commit().Error; err != nil {
		j.checkError(err)
		return false
	}
	committed = true

	var published []pendingBan
	if enforce {
		bans := j.inboundLimitBans(observed, attachedInbounds)
		j.pruneBannedSeen(attachedInbounds, bans)
		published = j.publishBans(bans)
	}

	// Xray disconnects run after the commit so their network round-trips never
	// extend the scan's write transaction (node syncs upsert the same table).
	shouldCleanLog = shouldCleanLog || len(published) > 0
	j.recordInboundRejections(published)
	clientsCache := make(map[int][]model.Client)
	for _, d := range published {
		clients, cached := clientsCache[d.inbound.Id]
		if !cached {
			clients, _ = service.ParseInboundSettingsClients(d.inbound.Settings)
			clientsCache[d.inbound.Id] = clients
		}
		j.disconnectClientTemporarily(d.inbound, d.email, clients)
	}

	j.recordLocalAttribution(attribution)
	if err := (&service.InboundService{}).RecordClientIpHistory(attribution); err != nil {
		logger.Debug("[LimitIP] record client ip history failed:", err)
	}

	return shouldCleanLog
}

// recordLocalAttribution stores this scan's local observations under this panel's
// own guid so a parent panel can attribute each IP to the node it is on.
// Best-effort: attribution is advisory and must never block IP-limit enforcement.
func (j *CheckClientIpJob) recordLocalAttribution(attribution map[string][]model.ClientIpEntry) {
	if len(attribution) == 0 {
		return
	}
	guid, err := (&service.SettingService{}).GetPanelGuid()
	if err != nil || guid == "" {
		return
	}
	if err := (&service.InboundService{}).RecordLocalClientIps(guid, attribution); err != nil {
		logger.Debug("[LimitIP] record local ip attribution failed:", err)
	}
}

// mergeClientIps retains fresh entries and exempts currently observed live
// connections from expiry even when their dispatch timestamps are old.
func mergeClientIps(old, new []model.ClientIpEntry, staleCutoff int64, newAlwaysLive bool) map[string]int64 {
	ipMap := make(map[string]int64, len(old)+len(new))
	for _, ipTime := range old {
		if ipTime.Timestamp < staleCutoff {
			continue
		}
		ipMap[ipTime.IP] = ipTime.Timestamp
	}
	for _, ipTime := range new {
		if !newAlwaysLive && ipTime.Timestamp < staleCutoff {
			continue
		}
		if existingTime, ok := ipMap[ipTime.IP]; !ok || ipTime.Timestamp > existingTime {
			ipMap[ipTime.IP] = ipTime.Timestamp
		}
	}
	return ipMap
}

type inboundIpUsage struct {
	ip       string
	lastSeen int64
	emails   map[string]struct{}
}

// inboundLimitBans applies each inbound's concurrent-IP cap across every client
// attached to it. One source IP occupies one slot even when several clients share it.
func (j *CheckClientIpJob) inboundLimitBans(observed map[string]map[string]int64, attached map[string][]*model.Inbound) []pendingBan {
	if len(attached) == 0 {
		return nil
	}
	type aggregate struct {
		inbound *model.Inbound
		ips     map[string]*inboundIpUsage
	}
	byInbound := make(map[int]*aggregate)
	for email, ipTimestamps := range observed {
		for _, inbound := range attached[email] {
			agg := byInbound[inbound.Id]
			if agg == nil {
				agg = &aggregate{inbound: inbound, ips: make(map[string]*inboundIpUsage)}
				byInbound[inbound.Id] = agg
			}
			for ip, ts := range ipTimestamps {
				if ip == "" || j.allowlist.contains(ip) {
					continue
				}
				if ts <= 0 {
					ts = time.Now().Unix()
				}
				use := agg.ips[ip]
				if use == nil {
					use = &inboundIpUsage{ip: ip, lastSeen: ts, emails: make(map[string]struct{})}
					agg.ips[ip] = use
				}
				if ts > use.lastSeen {
					use.lastSeen = ts
				}
				use.emails[email] = struct{}{}
			}
		}
	}

	var bans []pendingBan
	for _, agg := range byInbound {
		limit := agg.inbound.LimitIP
		if limit <= 0 || len(agg.ips) <= limit {
			continue
		}
		live := make([]*inboundIpUsage, 0, len(agg.ips))
		for _, use := range agg.ips {
			live = append(live, use)
		}
		sort.Slice(live, func(i, k int) bool {
			if live[i].lastSeen == live[k].lastSeen {
				return live[i].ip < live[k].ip
			}
			return live[i].lastSeen < live[k].lastSeen
		})
		var dropped []*inboundIpUsage
		if agg.inbound.LimitAction == "kick_oldest" {
			dropped = live[:len(live)-limit]
		} else {
			// reject_new: keep the oldest limit addresses and reject the newest overflow.
			dropped = live[limit:]
		}
		for _, use := range dropped {
			for email := range use.emails {
				bans = append(bans, pendingBan{
					inbound:    agg.inbound,
					email:      email,
					candidates: []model.ClientIpEntry{{IP: use.ip, Timestamp: use.lastSeen}},
					keptLive:   limit,
				})
			}
		}
	}
	return bans
}

func (j *CheckClientIpJob) checkFail2BanInstalled() bool {
	if !isFail2BanEnabled() {
		return false
	}

	cmd := "fail2ban-client"
	args := []string{"-h"}
	err := exec.CommandContext(context.Background(), cmd, args...).Run()
	return err == nil
}

func isFail2BanEnabled() bool {
	value, ok := os.LookupEnv("XUI_ENABLE_FAIL2BAN")
	return !ok || value == "true"
}

func (j *CheckClientIpJob) checkError(e error) {
	if e != nil {
		logger.Warning("client ip job err:", e)
	}
}

// delInboundClientIps drops the inbound_client_ips tracking row for an email
// that no longer maps to any inbound (a renamed or deleted client), so stale
// access-log entries don't keep a ghost row alive (#4963).
func (j *CheckClientIpJob) delInboundClientIps(tx *gorm.DB, clientEmail string) {
	if err := tx.Where("client_email = ?", clientEmail).Delete(&model.InboundClientIps{}).Error; err != nil {
		j.checkError(err)
	}
}

// updateInboundClientIps collects this scan's addresses into the display blob.
// Inbound-level enforcement happens after commit; this write never bans.
func (j *CheckClientIpJob) updateInboundClientIps(tx *gorm.DB, inboundClientIps *model.InboundClientIps, inbound *model.Inbound, clientEmail string, newIpsWithTime []model.ClientIpEntry, observedAreLive bool) {
	if inbound.Settings == "" {
		logger.Debug("wrong data:", inbound)
		return
	}

	staleCutoff := time.Now().Unix() - ipStaleAfterSeconds

	// Node sync merges into the same blob (#6587): compare-and-set it, and on a
	// miss re-read and re-merge so neither writer drops the other's IPs.
	for range service.ClientIpCasRetries {
		var oldIpsWithTime []model.ClientIpEntry
		if inboundClientIps.Ips != "" {
			_ = json.Unmarshal([]byte(inboundClientIps.Ips), &oldIpsWithTime)
		}
		ipMap := mergeClientIps(oldIpsWithTime, newIpsWithTime, staleCutoff, observedAreLive)

		dbIps := make([]model.ClientIpEntry, 0, len(ipMap))
		for ip, timestamp := range ipMap {
			dbIps = append(dbIps, model.ClientIpEntry{IP: ip, Timestamp: timestamp})
		}
		newIps, err := model.MarshalClientIpEntries(dbIps)
		if err != nil {
			j.checkError(err)
			return
		}
		if newIps == inboundClientIps.Ips {
			return
		}

		updated, err := service.CasUpdateInboundClientIps(tx, inboundClientIps.Id, inboundClientIps.Ips, newIps)
		if err != nil {
			logger.Error("failed to save inboundClientIps:", err)
			return
		}
		if updated {
			inboundClientIps.Ips = newIps
			return
		}
		if err := tx.Where("id = ?", inboundClientIps.Id).First(inboundClientIps).Error; err != nil {
			logger.Error("failed to re-read inboundClientIps after a concurrent write:", err)
			return
		}
	}
	logger.Error("failed to save inboundClientIps: exhausted CAS retries")
}

// pendingBan carries one client's enforcement outcome from inside the scan's
// transaction to the publication that may only follow a successful commit.
type pendingBan struct {
	inbound    *model.Inbound
	email      string
	candidates []model.ClientIpEntry
	keptLive   int
}

// publishBans returns the clients whose lines reached the log or were withheld as
// unproven. bannedSeen advances only for those, so a failed write stays retryable.
func (j *CheckClientIpJob) publishBans(bans []pendingBan) []pendingBan {
	published := make([]pendingBan, 0, len(bans))
	var logIpFile *os.File
	defer func() {
		if logIpFile == nil {
			return
		}
		if err := logIpFile.Close(); err != nil {
			logger.Errorf("failed to close IP limit log file: %s", err)
		}
	}()
	for _, b := range bans {
		actionable := j.selectAdvancedSinceLastBan(b.inbound.Id, b.email, b.candidates)
		if len(actionable) == 0 {
			j.recordBannedSeen(b.inbound.Id, b.email, b.candidates, nil)
			continue
		}
		// The caller still disconnects the client; only a firewall ban needs an
		// address the sender has proven to own.
		if j.sourceCanBeForged(b.email, b.inbound) {
			j.recordBannedSeen(b.inbound.Id, b.email, b.candidates, actionable)
			logger.Warningf("[LIMIT_IP] Inbound %s: client %s has %d IPs not queued for fail2ban because a protocol accepts forged sources", b.inbound.Tag, b.email, len(actionable))
			published = append(published, b)
			continue
		}
		if logIpFile == nil {
			f, err := os.OpenFile(xray.GetIPLimitLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
			if err != nil {
				logger.Errorf("failed to open IP limit log file: %s", err)
				return published
			}
			logIpFile = f
		}
		if err := writeBanLines(logIpFile, b.email, actionable); err != nil {
			logger.Errorf("failed to write IP limit bans for %s: %s", b.email, err)
			continue
		}
		j.recordBannedSeen(b.inbound.Id, b.email, b.candidates, actionable)
		logger.Infof("[LIMIT_IP] Inbound %s: client %s kept %d live IPs, queued %d for fail2ban", b.inbound.Tag, b.email, b.keptLive, len(actionable))
		published = append(published, b)
	}
	return published
}

// sourceCanBeForged checks every enabled inbound the client is attached to: an
// address only a datagram vouches for must never reach the fail2ban jail.
func (j *CheckClientIpJob) sourceCanBeForged(email string, current *model.Inbound) bool {
	if current != nil && acceptsUnverifiedSources(current) {
		return true
	}
	var inbounds []*model.Inbound
	err := database.GetDB().Model(&model.Inbound{}).
		Joins("JOIN client_inbounds ON client_inbounds.inbound_id = inbounds.id").
		Joins("JOIN clients ON clients.id = client_inbounds.client_id").
		Where("clients.email = ? AND inbounds.enable = ?", email, true).
		Find(&inbounds).Error
	if err != nil {
		j.checkError(err)
		return true
	}
	for _, inbound := range inbounds {
		if current != nil && inbound.Id == current.Id {
			continue
		}
		if acceptsUnverifiedSources(inbound) {
			return true
		}
	}
	return false
}

// pruneBannedSeen drops suppression entries for pairs no longer over the limit,
// so a client that goes under and over again is banned again.
func (j *CheckClientIpJob) pruneBannedSeen(attached map[string][]*model.Inbound, bans []pendingBan) {
	if len(j.bannedSeen) == 0 {
		return
	}
	current := make(map[string]struct{})
	for _, ban := range bans {
		for _, entry := range ban.candidates {
			current[banKey(ban.inbound.Id, ban.email, entry.IP)] = struct{}{}
		}
	}
	prefixes := make(map[string]struct{})
	for email, inbounds := range attached {
		for _, inbound := range inbounds {
			prefixes[strconv.Itoa(inbound.Id)+"|"+email+"|"] = struct{}{}
		}
	}
	for key := range j.bannedSeen {
		for prefix := range prefixes {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			if _, still := current[key]; !still {
				delete(j.bannedSeen, key)
			}
			break
		}
	}
}

// acceptsUnverifiedSources: Shadowsocks authenticates each UDP datagram on its own
// and mKCP takes the request with the first ones, so the core never answers first.
func acceptsUnverifiedSources(inbound *model.Inbound) bool {
	var stream struct {
		Method  string `json:"method"`
		Network string `json:"network"`
	}
	_ = json.Unmarshal([]byte(inbound.StreamSettings), &stream)
	// The core reads method as the newer name of network and prefers it.
	if stream.Method != "" {
		stream.Network = stream.Method
	}
	switch strings.ToLower(stream.Network) {
	case "kcp", "mkcp":
		return true
	}
	if inbound.Protocol != model.Shadowsocks {
		return false
	}
	var settings struct {
		Network *conf.NetworkList `json:"network"`
	}
	_ = json.Unmarshal([]byte(inbound.Settings), &settings)
	return xnet.HasNetwork(settings.Network.Build(), xnet.Network_UDP)
}

// writeBanLines emits one line per address; the wording is load-bearing, since
// x-ui.sh create_iplimit_jails builds filter.d/3x-ipl.conf failregex from it.
func writeBanLines(w io.Writer, clientEmail string, actionable []model.ClientIpEntry) error {
	stamp := time.Now().Format("2006/01/02 15:04:05")
	for _, ipTime := range actionable {
		if _, err := fmt.Fprintf(w, "%s [LIMIT_IP] Email = %s || Disconnecting OLD IP = %s || Timestamp = %d\n",
			stamp, clientEmail, ipTime.IP, ipTime.Timestamp); err != nil {
			return err
		}
	}
	return nil
}

// recordInboundRejections persists what publishBans actually acted on, so the
// inbound view can show it without parsing rotated log files.
func (j *CheckClientIpJob) recordInboundRejections(published []pendingBan) {
	if len(published) == 0 {
		return
	}
	rows := make([]model.InboundIpRejection, 0, len(published))
	for _, ban := range published {
		action := ban.inbound.LimitAction
		if action == "" {
			action = "reject_new"
		}
		for _, entry := range ban.candidates {
			if entry.IP == "" {
				continue
			}
			rows = append(rows, model.InboundIpRejection{
				InboundID: ban.inbound.Id,
				Tag:       ban.inbound.Tag,
				Email:     ban.email,
				IP:        entry.IP,
				Action:    action,
			})
		}
	}
	if err := (&service.InboundService{}).RecordInboundIpRejections(rows); err != nil {
		logger.Debug("[LimitIP] record inbound rejections failed:", err)
	}
}

func banKey(inboundID int, email, ip string) string {
	return strconv.Itoa(inboundID) + "|" + email + "|" + ip
}

// selectAdvancedSinceLastBan drops pairs with a frozen lastSeen: the core
// refreshes it only on a new dispatch, so those are unreaped dead connections.
func (j *CheckClientIpJob) selectAdvancedSinceLastBan(inboundID int, email string, banned []model.ClientIpEntry) []model.ClientIpEntry {
	actionable := make([]model.ClientIpEntry, 0, len(banned))
	for _, ipTime := range banned {
		if last, ok := j.bannedSeen[banKey(inboundID, email, ipTime.IP)]; ok && ipTime.Timestamp <= last {
			continue
		}
		actionable = append(actionable, ipTime)
	}
	return actionable
}

// recordBannedSeen marks published pairs and forgets addresses this scan no
// longer bans; it runs for every enforced client, which is what prunes the map.
func (j *CheckClientIpJob) recordBannedSeen(inboundID int, email string, banned, published []model.ClientIpEntry) {
	if j.bannedSeen == nil {
		j.bannedSeen = make(map[string]int64)
	}
	for _, ipTime := range published {
		j.bannedSeen[banKey(inboundID, email, ipTime.IP)] = ipTime.Timestamp
	}
	current := make(map[string]struct{}, len(banned))
	for _, ipTime := range banned {
		current[banKey(inboundID, email, ipTime.IP)] = struct{}{}
	}
	prefix := strconv.Itoa(inboundID) + "|" + email + "|"
	for key := range j.bannedSeen {
		if strings.HasPrefix(key, prefix) {
			if _, still := current[key]; !still {
				delete(j.bannedSeen, key)
			}
		}
	}
}

// disconnectClientTemporarily drops a client's credential for a moment, so new
// handshakes are refused; the fail2ban ban is what ends live traffic.
func (j *CheckClientIpJob) disconnectClientTemporarily(inbound *model.Inbound, clientEmail string, clients []model.Client) {
	var xrayAPI xray.XrayAPI
	apiPort := j.resolveXrayAPIPort()

	err := xrayAPI.Init(apiPort)
	if err != nil {
		logger.Warningf("[LIMIT_IP] Failed to init Xray API for disconnection: %v", err)
		return
	}
	defer xrayAPI.Close()

	// Find the client config
	var clientConfig map[string]any
	var reverseClient bool
	for _, client := range clients {
		if client.Email == clientEmail {
			// Convert client to map for API
			clientBytes, _ := json.Marshal(client)
			_ = json.Unmarshal(clientBytes, &clientConfig)
			reverseClient = client.Reverse != nil
			break
		}
	}

	if clientConfig == nil {
		return
	}

	// Protocols XrayAPI can remove and re-add from a marshaled model.Client.
	// wireguard stays out: keepAlive marshals as a number, AddUser wants a string.
	protocol := string(inbound.Protocol)
	switch protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "hysteria", "masque":
		// supported protocols, continue
	default:
		logger.Warningf("[LIMIT_IP] Temporary disconnect is not supported for protocol %s on inbound %s", protocol, inbound.Tag)
		return
	}

	// RemoveUser drops a reverse client's outbound handler and the re-add below
	// cannot restore it, so its tunnel would stay down until Xray restarts.
	if reverseClient {
		logger.Warningf("[LIMIT_IP] Not disconnecting %s: its reverse proxy config does not survive a temporary removal", clientEmail)
		return
	}

	// For Shadowsocks, ensure the required "cipher" field is present by
	// reading it from the inbound settings (e.g., settings["method"]).
	if string(inbound.Protocol) == "shadowsocks" {
		var inboundSettings map[string]any
		if err := json.Unmarshal([]byte(inbound.Settings), &inboundSettings); err != nil {
			logger.Warningf("[LIMIT_IP] Failed to parse inbound settings for shadowsocks cipher: %v", err)
		} else {
			if method, ok := inboundSettings["method"].(string); ok && method != "" {
				clientConfig["cipher"] = method
			}
		}
	}

	// The core's RemoveUser clears its validator: a session already up keeps
	// running, except a reverse vless client, which is skipped above.
	err = xrayAPI.RemoveUser(inbound.Tag, clientEmail)
	if err != nil {
		logger.Warningf("[LIMIT_IP] Failed to remove user %s: %v", clientEmail, err)
		return
	}

	// Nothing is pending here: AlterInbound applies the removal inline, so this
	// only widens the window in which new handshakes fail.
	time.Sleep(100 * time.Millisecond)

	// clientConfig is the scan's snapshot: a disable or delete committed since then
	// found no user to remove (or restarted the core) and will not come back for it.
	if !j.clientStillServed(inbound.Id, clientEmail) {
		logger.Infof("[LIMIT_IP] Not restoring %s: disabled or removed during its temporary disconnect", clientEmail)
		return
	}

	// Re-add user to allow new connections
	err = xrayAPI.AddUser(protocol, inbound.Tag, clientConfig)
	if err != nil {
		logger.Warningf("[LIMIT_IP] Failed to re-add user %s: %v", clientEmail, err)
		return
	}

	// Asked again: a commit can land between the check and the re-add. Writers touch
	// the core only after they commit, so one this check misses removes the user itself.
	if !j.clientStillServed(inbound.Id, clientEmail) {
		logger.Infof("[LIMIT_IP] Removing %s again: disabled or removed during its temporary disconnect", clientEmail)
		if err := xrayAPI.RemoveUser(inbound.Tag, clientEmail); err != nil {
			logger.Warningf("[LIMIT_IP] Failed to remove user %s again: %v", clientEmail, err)
		}
	}
}

// clientStillServed is GetXrayConfig's rule for handing a client to the core: linked to
// the enabled inbound, enabled, not depleted per client_traffics. A failed read is "no".
func (j *CheckClientIpJob) clientStillServed(inboundId int, clientEmail string) bool {
	var served int64
	err := database.GetDB().Table("client_inbounds").
		Joins("JOIN clients ON clients.id = client_inbounds.client_id").
		Joins("JOIN inbounds ON inbounds.id = client_inbounds.inbound_id").
		Where("client_inbounds.inbound_id = ? AND inbounds.enable = ?", inboundId, true).
		Where("clients.email = ? AND clients.enable = ?", clientEmail, true).
		Where("NOT EXISTS (SELECT 1 FROM client_traffics WHERE client_traffics.email = clients.email AND client_traffics.enable = ?)", false).
		Count(&served).Error
	j.checkError(err)
	return err == nil && served > 0
}

// resolveXrayAPIPort returns the API inbound port from running config, then template config, then default.
func (j *CheckClientIpJob) resolveXrayAPIPort() int {
	var configErr error
	var templateErr error

	if port, err := getAPIPortFromConfigPath(xray.GetConfigPath()); err == nil {
		return port
	} else {
		configErr = err
	}

	db := database.GetDB()
	var template model.Setting
	if err := db.Where("key = ?", "xrayTemplateConfig").First(&template).Error; err == nil {
		if port, parseErr := getAPIPortFromConfigData([]byte(template.Value)); parseErr == nil {
			return port
		} else {
			templateErr = parseErr
		}
	} else {
		templateErr = err
	}

	logger.Warningf(
		"[LIMIT_IP] Could not determine Xray API port from config or template; falling back to default port %d (config error: %v, template error: %v)",
		defaultXrayAPIPort,
		configErr,
		templateErr,
	)

	return defaultXrayAPIPort
}

func getAPIPortFromConfigPath(configPath string) (int, error) {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return 0, err
	}

	return getAPIPortFromConfigData(configData)
}

func getAPIPortFromConfigData(configData []byte) (int, error) {
	xrayConfig := &xray.Config{}
	if err := json.Unmarshal(configData, xrayConfig); err != nil {
		return 0, err
	}

	for _, inboundConfig := range xrayConfig.InboundConfigs {
		if inboundConfig.Tag == "api" && inboundConfig.Port > 0 {
			return inboundConfig.Port, nil
		}
	}

	return 0, errors.New("api inbound port not found")
}

// getInboundByEmail resolves the inbound that owns a client email. It prefers
// the exact clients/client_inbounds relation; a substring "settings LIKE
// %email%" can match the wrong inbound (an email that is a substring of another,
// or text that merely appears elsewhere in the settings JSON). The LIKE + JSON
// scan stays only as a fallback for clients not yet present in the relation, so
// nothing regresses when the join finds no row.
func (j *CheckClientIpJob) getInboundByEmail(clientEmail string) (*model.Inbound, error) {
	db := database.GetDB()
	inbound := &model.Inbound{}

	err := db.Model(&model.Inbound{}).
		Joins("JOIN client_inbounds ON client_inbounds.inbound_id = inbounds.id").
		Joins("JOIN clients ON clients.id = client_inbounds.client_id").
		Where("clients.email = ?", clientEmail).
		First(inbound).Error
	if err == nil {
		return inbound, nil
	}

	var candidates []model.Inbound
	if listErr := db.Model(&model.Inbound{}).Where("settings LIKE ?", "%"+clientEmail+"%").Find(&candidates).Error; listErr != nil {
		return nil, listErr
	}
	for i := range candidates {
		clients, jsonErr := service.ParseInboundSettingsClients(candidates[i].Settings)
		if jsonErr != nil {
			continue
		}
		for _, client := range clients {
			if client.Email == clientEmail {
				return &candidates[i], nil
			}
		}
	}

	return nil, err
}

// Runs before the apiMode gate: retention must hold for stored rows even
// while nothing is being collected.
func (j *CheckClientIpJob) pruneStaleIpRows() {
	now := time.Now().Unix()
	if now-j.lastIpPrune < ipPruneIntervalSeconds {
		return
	}
	j.lastIpPrune = now
	if err := (&service.InboundService{}).PruneStaleClientIps(); err != nil {
		logger.Warning("prune stale client ip rows failed:", err)
	}
	if err := (&service.InboundService{}).PruneClientIpHistory(); err != nil {
		logger.Warning("prune client ip history failed:", err)
	}
	if err := (&service.InboundService{}).PruneInboundIpRejections(); err != nil {
		logger.Warning("prune inbound ip rejections failed:", err)
	}
}
