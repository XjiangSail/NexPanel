package service

import (
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestDeviceMetaFromUserAgent(t *testing.T) {
	tests := []struct {
		name    string
		ua      string
		wantOS  string
		wantVer string
	}{
		{"android chrome", "Mozilla/5.0 (Linux; Android 14; Pixel 9) AppleWebKit/537.36", "Android", "14"},
		{"android v2rayng", "v2rayNG/1.8.5", "Android", ""},
		{"iphone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15", "iOS", "17.5"},
		{"ipad", "Mozilla/5.0 (iPad; CPU OS 16_3 like Mac OS X)", "iOS", "16.3"},
		{"shadowrocket", "Shadowrocket/2.2.35", "iOS", ""},
		{"windows chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Windows", "10.0"},
		{"v2rayn", "v2rayN/6.23", "Windows", ""},
		{"macos safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15", "macOS", "14.5"},
		{"linux", "curl/8.0 (x86_64-pc-linux-gnu)", "Linux", ""},
		{"unknown", "Happ/1.0", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotOS, gotVer := deviceMetaFromUserAgent(tc.ua)
			if gotOS != tc.wantOS || gotVer != tc.wantVer {
				t.Fatalf("deviceMetaFromUserAgent(%q) = (%q, %q), want (%q, %q)", tc.ua, gotOS, gotVer, tc.wantOS, tc.wantVer)
			}
		})
	}
}

func TestClientHwidGateInfersDeviceFromUserAgent(t *testing.T) {
	initClientHwidTestDB(t)
	svc := &ClientService{}
	seedHwidClient(t, 0)

	if _, err := svc.EnforceHwidForSubID("sub-hwid", HwidRequest{
		Hwid:      "ua-device-one",
		UserAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 9) AppleWebKit/537.36",
	}); err != nil {
		t.Fatalf("gate: %v", err)
	}

	list, err := svc.ListClientHwids("hwid@example.com")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].DeviceOS != "Android" || list[0].OsVersion != "14" {
		t.Fatalf("device metadata = %+v, want Android 14", list)
	}
}

func TestClientHwidListParsesLegacyUserAgent(t *testing.T) {
	initClientHwidTestDB(t)
	svc := &ClientService{}
	seedHwidClient(t, 0)

	now := time.Now().UnixMilli()
	legacy := &model.ClientHwid{
		SubID:     "sub-hwid",
		HwidHash:  hashHwid("legacy-device"),
		FirstSeen: now,
		LastSeen:  now,
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15",
	}
	if err := database.GetDB().Create(legacy).Error; err != nil {
		t.Fatalf("seed legacy HWID: %v", err)
	}

	list, err := svc.ListClientHwids("hwid@example.com")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].DeviceOS != "iOS" || list[0].OsVersion != "17.5" {
		t.Fatalf("legacy device metadata = %+v, want iOS 17.5", list)
	}
}
