package datagen

import (
	"net/netip"
	"sort"
	"time"

	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/event"
	"github.com/snelly1903/MeLi-waf-behavior-engine/internal/groundtruth"
)

type LegitProfile struct {
	Name string

	Pool IPPool

	UserAgents []string

	HasSession bool

	SendsReferer bool

	FetchesStaticAssets bool

	Paths        []string
	StaticAssets []string

	LoginPath string

	LoginRetryProbability float64

	BrokenLinkProbability float64

	MinRequests, MaxRequests int

	MinGap, MaxGap time.Duration
}

var (
	ProfileNavegante = LegitProfile{
		Name: "navegante",
		Pool: PoolResidentialSimA,
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
		},
		HasSession:            true,
		SendsReferer:          true,
		FetchesStaticAssets:   true,
		Paths:                 []string{"/", "/dashboard", "/products", "/products/42", "/account", "/help", "/settings"},
		StaticAssets:          []string{"/static/app.css", "/static/app.js", "/static/logo.png"},
		LoginPath:             DefaultLoginPath,
		LoginRetryProbability: 0.15,
		BrokenLinkProbability: 0.05,
		MinRequests:           5,
		MaxRequests:           15,
		MinGap:                2 * time.Second,
		MaxGap:                40 * time.Second,
	}

	ProfileAPIClient = LegitProfile{
		Name: "api_client",
		Pool: PoolResidentialSimB,
		UserAgents: []string{
			"MeLiApp/4.12.0 (iOS 17.4; iPhone15,3)",
			"MeLiApp/4.12.0 (Android 14; Pixel8)",
		},
		HasSession:            false,
		SendsReferer:          false,
		FetchesStaticAssets:   false,
		Paths:                 []string{"/api/v1/products", "/api/v1/orders", "/api/v1/account", "/api/v1/orders/8831", "/api/v1/notifications"},
		LoginPath:             "/api/login",
		LoginRetryProbability: 0.05,
		BrokenLinkProbability: 0.02,
		MinRequests:           3,
		MaxRequests:           10,
		MinGap:                500 * time.Millisecond,
		MaxGap:                5 * time.Second,
	}

	ProfileHostedTenant = func() LegitProfile {
		p := ProfileAPIClient
		p.Name = "hosted_tenant"
		p.Pool = PoolHostingSim
		return p
	}()

	ProfileOffice = LegitProfile{
		Name: "office_employee",
		Pool: PoolResidentialSimA,
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120",
		},
		HasSession:            true,
		SendsReferer:          true,
		FetchesStaticAssets:   true,
		Paths:                 []string{"/", "/dashboard", "/reports", "/reports/quarterly", "/account"},
		StaticAssets:          []string{"/static/app.css", "/static/app.js"},
		LoginPath:             DefaultLoginPath,
		LoginRetryProbability: 0.1,
		BrokenLinkProbability: 0.05,
		MinRequests:           4,
		MaxRequests:           12,
		MinGap:                1 * time.Second,
		MaxGap:                25 * time.Second,
	}
)

func GenerateLegitSession(rng *RNG, profile LegitProfile, start time.Time, clientIP netip.Addr) []groundtruth.LabeledEvent {
	clock := event.NewManualClock(start)
	userAgent := Pick(rng, profile.UserAgents)

	var sessionID string
	if profile.HasSession {
		sessionID = rng.ID("s-")
	}

	var events []groundtruth.LabeledEvent
	requestCount := rng.IntRange(profile.MinRequests, profile.MaxRequests)
	lastPath := ""

	emit := func(method, path string, status int, referer, loginUserHash string) {
		e := event.Event{
			RequestID:     rng.ID("r-"),
			Timestamp:     clock.Now(),
			ClientIP:      clientIP,
			SessionID:     sessionID,
			Method:        method,
			Path:          path,
			StatusCode:    status,
			UserAgent:     userAgent,
			Referer:       referer,
			LoginUserHash: loginUserHash,
		}
		events = append(events, groundtruth.LabeledEvent{Label: groundtruth.LabelLegit, Event: e})
		clock.Advance(rng.DurationRange(profile.MinGap, profile.MaxGap))
	}

	if profile.LoginPath != "" && rng.Bool(profile.LoginRetryProbability) {
		accountHash := rng.HexHash(64)
		emit("POST", profile.LoginPath, 401, lastPath, accountHash)
		emit("POST", profile.LoginPath, 200, profile.LoginPath, accountHash)
		lastPath = profile.LoginPath
	}

	for i := 0; i < requestCount; i++ {
		path := Pick(rng, profile.Paths)
		status := 200
		if rng.Bool(profile.BrokenLinkProbability) {
			status = 404
		}

		referer := ""
		if profile.SendsReferer {
			referer = lastPath
		}
		emit("GET", path, status, referer, "")

		if profile.FetchesStaticAssets && len(profile.StaticAssets) > 0 {
			asset := Pick(rng, profile.StaticAssets)
			assetReferer := ""
			if profile.SendsReferer {
				assetReferer = path
			}
			emit("GET", asset, 200, assetReferer, "")
		}

		lastPath = path
	}

	return events
}

func GenerateOfficeCluster(rng *RNG, employees int, clusterStart time.Time, startJitter time.Duration) []groundtruth.LabeledEvent {
	sharedIP := ProfileOffice.Pool.RandomAddr(rng)

	var all []groundtruth.LabeledEvent
	for i := 0; i < employees; i++ {
		employeeStart := clusterStart.Add(rng.DurationRange(0, startJitter))
		all = append(all, GenerateLegitSession(rng, ProfileOffice, employeeStart, sharedIP)...)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Event.Timestamp.Before(all[j].Event.Timestamp)
	})
	return all
}
