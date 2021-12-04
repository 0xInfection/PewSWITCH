package main

import (
	"fmt"
	"sync"
	"time"
)

type (
	JSONTime        time.Time
	ExpDetails41157 struct {
		Extension   string `json:"extension"`
		NotifsRecvd []struct {
			Timestamp JSONTime `json:"timestamp"`
			Message   string   `json:"notification"`
		} `json:"notifications_received"`
	}
	ExpDetails37624 struct {
		Extension    string `json:"extension"`
		SentMessages []struct {
			Message   string   `json:"message"`
			Timestamp JSONTime `json:"timestamp"`
		} `json:"sent_messages"`
		SentSuccessfully bool `json:"sent_successfully"`
	}
	fResult struct {
		Host    string `json:"host"`
		Details struct {
			CVE202137624 struct {
				IsVulnerable   bool              `json:"is_vulnerable"`
				ExploitDetails []ExpDetails37624 `json:"exploit_details"`
			} `json:"cve_2021_37624,omitempty"`
			CVE202141157 struct {
				IsVulnerable   bool              `json:"is_vulnerable"`
				ExploitDetails []ExpDetails41157 `json:"exploit_details"`
			} `json:"cve_2021_41157,omitempty"`
		} `json:"vulnerability_details"`
	}
)

var (
	delay, maxConcurrent, maxExpires int
	userAgent, cveToScan, extensions string
	extFile, outdir, sendmsgs        string
	monEvents, outFormat             string
	allexts, allEvents               []string
	finalResults                     []fResult
	msgstosend                       [][]string

	version      = "0.1"
	allvulns     = []string{"cve-2021-37624", "cve-2021-41157"}
	vulnToModule = map[string]interface{}{
		"cve-2021-37624": cve2021x37624,
		"cve-2021-41157": cve2021x41157,
	}
	globalTex = &sync.Mutex{}
	lackofart = fmt.Sprintf(`
     ___    .        ____       _ __      __
    / _ \___|\    __/ __/|   __(_) /_____/ /
   / ___/ -_) |/|/ /\ \| |/|/ / / __/ __/ _ \
  /_/   \__/|__,__/___/|__,__/_/\__/\__/_//_/  v%s

       "where we pew pew pew freeswitch"`, version)
	defaultMsgText = []string{
		"FBI",
		"022-324-3000",
		"FBI here. Open your door!",
	}
)

func (t JSONTime) MarshalJSON() ([]byte, error) {
	stamp := fmt.Sprintf("\"%s\"", time.Time(t).Format(time.RFC3339))
	return []byte(stamp), nil
}
