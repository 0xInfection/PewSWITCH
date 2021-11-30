package main

import "fmt"

type (
	VulnDetails struct {
		CVE202137624 struct {
			IsVulnerable   bool              `json:"is_vulnerable"`
			ExploitDetails []ExpDetails37624 `json:"exploit_details"`
		} `json:"cve_2021_37624"`
		CVE202141157 struct {
			IsVulnerable   bool              `json:"is_vulnerable"`
			ExploitDetails []ExpDetails41157 `json:"exploit_details"`
		} `json:"cve_2021_41157"`
	}
	ExpDetails41157 struct {
		Extension   string   `json:"extension"`
		NotifsRecvd []string `json:"notifications_received"`
	}
	ExpDetails37624 struct {
		Extension        string   `json:"extension"`
		Messages         []string `json:"messages"`
		SentSuccessfully bool     `json:"sent_successfully"`
	}
	fResult struct {
		Host    string      `json:"host"`
		Details VulnDetails `json:"vulnerability_details"`
	}
)

var (
	randomScan                       bool
	delay, maxConcurrent, timeout    int
	userAgent, cveToScan, extensions string
	extFile, outdir, sendmsgs        string
	allexts                          []string
	finalResults                     []fResult
	msgstosend                       [][]string

	version      = "0.1"
	allvulns     = []string{"cve-2021-37624", "cve-2021-41157"}
	vulnToModule = map[string]interface{}{
		"cve-2021-37624": cve2021x37624,
		"cve-2021-41157": cve2021x41157,
	}
	lackofart = fmt.Sprintf(`
     ___             ____       _ __      __
    / _ \___ _    __/ __/    __(_) /_____/ /
   / ___/ -_) |/|/ /\ \| |/|/ / / __/ __/ _ \
  /_/   \__/|__,__/___/|__,__/_/\__/\__/_//_/  v%s

       "where we pew pew pew freeswitch" `, version)
	defaultMsgText = []string{
		"FBI",
		"022-324-3000",
		"FBI here. Open your door!",
	}
)
