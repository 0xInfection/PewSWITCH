package main

import "fmt"

var (
	randomScan                       bool
	delay, maxConcurrent, timeout    int
	userAgent, cveToScan, extensions string
	extFile, outdir                  string
	allexts                          []string

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
)
