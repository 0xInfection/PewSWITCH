// Exploit for

package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

func processHost(host string) {
	for vuln, runner := range vulnToModule {
		if isItemIn(vuln, &allvulns) {
			runner.(func(string))(host)
		}
	}
}

func initScan(allhosts *[]string) {
	hosts := make(chan string, maxConcurrent)
	maxProcs := new(sync.WaitGroup)
	maxProcs.Add(maxConcurrent)
	startTime := time.Now()
	log.Println("Starting scan at:", startTime.String())
	for i := 0; i < maxConcurrent; i++ {
		go func() {
			for {
				host := <-hosts
				if host == "" {
					break
				}
				processHost(host)
			}
			maxProcs.Done()
		}()
	}
	for _, xhost := range *allhosts {
		hosts <- xhost
	}
	close(hosts)
	maxProcs.Wait()
	log.Println("Scan finished at:", time.Now().String())
	log.Printf("Total %d hosts scanned in %s.", len(*allhosts), time.Since(startTime).String())
}

func main() {
	flag.IntVar(&delay, "delay", 0, "Delay in seconds between subsequent requests.")
	flag.IntVar(&maxConcurrent, "threads", 2, "Number of concurrent hosts to process.")
	flag.StringVar(&userAgent, "ua", "FreePew/0.0.1", "Custom user-agent string to use.")
	flag.StringVar(&cveToScan, "cve", "", "Scan for a specific vuln rather than both.")
	flag.StringVar(&extensions, "exts", "", "Comma separated list of extensions to scan.")
	flag.BoolVar(&randomScan, "random-scan", false, "Here we go pew pew pew.")
	flag.Parse()

	fmt.Print(lackofart, "\n\n")
	targets := flag.Args()
	if len(targets) < 1 && !randomScan {
		log.Fatalln("You need to supply at least a valid target to scan!")
	}
	if len(cveToScan) != 0 {
		allvulns = []string{strings.ToLower(cveToScan)}
	}
	initScan(&targets)
}
