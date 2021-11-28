// Exploit for

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

func processHost(host string) {
	xwr, err := initWriter(path.Join(outdir, fmt.Sprintf("%s.csv", host)))
	if err != nil {
		log.Println("Can't initiate results writer:", err.Error())
		return
	}
	xwr.writeRow([]string{"cve_id", ""})
	for vuln, runner := range vulnToModule {
		if isItemIn(vuln, &allvulns) {
			runner.(func(string, *csvWriter))(host, xwr)
		}
	}
}

func initScan(allhosts, allexts *[]string) {
	log.Println("Checking if hosts are alive and responding to SIP...")

	var alivehosts []string
	xmap := checkAlive(allhosts)
	for target, alive := range xmap {
		if alive {
			alivehosts = append(alivehosts, target)
		} else {
			log.Printf("Looks like %s is down / not responding to SIP.", target)
		}
	}

	hosts := make(chan string, maxConcurrent)
	maxProcs := new(sync.WaitGroup)
	maxProcs.Add(maxConcurrent)

	log.Println("Creating output directory...")
	_, err := os.Stat(outdir)
	if err != nil {
		if os.IsNotExist(err) {
			if err = os.Mkdir(outdir, os.ModeDir); err != nil {
				log.Fatalln(err.Error())
			}
		}
	}

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

	for _, xhost := range alivehosts {
		for _, ext := range *allexts {
			mhost := fmt.Sprintf("%s@%s", ext, xhost)
			hosts <- mhost
		}
	}

	close(hosts)
	maxProcs.Wait()

	log.Println("Scan finished at:", time.Now().String())
	log.Printf("Total %d hosts scanned in %s.", len(*allhosts), time.Since(startTime).String())
}

func main() {
	flag.IntVar(&delay, "delay", 0, "Delay in seconds between subsequent requests.")
	flag.IntVar(&maxConcurrent, "threads", 2, "Number of concurrent hosts to process.")
	flag.StringVar(&userAgent, "ua", fmt.Sprintf("pewswitch/%s", version), "Custom user-agent string to use.")
	flag.StringVar(&cveToScan, "cve", "", "Scan for a specific vuln rather than both.")
	flag.StringVar(&extensions, "exts", "1005", "Comma separated list of extensions to scan.")
	flag.StringVar(&extFile, "ext-file", "", "Specify a file containing extensions instead of '-exts'")
	//flag.StringVar(&rport, "rport", "5060", "Destination port to use for the targets.")
	flag.StringVar(&outdir, "output", "./pewswitch/", "Output directory to write the results to.")
	flag.BoolVar(&randomScan, "random-scan", false, "Here we go pew pew pew.")
	flag.Parse()

	fmt.Print(lackofart, "\n\n")
	targets := flag.Args()
	if len(targets) < 1 && !randomScan {
		log.Println("You need to supply at least a valid target & extension to scan!\n\nUsage:")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if len(extensions) < 1 && len(extFile) < 1 {
		log.Println("You need to supply at least a valid extension to scan! Use '-exts' or '-ext-file'.\n\nUsage:")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if len(cveToScan) != 0 {
		allvulns = []string{strings.ToLower(cveToScan)}
	}
	xflag := false
	for x := range targets {
		if !strings.Contains(targets[x], ":") {
			xflag = true
			targets[x] = fmt.Sprintf("%s:5060", targets[x])
		}
	}
	if xflag {
		log.Println("No port supplied, using default port 5060 for targets...")
	}
	for _, ext := range strings.Split(extensions, ",") {
		allexts = append(allexts, strings.TrimSpace(ext))
	}
	if len(extFile) > 0 {
		allexts = append(allexts, *getExtensionsFromFile(extFile)...)
	}
	initScan(&targets, &allexts)
}
