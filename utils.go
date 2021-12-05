package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

type csvWriter struct {
	locker *sync.Mutex
	writer *csv.Writer
}

const letterRunes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func initCSVWriter(fname string) (*csvWriter, error) {
	csvf, err := os.Create(fname)
	if err != nil {
		return nil, err
	}
	wr := csv.NewWriter(csvf)
	return &csvWriter{
		locker: &sync.Mutex{},
		writer: wr,
	}, nil
}

func (wr *csvWriter) writeRow(row []string) {
	wr.locker.Lock()
	wr.writer.Write(row)
	wr.locker.Unlock()
}

func (wr *csvWriter) FlushBuffer() {
	wr.locker.Lock()
	wr.writer.Flush()
	wr.locker.Unlock()
}

// checks if a specific item is in a slice
func isItemIn(item string, allitems *[]string) bool {
	for x := range *allitems {
		if item == (*allitems)[x] {
			return true
		}
	}
	return false
}

func genRandStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func getLocalAddr() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatalln(err)
	}
	conn.Close()
	return conn.LocalAddr().String()
}

func sendPacket(hostport string, payload string, deadline int, termConn bool) (net.Conn, error) {
	conn, err := net.DialTimeout("udp", hostport, time.Duration(dialTimeout)*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
	_, err = conn.Write([]byte(payload))
	if err != nil {
		return nil, err
	}
	if termConn {
		err = conn.Close()
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func readExtensionsFromFile(fname string) *[]string {
	var exts []string
	file, err := os.Open(fname)
	if err != nil {
		log.Fatalln(err.Error())
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		exts = append(exts, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatalln(err.Error())
	}
	return &exts
}

func readCsvFile(filePath string) [][]string {
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatal("Unable to read input file "+filePath, err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal("Unable to parse file as CSV for "+filePath, err)
	}

	return records
}

func checkAlive(targets *[]string) map[string]bool {
	var dmap = make(map[string]bool)
	for _, targ := range *targets {
		dmap[targ] = false
		conn, err := net.DialTimeout("udp", targ, time.Duration(dialTimeout)*time.Second)
		if err != nil {
			log.Println(err.Error())
			continue
		}
		defer conn.Close()

		var payload string
		payload += fmt.Sprintf("OPTIONS sip:1000@%s;transport=UDP SIP/2.0\r\n", targ)
		payload += fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK001b84f6;rport\r\n", conn.LocalAddr().String())
		payload += "Max-Forwards: 70\r\n"
		payload += "To: \"PewSWITCH\" <sip:1000@1.1.1.1>\r\n"
		payload += "From: \"PewSWITCH\" <sip:1000@1.1.1.1>;tag=61633638380343437\r\n"
		payload += "User-Agent: pewswitch\r\n"
		payload += "Call-ID: AABkh3bjAZ3k2j3br5920I0\r\n"
		payload += fmt.Sprintf("Contact: sip:1000@%s\r\n", conn.LocalAddr().String())
		payload += "CSeq: 1 OPTIONS\r\n"
		payload += "Accept: application/sdp\r\n"
		payload += "Content-Length: 0\r\n"
		payload += "\r\n"

		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte(payload))
		if err != nil {
			continue
		}
		xbuf := make([]byte, 8192)
		_, err = conn.Read(xbuf)
		if err != nil {
			continue
		}
		if strings.HasPrefix(string(xbuf), "SIP/2.0") {
			dmap[targ] = true
			log.Printf("Host %s is up and responding to SIP.", targ)
		}
		server := serverHead.FindAllSubmatch(xbuf, -1)
		if server != nil {
			servstr := strings.ToLower(string(server[0][1]))
			if !strings.Contains(servstr, "freeswitch") {
				log.Println("Heuristics indicate that the server might not be FreeSWITCH!")
			} else {
				log.Println("Heuristics indicate that the server is FreeSWITCH.")
			}
		} else {
			log.Println("No server header found. Skipping heuristic checks...")
		}
	}
	return dmap
}

func postProcess(obj *[]fResult) *[]fResult {
	var (
		uniqhosts []string
		xresult   fResult
		count     = 0
		newObj    = make([]fResult, 0)
	)
	for _, x := range *obj {
		uniqhosts = append(uniqhosts, x.Host)
	}
	uniqhosts = *sortUnique(&uniqhosts)
	for _, mhost := range uniqhosts {
		xflag := false
		for _, res := range *obj {
			if res.Host == mhost {
				if !xflag {
					if count > 0 {
						newObj = append(newObj, xresult)
					}
					xresult = res
					xflag = true
					continue
				}
				xresult.Details.CVE202137624.ExploitDetails = append(xresult.Details.
					CVE202137624.ExploitDetails, res.Details.CVE202137624.ExploitDetails...)
				xresult.Details.CVE202141157.ExploitDetails = append(xresult.Details.
					CVE202141157.ExploitDetails, res.Details.CVE202141157.ExploitDetails...)
				count++
			}
		}
	}
	newObj = append(newObj, xresult)
	return &newObj
}

// writeToJSON writes the results of a scan to the specified directory
func writeToJSON(obj *[]fResult) error {
	obj = postProcess(obj)
	for _, res := range *obj {
		xdata, err := json.MarshalIndent(res, "", "    ")
		if err != nil {
			return err
		}
		if err = ioutil.WriteFile(path.Join(outdir,
			fmt.Sprintf("%s-report.json", res.Host)), xdata, 0644); err != nil {
			return err
		}
	}
	return nil
}

func writeToCSV(obj *[]fResult) error {
	var uniqhosts []string
	for _, x := range *obj {
		uniqhosts = append(uniqhosts, x.Host)
	}
	uniqhosts = *sortUnique(&uniqhosts)
	for _, xhost := range uniqhosts {
		xwriter, err := initCSVWriter(path.Join(outdir, fmt.Sprintf("%s-report.csv", xhost)))
		if err != nil {
			return err
		}
		xwriter.writeRow([]string{
			"extension",
			"host",
			"cve",
			"is_vulnerable",
			"message",
			"timestamp",
		})
		for _, res := range *obj {
			if xhost == res.Host {
				xdets := res.Details.CVE202137624.ExploitDetails
				if len(res.Details.CVE202137624.ExploitDetails) > 0 {
					for _, msg := range res.Details.CVE202137624.ExploitDetails[0].SentMessages {
						xwriter.writeRow([]string{
							xdets[0].Extension,
							xhost,
							"CVE-2021-37624",
							fmt.Sprint(res.Details.CVE202137624.IsVulnerable),
							msg.Message,
							time.Time(msg.Timestamp).Format(time.RFC3339),
						})
					}
				}
				xdetx := res.Details.CVE202141157.ExploitDetails
				if len(res.Details.CVE202141157.ExploitDetails) > 0 {
					for _, msg := range res.Details.CVE202141157.ExploitDetails[0].NotifsRecvd {
						xwriter.writeRow([]string{
							xdetx[0].Extension,
							xhost,
							"CVE-2021-41157",
							fmt.Sprint(res.Details.CVE202137624.IsVulnerable),
							// santizing the CSV so it doesn't span across lines
							sanitiseRex.ReplaceAllLiteralString(msg.Message, "\\n"),
							time.Time(msg.Timestamp).Format(time.RFC3339),
						})
					}
				}
			}
		}
		xwriter.FlushBuffer()
	}
	return nil
}

func sortUnique(sSlice *[]string) *[]string {
	var keys = make(map[string]bool)
	var list []string
	for _, entry := range *sSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return &list
}
