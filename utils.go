package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type csvWriter struct {
	locker *sync.Mutex
	writer *csv.Writer
}

const letterRunes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func initWriter(fname string) (*csvWriter, error) {
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

func getExtensionsFromFile(fname string) *[]string {
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
		xbuf := make([]byte, 64)
		_, err = conn.Read(xbuf)
		if err != nil {
			continue
		}
		if strings.HasPrefix(string(xbuf), "SIP/2.0") {
			dmap[targ] = true
			log.Printf("Host %s is up.", targ)
		}
	}
	return dmap
}
