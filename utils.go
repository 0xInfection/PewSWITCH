package main

import (
	"encoding/csv"
	"log"
	"math/rand"
	"net"
	"os"
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
