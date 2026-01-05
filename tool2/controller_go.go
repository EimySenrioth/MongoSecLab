package main

/*
#cgo LDFLAGS: -L. -lanalyzer_c
#include "analyzer_c.h"
*/
import "C"
import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

var listenPort = 27018
var mongoHost = "localhost"
var mongoPort = 27017

func isMalicious(data []byte) bool {
	if C.is_malicious((*C.uchar)(&data[0]), C.int(len(data))) == 1 {
		return true
	}
	return false
}

func handleConnection(client net.Conn, mongoAddr string, reportFile *os.File) {
	server, err := net.Dial("tcp", mongoAddr)
	if err != nil {
		log.Println("No se pudo conectar a MongoDB:", err)
		client.Close()
		return
	}
	defer server.Close()
	defer client.Close()
	// Cliente -> Servidor
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				if isMalicious(buf[:n]) {
					now := time.Now().Format("2006-01-02 15:04:05")
					srcAddr := client.RemoteAddr().String()
					motivo := "Vector de ataque detectado"
					reportFile.WriteString(fmt.Sprintf("[%s] Bloqueado: IP=%s len=%d motivo=%s\n", now, srcAddr, n, motivo))
					client.Write([]byte("Proxy: Peticion bloqueada por seguridad. [Go+C]"))
					return
				}
				server.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	io.Copy(client, server)
}

func main() {
	reportFile, err := os.OpenFile("reporte_intentos.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer reportFile.Close()
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[*] Proxy Go+C escuchando en el puerto %d", listenPort)
	for {
		client, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConnection(client, fmt.Sprintf("%s:%d", mongoHost, mongoPort), reportFile)
	}
}
