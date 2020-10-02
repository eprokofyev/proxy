package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"

	"log"
	"net"
	"net/http"
	"proxy/internal/pkg/analyzer"
	"proxy/internal/pkg/database"
	//"os"
	"proxy/internal/pkg/generation"
)

type Handler struct {
	ca *tls.Certificate
	tlsConfig *tls.Config
	db *database.DB
}

func NewHandler(ca *tls.Certificate, tlsConfig *tls.Config, db *database.DB) *Handler {
	return &Handler {
		ca,
		tlsConfig,
		db,
	}
}

func (h *Handler) HttpHandler(w http.ResponseWriter, r *http.Request) {
	r.Header.Del("Proxy-Connection")
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	go func() {
		v := analyzer.XSSCheck(r)
		buf := bytes.NewBuffer([]byte {})
		r.Write(buf)
		_, err := h.SaveRequest(buf, r.Host, "http", v)
		if err != nil {
			log.Println(err)
			return
		}

	} ()
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}


func (h *Handler) HttpsHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.Method, r.URL.Path)
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = ""
	}

	provisionalCert, err := generation.GenCert(h.ca, host)
	if err != nil {
		log.Println("cert", err)
		http.Error(w, "no upstream", 503)
		return
	}
	sConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	var sconn *tls.Conn
	sConfig.Certificates = []tls.Certificate{*provisionalCert}
	sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cConfig := &tls.Config {
			MinVersion: tls.VersionTLS12,
		}

		cConfig.ServerName = hello.ServerName
		sconn, err = tls.Dial("tcp", r.Host, cConfig)
		if err != nil {
			log.Println("dial", r.Host, err)
			return nil, err
		}

		return generation.GenCert(h.ca, hello.ServerName)
	}

	fmt.Println("hello")
	cconn, err := handshake(w, sConfig)
	if err != nil {
		log.Println("handshake", r.Host, err)
		return
	}
	//defer cconn.Close()
	if sconn == nil {
		log.Println("could not determine cert name for " + r.Host)
		return
	}
	//defer sconn.Close()
/*
	clientTlsReader := bufio.NewReader(cconn)
	clientTlsWriter := bufio.NewWriter(cconn)
	for {
		req, err := http.ReadRequest(clientTlsReader)
		if err != nil {
			return
		}
		b := bytes.NewBuffer([] byte{})
		req.Write(b)

		req, err = http.ReadRequest(bufio.NewReader(bytes.NewBuffer(b.Bytes())))
		if err != nil {
			log.Println(err)
		}

		go h.SaveRequest(b, r.Host, "https")

		req.URL.Scheme = "https"
		req.URL.Host = r.Host

		response, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			log.Println(err)
			continue
		}

		response.Write(clientTlsWriter)
		clientTlsWriter.Flush()
	}
	*/

	go func() {
		defer sconn.Close()
		defer cconn.Close()
		wr := bytes.NewBuffer([]byte{})
		hello := io.MultiWriter(sconn, wr)
		_, err := io.Copy(hello, cconn)
		if err == nil {
			go func() {
				buf := bufio.NewReader(wr)
				for {
					req, err := http.ReadRequest(buf)
					if err != nil {
						log.Println("gggg", err)
						return
					}
					b := bytes.NewBuffer([] byte {})
					err = req.Write(b)
					if err != nil {
						log.Println(err)
					}
					v := analyzer.XSSCheck(req)
					_, err = h.SaveRequest(b, r.Host, "https", v)
					if err != nil {
						log.Println("dddd",err)
					}
				}
			}()
		}
	} ()

	go func() {
		defer sconn.Close()
		defer cconn.Close()
		io.Copy(cconn, sconn)
	}()


}

func (h *Handler) SaveRequest(buf *bytes.Buffer, host string, scheme string, vulnerabilities []string) (interface{}, error) {
	res, err := h.db.Insert(database.Record{Req: string(buf.Bytes()), Scheme: scheme, Host: host, Vulnerabilities: vulnerabilities})
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return res, nil
}


func handshake(w http.ResponseWriter, config *tls.Config) (net.Conn, error) {
	raw, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", 503)
		fmt.Println("here3")
		return nil, err
	}

	if _, err = raw.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		raw.Close()
		fmt.Println("here2")
		return nil, err
	}

	conn := tls.Server(raw, config)
	err = conn.Handshake()
	if err != nil {
		fmt.Println("here")
		conn.Close()
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
