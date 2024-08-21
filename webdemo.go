package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// red := "\033[31m"
// green := "\033[32m"
// yellow := "\033[33m"
// blue := "\033[34m"
// reset := "\033[0m"

// func exit_path(filename string) int {
// 	_, err := os.Stat(filename)
// 	if err == nil {
// 		// fmt.Printf("文件 %s 存在\n", filename)
// 		return 0
// 	} else if os.IsNotExist(err) {
// 		// fmt.Printf("文件 %s 不存在\n", filename)
// 		return 1
// 	} else {
// 		// fmt.Printf("检查文件时发生错误: %v\n", err)
// 		return 2
// 	}
// }

func basicAuth(handler http.Handler, username, password, path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr  // 访问的 IP 地址
		ua := r.UserAgent() //r.Header.Get("User-Agent") 获取ua头

		if username != "" || password != "" { //默认空密码用户名，无需认证
			user, pass, ok := r.BasicAuth()

			if !ok || user != username || pass != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintln(w, "Unauthorized")
				log.Printf("\033[31m 非法访问者 %s \033[0m 使用%s 头,%s方式尝试请求文件\033[31m%s\033[0m", ip, ua, r.Method, path+r.URL.Path)
				return
			} else {
				log.Printf("\033[32m%s \033[0m使用%s 头,%s方式请求文件%s", ip, ua, r.Method, path+r.URL.Path)
			}
		} else {
			log.Printf("\033[33m%s \033[0m使用%s 头,%s方式请求文件%s", ip, ua, r.Method, path+r.URL.Path)
		}
		handler.ServeHTTP(w, r)

	})
}

func quicgo_ListenAndServeTLS(addr, certFile, keyFile string, handler http.Handler) error {
	//https://github.com/quic-go/quic-go/blob/master/http3/server.go#L709
	//可监听tcp端口，兼容性最好

	var err_certs error
	certs := make([]tls.Certificate, 1)
	certs[0], err_certs = tls.LoadX509KeyPair(certFile, keyFile)
	if err_certs != nil {
		return err_certs
	}

	// // 加载第二个证书密钥对
	// certs = append(certs, tls.Certificate{})
	// certs[2], err_certs = tls.LoadX509KeyPair(certFile, keyFile)
	// if err_certs != nil {
	// 	log.Fatal("Failed to load second certificate and key:", err)
	// }

	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.

	if addr == "" {
		addr = ":https"
	}

	// Open the listeners
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	if handler == nil {
		handler = http.DefaultServeMux
	}

	quicServer := http3.Server{
		Handler: handler,
		TLSConfig: http3.ConfigureTLSConfig(
			&tls.Config{
				Certificates:             certs,
				MinVersion:               tls.VersionTLS13,
				NextProtos:               []string{"h3", "h2", "http/1.1"},
				PreferServerCipherSuites: true,
			}),
		QUICConfig: &quic.Config{
			Allow0RTT:       true,
			EnableDatagrams: true,
		},
	}

	hErr := make(chan error, 1)
	qErr := make(chan error, 1)
	go func() {
		hErr <- http.ListenAndServeTLS(addr, certFile, keyFile, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			quicServer.SetQUICHeaders(w.Header())
			handler.ServeHTTP(w, r)
		}))
	}()
	go func() {
		qErr <- quicServer.Serve(udpConn)
	}()

	select {
	case err := <-hErr:
		quicServer.Close()
		return err
	case err := <-qErr:
		// Cannot close the HTTP server or wait for requests to complete properly :/
		return err
	}
}

func main() {
	var crtPath = flag.String("crt", "D:/study/ssh-key/webdemo/server.crt", "crt路径")
	var keyPath = flag.String("key", "D:/study/ssh-key/webdemo/server.key", "key路径")
	var username = flag.String("u", "", "用户名") //默认用户名admin
	var password string
	flag.StringVar(&password, "password", "", "密码") //长参数-password
	flag.StringVar(&password, "p", "", "密码")        //短参数-p
	port := flag.Int("port", 443, "端口")
	var path_show = flag.String("path", ".", "文件路径") //文件加载路径，绝对路径可以，相对路径也可以，但需要注意加引号
	flag.Parse()

	// result1 := exit_path(*crtPath) //crt证书是否存在
	// result2 := exit_path(*keyPath) //key密钥是否存在

	fileServer := http.FileServer(http.Dir(*path_show))
	authHandler := basicAuth(fileServer, *username, password, *path_show)

	log.Printf("\n用户名‘\033[32m" + *username + "\033[0m’ 密码‘\033[32m" + password + "\033[0m’")

	mux := http.NewServeMux()
	mux.Handle("/", authHandler) //当前目录

	cert, err_tls := tls.LoadX509KeyPair(*crtPath, *keyPath)

	if err_tls == nil {
		log.Println("文件路径 \033[33m" + *path_show + "\033[0m")
		log.Printf("\033[33m%d\033[0m端口启用https", *port)
		_ = cert

		// srv := http.Server{ //http2
		// 	Addr:    ":" + strconv.Itoa(*port), // fmt.Sprintf(":%d", *port),
		// 	Handler: mux,
		// 	TLSConfig: &tls.Config{
		// 		Certificates:             []tls.Certificate{cert},
		// 		MinVersion:               tls.VersionTLS13,
		// 		PreferServerCipherSuites: true},
		// }
		// err_https := srv.ListenAndServeTLS(*crtPath, *keyPath)

		// err_https := http.ListenAndServeTLS(fmt.Sprintf(":%d", *port), *crtPath, *keyPath, mux) //一句话的http2

		// srv3 := http3.Server{ //http3 quic协议纯粹只开放udp端口，不开放tcp端口
		// 	Handler: mux,
		// 	Addr:    ":" + strconv.Itoa(*port),
		// 	TLSConfig: http3.ConfigureTLSConfig(
		// 		&tls.Config{
		// 			Certificates:             []tls.Certificate{cert},
		// 			MinVersion:               tls.VersionTLS13,
		// 			NextProtos:               []string{"h3", "h2", "http/1.1"},
		// 			PreferServerCipherSuites: true,
		// 		}),
		// 	QUICConfig: &quic.Config{
		// 		Allow0RTT:       true,
		// 		EnableDatagrams: true,
		// 	},
		// }
		// err_https := srv3.ListenAndServeTLS(*crtPath, *keyPath)

		// err_https := http3.ListenAndServeTLS(":"+strconv.Itoa(*port), *crtPath, *keyPath, mux) //http3支持tcp端口，兼容性最好

		err_https := quicgo_ListenAndServeTLS(":"+strconv.Itoa(*port), *crtPath, *keyPath, mux) //http3.ListenAndServeTLS源代码增加了tls.config和quic.config

		if err_https != nil {
			log.Println(err_https.Error())
		}

		//可以使用crypto/tls中的generate_cert.go来生成cert.pem和key.pem
		//go run $GOROOT/src/crypto/tls/generate_cert.go --host 域名/IP

		//也可用https://github.com/FiloSottile/mkcert项目签发证书
		//.\mkcert-v1.4.4-windows-amd64.exe -key-file ./127.0.0.1-key -cert-file ./127.0.0.1.crt  127.0.0.1
	} else {
		if *port == 443 {
			*port = 80
		}
		log.Println(err_tls)
		log.Println("文件路径未指定或文件路径不存在，默认为当前目录")
		log.Printf("找不到证书和私钥，\033[33m%d\033[0m端口启用http", *port)

		// http.Handle("/", authHandler) //当前目录
		err_http := http.ListenAndServe(":"+strconv.Itoa(*port), mux)
		//监听8080端口，外网可访问http://ip:port
		if err_http != nil {
			log.Println(err_http.Error())
		}
	}
}
