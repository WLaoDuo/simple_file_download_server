package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	appVersion "webdemo/appinfo"

	"github.com/fatih/color"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// red := "\033[31m"
// green := "\033[32m"
// yellow := "\033[33m"
// blue := "\033[34m"
// reset := "\033[0m"

func exit_path(filename string) int {
	_, err := os.Stat(filename)
	if err == nil {
		// fmt.Printf("文件 %s 存在\n", filename)
		return 0
	} else if os.IsNotExist(err) {
		// fmt.Printf("文件 %s 不存在\n", filename)
		return 1
	} else {
		// fmt.Printf("检查文件时发生错误: %v\n", err)
		return 2
	}
}

func basicAuth(handler http.Handler, username, password, path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr  // 访问的 IP 地址
		ua := r.UserAgent() //r.Header.Get("User-Agent") 获取ua头

		if username != "" || password != "" { //默认空密码用户名，无需认证
			user, pass, ok := r.BasicAuth()

			if !ok || user != username || pass != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintln(w, "Unauthorized") //网页端认证失败返回文字

				log.Printf("%s 使用%s 头,%s方式尝试请求文件%s", color.RedString("非法访问者 "+ip), ua, r.Method, color.RedString(path+r.URL.Path))
				return
			} else {
				log.Printf("%s 使用%s 头,%s方式请求文件%s", color.GreenString(ip), ua, r.Method, path+r.URL.Path)
			}
		} else {
			log.Printf("%s 使用%s 头,%s方式请求文件%s", color.YellowString(ip), ua, r.Method, path+r.URL.Path)
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
				CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
				},
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

// 获取本机有效的局域网IP地址（IPv4和IPv6）
func getIP() ([]net.IP, []net.IP, error) {
	var ipv4Addrs []net.IP
	var ipv6Addrs []net.IP

	// 获取所有网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range interfaces {
		// 过滤无效接口（未启用或回环接口）
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// 获取接口地址
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			// 过滤回环地址
			if ip.IsLoopback() {
				continue
			}

			// 分类处理
			if ipv4 := ip.To4(); ipv4 != nil {
				ipv4Addrs = append(ipv4Addrs, ipv4)
			} else if ipv6 := ip.To16(); ipv6 != nil {
				// 过滤IPv6链路本地地址（可选）
				// if ipv6.IsLinkLocalUnicast() {
				// 	continue
				// }
				ipv6Addrs = append(ipv6Addrs, ipv6)
			}
		}
	}

	return ipv4Addrs, ipv6Addrs, nil
}

func logIPAddresses(port int, status string) {
	ipv4, ipv6, err := getIP()
	if err != nil {
		log.Printf("获取IP地址失败: %v", err)
		// return
	}
	if status == "https" {
		for _, ip := range ipv4 {
			log.Printf("IPv4地址: https://%s:%d", ip, port)
		}
		for _, ip := range ipv6 {
			log.Printf("IPv6地址: https://[%s]:%d", ip, port)
		}
	}
	if status == "http" {
		for _, ip := range ipv4 {
			log.Printf("IPv4地址: http://%s:%d", ip, port)
		}
		for _, ip := range ipv6 {
			log.Printf("IPv6地址: http://[%s]:%d", ip, port)
		}
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
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "-version输出版本信息")
	// var bandwidthRate = flag.Int64("speed", 10, "带宽限制（MB/秒）")
	flag.Parse()

	if showVersion {
		// fmt.Printf("%+v\n", appVersion.AppInfo)
		fmt.Println(appVersion.BuildVersion())
		os.Exit(0)
	}

	// result1 := exit_path(*crtPath) //crt证书是否存在
	// result2 := exit_path(*keyPath) //key密钥是否存在
	if exit_path(*path_show) != 0 {
		color.Green(*path_show)
		log.Printf("当前文件（文件夹）路径不存在，请重新输入\n")
		os.Exit(1)
	}

	fileServer := http.FileServer(http.Dir(*path_show))
	authHandler := basicAuth(fileServer, *username, password, *path_show)

	// fmt.Println("This", color.RedString("warning"), "should be not neglected.")
	// fmt.Printf("%v %v\n", color.GreenString("Info:"), "an important message.")

	log.Println("\n用户名‘" + color.GreenString(*username) + "’ 密码‘" + color.GreenString(password) + "’")

	mux := http.NewServeMux()

	// speed := *bandwidthRate * 1024 * 1024 // 1MB/s
	// rateLimitedHandler := BandwidthLimitMiddleware(speed, authedHandler)
	// mux.Handle("/", rateLimitedHandler)

	mux.Handle("/", authHandler) //当前目录

	cert, err_tls := tls.LoadX509KeyPair(*crtPath, *keyPath)

	log.Println("文件路径" + color.GreenString(*path_show))

	if err_tls == nil {
		log.Printf("%s端口启用https", color.GreenString(strconv.Itoa(*port)))

		logIPAddresses(*port, "https")

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
		log.Printf("找不到证书和私钥，%v端口启用http", color.GreenString(strconv.Itoa(*port)))

		logIPAddresses(*port, "http")

		// http.Handle("/", authHandler) //当前目录
		err_http := http.ListenAndServe(":"+strconv.Itoa(*port), mux)
		//监听8080端口，外网可访问http://ip:port
		if err_http != nil {
			log.Println(err_http.Error())
		}
	}
}
