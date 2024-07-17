package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/quic-go/quic-go/http3"
)

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

func basicAuth(handler http.Handler, username, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr  // 访问的 IP 地址
		ua := r.UserAgent() //r.Header.Get("User-Agent") 获取ua头

		log.Printf("%s 使用%s 头,%s方式请求文件%s", ip, ua, r.Method, *path_show+r.URL.Path)
		if username != "" || password != "" { //默认空密码用户名，无需认证
			user, pass, ok := r.BasicAuth()
			if !ok || user != username || pass != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintln(w, "Unauthorized")
				log.Printf("非法访问者 %s 使用%s 头,%s方式尝试请求文件%s", ip, ua, r.Method, *path_show+r.URL.Path)
				return
			}
		}
		handler.ServeHTTP(w, r)

	})
}

var path_show = flag.String("path", ".", "文件路径") //文件加载路径，绝对路径可以，相对路径也可以，但需要注意加引号

func main() {
	// red := "\033[31m"
	// green := "\033[32m"
	// yellow := "\033[33m"
	// blue := "\033[34m"
	// reset := "\033[0m"

	var crtPath = flag.String("crt", "D:/study/ssh-key/webdemo/server.crt", "crt路径")
	var keyPath = flag.String("key", "D:/study/ssh-key/webdemo/server.key", "key路径")
	var username = flag.String("u", "", "用户名") //默认用户名admin
	var password string
	flag.StringVar(&password, "password", "", "密码") //长参数-password
	flag.StringVar(&password, "p", "", "密码")        //短参数-p
	port := flag.Int("port", 443, "端口")

	flag.Parse()

	// result1 := exit_path(*crtPath) //crt证书是否存在
	// result2 := exit_path(*keyPath) //key密钥是否存在

	fileServer := http.FileServer(http.Dir(*path_show))
	authHandler := basicAuth(fileServer, *username, password)

	log.Printf("\n用户名‘" + *username + "’ 密码‘" + password + "’")

	mux := http.NewServeMux()
	mux.Handle("/", authHandler) //当前目录

	cert, err_tls := tls.LoadX509KeyPair(*crtPath, *keyPath)

	if err_tls == nil {
		log.Println("文件路径 " + *path_show)
		log.Printf("%d端口启用https", *port)
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

		// srv3 := http3.Server{ //http3 quic协议纯粹只开放udp端口，不开放tcp端口，火狐总是打不开网站，chrome可以
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
		// 		// Allow0RTT:       true,
		// 		// EnableDatagrams: true,
		// 	},
		// }
		// err_https := srv3.ListenAndServe()

		err_https := http3.ListenAndServeTLS(":"+strconv.Itoa(*port), *crtPath, *keyPath, mux) //http3支持tcp端口，兼容性最好

		if err_https != nil {
			log.Printf(err_https.Error())
		}

		//可以使用crypto/tls中的generate_cert.go来生成cert.pem和key.pem
		//go run $GOROOT/src/crypto/tls/generate_cert.go --host 域名/IP

		//也可用https://github.com/FiloSottile/mkcert项目签发证书
		//.\mkcert-v1.4.4-windows-amd64.exe -key-file ./127.0.0.1-key -cert-file ./127.0.0.1.crt  127.0.0.1
	}
	if err_tls != nil {
		if *port == 443 {
			*port = 80
		}
		log.Println(err_tls)
		log.Println("文件路径未指定或文件路径不存在，默认为当前目录")
		log.Printf("找不到证书和私钥，%d端口启用http", *port)

		// http.Handle("/", authHandler) //当前目录
		err_http := http.ListenAndServe(":"+strconv.Itoa(*port), mux)
		//监听8080端口，外网可访问http://ip:port
		if err_http != nil {
			log.Printf(err_http.Error())
		}
	}
}
