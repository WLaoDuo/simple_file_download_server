package main

import (
		"net/http"
		"fmt"
		"os"
		"flag"
		"log"
)

func exit_path(filename string) int {
	_, err := os.Stat(filename)

	// 判断文件是否存在
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

func basicAuth(handler http.Handler, username, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		// 打印请求信息及访问的 IP 地址
		log.Printf("%s使用%s方式请求文件%s", ip, r.Method, *path_show+r.URL.Path)

		user, pass, ok := r.BasicAuth()
		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Unauthorized")
			return
		}
		handler.ServeHTTP(w, r)
	})
}


var path_show = flag.String("path", ".", "文件路径")
func main() {

	
	var crtPath =flag.String("crt","D:/study/ssh-key/webdemo/server.crt","crt路径")
	var keyPath =flag.String("key","D:/study/ssh-key/webdemo/server.key","key路径")
	var username = flag.String("u","admin","用户名")
	var password = flag.String("p","admin","密码")
	flag.Parse()


	
	result1 := exit_path(*crtPath)
	result2 := exit_path(*keyPath)
	fileServer := http.FileServer(http.Dir(*path_show))
	authHandler := basicAuth(fileServer, *username, *password)

	if result1+result2 == 0 {
		
		log.Println("文件路径 "+*path_show)
		log.Printf("8081端口启用https")
		
		http.Handle("/", authHandler) //当前目录
		http.ListenAndServeTLS(":8081",*crtPath,*keyPath, nil) //https监听8081端口，外网可访问https://ip:8081

		// http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)可以使用crypto/tls中的generate_cert.go来生成cert.pem和key.pem
		//go run $GOROOT/src/crypto/tls/generate_cert.go --host 域名/IP
		
	} else {
		log.Println("文件路径  为当前目录")
		log.Printf("找不到证书和私钥，启用http")

		http.Handle("/", authHandler) //当前目录
		http.ListenAndServe(":8080", nil)    
		//监听8080端口，外网可访问http://ip:8080
	}
}
