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


var path_show = flag.String("path", ".", "文件路径") //文件加载路径，绝对路径可以，相对路径也可以，但需要注意加引号


func main() {

	

	var crtPath =flag.String("crt","D:/study/ssh-key/webdemo/server.crt","crt路径")
	var keyPath =flag.String("key","D:/study/ssh-key/webdemo/server.key","key路径")
	var username = flag.String("u","admin","用户名") //默认用户名admin
	var password string
	flag.StringVar(&password,"password","admin","密码") //长参数-password
	flag.StringVar(&password,"p","admin","密码") //短参数-p
	port := flag.Int("port",8080,"端口")
	
	flag.Parse()
	


	
	result1 := exit_path(*crtPath)
	result2 := exit_path(*keyPath)
	fileServer := http.FileServer(http.Dir(*path_show))
	authHandler := basicAuth(fileServer, *username, password)


	log.Printf("\n用户名"+*username+" 密码"+password)

	if result1+result2 == 0 {
		
		log.Println("文件路径 "+*path_show)
		log.Printf("%d端口启用https",*port)

		
		http.Handle("/", authHandler) //当前目录
		err := http.ListenAndServeTLS(fmt.Sprintf(":%d", *port),*crtPath,*keyPath, nil) //https监听8080端口，外网可访问https://ip:8080
		if err != nil {
			log.Printf(err.Error())
		}
		// http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)可以使用crypto/tls中的generate_cert.go来生成cert.pem和key.pem
		//go run $GOROOT/src/crypto/tls/generate_cert.go --host 域名/IP
		
	} else {
		log.Println("文件路径未指定或文件路径不存在，默认为当前目录")
		log.Printf("找不到证书和私钥，%d端口启用http",*port)


		http.Handle("/", authHandler) //当前目录
		err := http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)    
		//监听8080端口，外网可访问http://ip:port
		if err != nil {
			log.Printf(err.Error())
		}
	}
}
