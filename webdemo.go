package main

import (
	"net/http"
)

func main() {
	http.Handle("/", http.FileServer(http.Dir("."))) //当前目录
	http.ListenAndServe(":8080", nil)                //监听8080端口，外网可访问http://ip:8080
	//http.ListenAndServe(":8081","server.crt","server.privatekey", nil) //https监听8081端口，外网可访问https://ip:8081
}
