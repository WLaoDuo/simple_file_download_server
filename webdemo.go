package main

import (
		"net/http"
		"fmt"
		"os"
		"flag"
)

func exit_path(filename string) int {
// filename := "example.txt" // 要检查的文件名

// 使用 os.Stat 函数获取文件信息
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

func main() {
	// args := os.Args[1:] // 获取除程序名称外的参数
	// // fmt.Printf("os:"+os.Args[0]+"\n")
	// // 检查是否有参数传入，如果没有则设置默认值
	// var path_show string
	// var crtPath string
	// var keyPath string

	// if len(args) == 0 {
	// 	path_show = "."
	// } else if len(args) ==1 {
	// 	// fmt.Println("参数长度",len(args))
	// 	path_show = args[0]
	// 	crtPath ="D:/study/ssh-key/webdemo/server.crt"
	// 	keyPath ="D:/study/ssh-key/webdemo/server.key"
	// } else if len(args) ==3 {
	// 	path_show = args[0]
	// 	crtPath=args[1]
	// 	keyPath=args[2]
	// }




	var path_show = flag.String("p", ".", "文件路径")
	var crtPath =flag.String("crt","D:/study/ssh-key/webdemo/server.crt","crt路径")
	var keyPath =flag.String("key","D:/study/ssh-key/webdemo/server.key","key路径")
	flag.Parse()


	
	result1 := exit_path(*crtPath)
	result2 := exit_path(*keyPath)


	if result1+result2 == 0 {
		
		fmt.Println("文件路径 "+*path_show)
		fmt.Printf("8081端口启用https")
		
		http.Handle("/", http.FileServer(http.Dir(*path_show))) //当前目录
		http.ListenAndServeTLS(":8081",*crtPath,*keyPath, nil) //https监听8081端口，外网可访问https://ip:8081

		// http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)可以使用crypto/tls中的generate_cert.go来生成cert.pem和key.pem
		//go run $GOROOT/src/crypto/tls/generate_cert.go --host 域名/IP
		
	} else {
		fmt.Println("文件路径  为当前目录")
		fmt.Printf("找不到证书和私钥，启用http")

		http.Handle("/", http.FileServer(http.Dir(*path_show))) //当前目录
		http.ListenAndServe(":8080", nil)    
		//监听8080端口，外网可访问http://ip:8080
	}
}
