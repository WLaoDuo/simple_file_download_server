package main

import (
		"net/http"
		"fmt"
		"os"
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
	result1 := exit_path("./certs/server.crt")
	result2 := exit_path("./certs/server.key")
	if result1+result2 == 0 {
		fmt.Printf("8081端口启用https")

		http.Handle("/", http.FileServer(http.Dir("."))) //当前目录
		http.ListenAndServeTLS(":8081","./certs/server.crt","./certs/server.key", nil) //https监听8081端口，外网可访问https://ip:8081
		
	} else {
		fmt.Printf("找不到证书和私钥，8080端口启用http")

		http.Handle("/", http.FileServer(http.Dir("."))) //当前目录
		http.ListenAndServe(":8080", nil)    
		//监听8080端口，外网可访问http://ip:8080
	}
}
