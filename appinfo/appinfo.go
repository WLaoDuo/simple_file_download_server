package webdemo

import (
	"fmt"
	"runtime"
)

var (
	BuiltBy string
	Tag     string
	Commit  string
	Date    string
)

type Info struct {
	AppName    string
	AppVersion string
	BuildTime  string
	GitHash    string
	// Pid        int
	Platform  string
	GoVersion string
}

var (
	AppInfo = Info{
		AppName:    "简易文件服务器",
		AppVersion: Tag,
		BuildTime:  Date,
		GitHash:    Commit,
		// Pid:        os.Getpid(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		GoVersion: runtime.Version(),
	}
)
