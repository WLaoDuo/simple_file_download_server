package appVersion

import (
	goversion "github.com/caarlos0/go-version"
)

var (
	BuiltBy   string
	Tag       string
	Commit    string
	Date      string
	TreeState string
)

// type infomation struct {
// 	AppName    string
// 	AppVersion string
// 	BuildTime  string
// 	GitHash    string
// 	// Pid        int
// 	Platform  string
// 	GoVersion string
// }

// var (
// 	AppInfo = infomation{
// 		AppName:    "简易文件服务器",
// 		AppVersion: Tag,
// 		BuildTime:  Date,
// 		GitHash:    Commit,
// 		// Pid:        os.Getpid(),
// 		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
// 		GoVersion: runtime.Version(),
// 	}
// )

func BuildVersion() goversion.Info {
	return goversion.GetVersionInfo(
		goversion.WithAppDetails("简易文件http服务器", "局域网发送本地文件", "-h查询帮助"),
		// goversion.WithASCIIName(asciiArt),
		func(i *goversion.Info) {
			if Commit != "" {
				i.GitCommit = Commit
			}
			if TreeState != "" {
				i.GitTreeState = TreeState
			}
			if Date != "" {
				i.BuildDate = Date
			}
			if Tag != "" {
				i.GitVersion = Tag
			}
			if BuiltBy != "" {
				i.BuiltBy = BuiltBy
			}
		},
	)
}
