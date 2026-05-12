package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	appVersion "webdemo/appinfo"

	"github.com/fatih/color"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sync/errgroup"
)

// Config 服务器配置
type Config struct {
	CertFile string
	KeyFile  string
	Username string
	Password string
	Port     int
	Path     string
	Version  bool
}

func parseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.CertFile, "crt", "D:/study/ssh-key/webdemo/server.crt", "TLS 证书crt文件路径")
	flag.StringVar(&cfg.KeyFile, "key", "D:/study/ssh-key/webdemo/server.key", "TLS 私钥文件路径")
	flag.StringVar(&cfg.Username, "u", "", "BasicAuth 用户名")
	flag.StringVar(&cfg.Password, "password", "", "BasicAuth 密码 (长参数)")
	flag.StringVar(&cfg.Password, "p", "", "BasicAuth 密码 (短参数)")
	flag.IntVar(&cfg.Port, "port", 443, "监听端口")
	flag.StringVar(&cfg.Path, "path", ".", "共享的文件目录路径")
	flag.BoolVar(&cfg.Version, "version", false, "输出版本信息")
	flag.Parse()

	return cfg
}

func main() {
	cfg := parseFlags()

	if cfg.Version {
		fmt.Println(appVersion.BuildVersion())
		os.Exit(0)
	}

	// 验证目录存在
	absPath, err := filepath.Abs(cfg.Path)
	if err != nil {
		log.Fatalf("无法解析路径 %s: %v", cfg.Path, err)
	}
	if info, err := os.Stat(absPath); err != nil || !info.IsDir() {
		log.Fatalf("路径不存在或不是目录: %s", absPath)
	}

	// 创建服务器实例
	srv, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("创建服务器失败: %v", err)
	}

	// 启动并等待关闭信号
	if err := srv.quicgo_ListenAndServeTLS(); err != nil {
		log.Fatalf("服务器运行异常: %v", err)
	}
}

// Server 文件服务器实体
type Server struct {
	config   Config
	handler  http.Handler
	cert     tls.Certificate
	http2Srv *http.Server
	http3Srv *http3.Server
}

// NewServer 创建服务器，提前检查证书等资源
func NewServer(cfg *Config) (*Server, error) {
	absPath, _ := filepath.Abs(cfg.Path)
	fileServer := http.FileServer(http.Dir(absPath))

	// 认证中间件
	var handler http.Handler = fileServer
	if cfg.Username != "" || cfg.Password != "" {
		handler = basicAuth(handler, cfg.Username, cfg.Password, absPath)
	} else {
		handler = loggingMiddleware(handler, absPath)
	}

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	// 尝试加载证书，失败则降级为 HTTP
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		// 证书缺失，降级为 HTTP
		log.Printf("警告: 加载证书失败 (%v)，将启用 HTTP 模式", err)
		return &Server{
			config:  *cfg,
			handler: mux,
		}, nil
	}

	return &Server{
		config:  *cfg,
		handler: mux,
		cert:    cert,
	}, nil
}

// 启动服务器并处理优雅关闭
func (s *Server) quicgo_ListenAndServeTLS() error {
	// 没有证书 -> 仅 HTTP
	if s.cert.Certificate == nil {
		addr := fmt.Sprintf(":%d", s.config.Port)
		log.Printf("HTTP 文件服务器已启动 -> http://0.0.0.0%s", addr)
		logIPAddresses(s.config.Port, "http")
		return http.ListenAndServe(addr, s.handler)
	}

	// 配置 TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3", "h2", "http/1.1"},
	}
	http3TLSConfig := http3.ConfigureTLSConfig(tlsConfig)

	// 创建 HTTP/2 服务器 (用于 TCP，并设置 Alt-Svc 头以通告 QUIC)
	http2Srv := &http.Server{
		Addr: fmt.Sprintf(":%d", s.config.Port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 设置 Alt-Svc 头，支持 QUIC 升级
			s.http3Srv.SetQUICHeaders(w.Header())
			s.handler.ServeHTTP(w, r)
		}),
		TLSConfig: tlsConfig,
	}

	// 创建 QUIC 服务器
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", s.config.Port))
	if err != nil {
		return fmt.Errorf("解析 UDP 地址失败: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("监听 UDP 端口失败: %w", err)
	}
	defer udpConn.Close()

	s.http3Srv = &http3.Server{
		Handler:   s.handler,
		TLSConfig: http3TLSConfig,
		QUICConfig: &quic.Config{
			Allow0RTT:       true,
			EnableDatagrams: true,
		},
	}

	// 使用 errgroup 管理两个服务器的生命周期
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	// 启动 HTTP/2 TCP 服务器
	g.Go(func() error {
		log.Printf("HTTPS (HTTP/2) 服务已启动 -> https://0.0.0.0:%d", s.config.Port)
		logIPAddresses(s.config.Port, "https")
		err := http2Srv.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})

	// 启动 QUIC (HTTP/3) 服务器
	g.Go(func() error {
		log.Printf("QUIC (HTTP/3) 服务已启动 -> https://0.0.0.0:%d (UDP)", s.config.Port)
		err := s.http3Srv.Serve(udpConn)
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})

	// 监听退出信号，优雅关闭
	g.Go(func() error {
		<-ctx.Done()
		log.Println("正在关闭服务器...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// 关闭 HTTP 服务器
		if err := http2Srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("HTTP 服务器关闭失败: %w", err)
		}
		// 关闭 QUIC 服务器
		if err := s.http3Srv.Close(); err != nil {
			return fmt.Errorf("QUIC 服务器关闭失败: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return err
	}
	log.Println("服务器已安全退出")
	return nil
}

// basicAuth 中间件，提供基础认证和日志
func basicAuth(handler http.Handler, username, password, path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		ua := r.UserAgent()

		user, pass, ok := r.BasicAuth()
		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Unauthorized")
			log.Printf("%s 尝试访问 %s (UA: %s)", color.RedString("非法访问者 "+ip), color.RedString(path+"/"+r.URL.Path), ua)
			return
		}
		log.Printf("%s 请求文件 %s (UA: %s)", color.GreenString(ip), path+"/"+r.URL.Path, ua)
		handler.ServeHTTP(w, r)
	})
}

// loggingMiddleware 无认证时的简单日志
func loggingMiddleware(handler http.Handler, path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s 请求文件 %s (UA: %s)", color.YellowString(r.RemoteAddr), path+"/"+r.URL.Path, r.UserAgent())
		handler.ServeHTTP(w, r)
	})
}

// getIP 获取本机非回环的 IPv4 和 IPv6 地址
func getIP() (ipv4, ipv6 []net.IP, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := net.IP{}
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				ipv4 = append(ipv4, ip4)
			} else if ip6 := ip.To16(); ip6 != nil {
				ipv6 = append(ipv6, ip6)
			}
		}
	}
	return
}

// logIPAddresses 打印本机 IP 访问地址
func logIPAddresses(port int, scheme string) {
	ipv4, ipv6, err := getIP()
	if err != nil {
		log.Printf("获取本机 IP 失败: %v", err)
		return
	}
	for _, ip := range ipv4 {
		log.Printf("  %s://%s:%d", scheme, ip, port)
	}
	for _, ip := range ipv6 {
		log.Printf("  %s://[%s]:%d", scheme, ip, port)
	}
}
