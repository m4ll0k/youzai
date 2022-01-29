package main

import (
	"flag"
	"strings"
	"time"
	"youzai/active"
	"youzai/report"
	"youzai/util"

	"github.com/gookit/color"
)

func banner_Info() {
	banner := []string{`
	  ▓██   ██▓ ▒█████   █    ██ ▒███████▒ ▄▄▄       ██▓
	   ▒██  ██▒▒██▒  ██▒ ██  ▓██▒▒ ▒ ▒ ▄▀░▒████▄    ▓██▒
	    ▒██ ██░▒██░  ██▒▓██  ▒██░░ ▒ ▄▀▒░ ▒██  ▀█▄  ▒██▒
	    ░ ▐██▓░▒██   ██░▓▓█  ░██░  ▄▀▒   ░░██▄▄▄▄██ ░██░
	    ░ ██▒▓░░ ████▓▒░▒▒█████▓ ▒███████▒ ▓█   ▓██▒░██░
	     ██▒▒▒ ░ ▒░▒░▒░ ░▒▓▒ ▒ ▒ ░▒▒ ▓░▒░▒ ▒▒   ▓▒█░░▓  
	   ▓██ ░▒░   ░ ▒ ▒░ ░░▒░ ░ ░ ░░▒ ▒ ░ ▒  ▒   ▒▒ ░ ▒ ░
	   ▒ ▒ ░░  ░ ░ ░ ▒   ░░░ ░ ░ ░ ░ ░ ░ ░  ░   ▒    ▒ ░
	   ░ ░         ░ ░     ░       ░ ░          ░  ░ ░  
	   ░ ░                       ░                      
	`,
		`
	  ██╗   ██╗ ██████╗ ██╗   ██╗███████╗ █████╗ ██╗
	  ╚██╗ ██╔╝██╔═══██╗██║   ██║╚══███╔╝██╔══██╗██║
	   ╚████╔╝ ██║   ██║██║   ██║  ███╔╝ ███████║██║
	    ╚██╔╝  ██║   ██║██║   ██║ ███╔╝  ██╔══██║██║
	     ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██║██║
	     ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝	                                                
	`}
	color.Blueln(banner[1])
	color.Magenta.Print("Version：v 1.0")
	color.Cyanln("\t\t\t\t\t\t", "By youzai\n")
	time.Sleep(time.Millisecond * 500)
}

// 帮助信息
func usage_info() {
	banner_Info()
	var h string = `Usage of YOUZAI [github:https://github.com/qian-shen/youzai]

--url:
	设置需要扫描的url (Config the Scan Url)
--agent:
	设置请求的代理 (Config the User-Agent)
--timeout:
	设置请求的超时时间 (Config the request timeout)
--proxy:
	设置代理url，如：--proxy=http://proxy.com (目前仅支持http代理) (Config the http proxy)
--speed:
	设置扫描速度，有四个等级，1~4 (Config the scan speed)
--ceye-rul:
	设置ceye的域名，如：--ceye-url=example.ceye.io (Cofig the ceye url)
--ceye-token:
	设置ceye的token信息 (Config the ceye token)
--vuln:
	设置扫描的漏洞类型，如：--vuln=xss (xss/info/ssrf)
	`
	color.Cyanln(h)
}

// 执行扫描
func active_Check(vuln_type string) {
	// 检查是否使用代理
	if active.Target.Proxy {
		if !util.Net_Check(active.Target.Proxy_Url) {
			return
		}
	} else {
		if !util.Net_Check(active.Target.Target_Url) {
			return
		}
	}
	active.PocInit()
	active.Scan(vuln_type)
}

// 通过命令设置扫描参数信息
func config_info() {
	var url = flag.String("url", "", "Config the Scan Url")
	var user_agent = flag.String("agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.163 Safari/535.1", "Config the User-Agent")
	var timeout = flag.Int("timeout", 20, "Config the request timeout")
	var Proxy_Url = flag.String("proxy", "", "Config the http proxy")
	var speed = flag.Int("speed", 1, "Config the scan speed")
	var ceye_url = flag.String("ceye-url", "rp7vj6.ceye.io", "Cofig the ceye url, example:--ceye-url=example.ceye.io")
	var ceye_token = flag.String("ceye-token", "9f5824c076d1a459e31266e8b016b591", "Config the ceye token, example:--ceye-token=abcdefg")
	var vuln = flag.String("vuln", "all", "Config the vuln Type")
	flag.Usage = usage_info
	flag.Parse() // 注册

	if *url == "" {
		usage_info()
		color.Println("<fg=FFA500>[WARNING]</>", "Please Config The Target Url")
		return
	}

	active.Target.Target_Url = *url
	active.Target.User_Agent = *user_agent
	active.Target.Timeout = *timeout
	if *Proxy_Url != "" {
		active.Target.Proxy = true
		active.Target.Proxy_Url = *Proxy_Url
	} else {
		active.Target.Proxy = false
		active.Target.Proxy_Url = ""
	}
	if *speed > 4 || *speed <= 0 {
		active.Target.Speed = 1
	} else {
		active.Target.Speed = *speed
	}
	active.Target.Ceye_Url = *ceye_url
	active.Target.Ceye_Token = *ceye_token

	banner_Info()
	active_Check(strings.ToLower(*vuln))
	report.OutTable()
}

// 扫描器入口
func main() {
	config_info()
}
