package main

import (
	"os/exec"
	"time"
	"youzai/active"
	"youzai/report"

	"github.com/gookit/color"
)

func banner() {
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
}

// 生成目标信息
func target_Info() {
	url := "http://localhost/wordpress"
	userAgent := "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.163 Safari/535.1"

	active.Target.Target_Url = url
	active.Target.User_Agent = userAgent
	active.Target.Timeout = 5
	active.Target.Proxy = true
	active.Target.Proxy_Url = "http://127.0.0.1:8888"
	active.Target.Speed = 1
}

// 执行扫描
func active_Check() {
	active.PocInit()
	active.Scan()
}

// 扫描器入口
func main() {
	cmd2 := exec.Command("powershell", "mode con cols=135 lines=40")
	cmd2.Run()
	time.Sleep(time.Second)

	banner()
	target_Info()
	active_Check()
	report.OutTable()
}
