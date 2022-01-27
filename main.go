package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"youzai/active"
	"youzai/report"

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

// 生成目标信息
func target_Info() {
	url := "http://192.168.65.129:8080"
	userAgent := "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.163 Safari/535.1"

	active.Target.Target_Url = url
	active.Target.User_Agent = userAgent
	active.Target.Timeout = 5
	active.Target.Proxy = true
	active.Target.Proxy_Url = "http://127.0.0.1:8888"
	active.Target.Speed = 1
	active.Target.Ceye_Url = "rp7vj6.ceye.io"
	active.Target.Ceye_Token = "9f5824c076d1a459e31266e8b016b591"
}

// 执行扫描
func active_Check() {
	active.PocInit()
	active.Scan()
}

func config_Screen() {
	os := runtime.GOOS
	green := color.Green.Render
	blue := color.Blue.Render
	if strings.Contains(os, "windows") {
		cmd := exec.Command("powershell", "mode con cols=135 lines=40")
		err := cmd.Run()
		if err != nil {
			time.Sleep(time.Second)
			fmt.Println(green("[INFO]"), "Screen Config Failed")
		}
		time.Sleep(time.Second)
		fmt.Println(green("[INFO]"), blue("Screen Config Successful"))
		time.Sleep(time.Second)
	}
	fmt.Println(green("[INFO]"), blue("Prepare For Running The Scan"))
	time.Sleep(time.Second)
}

func check_Network() {

}

// 扫描器入口
func main() {
	config_Screen()
	banner_Info()
	target_Info()
	active_Check()
	report.OutTable()
}
