package util

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/gookit/color"
)

// 存储ceye信息的结构体
type Ceye_Info struct {
	Ceye_Url   string
	Ceye_Token string
	Timeout    int
	Proxy      bool
	Proxy_Url  string
}

var Ceye = Ceye_Info{}

// 用于检测ssrf的函数
func Ceye_Check(randstr string) bool {
	red := color.Red.Render
	lightred := color.LightRed.Render
	cli := Http_Client(Ceye.Timeout, Ceye.Proxy, Ceye.Proxy_Url)
	check_url := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", Ceye.Ceye_Token, randstr)
	request, err := http.NewRequest("GET", check_url, nil)
	if err != nil {
		color.Println(red("[ERROR]"), lightred("Ceye Interface Information Not Available"), strings.Repeat(" ", 35))
		return false
	} else {
		response, err := cli.Do(request)
		if err != nil {
			color.Println(red("[ERROR]"), lightred("Ceye Interface Information Not Available"), strings.Repeat(" ", 35))
			return false
		}
		body, _ := ioutil.ReadAll(response.Body)
		return strings.Contains(string(body), randstr)
	}
}

// 生成http客户端
func Http_Client(timeout int, proxy bool, proxy_url string) *http.Client {
	// 设置请求属性
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // 取消证书认证
		ResponseHeaderTimeout: time.Second * time.Duration(timeout),  // 设置超时时间
	}
	// 检查是否使用代理
	if proxy && proxy_url != "" {
		urli := url.URL{}
		urlProxy, _ := urli.Parse(proxy_url)
		transport.Proxy = http.ProxyURL(urlProxy) // 设置代理
	}

	// 生成http客户端
	cli := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { // 不进入重定向
			return http.ErrUseLastResponse
		},
	}

	return cli
}

// 检测网络连通性
func Net_Check(url string) bool {
	green := color.FgGreen.Render
	red := color.FgRed.Render
	yellow := color.FgYellow.Render
	var connect, start time.Time

	request, _ := http.NewRequest("GET", url, nil)
	trace := &httptrace.ClientTrace{
		ConnectStart: func(network, addr string) { connect = time.Now() },
		ConnectDone: func(network, addr string, err error) {
			link_time := time.Since(connect)
			if link_time >= time.Duration(time.Second*10) {
				color.Println(green("[INFO]"), "Connect Time:", yellow(link_time))
				color.Println("<fg=FFA500>[WARNING]</>", "The link to the url doesn't seem well")
				color.Println("<fg=FFA500>[WARNING]</>", "Please check your network")
			} else {
				color.Println(green("[INFO]"), "Connect Time:", yellow(link_time))
			}
		},
		GotFirstResponseByte: func() {
			color.Println(green("[INFO]"), "Response Time :", yellow(time.Since(start)))
		},
	}
	req := request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	start = time.Now()
	if _, err := http.DefaultTransport.RoundTrip(req); err != nil {
		color.Println(red("[ERROR]"), err, strings.Repeat(" ", 50))
		return false
	} else {
		return true
	}
}
