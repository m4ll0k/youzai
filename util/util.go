package util

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strconv"
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

// 获取ceye随机数和域名
func Get_Ceye() (randstr, ceye_url string) {
	rand.Seed(time.Now().UnixNano())
	t := rand.Intn(100000)
	randstr = fmt.Sprintf("%d", t)
	ceye_url = randstr + "." + Ceye.Ceye_Url
	return randstr, ceye_url
}

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

// 使用tcp发送数据
func Tcp_Send(target_url string, data string, timeout int) (response_data string, response_code int) {
	reg := regexp.MustCompile(`.*(\d{3}).*`)
	urli := url.URL{}
	url, _ := urli.Parse(target_url)
	switch url.Scheme {
	case "http":
		var host = url.Host
		if !strings.Contains(host, ":") {
			host = url.Host + ":80"
		}
		net, err := net.DialTimeout("tcp", host, time.Second*time.Duration(timeout))
		if err != nil {
			color.Println("<fg=FFA500>[WARNING]</>", err)
		}
		defer net.Close()
		_, _ = net.Write([]byte(data))
		buf := make([]byte, 20480)
		n, err := net.Read(buf)
		if err != nil {
			color.Println("<fg=FFA500>[WARNING]</>", err)
		}
		result := reg.FindStringSubmatch(string(buf[:n]))
		if len(result) != 0 {
			code, _ := strconv.Atoi(result[len(result)-1])
			return string(buf[:n]), code
		}
		return "", 0

	case "https":
		conf := &tls.Config{
			InsecureSkipVerify: false,
		}
		var host = url.Host
		if !strings.Contains(host, ":") {
			host = url.Host + ":443"
		}
		net, err := tls.Dial("tcp", host, conf)
		if err != nil {
			color.Println("<fg=FFA500>[WARNING]</>", err)
		}
		defer net.Close()
		_, _ = net.Write([]byte(data))
		buf := make([]byte, 20480)
		n, err := net.Read(buf)
		if err != nil {
			color.Println("<fg=FFA500>[WARNING]</>", err)
		}
		result := reg.FindStringSubmatch(string(buf[:n]))
		if len(result) != 0 {
			code, _ := strconv.Atoi(result[len(result)-1])
			return string(buf[:n]), code
		}
	}
	return "", 0
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
