package active

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"youzai/active/poc"

	"github.com/gookit/color"
)

// 用于存储目标扫描的信息
type Target_Info struct {
	Target_Url string        // 目标的url
	User_Agent string        // 存放agent
	Timeout    int           // 请求的超时时间
	Proxy      bool          // 是否使用代理
	Proxy_Url  string        // 代理的url
	Speed      int           //扫描的速度 [1]慢 [2]中等 [3]快 [4]最高
	Vulns      []poc.PocInfo // 存放漏洞信息
}

var Target = &Target_Info{} // 实例化用于存储扫描结果的对象

var Scan_Num float64 = 0 // 用于进度条计数

// 此函数适用于安全性
// 此函数用于生成所有poc
// func PocInit() {
// 	methodName := []string{}                // 用于保存方法名
// 	pocStruct := &poc.PocInfo{}             // 实例化一个poc结构体，主要用于通过反射调用poc结构体内的方法
// 	pocReflect := reflect.TypeOf(pocStruct) // 用于获取方法的数量、方法名

// 	// 将方法名添加到数组中
// 	for i := 0; i < pocReflect.NumMethod(); i++ {
// 		method := pocReflect.Method(i) // 获取方法名
// 		methodName = append(methodName, method.Name)
// 	}

// 	// 调用方法，生成poc
// 	for _, pocName := range methodName {
// 		if fun, bl := pocReflect.MethodByName(pocName); bl {
// 			fun.Func.Call([]reflect.Value{reflect.ValueOf(pocStruct)}) // 调用方法生成poc
// 		}
// 	}
// }

// 扫描提示语
func Scanning(wg *sync.WaitGroup) {
	before := time.Now().Unix()
	Scanning := []string{" scanning  |", " Scanning  /", " sCanning  -", " scAnning  \\", " scaNning  |", " scanNing  /", " scannIng  -", " scanniNg  \\", " scanninG  |", " scanning  /", " scanning  -", " scanning  \\"}
	green := color.FgGreen.Render
	blue := color.FgBlue.Render
	yellow := color.FgYellow.Render
	is_Stop := false
	for {
		if is_Stop {
			wg.Done()
			break
		}
		for i := 0; i < len(Scanning); i++ {
			numtemp, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(Scan_Num)/float64(len(poc.PocStruct))), 64)
			num := int(numtemp * 50)
			color.Print(green("[INFO]"), blue(Scanning[i]), yellow("  ["), strings.Repeat("=", num), strings.Repeat(" ", 50-num), yellow("]  "), int(numtemp*100), "%", "\r")
			time.Sleep(time.Millisecond * 100)
			if num == 50 {
				after := time.Now().Unix()
				color.Println(green("[INFO]"), blue("Scan Finish"))
				time.Sleep(time.Millisecond * 500)
				color.Println(green("[INFO]"), yellow("Total Time"), after-before, yellow("Seconds"))
				time.Sleep(time.Millisecond * 500)
				is_Stop = true
				break
			}
		}
	}
}

// 此函数适用于快捷性
// 此函数用于生成所有poc
func PocInit() {
	// 设置自定义poc的配置
	func() {
		poc.PocCustomize.Config.Url = Target.Target_Url
		poc.PocCustomize.Config.User_Agent = Target.User_Agent
		poc.PocCustomize.Config.Timeout = Target.Timeout
		poc.PocCustomize.Config.Proxy = Target.Proxy
		poc.PocCustomize.Config.Proxy_Url = Target.Proxy_Url
	}()

	func() {
		pocStruct := &poc.PocInfo{} // 实例化一个poc结构体，主要用于通过反射调用poc结构体内的方法
		pocReflect := reflect.ValueOf(pocStruct)

		for i := 0; i < pocReflect.NumMethod(); i++ {
			method := pocReflect.Method(i)
			method.Call(make([]reflect.Value, 0)) // 调用方法，生成poc
		}
	}()

	for _, pocStruct := range poc.PocStruct { // 将poc按照类型分类
		var pocType = pocStruct.Info.Type
		switch pocType {
		case "XSS":
			poc.PocMap["XSS"] = append(poc.PocMap["XSS"], pocStruct)

		case "SQLI":
			poc.PocMap["SQLI"] = append(poc.PocMap["SQLI"], pocStruct)

		case "RCE":
			poc.PocMap["RCE"] = append(poc.PocMap["RCE"], pocStruct)

		case "SSRF":
			poc.PocMap["SSRF"] = append(poc.PocMap["SSRF"], pocStruct)

		case "LFR":
			poc.PocMap["LFT"] = append(poc.PocMap["LFT"], pocStruct)

		case "UNAUTH":
			poc.PocMap["UNAUTH"] = append(poc.PocMap["UNAUTH"], pocStruct)

		case "INFO":
			poc.PocMap["INFO"] = append(poc.PocMap["INFO"], pocStruct)

		case "XXE":
			poc.PocMap["XXE"] = append(poc.PocMap["XXE"], pocStruct)

		default:
			poc.PocMap["OTHER"] = append(poc.PocMap["OTHER"], pocStruct)
		}
	}

	func() {
		// 用于存储漏洞等级数量，主要作用是终端显示
		type Vuln_Level_Num struct {
			Low_Risk    int
			Medium_Risk int
			High_Risk   int
			Critical    int
		}
		var Vuln_Level_Info = &Vuln_Level_Num{} // 实例化一个用于存储漏洞等级的结构体
		l_vuln := 0
		m_vuln := 0
		h_vuln := 0
		c_vuln := 0
		gary := color.Gray.Render
		green := color.Green.Render
		blue := color.Blue.Render
		red := color.Red.Render
		cyan := color.FgCyan.Render
		for _, pocStruct := range poc.PocStruct {
			var level = pocStruct.Info.Level
			switch level {
			case 0:
				c_vuln++

			case 1:
				h_vuln++

			case 2:
				m_vuln++

			case 3:
				l_vuln++

			default:
				continue
			}
		}
		Vuln_Level_Info.Low_Risk = l_vuln
		Vuln_Level_Info.Medium_Risk = m_vuln
		Vuln_Level_Info.High_Risk = h_vuln
		Vuln_Level_Info.Critical = c_vuln
		color.Println(green("[INFO]"), cyan("POC Total Tips ["), gary("Low•", Vuln_Level_Info.Low_Risk), green("      Medium•", Vuln_Level_Info.Medium_Risk), blue("      High•", Vuln_Level_Info.High_Risk), red("      Critical•", Vuln_Level_Info.Critical), cyan("]"))
		time.Sleep(time.Second * 1)
	}()
}

// 扫描入口
func Scan() {
	threads := 1
	switch Target.Speed {
	case 1:
		threads = 1

	case 2:
		threads = 5

	case 3:
		threads = 10

	case 4:
		threads = 20

	default:
		threads = 1
	}

	poc_Array := func(poc_all []poc.PocInfo) [][]poc.PocInfo {
		i := 0                        // 用于读取计数
		scan_thread := 1              // 扫描的线程
		poc_list := [][]poc.PocInfo{} // poc分组
		temp := []poc.PocInfo{}       //临时存储各个分组的poc
		if len(poc_all) <= threads {
			scan_thread = len(poc_all)
		} else {
			scan_thread = threads
		}
		one_thread_num := int(math.Ceil(float64(len(poc_all)) / float64(scan_thread)))
		for _, poc_temp := range poc_all {
			i++
			if i%one_thread_num == 0 {
				temp = append(temp, poc_temp)
				poc_list = append(poc_list, temp)
				temp = []poc.PocInfo{}
			} else if i == len(poc_all) {
				temp = append(temp, poc_temp)
				poc_list = append(poc_list, temp)
			} else {
				temp = append(temp, poc_temp)
			}
		}
		return poc_list // 返回线程列表
	}

	wg := sync.WaitGroup{} // 用于等待协程
	num_m := sync.Mutex{}  // 用于同步已扫描的漏洞数
	vuln_m := sync.Mutex{} // 用于同步目标的漏洞数

	wg.Add(1)
	go Scanning(&wg)

	if xss_poc_all, ok := poc.PocMap["XSS"]; ok {
		poc_list := poc_Array(xss_poc_all)
		for _, xss_poc_list := range poc_list {
			wg.Add(1)
			go XSS_Check(xss_poc_list, Target.Timeout, Target.Proxy, Target.Proxy_Url, &wg, &num_m, &vuln_m)
		}
	}

	if info_poc_all, ok := poc.PocMap["INFO"]; ok {
		poc_list := poc_Array(info_poc_all)
		for _, info_poc_list := range poc_list {
			wg.Add(1)
			go INFO_Check(info_poc_list, Target.Timeout, Target.Proxy, Target.Proxy_Url, &wg, &num_m, &vuln_m)
		}
	}

	wg.Wait() // 等待协程结束
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

// XSS检测函数
func XSS_Check(xss_poc_all []poc.PocInfo, timeout int, proxy bool, proxy_url string, wg *sync.WaitGroup, num_m *sync.Mutex, vuln_m *sync.Mutex) { // 第一个参数设置请求超时时间，第二个参数设置是否使用代理，第三个参数设置代理的url
	// fmt.Println("加载的XSS检测poc数量：", len(xss_poc_all))
	green := color.FgGreen.Render
	lightRed := color.FgLightRed.Render
	lightCyan := color.FgLightCyan.Render

	cli := Http_Client(timeout, proxy, proxy_url)

	for _, xss_poc := range xss_poc_all {
		if xss_poc.Config.Customize { //判断是否是自定义poc
			check := xss_poc.Config.Check
			if check() {
				vuln_m.Lock()
				Target.Vulns = append(Target.Vulns, xss_poc)
				color.Println(green("[INFO]"), lightCyan("Find a vulnerability name of"), "{", lightRed(xss_poc.Info.Name), "}", strings.Repeat(" ", 50))
				vuln_m.Unlock()
			}
		} else { // 模板poc检测规则
			if xss_poc.Poc.Method == "GET" { // GET方法
				for i, path := range xss_poc.Poc.Path {
					request, err := http.NewRequest(xss_poc.Poc.Method, Target.Target_Url+path, nil)
					if err != nil {
						continue
					}
					request.Header.Add("User-Agent", Target.User_Agent) // 设置User-Agent
					if len(xss_poc.Poc.Header) != 0 {                   // 获取poc中的header
						for header, value := range xss_poc.Poc.Header {
							request.Header.Add(header, value)
						}
					}
					if response, err := cli.Do(request); err != nil { // 发起http请求
						continue
					} else {
						defer response.Body.Close()
						body, _ := ioutil.ReadAll(response.Body)
						// 判断是否有多个word
						word := xss_poc.Poc.Word[0]
						if len(xss_poc.Poc.Word) > 1 {
							word = xss_poc.Poc.Word[i]
						}

						if strings.Contains(string(body), word) {
							vuln_m.Lock()
							Target.Vulns = append(Target.Vulns, xss_poc)
							color.Println(green("[INFO]"), lightCyan("Find a vulnerability name of"), "{", lightRed(xss_poc.Info.Name), "}", strings.Repeat(" ", 50))
							vuln_m.Unlock()
							break
						} else {
							continue
						}
					}
				}
			} else if xss_poc.Poc.Method == "POST" { // POST方法
				for i, path := range xss_poc.Poc.Path {
					// 判断数据包是否多个
					data := xss_poc.Poc.Data[0]
					if len(xss_poc.Poc.Data) > 1 {
						data = xss_poc.Poc.Data[i]
					}

					request, err := http.NewRequest(xss_poc.Poc.Method, Target.Target_Url+path, strings.NewReader(data))
					if err != nil {
						continue
					}
					request.Header.Add("User-Agent", Target.User_Agent) // 设置User-Agent
					if len(xss_poc.Poc.Header) != 0 {                   // 获取poc中的header
						for header, value := range xss_poc.Poc.Header {
							request.Header.Add(header, value)
						}
					}
					if response, err := cli.Do(request); err != nil { // 发起http请求
						continue
					} else {
						defer response.Body.Close()
						body, _ := ioutil.ReadAll(response.Body)
						// 判断是否有多个word
						word := xss_poc.Poc.Word[0]
						if len(xss_poc.Poc.Word) > 1 {
							word = xss_poc.Poc.Word[i]
						}
						if strings.Contains(string(body), word) {
							vuln_m.Lock()
							Target.Vulns = append(Target.Vulns, xss_poc)
							color.Println(green("[INFO]"), lightCyan("Find a vulnerability name of"), "{", lightRed(xss_poc.Info.Name), "}", strings.Repeat(" ", 50))
							vuln_m.Unlock()
							break
						} else {
							continue
						}
					}
				}
			} else {
				return
			}
		}
		num_m.Lock()
		Scan_Num++
		num_m.Unlock()
	}
	wg.Done()
}

// INFO检测函数
func INFO_Check(info_poc_all []poc.PocInfo, timeout int, proxy bool, proxy_url string, wg *sync.WaitGroup, num_m *sync.Mutex, vuln_m *sync.Mutex) {
	// fmt.Println("加载的INFO检测poc数量：", len(info_poc_all))
	green := color.FgGreen.Render
	lightRed := color.FgLightRed.Render
	lightCyan := color.FgLightCyan.Render

	cli := Http_Client(timeout, proxy, proxy_url)

	for _, info_poc := range info_poc_all {
		if info_poc.Config.Customize {
			check := info_poc.Config.Check
			if check() {
				vuln_m.Lock()
				Target.Vulns = append(Target.Vulns, info_poc)
				color.Println(green("[INFO]"), lightCyan("Find a vulnerability name of"), "{", lightRed(info_poc.Info.Name), "}", strings.Repeat(" ", 50))
				vuln_m.Unlock()
			}
		} else {
			if info_poc.Poc.Method == "GET" { // GET方法
				for _, path := range info_poc.Poc.Path {
					request, err := http.NewRequest(info_poc.Poc.Method, Target.Target_Url+path, nil)
					if err != nil {
						continue
					}
					request.Header.Add("User-Agent", Target.User_Agent) // 设置User-Agent
					if len(info_poc.Poc.Header) != 0 {                  // 获取poc中的header
						for header, value := range info_poc.Poc.Header {
							request.Header.Add(header, value)
						}
					}
					if response, err := cli.Do(request); err != nil { // 发起http请求
						continue
					} else {
						defer response.Body.Close()
						body, _ := ioutil.ReadAll(response.Body)
						// 判断是否有多个word
						if len(info_poc.Poc.Word) == 1 {
							word := info_poc.Poc.Word[0]
							if strings.Contains(string(body), word) {
								vuln_m.Lock()
								Target.Vulns = append(Target.Vulns, info_poc)
								color.Println(green("[INFO]"), lightCyan("Find a vulnerability name of"), "{", lightRed(info_poc.Info.Name), "}", strings.Repeat(" ", 50))
								vuln_m.Unlock()
								break
							} else {
								continue
							}
						} else {
							for _, word := range info_poc.Poc.Word {
								if strings.Contains(string(body), word) {
									vuln_m.Lock()
									Target.Vulns = append(Target.Vulns, info_poc)
									color.Println(green("[INFO]"), lightCyan("Find a vulnerability name of"), "{", lightRed(info_poc.Info.Name), "}", strings.Repeat(" ", 50))
									vuln_m.Unlock()
									break
								} else {
									continue
								}
							}
						}
					}
				}
			} else if info_poc.Poc.Method == "POST" { // POST方法
				for i, path := range info_poc.Poc.Path {
					// 判断数据包是否多个
					data := info_poc.Poc.Data[0]
					if len(info_poc.Poc.Data) > 1 {
						data = info_poc.Poc.Data[i]
					}

					request, err := http.NewRequest(info_poc.Poc.Method, Target.Target_Url+path, strings.NewReader(data))
					if err != nil {
						continue
					}
					request.Header.Add("User-Agent", Target.User_Agent) // 设置User-Agent
					if len(info_poc.Poc.Header) != 0 {                  // 获取poc中的header
						for header, value := range info_poc.Poc.Header {
							request.Header.Add(header, value)
						}
					}
					if response, err := cli.Do(request); err != nil { // 发起http请求
						continue
					} else {
						defer response.Body.Close()
						body, _ := ioutil.ReadAll(response.Body)
						// 判断是否有多个word
						if len(info_poc.Poc.Word) == 1 {
							word := info_poc.Poc.Word[0]
							if strings.Contains(string(body), word) {
								vuln_m.Lock()
								color.Println(green("[INFO]"), lightCyan("Find a vulnerability name of"), "{", lightRed(info_poc.Info.Name), "}", strings.Repeat(" ", 50))
								fmt.Println("[INFO] hit some poc")
								vuln_m.Unlock()
								break
							} else {
								continue
							}
						} else {
							for _, word := range info_poc.Poc.Word {
								if strings.Contains(string(body), word) {
									vuln_m.Lock()
									Target.Vulns = append(Target.Vulns, info_poc)
									color.Println(green("[INFO]"), lightCyan("Find a vulnerability name of"), "{", lightRed(info_poc.Info.Name), "}", strings.Repeat(" ", 50))
									vuln_m.Unlock()
									break
								} else {
									continue
								}
							}
						}
					}
				}
			} else {
				return
			}
		}
		num_m.Lock()
		Scan_Num++
		num_m.Unlock()
	}
	wg.Done()
}
