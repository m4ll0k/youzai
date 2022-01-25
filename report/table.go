package report

import (
	"strings"
	"time"
	"youzai/active"

	"github.com/gookit/color"
)

// 用于表格输出的函数，调用前需判断漏洞信息是否为空
func OutTable() {
	signs := []string{`+`, `-`, `|`} // 表格输出符号
	green := color.FgGreen.Render
	red := color.FgRed.Render
	blue := color.FgBlue.Render
	cyan := color.FgCyan.Render
	magenta := color.FgMagenta.Render

	if len(active.Target.Vulns) == 0 {
		color.Println(green("[INFO]"), blue("No Vulnerabilities Find"))
		return
	}

	// 计算漏洞url最大的长度
	target_url_length := func() int {
		length := 0
		if len(active.Target.Target_Url) <= 10 {
			length = 10
		} else {
			length = len(active.Target.Target_Url) + 2
		}
		return length
	}()

	// 计算漏洞名最大长度
	target_vuln_name_length := func() int {
		length_all := []int{}
		var maxVal int
		for _, poc := range active.Target.Vulns {
			length_all = append(length_all, len(poc.Info.Name))
		}
		func(arr []int) {
			maxVal = arr[0]
			for i := 1; i < len(arr); i++ {
				if maxVal < arr[i] {
					maxVal = arr[i]
				}
			}
		}(length_all)
		if maxVal < 10 {
			maxVal = 10
		}
		return maxVal + 2
	}()

	target_vuln_id_length := func() int { // 计算漏id最大长度
		length_all := []int{}
		var maxVal int
		for _, poc := range active.Target.Vulns {
			length_all = append(length_all, len(poc.Info.ID))
		}
		func(arr []int) {
			maxVal = arr[0]
			for i := 1; i < len(arr); i++ {
				if maxVal < arr[i] {
					maxVal = arr[i]
				}
			}
		}(length_all)
		if maxVal < 8 {
			maxVal = 8
		}
		return maxVal + 2
	}()

	target_vuln_level_length := 14 // 漏洞等级最大长度

	// 打印边界线
	line := func() {
		color.Cyanln(signs[0], strings.Repeat(signs[1], target_url_length), signs[0], strings.Repeat(signs[1], target_vuln_name_length), signs[0], strings.Repeat(signs[1], target_vuln_id_length), signs[0], strings.Repeat(signs[1], target_vuln_level_length), signs[0])
	}

	color.Println(green("[INFO]"), red("Scan Results Info"))
	time.Sleep(time.Millisecond * 500)

	line()

	color.Cyanln(signs[2], "Target_Url", strings.Repeat(" ", target_url_length-11), signs[2], "Vuln_Name", strings.Repeat(" ", target_vuln_name_length-10), signs[2], "Vuln_ID", strings.Repeat(" ", target_vuln_id_length-8), signs[2], "Vuln_Level", strings.Repeat(" ", target_vuln_level_length-11), signs[2])

	line()

	time.Sleep(time.Millisecond * 500)

	for _, poc := range active.Target.Vulns {
		level := poc.Info.Level
		var level_info string
		switch level {
		case 0:
			level_info = "<fg=FF0000>Critical</>"

		case 1:
			level_info = "<fg=FFA500>High</>"

		case 2:
			level_info = "<fg=00FF00>Medium</>"

		case 3:
			level_info = "<fg=808080>Low</>"
		}
		// 打印漏洞信息
		func() {
			color.Println(cyan(signs[2]), green(active.Target.Target_Url), strings.Repeat(" ", target_url_length-(len(active.Target.Target_Url)+1)), cyan(signs[2]), green(poc.Info.Name), strings.Repeat(" ", target_vuln_name_length-(len(poc.Info.Name)+1)), cyan(signs[2]), magenta(poc.Info.ID), strings.Repeat(" ", target_vuln_id_length-(len(poc.Info.ID)+1)), cyan(signs[2]), level_info, strings.Repeat(" ", target_vuln_level_length+13-len(level_info)), cyan(signs[2]))
		}()
		line()
		time.Sleep(time.Millisecond * 200)
	}
}
