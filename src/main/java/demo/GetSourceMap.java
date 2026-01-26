package demo;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

public class GetSourceMap implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        // 设置扩展名称
        api.extension().setName("GetSourceMap");
        
        // 注册 HTTP 处理器来拦截请求
        api.http().registerHttpHandler(new SourceMapHttpHandler(api));
        
        // 创建并注册 UI 组件
        SourceMapUI sourceMapUI = new SourceMapUI(api);
        api.userInterface().registerSuiteTab("SourceMap", sourceMapUI.getUiComponent());
        
        // 注册扩展卸载处理器
        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                sourceMapUI.saveData();
            }
        });
        
        api.logging().logToOutput("GetSourceMap extension loaded successfully.");
    }
}