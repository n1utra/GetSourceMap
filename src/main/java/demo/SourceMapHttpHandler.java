package demo;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

public class SourceMapHttpHandler implements HttpHandler {
    private final MontoyaApi api;
    private final ExecutorService executorService;
    // 预编译 SourceMap 检测正则
    private static final Pattern VERSION_PATTERN = Pattern.compile("\"version\":\\d+");
    // 请求层去重：已探测过的 JS URL
    private final Set<String> checkedJsUrls = ConcurrentHashMap.newKeySet();

    public SourceMapHttpHandler(MontoyaApi api) {
        this.api = api;
        // 使用有界线程池，避免无限制创建线程
        this.executorService = Executors.newFixedThreadPool(10);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // 检查是否是 JavaScript 文件请求
        String urlWithoutQueryParams = removeQueryParameters(requestToBeSent.url());
        if (urlWithoutQueryParams.endsWith(".js")) {
            // 请求层去重：同一JS URL只探测一次
            if (checkedJsUrls.add(urlWithoutQueryParams)) {
                // 检查请求来源工具是否被选中
                boolean shouldProcess = SourceMapUI.getInstance().isToolEnabled(requestToBeSent.toolSource());

                if (shouldProcess) {
                    executorService.submit(() -> checkForSourceMap(urlWithoutQueryParams, requestToBeSent));
                }
            }
        }

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // 我们不需要修改响应，所以继续正常处理
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    // 添加一个方法用于移除URL中的查询参数
    private String removeQueryParameters(String url) {
        int queryIndex = url.indexOf('?');
        if (queryIndex != -1) {
            return url.substring(0, queryIndex);
        }
        return url;
    }

    private void checkForSourceMap(String jsUrl, HttpRequestToBeSent originalRequest) {
        try {
            String sourceMapUrl = jsUrl + ".map";
            // 使用正确的方式创建带Header的请求
            HttpRequest sourceMapRequest = HttpRequest.httpRequestFromUrl(sourceMapUrl)
                    .withHeader("Range", "bytes=0-9999");
            
            // 发送对 .map 文件的请求
            HttpResponse sourceMapResponse = api.http().sendRequest(sourceMapRequest).response();
            
            if (sourceMapResponse != null) {
                // 检查响应的Content-Type头是否包含html，如果包含则跳过
                String contentType = null;
                List<HttpHeader> headers = sourceMapResponse.headers();
                for (HttpHeader header : headers) {
                    if ("Content-Type".equalsIgnoreCase(header.name())) {
                        contentType = header.value();
                        break;
                    }
                }
                
                if (contentType != null && contentType.toLowerCase().contains("html")) {
                    return; // 跳过包含html的内容类型
                }
                
                String responseBody = sourceMapResponse.bodyToString();
                // 修改检测逻辑：使用正则表达式匹配 "version":\d,"sources":
                // 使用预编译的正则表达式检测
                boolean maybeVuln = VERSION_PATTERN.matcher(responseBody).find();
                
                // 将结果添加到 UI
                SourceMapResult result = new SourceMapResult(
                    sourceMapUrl,
                    sourceMapResponse.statusCode(),
                    sourceMapResponse.body().length(),
                    sourceMapRequest.toByteArray(),
                    sourceMapResponse.toByteArray(),
                    maybeVuln
                );
                
                // 更新 UI
                SourceMapUI.addToResults(result);
            }
        } catch (Exception e) {
            api.logging().logToError("Error checking for sourcemap: " + e.getMessage());
        }
    }
}