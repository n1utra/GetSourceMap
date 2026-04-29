package demo;

import burp.api.montoya.core.ByteArray;

public class SourceMapResult {
    private final String url;
    private final int statusCode;
    private final int responseLength;
    private final ByteArray request;
    private final ByteArray response;
    private final boolean maybeVuln;

    public SourceMapResult(String url, int statusCode, int responseLength, ByteArray request, ByteArray response, boolean maybeVuln) {
        this.url = url;
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.request = request;
        this.response = response;
        this.maybeVuln = maybeVuln;
    }

    // Getters
    public String getUrl() {
        return url;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public int getResponseLength() {
        return responseLength;
    }

    public ByteArray getRequest() {
        return request;
    }

    public ByteArray getResponse() {
        return response;
    }
    
    public boolean isMaybeVuln() {
        return maybeVuln;
    }
}