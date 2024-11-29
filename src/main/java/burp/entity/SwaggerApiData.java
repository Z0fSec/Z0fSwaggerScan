package burp.entity;

import burp.util.HttpRequestResponse;
import lombok.Data;


@Data
public class SwaggerApiData {
    private String method;
    private String url;
    private String summary;
    private HttpRequestResponse httpRequestResponse;

    public SwaggerApiData(String method, String url, String summary, HttpRequestResponse httpRequestResponse) {
        this.method = method;
        this.url = url;
        this.summary = summary;
        this.httpRequestResponse = httpRequestResponse;
    }
}