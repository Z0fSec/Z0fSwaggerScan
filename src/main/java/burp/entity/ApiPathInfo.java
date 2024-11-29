package burp.entity;

import lombok.Data;

import java.util.Map;

@Data
public class ApiPathInfo {
    public String basePath;
    public String path;
    public String method;
    public String contentType;
    public Map<String, String> parametesBody;
    public Map<String, String> parametesHeader;
    public Map<String, String> parametesQueue;
    public String summary;

    public ApiPathInfo(String basePath, String path, String method, String contentType, Map<String, String> parametesBody, Map<String, String> parametesHeader, Map<String, String> parametesQueue, String summary) {
        this.basePath = basePath;
        this.path = path;
        this.method = method;
        this.contentType = contentType;
        this.parametesBody = parametesBody;
        this.parametesHeader = parametesHeader;
        this.parametesQueue = parametesQueue;
        this.summary = summary;
    }
}