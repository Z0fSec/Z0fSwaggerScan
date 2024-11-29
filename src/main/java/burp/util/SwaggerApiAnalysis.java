package burp.util;

import burp.entity.ApiPathInfo;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.intellij.uiDesigner.UIFormXmlConstants;
import org.apache.commons.httpclient.cookie.CookieSpec;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class SwaggerApiAnalysis {
    public static List<ApiPathInfo> getAllApiPath(URL url) {
        return getAllApiPath(url, null, null);
    }

    public static List<ApiPathInfo> getAllApiPath(URL url, String diyHost, String diyBasePath) {
        JSONObject data3;
        List<ApiPathInfo> apis = new ArrayList<>();
        String result = HttpUtil.doGet(String.valueOf(url));
        JSONObject api = JSON.parseObject(result);
        String basePath = api.getString("basePath");
        if (basePath == null) {
            basePath = CookieSpec.PATH_DELIM;
        } else if (basePath.equals(CookieSpec.PATH_DELIM)) {
            if (url.getPath().contains("/v2/api-docs")) {
                if (url.getPath().split("/v2/api-docs").length == 0) {
                    basePath = CookieSpec.PATH_DELIM;
                } else {
                    basePath = url.getPath().split("/v2/api-docs")[0];
                }
            }
            if (url.getPath().contains("/v3/api-docs")) {
                if (url.getPath().split("/v3/api-docs").length == 0) {
                    basePath = CookieSpec.PATH_DELIM;
                } else {
                    basePath = url.getPath().split("/v3/api-docs")[0];
                }
            }
        } else {
            basePath = url.getPath().split(basePath)[0] + basePath;
        }
        if (diyBasePath != null) {
            basePath = diyBasePath;
        }
        JSONObject definitionsJson = api.getJSONObject("definitions");
        JSONObject apiPath = (JSONObject) api.get("paths");
        for (Map.Entry<String, Object> pathEntry : apiPath.entrySet()) {
            String path = pathEntry.getKey();
            JSONObject pathJson = (JSONObject) pathEntry.getValue();
            for (Map.Entry<String, Object> methodEntry : pathJson.entrySet()) {
                Map<String, String> paramBody = new HashMap<>();
                Map<String, String> paramHeader = new HashMap<>();
                Map<String, String> paramQuery = new HashMap<>();
                String method = methodEntry.getKey();
                JSONObject methodJson = (JSONObject) methodEntry.getValue();
                String reuqestSummary = methodJson.getString("summary");
                String contentType = methodJson.getJSONArray("produces").getString(0);
                JSONArray parameters = methodJson.getJSONArray("parameters");
                if (parameters == null) {
                    apis.add(new ApiPathInfo(basePath, path, method, contentType, paramBody, paramHeader, paramQuery, reuqestSummary));
                } else {
                    for (int i = 0; i < parameters.size(); i++) {
                        JSONObject dataJson = JSONObject.parseObject(parameters.getString(i));
                        String parameterPosition = (String) dataJson.get("in");
                        if (parameterPosition != null) {
                            switch (parameterPosition) {
                                case "header":
                                    paramHeader.put(dataJson.getString(UIFormXmlConstants.ATTRIBUTE_NAME), dataJson.getString(UIFormXmlConstants.ATTRIBUTE_TYPE));
                                    break;
                                case "body":
                                    if (dataJson.containsKey("schema")) {
                                        if (dataJson.getJSONObject("schema").containsKey("$ref")) {
                                            String keyName = dataJson.getJSONObject("schema").getString("$ref").split("#/definitions/")[1];
                                            JSONObject data2 = definitionsJson.getJSONObject(keyName);
                                            if (data2 != null && (data3 = data2.getJSONObject(UIFormXmlConstants.ELEMENT_PROPERTIES)) != null) {
                                                for (Map.Entry<String, Object> param : data3.entrySet()) {
                                                    JSONObject test = (JSONObject) param.getValue();
                                                    paramBody.put(param.getKey(), test.getString(UIFormXmlConstants.ATTRIBUTE_TYPE));
                                                }
                                            }
                                        }
                                    } else {
                                        paramBody.put(dataJson.getString(UIFormXmlConstants.ATTRIBUTE_NAME), dataJson.getString(UIFormXmlConstants.ATTRIBUTE_TYPE));
                                    }
                                    break;
                                case "query":
                                    paramQuery.put(dataJson.getString(UIFormXmlConstants.ATTRIBUTE_NAME), dataJson.getString(UIFormXmlConstants.ATTRIBUTE_TYPE));
                                    break;
                            }
                        }
                    }
                    apis.add(new ApiPathInfo(basePath, path, method, contentType, paramBody, paramHeader, paramQuery, reuqestSummary));
                }
            }
        }
        return apis;
    }
}