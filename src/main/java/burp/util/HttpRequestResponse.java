package burp.util;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import lombok.Data;

@Data
public class HttpRequestResponse implements IHttpRequestResponse {
    public byte[] request;
    public byte[] response;
    public IHttpService iHttpService;
    public IHttpRequestResponse iHttpRequestResponse;
    public String comment;
    public String highlight;
    public BurpExtender burpExtender;

    public HttpRequestResponse(IHttpRequestResponse iHttpRequestResponse, BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.request = iHttpRequestResponse.getRequest();
        this.response = iHttpRequestResponse.getResponse();
        this.iHttpService = iHttpRequestResponse.getHttpService();
        this.comment = iHttpRequestResponse.getComment();
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.highlight = iHttpRequestResponse.getHighlight();
    }

    public String getPath() {
        String h0 = this.burpExtender.helpers.analyzeRequest(this.request).getHeaders().get(0);
        return h0.split(" ")[1];
    }

    @Override
    public IHttpService getHttpService() {
        return this.iHttpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.iHttpRequestResponse.setHttpService(httpService);
    }
}