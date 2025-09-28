package burp;

public interface IExtensionHelpers {
    IRequestInfo analyzeRequest(byte[] request);
    IResponseInfo analyzeResponse(byte[] response);
}