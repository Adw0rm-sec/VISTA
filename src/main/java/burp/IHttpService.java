package burp;

/**
 * Represents an HTTP service (host, port, protocol).
 */
public interface IHttpService {
    String getHost();
    int getPort();
    String getProtocol();
}
