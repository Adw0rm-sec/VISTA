package burp;

import java.util.List;

public interface IRequestInfo {
    List<String> getHeaders();
    int getBodyOffset();
}