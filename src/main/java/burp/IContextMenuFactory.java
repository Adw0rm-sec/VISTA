package burp;

import java.util.List;
import javax.swing.JMenuItem;

public interface IContextMenuFactory {
    List<JMenuItem> createMenuItems(IContextMenuInvocation invocation);
}