package burp;

import burp.entity.SwaggerApiData;
import burp.entity.ApiPathInfo;
import burp.util.SwaggerApiAnalysis;
import burp.util.HttpRequestResponse;
import burp.util.Utils;
import lombok.Data;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

@Data
public class BurpExtender extends JPanel implements IBurpExtender, IContextMenuFactory, ITab {
    private static final float X = 1.0f;
    private static final float Y = 0.0f;
    public static String NAME = "Z0fSwaggerScan";
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter std;

    // UI 显示界面
    public SwaggerApiPanel swaggerApiPanel;
    private AuthDataPanel authDataPanel;

    private JTabbedPane tabbedPane = new JTabbedPane();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        Utils.callbacks = iBurpExtenderCallbacks;
        Utils.helpers = iBurpExtenderCallbacks.getHelpers();
        Utils.stdout = new PrintWriter(iBurpExtenderCallbacks.getStdout(), true);
        Utils.stderr = new PrintWriter(iBurpExtenderCallbacks.getStderr(), true);

        callbacks = iBurpExtenderCallbacks;
        helpers = callbacks.getHelpers();
        std = new PrintWriter(callbacks.getStdout(), true);

        std.println("Author: EatMans@Z0fSec");

        callbacks.setExtensionName(NAME);
        callbacks.registerContextMenuFactory(this);
        swaggerApiPanel = new SwaggerApiPanel(callbacks, std, NAME, BurpExtender.this);
        authDataPanel = new AuthDataPanel(callbacks, std);

        tabbedPane.setAlignmentX(X);
        tabbedPane.setAlignmentY(Y);
        tabbedPane.addTab("API接口", swaggerApiPanel);
        tabbedPane.addTab("越权测试", authDataPanel);
        add(tabbedPane);

        // 将主页面(tab)添加到Burp面板中
        SwingUtilities.invokeLater(() -> iBurpExtenderCallbacks.addSuiteTab(BurpExtender.this));

    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> menu_item_list = new ArrayList<>();
        JMenuItem authTestItem = new JMenuItem("API接口越权测试");
        JMenuItem apiScanItem = new JMenuItem("Swagger文档分析");

        authTestItem.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        AuthDataPanel.CheckByMenuItem(iContextMenuInvocation.getSelectedMessages(), "右键");
                    }
                });
                thread.start();
            }
        });

        apiScanItem.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new Thread(() -> {
                    apiAnalysis(iContextMenuInvocation.getSelectedMessages()[0]);
                }).start();
            }
        });

        menu_item_list.add(authTestItem);
        menu_item_list.add(apiScanItem);
        return menu_item_list;
    }

    //分析api-docs接口地址方法
    public void apiAnalysis(IHttpRequestResponse iHttpRequestResponse) {
        URL url = helpers.analyzeRequest(iHttpRequestResponse).getUrl();
        List<ApiPathInfo> allApiPath = new ArrayList<>();
        if (SwaggerApiPanel.isDiyAPIInfo) {
            allApiPath = SwaggerApiAnalysis.getAllApiPath(url, SwaggerApiPanel.diyHost, SwaggerApiPanel.diyBasePath);
        } else {
            allApiPath = SwaggerApiAnalysis.getAllApiPath(url);
        }
        for (ApiPathInfo pathInfo : allApiPath) {
            HttpRequestResponse data = swaggerApiPanel.buildRequest(pathInfo, iHttpRequestResponse);
            swaggerApiPanel.addApiData(new SwaggerApiData(pathInfo.method.toUpperCase(), data.getPath(), pathInfo.summary, data));
        }
    }

    @Override
    public String getTabCaption() {
        return NAME;
    }

    /**
     * 插件主页面
     *
     * @return 主页面
     */
    @Override
    public Component getUiComponent() {
        return tabbedPane;
    }

}
