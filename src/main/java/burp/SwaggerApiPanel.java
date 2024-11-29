package burp;

import burp.UIHepler.GridBagConstraintsHelper;
import burp.entity.ApiPathInfo;
import burp.entity.SwaggerApiData;
import burp.entity.SwaggerApiTableMode;
import burp.util.HttpRequestResponse;
import cn.hutool.core.date.DateUtil;
import cn.hutool.poi.excel.ExcelUtil;
import cn.hutool.poi.excel.ExcelWriter;
import com.alibaba.fastjson.JSON;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.PrintWriter;
import java.util.List;
import java.util.*;

public class SwaggerApiPanel extends JPanel implements IMessageEditorController {

    public static SwaggerApiTableMode swaggerApiTableMode;
    public static boolean isDiyAPIInfo; // 是否自定义API信息
    static boolean genParameters; // 是否生成参数
    static String diyHeaders; // 自定义请求头列表列表
    static String diyHost;
    static String diyBasePath;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter std;
    private final String name;
    BurpExtender burpExtender;
    private JPanel panel; // 主面板
    // UI 组件
    private JSplitPane mainPane;
    private APIListTable apiListTable;
    private HttpRequestResponse currentlyDisplayedItem;
    private JSplitPane mainSplitPane;
    private JPanel rightSplitPane; // 右边面板
    private JPanel rightTopPane;
    private JCheckBox genParametersCheckBox; // 生成参数选择框
    private JLabel diyHeadersLabel;  // 自定义请求头Label
    private JCheckBox diyHeadersCheckBox; // 自定义请求头选择框
    private JScrollPane diyHeadersTextAreascrollPane;
    private JTextArea diyHeadersTextArea; // 白名单域名输入框
    private JCheckBox hasBasePathCheckBox; // 包含basePath按钮
    private JButton saveAPIDataButton; // 保存认证数据按钮
    private JButton refreshButton; // 刷新按钮
    private JButton clearButton; // 清空数据按钮
    private JTabbedPane vulDetailTabbedPane;
    private IMessageEditor originalRequestViewer;
    private IMessageEditor originalResponseViewer;
    private JLabel diyBasePathLabel;  // DIY BasePath Label
    private JScrollPane diyBasePathTextAreascrollPane; // DIY BasePath
    private JTextArea diyBasePathTextArea; // DIY BasePath 输入框
    private JLabel diyHostLabel;  // DIY 主机域名Label
    private JScrollPane diyHostAreascrollPane; // DIY 主机域名
    private JTextArea diyHostTextArea; // DIY 主机域名输入框

    public SwaggerApiPanel(IBurpExtenderCallbacks callbacks, PrintWriter std, String name, BurpExtender burpExtender) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.std = std;
        this.name = name;
        this.burpExtender = burpExtender;
        init();
    }

    public void init() {
        // 主页面
        panel = new JPanel();
        panel.setLayout(new BorderLayout());
        panel.setMaximumSize(panel.getPreferredSize()); // 设置最大尺寸等于首选尺寸，禁止自动调整

        mainPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplitPane.setResizeWeight(0.9);
        // 左边的面板
        // 左边的面板上下分割,比例为7：3
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftSplitPane.setResizeWeight(0.7);
        leftSplitPane.setDividerLocation(0.7);

        // 右边的上面
        // 生成请求参数选择框
        genParametersCheckBox = new JCheckBox("生成请求参数");
        // 自定义请求头选择框
        diyHeadersCheckBox = new JCheckBox("自定义接口");
        // 自定义请求头Label
        diyHeadersLabel = new JLabel("自定义请求头");
        // 白名单域名输入框
        diyHeadersTextArea = new JTextArea(5, 10);
        diyHeadersTextArea.setLineWrap(false); // 自动换行
        diyHeadersTextArea.setWrapStyleWord(false); // 按单词换行
        diyHeadersTextAreascrollPane = new JScrollPane(diyHeadersTextArea);

        // diyBasePathLabel
        diyBasePathLabel = new JLabel("自定义basePath");
        // Origin域名输入框
        diyBasePathTextArea = new JTextArea(5, 10);
        diyBasePathTextArea.setLineWrap(false); // 自动换行
        diyBasePathTextArea.setWrapStyleWord(false); // 按单词换行
        diyBasePathTextAreascrollPane = new JScrollPane(diyBasePathTextArea);

        // diyHostLabel
        diyHostLabel = new JLabel("自定义Host");
        // Origin域名输入框
        diyHostTextArea = new JTextArea(5, 10);
        diyHostTextArea.setLineWrap(false); // 自动换行
        diyHostTextArea.setWrapStyleWord(false); // 按单词换行
        diyHostAreascrollPane = new JScrollPane(diyHostTextArea);

        // 是否包含basePath按钮
        hasBasePathCheckBox = new JCheckBox("含有basePath");
        // 导出接口数据
        saveAPIDataButton = new JButton("导出为Xlsx");
        // 刷新按钮
        refreshButton = new JButton("刷新表格");
        // 清空数据按钮
        clearButton = new JButton("清空表格");
        rightTopPane = new JPanel(new GridBagLayout());
        rightSplitPane = new JPanel(new BorderLayout());
        // genParametersCheckBox和diyHeadersCheckBox在第一行
        rightTopPane.add(genParametersCheckBox, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPane.add(diyHeadersCheckBox, new GridBagConstraintsHelper(1, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // saveWhiteListButton和saveAPIDataButton在第二行
        rightTopPane.add(hasBasePathCheckBox, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPane.add(saveAPIDataButton, new GridBagConstraintsHelper(1, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // refreshButton和clearButton在第五行
        rightTopPane.add(refreshButton, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPane.add(clearButton, new GridBagConstraintsHelper(1, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // diyHeadersLabel在第三行
        rightTopPane.add(diyHeadersLabel, new GridBagConstraintsHelper(0, 3, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // whiteListTextArea在第四行
        rightTopPane.add(diyHeadersTextAreascrollPane, new GridBagConstraintsHelper(0, 4, 2, 1).setInsets(5).setIpad(0, 0).setWeight(1, 1).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));

        // OriginListLabel在第六行
        rightTopPane.add(diyHostLabel, new GridBagConstraintsHelper(0, 5, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // OriginListTextArea在第七行
        rightTopPane.add(diyHostAreascrollPane, new GridBagConstraintsHelper(0, 6, 2, 1).setInsets(5).setIpad(0, 0).setWeight(1, 1).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));

        // OriginListLabel在第八行
        rightTopPane.add(diyBasePathLabel, new GridBagConstraintsHelper(0, 7, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // OriginListTextArea在第九行
        rightTopPane.add(diyBasePathTextAreascrollPane, new GridBagConstraintsHelper(0, 8, 2, 1).setInsets(5).setIpad(0, 0).setWeight(1, 1).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));

        // 漏洞列表
        swaggerApiTableMode = new SwaggerApiTableMode();
        apiListTable = new APIListTable(swaggerApiTableMode);

        JScrollPane scrollPane = new JScrollPane(apiListTable);

        // 绑定到主页面上
        mainPane.setLeftComponent(scrollPane);

        // 漏洞请求数据详情
        vulDetailTabbedPane = new JTabbedPane();
        originalRequestViewer = callbacks.createMessageEditor(new MessageEditor(), false);
        originalResponseViewer = callbacks.createMessageEditor(new MessageEditor(), false);
        vulDetailTabbedPane.addTab("请求", originalRequestViewer.getComponent());
        vulDetailTabbedPane.addTab("响应", originalResponseViewer.getComponent());
        // 绑定到主页面
        mainPane.setRightComponent(vulDetailTabbedPane);

        rightSplitPane.add(rightTopPane);
        leftSplitPane.add(mainPane);
        mainSplitPane.setLeftComponent(leftSplitPane);
        mainSplitPane.setRightComponent(rightSplitPane);

        panel.add(mainSplitPane);
        setLayout(new BorderLayout());
        add(panel);
        initEvent();
    }

    public void initEvent() {
        // 开启生成接口参数的点击事件
        genParametersCheckBox.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e2) {
                if (genParametersCheckBox.isSelected()) {
                    std.println("启动生成参数");
                    genParameters = true;
                } else {
                    std.println("关闭生成参数");
                    genParameters = false;
                }
            }
        });

        // 启动自定义接口信息参数
        diyHeadersCheckBox.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e2) {
                if (diyHeadersCheckBox.isSelected()) {
                    std.println("启动自定义接口信息");
                    diyHeadersTextArea.setEditable(false);
                    diyHeaders = diyHeadersTextArea.getText();
                    diyHost = diyHostTextArea.getText();
                    diyBasePath = diyBasePathTextArea.getText();
                    isDiyAPIInfo = true;
                } else {
                    std.println("关闭自定义接口信息");
                    diyHeadersTextArea.setEditable(true);
                    isDiyAPIInfo = false;
                }
            }
        });

        // 刷新表格
        refreshButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e2) {
                std.println("刷新表格");
                diyHeaders = diyHeadersTextArea.getText();
                diyHost = diyHostTextArea.getText();
                diyBasePath = diyBasePathTextArea.getText();
                swaggerApiTableMode.fireTableDataChanged();
            }
        });

        // 清除表格
        clearButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e2) {
                swaggerApiTableMode.getSwaggerApiData().clear();
                swaggerApiTableMode.fireTableDataChanged();
                std.println("清空表格");
            }
        });

        // 是否含有basePath事件
        hasBasePathCheckBox.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e2) {
                if (hasBasePathCheckBox.isSelected()) {

                } else {
                    std.println("关闭自定义接口信息");
                    diyHeadersTextArea.setEditable(true);
                    isDiyAPIInfo = false;
                }
            }
        });

        // 导出API接口点击事件
        saveAPIDataButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<SwaggerApiData> swaggerApiDataList = swaggerApiTableMode.getSwaggerApiData();
                if (swaggerApiDataList.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "暂无数据", "提示", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
                Date date = DateUtil.date();
                String dataStr = DateUtil.format(date, "yyyyMMddHHmmssSSS");
                // 创建ExcelWriter，指定文件路径和分隔符
                ExcelWriter writer = ExcelUtil.getWriter("D:\\Z0fData\\api" + dataStr + "API接口数据.xlsx", "API接口列表");
                // 添加标题，根据需要添加别名
                writer.addHeaderAlias("column0", "序号");
                writer.addHeaderAlias("column1", "请求方法");
                writer.addHeaderAlias("column2", "API地址");
                writer.addHeaderAlias("column3", "接口描述");

                List<Map<String, Object>> data = new ArrayList<>();
                for (int i = 0; i < swaggerApiDataList.size(); i++) {
                    Map<String, Object> row1 = new HashMap<>();
                    row1.put("column0", i);
                    row1.put("column1", swaggerApiDataList.get(i).getMethod());
                    row1.put("column2", swaggerApiDataList.get(i).getUrl());
                    row1.put("column3", swaggerApiDataList.get(i).getSummary());
                    data.add(row1);
                }
                // 写入数据到CSV文件
                writer.write(data, true);
                writer.close();
                JOptionPane.showMessageDialog(null, "保存成功，请到D:\\Z0fData查看", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });
    }

    public void addApiData(SwaggerApiData swaggerApiData) {
        swaggerApiTableMode.addRow(swaggerApiData);
        // 刷新数据
        swaggerApiTableMode.fireTableDataChanged();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    //构造Api的HttpRequestResponse数据
    public HttpRequestResponse buildRequest(ApiPathInfo apiPathInfo, IHttpRequestResponse iHttpRequestResponse) {
        HttpRequestResponse requestResponse = new HttpRequestResponse(iHttpRequestResponse, burpExtender);
        byte[] newRquest = requestResponse.getRequest();
        if (isDiyAPIInfo) {
            apiPathInfo.setBasePath(diyBasePath);
        }
        newRquest = buildApiHeader(newRquest, apiPathInfo);

        //URL内的参数,这里不知道为什么helps的addParameter方法失效了，自己写了给方法
        if (!apiPathInfo.parametesQueue.isEmpty()) {
            for (Map.Entry<String, String> param : apiPathInfo.parametesQueue.entrySet()) {
                newRquest = addParam(newRquest, param.getKey(), param.getValue());
            }
        }

        //header内的参数
        if (!apiPathInfo.parametesHeader.isEmpty()) {
            List<String> headers = helpers.analyzeRequest(newRquest).getHeaders();
            for (Map.Entry<String, String> header : apiPathInfo.parametesHeader.entrySet()) {
                headers.add(header.getKey() + ": " + header.getValue());
            }
            if (isDiyAPIInfo && !diyHeaders.isEmpty()) {
                headers.add(diyHeaders);
            }
            if (isDiyAPIInfo && !diyHost.isEmpty()) {
                for (Map.Entry<String, String> header : apiPathInfo.parametesHeader.entrySet()) {
                    if (header.getKey() == "Host") {
                        headers.add("Host" + ": " + diyHost);
                    }
                }
            }
            newRquest = helpers.buildHttpMessage(headers, null);
        }

        //body内的参数
        if (apiPathInfo.parametesBody != null) {
            newRquest = helpers.buildHttpMessage(helpers.analyzeRequest(newRquest).getHeaders(), JSON.toJSONBytes(apiPathInfo.parametesBody));
        }

        requestResponse.setRequest(newRquest);
        requestResponse.setResponse("".getBytes());
        return requestResponse;
    }

    public byte[] addParam(byte[] request, String key, String value) {
        List<String> headers = helpers.analyzeRequest(request).getHeaders();
        String path;
        String pathData = headers.get(0);
        String[] pathInfo = pathData.split(" ");
        if (!pathInfo[1].contains("?")) {
            path = pathInfo[1] + "?" + key + "=" + value;
        } else {
            path = pathInfo[1] + "&" + key + "=" + value;
        }
        headers.set(0, pathInfo[0] + " " + path + " " + pathInfo[2]);
        return helpers.buildHttpMessage(headers, null);
    }

    public byte[] buildApiHeader(byte[] req, ApiPathInfo apiPathInfo) {
        List<String> headers = helpers.analyzeRequest(req).getHeaders();
        headers.set(0, apiPathInfo.method.toUpperCase() + " " + apiPathInfo.basePath + apiPathInfo.path + " HTTP/1.1");
        for (String header : headers) {
            if (header.startsWith("Content-Type")) {
                headers.remove(header);
            }
        }
        headers.add("Content-Type: application/json");

        return helpers.buildHttpMessage(headers, null);
    }

    private class APIListTable extends JTable {

        public APIListTable(TableModel dm) {
            super(dm, null, null);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
            SwaggerApiData data = swaggerApiTableMode.getSwaggerApiData().get(rowIndex);
            originalRequestViewer.setMessage(data.getHttpRequestResponse().getRequest(), true);
            originalResponseViewer.setMessage(data.getHttpRequestResponse().getResponse(), false);
            currentlyDisplayedItem = data.getHttpRequestResponse();
            super.changeSelection(rowIndex, columnIndex, toggle, extend);
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            // 不可编辑
            return false;
        }
    }

    private class MessageEditor implements IMessageEditorController {

        public IHttpService getHttpService() {
            return null;
        }

        public byte[] getRequest() {
            return new byte[0];
        }

        public byte[] getResponse() {
            return new byte[0];
        }
    }
}
