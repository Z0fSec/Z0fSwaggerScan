package burp;

import burp.UIHepler.GridBagConstraintsHelper;
import burp.entity.SwaggerApiData;
import burp.entity.PermBean;
import burp.util.HttpRequestResponse;
import burp.util.Utils;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.io.FileUtil;
import cn.hutool.json.JSONUtil;
import cn.hutool.poi.excel.ExcelUtil;
import cn.hutool.poi.excel.ExcelWriter;
import lombok.Data;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static burp.SwaggerApiPanel.swaggerApiTableMode;
import static burp.dao.PermDao.*;

public class AuthDataPanel extends JPanel implements IMessageEditorController {
    private static final List<PermEntry> permLogList = new ArrayList<>(); // permLogList 用于存储请求
    private static PrintWriter std;
    private static JTable permTable; // perm表格
    private final IBurpExtenderCallbacks iBurpExtenderCallbacks;
    private JPanel panel; // 主面板
    private JSplitPane mainsplitPane;
    private JPanel rightSplitPane; // 右边面板
    private IHttpRequestResponse currentlyDisplayedItem; // 当前显示的请求
    private JPanel lowpermPane; // 低权限请求面板
    private JPanel nopermPane; // 无权限请求面板
    private JTextArea highPermAuthTextArea; // 高权限请求头输入框
    private JButton batchCheckAPIButton; // API批量检测按钮
    private JButton saveAuthDataButton; // 保存认证数据按钮
    private JButton refreshButton; // 刷新按钮
    private JButton clearButton; // 清空数据按钮
    private JButton exportJsonButton; // 导出Json按钮
    private JButton exportXlsxButton; // 导出xlsx按钮
    private JTextArea lowPermAuthTextArea; // 低权限认证请求信息输入框
    private JTextArea noPermAuthTextArea; // 无权限认证请求信息输入框
    private IMessageEditor originarequest;  // 原始请求
    private IMessageEditor originaresponse; // 原始响应
    private IMessageEditor lowpermrequest; // 低权限请求
    private IMessageEditor lowpermresponse; // 低权限响应
    private IMessageEditor nopermrequest; // 无权限请求
    private IMessageEditor nopermresponse; // 无权限响应
    private JScrollPane noPermAuthTextAreascrollPane;
    private JLabel highPermLabel;  // 高权限请求头Label
    private JScrollPane highPermTextAreascrollPane;
    private JScrollPane lowPermAuthTextAreascrollPane;
    private JLabel lowPermAuthLabel; // 低权限认证请求信息Label
    private JLabel noPermAuthLabel;  // 无权限认证请求信息Label
    private JPanel rightPanel;
    private JPanel rightTopPane;

    private final ExecutorService executor;

    public AuthDataPanel(IBurpExtenderCallbacks iBurpExtenderCallbacks, PrintWriter std) {
        this.iBurpExtenderCallbacks = iBurpExtenderCallbacks;
        AuthDataPanel.std = std;
        initComponent();
        initEvent();
        executor = Executors.newFixedThreadPool(1); // 限制最大线程数为1
    }

    // 右键检测方法
    public static void CheckByMenuItem(IHttpRequestResponse[] responses, String env) {
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        String url = analyzeRequest.getUrl().toString();
        // url 中匹配为静态资源
        if (Utils.isUrlBlackListSuffix(url)) {
            return;
        }
        std.println("[*]APIAuthTest: " + url);
        sendDefaultHttp(baseRequestResponse, analyzeRequest, env);
    }

    // 核心检测方法
    public static void CheckPerm(HttpRequestResponse responses, String env) {
        IHttpRequestResponse baseRequestResponse = responses.getIHttpRequestResponse();
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        std.println("[*]APIAuthTest: " + responses.getPath());
        sendDefaultHttp(responses, analyzeRequest, env);
    }

    private static void sendDefaultHttp(IHttpRequestResponse baseRequestResponse, IRequestInfo analyzeRequest, String env) {
        // 原始请求
        List<String> originalheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        List<PermBean> permBeanHighAuth = getPermListsByType("permHighAuth");
        for (PermBean permBean : permBeanHighAuth) {
            String highAuthText = permBean.getValue();
            String head = highAuthText.split(":")[0];
            boolean headerFound = false;
            for (int i = 0; i < originalheaders.size(); i++) {
                String highheader = originalheaders.get(i);
                if (highheader.contains(head)) {
                    originalheaders.set(i, highAuthText);
                    headerFound = true;
                    break;
                }
            }
            if (!headerFound) {
                originalheaders.add(highAuthText);
            }
        }

        byte[] byte_Request = baseRequestResponse.getRequest();
        String method = Utils.helpers.analyzeRequest(baseRequestResponse).getMethod();
        String url = Utils.helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
        int bodyOffset = Utils.helpers.analyzeRequest(baseRequestResponse).getBodyOffset();
        int len = byte_Request.length;
        byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, len);
        byte[] highMessage = Utils.helpers.buildHttpMessage(originalheaders, body);
        IHttpRequestResponse highRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), highMessage);
        byte[] highResponseBody = highRequestResponse.getResponse();
        String originallength = "";
        if (highResponseBody != null) {
            IResponseInfo originalReqResponse = Utils.helpers.analyzeResponse(highResponseBody);
            List<String> headers = originalReqResponse.getHeaders();
            for (String header : headers) {
                if (header.contains("Content-Length")) {
                    originallength = header.split(":")[1].trim();
                    break;
                }
            }
        }
        if (originallength.isEmpty()) {
            assert highResponseBody != null;
            originallength = String.valueOf(highResponseBody.length);
        }
        // 如果原始请求的响应体为空，则不进行后续操作
        if (highResponseBody == null) {
            return;
        }

        // 获取低权限数据去构造请求
        List<String> lowheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        List<PermBean> permBeanLowAuth = getPermListsByType("permLowAuth");
        for (PermBean permBean : permBeanLowAuth) {
            String lowAuthText = permBean.getValue();
            String head = lowAuthText.split(":")[0];
            boolean headerFound = false;
            for (int i = 0; i < lowheaders.size(); i++) {
                String lowheader = lowheaders.get(i);
                if (lowheader.contains(head)) {
                    lowheaders.set(i, lowAuthText);
                    headerFound = true;
                    break;
                }
            }
            if (!headerFound) {
                lowheaders.add(lowAuthText);
            }
        }

        byte[] lowMessage = Utils.helpers.buildHttpMessage(lowheaders, body);
        IHttpRequestResponse lowRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), lowMessage);
        byte[] lowresponseBody = lowRequestResponse.getResponse();
        String lowlength = "";
        IResponseInfo lowReqResponse = Utils.helpers.analyzeResponse(lowresponseBody);
        List<String> lowReqResheaders = lowReqResponse.getHeaders();
        for (String header : lowReqResheaders) {
            if (header.contains("Content-Length")) {
                lowlength = header.split(":")[1].trim();
                break;
            }
        }

        if (lowlength.isEmpty()) {
            lowlength = String.valueOf(lowresponseBody.length);
        }

        // 无权限请求
        List<String> noheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        List<PermBean> permBeanNoAuth = getPermListsByType("permNoAuth");
        List<String> updatedHeaders = new ArrayList<>();

        for (String header : noheaders) {
            boolean shouldKeep = true;
            for (PermBean permBean : permBeanNoAuth) {
                String noAuthText = permBean.getValue();
                if (header.contains(noAuthText)) {
                    shouldKeep = false;
                    break;
                }
            }
            if (shouldKeep) {
                updatedHeaders.add(header);
            }
        }

        // 更新原始的noheaders列表
        noheaders.clear();
        noheaders.addAll(updatedHeaders);

        byte[] noMessage = Utils.helpers.buildHttpMessage(noheaders, body);
        IHttpRequestResponse noRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), noMessage);
        byte[] noresponseBody = noRequestResponse.getResponse();
        String nolength = "";
        IResponseInfo noReqResponse = Utils.helpers.analyzeResponse(noresponseBody);
        List<String> noReqResheaders = noReqResponse.getHeaders();
        for (String header : noReqResheaders) {
            if (header.contains("Content-Length")) {
                nolength = header.split(":")[1].trim();
                break;
            }
        }
        if (nolength.isEmpty()) {
            nolength = String.valueOf(noresponseBody.length);
        }
        String isSuccess = "×";
        if (originallength.equals(lowlength) && lowlength.equals(nolength)) {
            isSuccess = "可能存在";
        } else {
            isSuccess = "不存在";
        }

        add(env, method, url, originallength, lowlength, nolength, isSuccess, highRequestResponse, lowRequestResponse, noRequestResponse);
    }

    private static void add(String env, String method, String url, String originalength, String lowlength, String nolength, String isSuccess, IHttpRequestResponse baseRequestResponse, IHttpRequestResponse lowRequestResponse, IHttpRequestResponse noRequestResponse) {
        synchronized (permLogList) {
            int id = permLogList.size();
            permLogList.add(new PermEntry(id, env, method, url, originalength, lowlength, nolength, isSuccess, baseRequestResponse, lowRequestResponse, noRequestResponse));
            permTable.updateUI();
        }
    }

    /**
     * 初始化组件
     */

    public void initComponent() {
        panel = new JPanel();
        panel.setLayout(new BorderLayout());
        panel.setMaximumSize(panel.getPreferredSize()); // 设置最大尺寸等于首选尺寸，禁止自动调整
        mainsplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainsplitPane.setResizeWeight(0.9);

        // 左边的面板
        // 左边的面板上下分割,比例为7：3
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftSplitPane.setResizeWeight(0.7);
        leftSplitPane.setDividerLocation(0.7);

        // 将urlTable添加到leftSplitPane的上边
        JScrollPane leftScrollPane = new JScrollPane();
        permTable = new URLTable(new PermModel());
        permTable.setAutoCreateRowSorter(true);
        leftScrollPane.setViewportView(permTable);
        leftSplitPane.setTopComponent(leftScrollPane);

        // 左边的面板下部分对称分割，比例为5：5
        JSplitPane leftBottomSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        leftBottomSplitPane.setResizeWeight(0.5);
        leftBottomSplitPane.setDividerLocation(0.5);
        leftSplitPane.setBottomComponent(leftBottomSplitPane);

        // 请求tab
        JTabbedPane tabbedPanereqresp = new JTabbedPane();
        // 添加原始请求面板
        // 原始请求面板
        JPanel originPane = new JPanel(new BorderLayout());
        final JSplitPane originPaneSplitPane = new JSplitPane();
        originPaneSplitPane.setDividerSize(1);
        originPaneSplitPane.setResizeWeight(0.5);
        originarequest = iBurpExtenderCallbacks.createMessageEditor(AuthDataPanel.this, true);
        originaresponse = iBurpExtenderCallbacks.createMessageEditor(AuthDataPanel.this, false);
        originPaneSplitPane.setLeftComponent(originarequest.getComponent());
        originPaneSplitPane.setRightComponent(originaresponse.getComponent());
        originPane.add(originPaneSplitPane, BorderLayout.CENTER);
        tabbedPanereqresp.addTab("高权限请求包", originPane);

        // 添加低权限请求面板
        lowpermPane = new JPanel(new BorderLayout());
        final JSplitPane lowpermPaneSplitPane = new JSplitPane();
        lowpermPaneSplitPane.setDividerSize(1);
        lowpermPaneSplitPane.setResizeWeight(0.5);
        lowpermrequest = iBurpExtenderCallbacks.createMessageEditor(AuthDataPanel.this, true);
        lowpermresponse = iBurpExtenderCallbacks.createMessageEditor(AuthDataPanel.this, false);
        lowpermPaneSplitPane.setLeftComponent(lowpermrequest.getComponent());
        lowpermPaneSplitPane.setRightComponent(lowpermresponse.getComponent());
        lowpermPane.add(lowpermPaneSplitPane, BorderLayout.CENTER);
        tabbedPanereqresp.addTab("低权限请求包", lowpermPane);

        // 添加无权限请求面板
        nopermPane = new JPanel(new BorderLayout());
        final JSplitPane nopermPaneSplitPane = new JSplitPane();
        nopermPaneSplitPane.setDividerSize(1);
        nopermPaneSplitPane.setResizeWeight(0.5);
        nopermrequest = iBurpExtenderCallbacks.createMessageEditor(AuthDataPanel.this, true);
        nopermresponse = iBurpExtenderCallbacks.createMessageEditor(AuthDataPanel.this, false);
        nopermPaneSplitPane.setLeftComponent(nopermrequest.getComponent());
        nopermPaneSplitPane.setRightComponent(nopermresponse.getComponent());
        nopermPane.add(nopermPaneSplitPane, BorderLayout.CENTER);
        tabbedPanereqresp.addTab("无权限请求包", nopermPane);

        // 请求tab添加到leftBottomSplitPane的左边
        leftBottomSplitPane.setLeftComponent(tabbedPanereqresp);

        // 将leftSplitPane添加到mainsplitPane的左边
        mainsplitPane.add(leftSplitPane);

        rightPanel = new JPanel(new BorderLayout());
        rightTopPane = new JPanel(new GridBagLayout());
        rightSplitPane = new JPanel(new GridBagLayout());
        // 右边的上面
        // 高权限请求头Label
        highPermLabel = new JLabel("高权限认证请求信息");
        // 高权限请求头输入框
        highPermAuthTextArea = new JTextArea(5, 10);
        highPermAuthTextArea.setLineWrap(false); // 自动换行
        highPermAuthTextArea.setWrapStyleWord(false); // 按单词换行
        highPermTextAreascrollPane = new JScrollPane(highPermAuthTextArea);

        // API批量检测按钮
        batchCheckAPIButton = new JButton("API批量检测");
        // 保存认证数据按钮
        saveAuthDataButton = new JButton("保存认证数据");
        // 刷新按钮
        refreshButton = new JButton("刷新表格");
        // 清空数据按钮
        clearButton = new JButton("清空表格");

        exportJsonButton = new JButton("导出Json");
        exportXlsxButton = new JButton("导出Xlsx");

        // 右边的下部分
        // 低权限认证请求信息Label
        lowPermAuthLabel = new JLabel("低权限认证请求信息");
        // 低权限认证请求信息输入框
        lowPermAuthTextArea = new JTextArea(5, 10);
        lowPermAuthTextArea.setLineWrap(false); // 自动换行
        lowPermAuthTextArea.setWrapStyleWord(false); // 按单词换行
        lowPermAuthTextAreascrollPane = new JScrollPane(lowPermAuthTextArea);

        // 无权限认证请求信息Label
        noPermAuthLabel = new JLabel("无权限认证请求信息(输入请求头信息，不输入请求体信息)");
        // 无权限认证请求信息输入框
        noPermAuthTextArea = new JTextArea(5, 10);
        noPermAuthTextArea.setLineWrap(false); // 自动换行
        noPermAuthTextArea.setWrapStyleWord(false); // 按单词换行
        noPermAuthTextAreascrollPane = new JScrollPane(noPermAuthTextArea);

        rightTopPane.add(exportJsonButton, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPane.add(exportXlsxButton, new GridBagConstraintsHelper(1, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
//        // passiveScanCheckBox和hightPermHeaderCheckBox在第一行
        rightTopPane.add(refreshButton, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPane.add(clearButton, new GridBagConstraintsHelper(1, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
//        // saveWhiteListButton和saveAuthDataButton在第二行
        rightTopPane.add(batchCheckAPIButton, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPane.add(saveAuthDataButton, new GridBagConstraintsHelper(1, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // highPermLabel在第三行
        rightTopPane.add(highPermLabel, new GridBagConstraintsHelper(0, 3, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // hightPermTextArea在第四行
        rightTopPane.add(highPermTextAreascrollPane, new GridBagConstraintsHelper(0, 4, 2, 1).setInsets(5).setIpad(0, 0).setWeight(1, 1).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        // lowPermAuthLabel在第六行
        rightSplitPane.add(lowPermAuthLabel, new GridBagConstraintsHelper(0, 0, 2, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // lowPermAuthTextArea在第七行
        rightSplitPane.add(lowPermAuthTextAreascrollPane, new GridBagConstraintsHelper(0, 1, 2, 1).setInsets(5).setIpad(0, 0).setWeight(1, 1).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        // noPermAuthLabel在第八行
        rightSplitPane.add(noPermAuthLabel, new GridBagConstraintsHelper(0, 2, 2, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // noPermAuthTextArea在第九行
        rightSplitPane.add(noPermAuthTextAreascrollPane, new GridBagConstraintsHelper(0, 3, 2, 1).setInsets(5).setIpad(0, 0).setWeight(1, 1).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));

        rightPanel.add(rightTopPane, BorderLayout.NORTH);
        rightPanel.add(rightSplitPane, BorderLayout.CENTER);
        // 将rightSplitPane添加到mainsplitPane的右边
        mainsplitPane.add(new JScrollPane(rightPanel));
        panel.add(mainsplitPane);
        setLayout(new BorderLayout());
        add(panel);
    }

    /**
     * 初始化事件
     */
    public void initEvent() {

        // 批量检测
        batchCheckAPIButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                final List<SwaggerApiData> swaggerApiDataList = swaggerApiTableMode.getSwaggerApiData();
                std.println("当前共有API数：" + swaggerApiDataList.size());
                for (SwaggerApiData swaggerApiData : swaggerApiDataList) {
                    std.println(swaggerApiData.getUrl());
                    Thread thread = new Thread(new Runnable() {
                        @Override
                        public void run() {
                            CheckPerm(swaggerApiData.getHttpRequestResponse(), "批量");
                        }
                    });
                    thread.start();
                }
            }
        });

        // 保存认证数据
        saveAuthDataButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String highPermAuthText = highPermAuthTextArea.getText();
                String lowPermAuthText = lowPermAuthTextArea.getText();
                String noPermAuthText = noPermAuthTextArea.getText();
                deletePerm("permHighAuth");
                deletePerm("permLowAuth");
                deletePerm("permNoAuth");
                if (highPermAuthText.contains("\n")) {
                    String[] split = highPermAuthText.split("\n");
                    for (String highAuth : split) {
                        PermBean permBean = new PermBean("permHighAuth", highAuth);
                        savePerm(permBean);
                    }
                } else {
                    PermBean permBean = new PermBean("permLowAuth", lowPermAuthText);
                    savePerm(permBean);
                }
                if (lowPermAuthText.contains("\n")) {
                    String[] split = lowPermAuthText.split("\n");
                    for (String lowAuth : split) {
                        PermBean permBean = new PermBean("permLowAuth", lowAuth);
                        savePerm(permBean);
                    }
                } else {
                    PermBean permBean = new PermBean("permLowAuth", lowPermAuthText);
                    savePerm(permBean);
                }
                if (noPermAuthText.contains("\n")) {
                    String[] split = noPermAuthText.split("\n");
                    for (String noAuth : split) {
                        PermBean permBean = new PermBean("permNoAuth", noAuth);
                        savePerm(permBean);
                    }
                } else {
                    PermBean permBean = new PermBean("permNoAuth", noPermAuthText);
                    savePerm(permBean);
                }
                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // 刷新
        refreshButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                permTable.updateUI();
            }
        });

        // 清空
        clearButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                permLogList.clear();
                originarequest.setMessage(new byte[0], true);
                originaresponse.setMessage(new byte[0], false);
                lowpermrequest.setMessage(new byte[0], false);
                lowpermresponse.setMessage(new byte[0], false);
                nopermrequest.setMessage(new byte[0], false);
                nopermresponse.setMessage(new byte[0], false);
                permTable.updateUI();
            }
        });
        // 导出API测试状态为 Json 文件
        exportJsonButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<SwaggerApiData> swaggerApiDataList = swaggerApiTableMode.getSwaggerApiData();
                String json = JSONUtil.toJsonStr(swaggerApiDataList);
                if (swaggerApiDataList.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "暂无数据", "提示", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
                Date date = DateUtil.date();
                String dataStr = DateUtil.format(date, "yyyyMMddHHmmssSSS");
                FileUtil.writeString(json, "D:\\Z0fData\\api" + dataStr + ".json", "UTF-8");
                JOptionPane.showMessageDialog(null, "保存成功，请到D:\\Z0fData查看", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // permBeanHighAuth
        List<PermBean> permBeanHighAuth = getPermListsByType("permHighAuth");
        for (PermBean permBean : permBeanHighAuth) {
            // 如果是最后一个，就不加换行符
            if (permBeanHighAuth.indexOf(permBean) == permBeanHighAuth.size() - 1) {
                highPermAuthTextArea.setText(highPermAuthTextArea.getText() + permBean.getValue());
                break;
            }
            highPermAuthTextArea.setText(highPermAuthTextArea.getText() + permBean.getValue() + "\n");
        }

        // permLowAuth输入框
        List<PermBean> permBeanLowAuth = getPermListsByType("permLowAuth");
        for (PermBean permBean : permBeanLowAuth) {
            // 如果是最后一个，就不加换行符
            if (permBeanLowAuth.indexOf(permBean) == permBeanLowAuth.size() - 1) {
                lowPermAuthTextArea.setText(lowPermAuthTextArea.getText() + permBean.getValue());
                break;
            }
            lowPermAuthTextArea.setText(lowPermAuthTextArea.getText() + permBean.getValue() + "\n");
        }

        // permNoAuth输入框
        List<PermBean> permBeanNoAuth = getPermListsByType("permNoAuth");
        for (PermBean permBean : permBeanNoAuth) {
            // 如果是最后一个，就不加换行符
            if (permBeanNoAuth.indexOf(permBean) == permBeanNoAuth.size() - 1) {
                noPermAuthTextArea.setText(noPermAuthTextArea.getText() + permBean.getValue());
                break;
            }
            noPermAuthTextArea.setText(noPermAuthTextArea.getText() + permBean.getValue() + "\n");
        }

        // 导出API接口测试结果事件
        exportXlsxButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (permLogList.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "暂无数据", "提示", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
                // 创建ExcelWriter，指定文件路径和分隔符，这里使用逗号分隔符导出Xlsx格式
                ExcelWriter writer = ExcelUtil.getWriter("D:\\Z0fData\\API接口数据" + Utils.getTimeNow() + ".xlsx", "API测试结果集合");
                // 添加标题，根据需要添加别名
                writer.addHeaderAlias("column0", "序号");
                writer.addHeaderAlias("column1", "环境");
                writer.addHeaderAlias("column2", "请求方式");
                writer.addHeaderAlias("column3", "URL");
                writer.addHeaderAlias("column4", "高权限包长度");
                writer.addHeaderAlias("column5", "低权限包长度");
                writer.addHeaderAlias("column6", "无权限包长度");
                writer.addHeaderAlias("column7", "是否存在");
                writer.addHeaderAlias("column8", "高权限包响应体");
                writer.addHeaderAlias("column9", "低权限包响应体");
                writer.addHeaderAlias("column10", "无权限包响应体");
                List<Map<String, Object>> data = new ArrayList<>();
                for (int i = 0; i < permLogList.size(); i++) {
                    Map<String, Object> row1 = new HashMap<>();
                    row1.put("column0", permLogList.get(i).getId());
                    row1.put("column1", permLogList.get(i).getEnv());
                    row1.put("column2", permLogList.get(i).getMethod());
                    row1.put("column3", permLogList.get(i).getUrl());
                    row1.put("column4", permLogList.get(i).getOriginalength());
                    row1.put("column5", permLogList.get(i).getLowlength());
                    row1.put("column6", permLogList.get(i).getNolength());
                    row1.put("column7", permLogList.get(i).getIsSuccess());
                    String highResponse = new String(permLogList.get(i).getRequestResponse().getResponse(), StandardCharsets.UTF_8);
                    if (highResponse.length() > 32767) {
                        highResponse = highResponse.substring(0, 32767);
                    }
                    row1.put("column8", highResponse);
                    String lowResponse = new String(permLogList.get(i).getLowRequestResponse().getResponse(), StandardCharsets.UTF_8);
                    if (lowResponse.length() > 32767) {
                        lowResponse = lowResponse.substring(0, 32767);
                    }
                    row1.put("column9", lowResponse);
                    String noPermResponse = new String(permLogList.get(i).getNoRequestResponse().getResponse(), StandardCharsets.UTF_8);
                    if (noPermResponse.length() > 32767) {
                        noPermResponse = noPermResponse.substring(0, 32767);
                    }
                    row1.put("column10", noPermResponse);
                    data.add(row1);
                }
                // 写入数据到CSV文件
                writer.write(data, true);
                writer.close();
                JOptionPane.showMessageDialog(null, "保存成功，请到D:\\Z0fData\\查看", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });
    }

    // 初始化ui
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

    // perm 模型
    static class PermModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return permLogList.size();
        }

        @Override
        public int getColumnCount() {
            return 8;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return permLogList.get(rowIndex).id;
                case 1:
                    return permLogList.get(rowIndex).env;
                case 2:
                    return permLogList.get(rowIndex).method;
                case 3:
                    return permLogList.get(rowIndex).url;
                case 4:
                    return permLogList.get(rowIndex).originalength;
                case 5:
                    return permLogList.get(rowIndex).lowlength;
                case 6:
                    return permLogList.get(rowIndex).nolength;
                case 7:
                    return permLogList.get(rowIndex).isSuccess;
                default:
                    return null;
            }
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "编号";
                case 1:
                    return "环境";
                case 2:
                    return "请求方式";
                case 3:
                    return "URL";
                case 4:
                    return "原始包长度";
                case 5:
                    return "低权限包长度";
                case 6:
                    return "无权限包长度";
                case 7:
                    return "是否存在";
                default:
                    return null;
            }
        }
    }

    // perm 实体
    @Data
    private static class PermEntry {
        final int id;
        final String env;
        final String method;
        final String url;
        final String originalength;
        final String lowlength;
        final String nolength;
        final String isSuccess;
        IHttpRequestResponse requestResponse;
        IHttpRequestResponse lowRequestResponse;
        IHttpRequestResponse noRequestResponse;

        public PermEntry(int id, String env, String method, String url, String originalength, String lowlength, String nolength, String isSuccess, IHttpRequestResponse requestResponse, IHttpRequestResponse lowRequestResponse, IHttpRequestResponse noRequestResponse) {
            this.id = id;
            this.env = env;
            this.method = method;
            this.url = url;
            this.originalength = originalength;
            this.lowlength = lowlength;
            this.nolength = nolength;
            this.isSuccess = isSuccess;
            this.requestResponse = requestResponse;
            this.lowRequestResponse = lowRequestResponse;
            this.noRequestResponse = noRequestResponse;
        }
    }

    // perm 表格
    private class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            PermEntry logEntry = permLogList.get(row);
            originarequest.setMessage(logEntry.requestResponse.getRequest(), true);
            originaresponse.setMessage(logEntry.requestResponse.getResponse(), false);
            if (logEntry.lowRequestResponse == null || logEntry.noRequestResponse == null) {
                lowpermrequest.setMessage(null, false);
                lowpermresponse.setMessage(null, false);
                nopermrequest.setMessage(null, false);
                nopermresponse.setMessage(null, false);
                return;
            }
            lowpermrequest.setMessage(logEntry.lowRequestResponse.getRequest(), true);
            lowpermresponse.setMessage(logEntry.lowRequestResponse.getResponse(), false);
            nopermrequest.setMessage(logEntry.noRequestResponse.getRequest(), true);
            nopermresponse.setMessage(logEntry.noRequestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

}
