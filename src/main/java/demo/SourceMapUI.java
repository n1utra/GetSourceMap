package demo;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class SourceMapUI {
    private static SourceMapUI instance;
    
    private final MontoyaApi api;
    private final JPanel mainPanel;
    private final SourceMapTableModel tableModel;
    private final JTable resultsTable;
    private final HttpRequestEditor requestViewer;
    private final HttpResponseEditor responseViewer;
    private final List<SourceMapResult> results;
    private final List<SourceMapResult> filteredResults;
    private final Set<String> processedUrls = new HashSet<>();
    private final JTextField searchField;
    private final JCheckBox deduplicateCheckbox;
    // 添加状态码范围筛选复选框
    private final JCheckBox status2xxCheckbox;
    private final JCheckBox status3xxCheckbox;
    private final JCheckBox status4xxCheckbox;
    private final JCheckBox status5xxCheckbox;
    // 添加工具来源复选框
    private final JCheckBox proxyCheckbox;
    private final JCheckBox intruderCheckbox;
    private final JCheckBox repeaterCheckbox;

    public SourceMapUI(MontoyaApi api) {
        this.api = api;
        this.results = new ArrayList<>();
        this.filteredResults = new ArrayList<>();
        instance = this;
        
        // 创建主面板
        mainPanel = new JPanel(new BorderLayout());
        
        // 创建顶部控制面板
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlPanel.add(new JLabel("SourceMap Results:"));
        
        // 添加工具来源复选框
        proxyCheckbox = new JCheckBox("Proxy", true);
        proxyCheckbox.addActionListener(e -> filterResults());
        controlPanel.add(proxyCheckbox);
        
        intruderCheckbox = new JCheckBox("Intruder", true);
        intruderCheckbox.addActionListener(e -> filterResults());
        controlPanel.add(intruderCheckbox);
        
        repeaterCheckbox = new JCheckBox("Repeater", true);
        repeaterCheckbox.addActionListener(e -> filterResults());
        controlPanel.add(repeaterCheckbox);
        
        // 添加搜索框
        searchField = new JTextField(20);
        searchField.setToolTipText("支持通配符*的域名搜索");
        searchField.addActionListener(e -> filterResults());
        controlPanel.add(new JLabel("搜索域名:"));
        controlPanel.add(searchField);
        
        // 添加去重复选框
        deduplicateCheckbox = new JCheckBox("是否去重", false);
        deduplicateCheckbox.addActionListener(e -> {
            // 当更改去重选项时，需要重新处理所有结果
            if (!deduplicateCheckbox.isSelected()) {
                processedUrls.clear();
            }
            filterResults();
        });
        controlPanel.add(deduplicateCheckbox);
        
        // 添加状态码范围筛选复选框
        status2xxCheckbox = new JCheckBox("2XX", true);
        status2xxCheckbox.addActionListener(e -> filterResults());
        controlPanel.add(status2xxCheckbox);
        
        status3xxCheckbox = new JCheckBox("3XX", true);
        status3xxCheckbox.addActionListener(e -> filterResults());
        controlPanel.add(status3xxCheckbox);
        
        status4xxCheckbox = new JCheckBox("4XX", true);
        status4xxCheckbox.addActionListener(e -> filterResults());
        controlPanel.add(status4xxCheckbox);
        
        status5xxCheckbox = new JCheckBox("5XX", true);
        status5xxCheckbox.addActionListener(e -> filterResults());
        controlPanel.add(status5xxCheckbox);
        
        // 创建表格模型和表格
        tableModel = new SourceMapTableModel();
        resultsTable = new JTable(tableModel);
        resultsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        
        // 设置表格列宽比例
        setupColumnWidths();
        
        // 添加排序功能
        TableRowSorter<SourceMapTableModel> sorter = new TableRowSorter<>(tableModel);
        resultsTable.setRowSorter(sorter);
        
        // 设置居中对齐渲染器
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        resultsTable.getColumnModel().getColumn(0).setCellRenderer(centerRenderer); // 序号列
        resultsTable.getColumnModel().getColumn(2).setCellRenderer(centerRenderer); // 状态码列
        resultsTable.getColumnModel().getColumn(3).setCellRenderer(centerRenderer); // 响应长度列
        resultsTable.getColumnModel().getColumn(4).setCellRenderer(centerRenderer); // Maybe Vuln 列
        
        // 创建 Burp 的 Request 和 Response 查看器
        requestViewer = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseViewer = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        
        // 创建请求和响应显示区域，使用 Burp 风格的展示方式
        JSplitPane requestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        // 请求面板
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestPanel.add(requestViewer.uiComponent(), BorderLayout.CENTER);
        
        // 响应面板
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responsePanel.add(responseViewer.uiComponent(), BorderLayout.CENTER);
        
        requestResponseSplitPane.setLeftComponent(requestPanel);
        requestResponseSplitPane.setRightComponent(responsePanel);
        requestResponseSplitPane.setDividerLocation(0.5);
        requestResponseSplitPane.setResizeWeight(0.5);
        
        // 创建包含表格和详情区域的垂直分割面板
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        
        // 添加滚动面板
        JScrollPane tableScrollPane = new JScrollPane(resultsTable);
        
        // 设置主分割面板
        mainSplitPane.setTopComponent(tableScrollPane);
        mainSplitPane.setBottomComponent(requestResponseSplitPane);
        mainSplitPane.setDividerLocation(0.7); // 默认将70%的空间分配给表格
        mainSplitPane.setResizeWeight(0.7); // 调整大小时70%的空间分配给表格
        
        // 布局
        mainPanel.add(controlPanel, BorderLayout.NORTH);
        mainPanel.add(mainSplitPane, BorderLayout.CENTER);
        
        // 设置表格行高
        resultsTable.setRowHeight(25);
        
        // 添加表格选择监听器
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = resultsTable.getSelectedRow();
                if (selectedRow >= 0 && selectedRow < resultsTable.getRowCount()) {
                    // 获取实际的模型行索引（考虑排序）
                    int modelIndex = resultsTable.convertRowIndexToModel(selectedRow);
                    if (modelIndex >= 0 && modelIndex < filteredResults.size()) {
                        SourceMapResult result = filteredResults.get(modelIndex);
                        
                        try {
                            // 解析请求和响应并显示在 Burp 查看器中
                            HttpRequest request = HttpRequest.httpRequest(result.getRequest());
                            requestViewer.setRequest(request);
                            
                            HttpResponse response = HttpResponse.httpResponse(result.getResponse());
                            responseViewer.setResponse(response);
                        } catch (Exception ex) {
                            api.logging().logToError("Error parsing HTTP message: " + ex.getMessage());
                            // 如果解析失败，则清空查看器
                            requestViewer.setRequest(HttpRequest.httpRequest(""));
                            responseViewer.setResponse(HttpResponse.httpResponse(""));
                        }
                    }
                }
            }
        });
        
        // 添加右键菜单
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyUrlItem = new JMenuItem("Copy URL");
        JMenuItem copySelectedUrlsItem = new JMenuItem("Copy Selected URLs");
        JMenuItem copyAllUrlsItem = new JMenuItem("Copy All URLs");
        
        copyUrlItem.addActionListener(e -> {
            int selectedRow = resultsTable.getSelectedRow();
            if (selectedRow >= 0) {
                // 获取实际的模型行索引（考虑排序）
                int modelIndex = resultsTable.convertRowIndexToModel(selectedRow);
                if (modelIndex < filteredResults.size()) {
                    String url = filteredResults.get(modelIndex).getUrl();
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
                    api.logging().logToOutput("Copied URL to clipboard: " + url);
                }
            }
        });
        
        // 添加复制选中URL的功能
        copySelectedUrlsItem.addActionListener(e -> {
            int[] selectedRows = resultsTable.getSelectedRows();
            if (selectedRows.length > 0) {
                StringBuilder urls = new StringBuilder();
                for (int selectedRow : selectedRows) {
                    // 获取实际的模型行索引（考虑排序）
                    int modelIndex = resultsTable.convertRowIndexToModel(selectedRow);
                    if (modelIndex < filteredResults.size()) {
                        urls.append(filteredResults.get(modelIndex).getUrl()).append("\n");
                    }
                }
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(urls.toString()), null);
                api.logging().logToOutput("Copied " + selectedRows.length + " selected URLs to clipboard");
            }
        });
        
        copyAllUrlsItem.addActionListener(e -> {
            StringBuilder urls = new StringBuilder();
            for (SourceMapResult result : filteredResults) {
                urls.append(result.getUrl()).append("\n");
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(urls.toString()), null);
            api.logging().logToOutput("Copied all URLs to clipboard");
        });
        
        popupMenu.add(copyUrlItem);
        popupMenu.add(copySelectedUrlsItem);
        popupMenu.add(copyAllUrlsItem);
        
        resultsTable.setComponentPopupMenu(popupMenu);
        
        // 添加双击事件查看详细信息
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int selectedRow = resultsTable.getSelectedRow();
                    if (selectedRow >= 0) {
                        // 获取实际的模型行索引（考虑排序）
                        int modelIndex = resultsTable.convertRowIndexToModel(selectedRow);
                        if (modelIndex >= 0 && modelIndex < filteredResults.size()) {
                            SourceMapResult result = filteredResults.get(modelIndex);
                            showDetailDialog(result);
                        }
                    }
                }
            }
        });
        
        // 初始化查看器为空内容
        requestViewer.setRequest(HttpRequest.httpRequest(""));
        responseViewer.setResponse(HttpResponse.httpResponse(""));
    }
    
    public static SourceMapUI getInstance() {
        return instance;
    }
    
    private void setupColumnWidths() {
        if (resultsTable.getColumnCount() < 5) return;
        
        // 设置列宽比例
        TableColumn indexColumn = resultsTable.getColumnModel().getColumn(0);
        indexColumn.setPreferredWidth(25); // 序号列约占5%
        
        TableColumn urlColumn = resultsTable.getColumnModel().getColumn(1);
        urlColumn.setPreferredWidth(400); // URL列约占70%
        
        TableColumn statusCodeColumn = resultsTable.getColumnModel().getColumn(2);
        statusCodeColumn.setPreferredWidth(50); // 状态码列约占5%
        
        TableColumn responseLengthColumn = resultsTable.getColumnModel().getColumn(3);
        responseLengthColumn.setPreferredWidth(75); // 响应长度列约占10%
        
        TableColumn maybeVulnColumn = resultsTable.getColumnModel().getColumn(4);
        maybeVulnColumn.setPreferredWidth(75); // Maybe Vuln列约占10%
    }
    
    public static void addToResults(SourceMapResult result) {
        if (instance != null) {
            SwingUtilities.invokeLater(() -> instance.addResult(result));
        }
    }
    
    private void addResult(SourceMapResult result) {
        // 检查是否启用去重功能
        if (deduplicateCheckbox.isSelected()) {
            if (processedUrls.contains(result.getUrl())) {
                return; // 如果启用了去重并且URL已处理过，则跳过
            }
            processedUrls.add(result.getUrl());
        }
        
        results.add(result);
        filterResults(); // 更新过滤后的结果
    }
    
    private void filterResults() {
        String searchText = searchField.getText().trim();
        filteredResults.clear();
        
        // 获取工具来源筛选选项
        boolean showProxy = proxyCheckbox.isSelected();
        boolean showIntruder = intruderCheckbox.isSelected();
        boolean showRepeater = repeaterCheckbox.isSelected();
        
        // 获取状态码筛选选项
        boolean show2xx = status2xxCheckbox.isSelected();
        boolean show3xx = status3xxCheckbox.isSelected();
        boolean show4xx = status4xxCheckbox.isSelected();
        boolean show5xx = status5xxCheckbox.isSelected();
        
        List<SourceMapResult> statusFilteredResults = new ArrayList<>();
        
        // 首先根据状态码范围筛选
        for (SourceMapResult result : results) {
            int statusCode = result.getStatusCode();
            boolean shouldInclude = false;
            
            if (show2xx && statusCode >= 200 && statusCode < 300) {
                shouldInclude = true;
            } else if (show3xx && statusCode >= 300 && statusCode < 400) {
                shouldInclude = true;
            } else if (show4xx && statusCode >= 400 && statusCode < 500) {
                shouldInclude = true;
            } else if (show5xx && statusCode >= 500 && statusCode < 600) {
                shouldInclude = true;
            }
            
            if (shouldInclude) {
                statusFilteredResults.add(result);
            }
        }
        
        if (searchText.isEmpty()) {
            filteredResults.addAll(statusFilteredResults);
        } else {
            // 实现通配符匹配
            String regexPattern;
            if (searchText.startsWith("*.")) {
                // 特殊处理 *.domain.com 格式，匹配所有包含 domain.com 的域名
                String domain = searchText.substring(2); // 移除 "*."
                regexPattern = ".*" + Pattern.quote(domain) + ".*";
            } else {
                // 普通通配符处理
                regexPattern = searchText.replace("*", ".*").replace(".", "\\.");
            }
            
            Pattern pattern;
            try {
                pattern = Pattern.compile(regexPattern, Pattern.CASE_INSENSITIVE);
            } catch (PatternSyntaxException e) {
                // 如果正则表达式无效，则回退到简单包含检查
                pattern = null;
            }
            
            for (SourceMapResult result : statusFilteredResults) {
                try {
                    URL url = new URL(result.getUrl());
                    String host = url.getHost();
                    
                    boolean match;
                    if (pattern != null) {
                        match = pattern.matcher(host).matches();
                    } else {
                        match = host.contains(searchText);
                    }
                    
                    if (match) {
                        filteredResults.add(result);
                    }
                } catch (MalformedURLException e) {
                    // 如果URL格式无效，则尝试直接匹配整个URL
                    boolean match;
                    if (pattern != null) {
                        match = pattern.matcher(result.getUrl()).matches();
                    } else {
                        match = result.getUrl().contains(searchText);
                    }
                    
                    if (match) {
                        filteredResults.add(result);
                    }
                }
            }
        }
        
        tableModel.fireTableDataChanged();
        setupColumnWidths();
    }
    
    public Component getUiComponent() {
        return mainPanel;
    }
    
    public void saveData() {
        // 在扩展卸载时保存数据的逻辑
        api.logging().logToOutput("Saving SourceMap data...");
    }
    
    private void showDetailDialog(SourceMapResult result) {
        JDialog dialog = new JDialog((JFrame) null, "SourceMap Detail", true);
        dialog.setLayout(new BorderLayout());
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        // 创建 Burp 的 Request 和 Response 查看器
        HttpRequestEditor detailRequestViewer = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        HttpResponseEditor detailResponseViewer = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        
        try {
            // 解析请求和响应并显示在 Burp 查看器中
            HttpRequest request = HttpRequest.httpRequest(result.getRequest());
            detailRequestViewer.setRequest(request);
            
            HttpResponse response = HttpResponse.httpResponse(result.getResponse());
            detailResponseViewer.setResponse(response);
        } catch (Exception ex) {
            api.logging().logToError("Error parsing HTTP message in dialog: " + ex.getMessage());
        }
        
        splitPane.setLeftComponent(detailRequestViewer.uiComponent());
        splitPane.setRightComponent(detailResponseViewer.uiComponent());
        splitPane.setDividerLocation(0.5);
        splitPane.setResizeWeight(0.5);
        
        dialog.add(splitPane, BorderLayout.CENTER);
        dialog.setSize(800, 600);
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }
    
    // 表格模型类
    private class SourceMapTableModel extends AbstractTableModel {
        private final String[] columnNames = {"#", "URL", "Status Code", "Response Length", "Maybe Vuln"};
        
        @Override
        public int getRowCount() {
            return filteredResults.size();
        }
        
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }
        
        @Override
        public Class<?> getColumnClass(int columnIndex) {
            switch (columnIndex) {
                case 0: // 序号
                    return Integer.class;
                case 2: // 状态码
                case 3: // 响应长度
                    return Integer.class;
                case 4: // Maybe Vuln
                    return String.class; // 修改为String类型
                case 1: // URL
                default:
                    return String.class;
            }
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex >= filteredResults.size()) {
                return "";
            }
            
            SourceMapResult result = filteredResults.get(rowIndex);
            switch (columnIndex) {
                case 0: // 序号
                    return rowIndex + 1;
                case 1: // URL
                    return result.getUrl();
                case 2: // 状态码
                    return result.getStatusCode();
                case 3: // 响应长度
                    return result.getResponseLength();
                case 4: // Maybe Vuln - 修改为显示"Maybe"或空字符串
                    return result.isMaybeVuln() ? "Maybe" : "";
                default:
                    return "";
            }
        }
    }
    
    // Getters for tool source checkboxes
    public JCheckBox getProxyCheckbox() {
        return proxyCheckbox;
    }
    
    public JCheckBox getIntruderCheckbox() {
        return intruderCheckbox;
    }
    
    public JCheckBox getRepeaterCheckbox() {
        return repeaterCheckbox;
    }
}