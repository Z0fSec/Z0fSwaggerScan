package burp.entity;


import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;


@Setter
@Getter
@Data
public class SwaggerApiTableMode extends AbstractTableModel {
    private List<SwaggerApiData> swaggerApiData = new ArrayList<>();
    private String[] tableHeader = {"#", "请求方法", "API地址", "接口描述"};

    public int getRowCount() {
        return this.swaggerApiData.size();
    }

    public int getColumnCount() {
        return 4;
    }

    public String getColumnName(int column) {
        return this.tableHeader[column];
    }

    public Object getValueAt(int rowIndex, int columnIndex) {
        SwaggerApiData data = this.swaggerApiData.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return String.valueOf(rowIndex + 1);
            case 1:
                return data.getMethod();
            case 2:
                return data.getUrl();
            case 3:
                return data.getSummary();
            default:
                return "";
        }
    }

    public void addRow(SwaggerApiData data) {
        this.swaggerApiData.add(data);
        fireTableRowsInserted(this.swaggerApiData.size(), this.swaggerApiData.size());
    }

    public void clearRow() {
        this.swaggerApiData.clear();
        fireTableRowsDeleted(this.swaggerApiData.size(), this.swaggerApiData.size());
    }

    public Boolean contiansUrl(String url) {
        if (this.swaggerApiData == null) {
            return false;
        }
        for (SwaggerApiData info : this.swaggerApiData) {
            if (url.equals(info.getUrl())) {
                return true;
            }
        }
        return false;
    }
}