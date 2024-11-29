package burp.entity;


import lombok.Data;

@Data
public class PermBean {
    private int id;
    private String type;
    private String value;

    public PermBean() {
    }

    public PermBean(String type, String value) {
        this.type = type;
        this.value = value;
    }
}
