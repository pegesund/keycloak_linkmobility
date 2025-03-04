package netzbegruenung.keycloak.authenticator.twofactor;

public class MessageBean {
    private String summary;
    private String type;

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
