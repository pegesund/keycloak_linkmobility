package netzbegruenung.keycloak.authenticator.twofactor;

import org.keycloak.services.util.ResolveRelative;
import jakarta.ws.rs.core.UriInfo;

public class UrlBean {
    private final UriInfo uriInfo;

    public UrlBean(UriInfo uriInfo) {
        this.uriInfo = uriInfo;
    }

    public String getLoginAction() {
        return uriInfo.getBaseUri().toString() + "login-actions";
    }

    public String getLoginRestartFlowUrl() {
        return uriInfo.getBaseUri().toString() + "login-actions/restart-flow";
    }

    public String getRegistrationAction() {
        return uriInfo.getBaseUri().toString() + "registration";
    }

    public String getFirstBrokerLoginAction() {
        return uriInfo.getBaseUri().toString() + "first-broker-login";
    }
}
