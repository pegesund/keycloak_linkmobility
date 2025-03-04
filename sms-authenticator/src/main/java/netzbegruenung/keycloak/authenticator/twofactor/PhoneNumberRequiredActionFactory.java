package netzbegruenung.keycloak.authenticator.twofactor;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;


public class PhoneNumberRequiredActionFactory implements RequiredActionFactory {

    private static final PhoneNumberRequiredAction SINGLETON = new PhoneNumberRequiredAction();

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PhoneNumberRequiredAction.PROVIDER_ID;  // Use the same ID
    }

    @Override
    public String getDisplayText() {
        return "Configure SMS Authentication";
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

}
