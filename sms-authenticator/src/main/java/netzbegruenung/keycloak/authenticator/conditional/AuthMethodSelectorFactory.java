package netzbegruenung.keycloak.authenticator.conditional;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class AuthMethodSelectorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "auth-method-selector";
    private static final AuthMethodSelector SINGLETON = new AuthMethodSelector();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Auth Method Selector";
    }

    @Override
    public String getHelpText() {
        return "Selects between SMS and 2FA authentication based on URL parameters and referrer";
    }

    @Override
    public String getReferenceCategory() {
        return "auth-method-selector";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> properties = new ArrayList<>();
        
        // Default country code
        ProviderConfigProperty defaultCountryCode = new ProviderConfigProperty();
        defaultCountryCode.setName("defaultCountryCode");
        defaultCountryCode.setLabel("Default Country Code");
        defaultCountryCode.setType(ProviderConfigProperty.STRING_TYPE);
        defaultCountryCode.setHelpText("Default country code (without +) to prepend to phone numbers that don't have one");
        defaultCountryCode.setDefaultValue("47");
        properties.add(defaultCountryCode);
        
        // API URL
        ProviderConfigProperty apiUrl = new ProviderConfigProperty();
        apiUrl.setName("apiurl");
        apiUrl.setLabel("SMS Gateway API URL");
        apiUrl.setType(ProviderConfigProperty.STRING_TYPE);
        apiUrl.setHelpText("The URL for the SMS gateway API");
        properties.add(apiUrl);
        
        // API User
        ProviderConfigProperty apiUser = new ProviderConfigProperty();
        apiUser.setName("apiuser");
        apiUser.setLabel("API Username");
        apiUser.setType(ProviderConfigProperty.STRING_TYPE);
        apiUser.setHelpText("Username for the SMS gateway API");
        properties.add(apiUser);
        
        // API Password
        ProviderConfigProperty apiPassword = new ProviderConfigProperty();
        apiPassword.setName("apipassword");
        apiPassword.setLabel("API Password");
        apiPassword.setType(ProviderConfigProperty.PASSWORD);
        apiPassword.setHelpText("Password for the SMS gateway API");
        properties.add(apiPassword);
        
        // Sender Name
        ProviderConfigProperty sender = new ProviderConfigProperty();
        sender.setName("sender");
        sender.setLabel("Sender Name");
        sender.setType(ProviderConfigProperty.STRING_TYPE);
        sender.setHelpText("Name that will appear as the SMS sender");
        sender.setDefaultValue("LINK TEST");
        properties.add(sender);
        
        // Platform Partner ID
        ProviderConfigProperty platformPartnerId = new ProviderConfigProperty();
        platformPartnerId.setName("platformPartnerId");
        platformPartnerId.setLabel("Platform Partner ID");
        platformPartnerId.setType(ProviderConfigProperty.STRING_TYPE);
        platformPartnerId.setHelpText("Platform Partner ID for the SMS gateway");
        properties.add(platformPartnerId);

        return properties;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // Not needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Not needed
    }

    @Override
    public void close() {
        // Not needed
    }
}
