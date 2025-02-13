package netzbegruenung.keycloak.authenticator.smsonly;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;
import java.util.ArrayList;

public class SmsOnlyAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "sms-only-authenticator";
    private static final String DISPLAY_TYPE = "SMS Authentication";
    private static final String HELP_TEXT = "Authenticates using SMS code only, no password required";
    
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    
    static {
        // Add the same configuration properties as the SMS authenticator
        ProviderConfigProperty apiurl = new ProviderConfigProperty();
        apiurl.setName("apiurl");
        apiurl.setLabel("API URL");
        apiurl.setType(ProviderConfigProperty.STRING_TYPE);
        apiurl.setHelpText("URL of the SMS gateway API");
        configProperties.add(apiurl);

        ProviderConfigProperty apiuser = new ProviderConfigProperty();
        apiuser.setName("apiuser");
        apiuser.setLabel("API User");
        apiuser.setType(ProviderConfigProperty.STRING_TYPE);
        apiuser.setHelpText("Username for the SMS gateway API");
        configProperties.add(apiuser);

        ProviderConfigProperty source = new ProviderConfigProperty();
        source.setName("source");
        source.setLabel("Source");
        source.setType(ProviderConfigProperty.STRING_TYPE);
        source.setHelpText("Source/Sender ID for the SMS");
        configProperties.add(source);

        ProviderConfigProperty countrycode = new ProviderConfigProperty();
        countrycode.setName("countrycode");
        countrycode.setLabel("Default Country Code");
        countrycode.setType(ProviderConfigProperty.STRING_TYPE);
        countrycode.setHelpText("Default country code for phone numbers");
        configProperties.add(countrycode);

        ProviderConfigProperty platformPartnerId = new ProviderConfigProperty();
        platformPartnerId.setName("platformPartnerId");
        platformPartnerId.setLabel("Platform Partner ID");
        platformPartnerId.setType(ProviderConfigProperty.STRING_TYPE);
        platformPartnerId.setHelpText("Platform Partner ID for the SMS gateway");
        configProperties.add(platformPartnerId);
    }

    private static final SmsOnlyAuthenticator SINGLETON = new SmsOnlyAuthenticator();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public String getReferenceCategory() {
        return "auth-sms-authentication-form";  // Must match PROVIDER_ID of SmsAuthenticationFormFactory
    }

    @Override
    public String getDisplayType() {
        return DISPLAY_TYPE;
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
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
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
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

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
}
