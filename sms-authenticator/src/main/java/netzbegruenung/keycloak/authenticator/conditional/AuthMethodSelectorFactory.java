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

        // Code length
        ProviderConfigProperty length = new ProviderConfigProperty();
        length.setName("length");
        length.setLabel("Code length");
        length.setType(ProviderConfigProperty.STRING_TYPE);
        length.setHelpText("The number of digits of the generated code");
        length.setDefaultValue("6");
        properties.add(length);

        // TTL
        ProviderConfigProperty ttl = new ProviderConfigProperty();
        ttl.setName("ttl");
        ttl.setLabel("Time-to-live");
        ttl.setType(ProviderConfigProperty.STRING_TYPE);
        ttl.setHelpText("The time to live in seconds for the code to be valid");
        ttl.setDefaultValue("300");
        properties.add(ttl);

        // Simulation mode
        ProviderConfigProperty simulation = new ProviderConfigProperty();
        simulation.setName("simulation");
        simulation.setLabel("Simulation mode");
        simulation.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        simulation.setHelpText("In simulation mode, the SMS won't be sent, but printed to the server logs");
        simulation.setDefaultValue(true);
        properties.add(simulation);

        // Format phone number
        ProviderConfigProperty normalizePhoneNumber = new ProviderConfigProperty();
        normalizePhoneNumber.setName("normalizePhoneNumber");
        normalizePhoneNumber.setLabel("Format phone number");
        normalizePhoneNumber.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        normalizePhoneNumber.setHelpText("Normalize the phone number using the E164 standard");
        normalizePhoneNumber.setDefaultValue(false);
        properties.add(normalizePhoneNumber);

        // Force retry on bad format
        ProviderConfigProperty forceRetry = new ProviderConfigProperty();
        forceRetry.setName("forceRetryOnBadFormat");
        forceRetry.setLabel("Force retry on bad format");
        forceRetry.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        forceRetry.setHelpText("If phone number formatting fails, force the user to retry");
        forceRetry.setDefaultValue(false);
        properties.add(forceRetry);

        return properties;
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
}
