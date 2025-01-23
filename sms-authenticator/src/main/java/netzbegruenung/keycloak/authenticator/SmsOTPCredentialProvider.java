package netzbegruenung.keycloak.authenticator;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialData;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;
import org.keycloak.credential.*;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.dto.OTPCredentialData;
import org.keycloak.models.credential.dto.OTPSecretData;
import org.jboss.logging.Logger;
import org.keycloak.util.JsonSerialization;
import org.keycloak.common.util.Time;
import org.keycloak.models.utils.HmacOTP;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;

public class SmsOTPCredentialProvider implements CredentialProvider<OTPCredentialModel>, CredentialInputValidator {
    private static final Logger logger = Logger.getLogger(SmsOTPCredentialProvider.class);
    private final KeycloakSession session;

    public SmsOTPCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return OTPCredentialModel.TYPE;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, OTPCredentialModel credentialModel) {
        if (credentialModel.getOTPCredentialData() != null) {
            String phoneNumber = getPhoneNumber(user);
            if (phoneNumber == null) {
                throw new IllegalStateException("Cannot create SMS OTP credential: No phone number registered for user");
            }
            
            credentialModel.setUserLabel("SMS OTP for " + maskPhoneNumber(phoneNumber));
            sendOTPViaSMS(user, credentialModel.getOTPSecretData().getValue());
            return user.credentialManager().createStoredCredential(credentialModel);
        }
        throw new IllegalStateException("Cannot create SMS OTP credential: No OTP data provided");
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    @Override
    public OTPCredentialModel getCredentialFromModel(CredentialModel model) {
        return OTPCredentialModel.createFromCredentialModel(model);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getType().equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType)) {
            return false;
        }

        // First check if user has a phone number registered
        if (getPhoneNumber(user) == null) {
            return false;
        }

        // Then check if they have an OTP credential
        return user.credentialManager()
            .getStoredCredentialsByTypeStream(credentialType)
            .findAny()
            .isPresent();
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof UserCredentialModel)) {
            return false;
        }
        if (!input.getType().equals(getType())) {
            return false;
        }

        String challengeResponse = input.getChallengeResponse();
        if (challengeResponse == null) {
            return false;
        }

        CredentialModel credential = user.credentialManager()
            .getStoredCredentialsByTypeStream(getType())
            .findFirst()
            .orElse(null);
            
        if (credential == null) {
            return false;
        }

        OTPCredentialModel otpCredential = getCredentialFromModel(credential);
        OTPPolicy policy = realm.getOTPPolicy();
        
        // Validate OTP using HmacOTP
        HmacOTP validator = new HmacOTP(policy.getDigits(), policy.getAlgorithm(), policy.getLookAheadWindow());
        try {
            int counter = (int) (Time.currentTimeMillis() / 30000L); // 30-second time slice
            int result = validator.validateHOTP(otpCredential.getOTPSecretData().getValue(), challengeResponse, counter);
            return result >= 0;
        } catch (NumberFormatException e) {
            logger.error("Invalid OTP format", e);
            return false;
        }
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
            .type(getType())
            .category(CredentialTypeMetadata.Category.TWO_FACTOR)
            .displayName("SMS OTP")
            .helpText("One-time password sent via SMS")
            .createAction(PhoneValidationRequiredAction.PROVIDER_ID)
            .removeable(true)
            .build(session);
    }

    private void sendOTPViaSMS(UserModel user, String otpSecret) {
        try {
            // Get the user's phone number from their SMS credentials
            Optional<CredentialModel> model = user.credentialManager()
                .getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE)
                .findFirst();

            if (model.isPresent()) {
                String mobileNumber = JsonSerialization.readValue(
                    model.get().getCredentialData(), 
                    SmsAuthCredentialData.class
                ).getMobileNumber();

                // Format the OTP setup message
                String message = String.format(
                    "Your OTP setup code is: %s\nUse this to configure your authenticator app.", 
                    otpSecret
                );

                // Get the SMS configuration from realm
                AuthenticatorConfigModel config = session.getContext().getRealm().getAuthenticatorConfigByAlias("sms-2fa");
                Map<String, String> smsConfig = config != null ? config.getConfig() : new HashMap<>();

                // Send the OTP secret via SMS
                SmsServiceFactory.get(smsConfig)
                    .send(mobileNumber, message);
            } else {
                logger.warn("No phone number found for user: " + user.getUsername());
            }
        } catch (IOException e) {
            logger.error("Failed to send OTP via SMS", e);
        }
    }

    private String maskPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.length() < 4) {
            return "****";
        }
        return "****" + phoneNumber.substring(Math.max(0, phoneNumber.length() - 4));
    }

    private String getPhoneNumber(UserModel user) {
        try {
            Optional<CredentialModel> model = user.credentialManager()
                .getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE)
                .findFirst();

            if (model.isPresent()) {
                return JsonSerialization.readValue(
                    model.get().getCredentialData(), 
                    SmsAuthCredentialData.class
                ).getMobileNumber();
            }
        } catch (IOException e) {
            logger.error("Error getting phone number", e);
        }
        return null;
    }
}
