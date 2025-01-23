/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialData;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.jboss.logging.Logger;
import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class SmsAuthCredentialProvider implements CredentialProvider<SmsAuthCredentialModel>, CredentialInputValidator {
    private static final Logger logger = Logger.getLogger(SmsAuthCredentialProvider.class);
    private final KeycloakSession session;

    public SmsAuthCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return SmsAuthCredentialModel.TYPE;
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
        return user.credentialManager().getStoredCredentialsByTypeStream(credentialType).findAny().isPresent();
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof CredentialInput)) {
            return false;
        }
        if (!input.getType().equals(getType())) {
            return false;
        }
        String challengeResponse = input.getChallengeResponse();
        if (challengeResponse == null) {
            return false;
        }
        return user.credentialManager().getStoredCredentialsByTypeStream(input.getType()).findAny().isPresent();
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, SmsAuthCredentialModel credentialModel) {
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(System.currentTimeMillis());
        }
        credentialModel.setUserLabel("Phone: " + maskPhoneNumber(getPhoneNumber(credentialModel)));
        return user.credentialManager().createStoredCredential(credentialModel);
    }

    private String maskPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.length() < 4) {
            return "****";
        }
        return "****" + phoneNumber.substring(Math.max(0, phoneNumber.length() - 4));
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    @Override
    public SmsAuthCredentialModel getCredentialFromModel(CredentialModel model) {
        return SmsAuthCredentialModel.createFromCredentialData(getPhoneNumber(model));
    }

    private String getPhoneNumber(CredentialModel model) {
        try {
            return JsonSerialization.readValue(model.getCredentialData(), SmsAuthCredentialData.class).getMobileNumber();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String getPhoneNumber(SmsAuthCredentialModel model) {
        try {
            return JsonSerialization.readValue(model.getCredentialData(), SmsAuthCredentialData.class).getMobileNumber();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
            .type(getType())
            .category(CredentialTypeMetadata.Category.TWO_FACTOR)
            .displayName("Phone Number")
            .helpText("Phone number used for SMS authentication")
            .createAction(PhoneNumberRequiredAction.PROVIDER_ID)
            .removeable(true)
            .build(session);
    }
}
