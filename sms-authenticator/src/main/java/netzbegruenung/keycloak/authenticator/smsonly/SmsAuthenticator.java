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
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator.smsonly;

import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;
import netzbegruenung.keycloak.authenticator.twofactor.PhoneNumberRequiredAction;
import netzbegruenung.keycloak.authenticator.twofactor.PhoneNumberRequiredActionFactory;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Locale;
import java.util.Collections;
import java.util.List;

public class SmsAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(SmsAuthenticator.class);
    private static final String TPL_CODE = "login-sms.ftl";
    private static final String TPL_MOBILE = "mobile_number_form.ftl";
    private static final String MOBILE_NUMBER_ATTRIBUTE = "mobile_number";
    private static final String MOBILE_NUMBER_FIELD = "mobile_number";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null) {
            logger.error("SMS authenticator config not found");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError("smsAuthConfigError", "SMS authentication not properly configured").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }

        // Check if we have a mobile number in the form data
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String mobileNumber = formData.getFirst(MOBILE_NUMBER_FIELD);
        
        if (mobileNumber != null && !mobileNumber.trim().isEmpty()) {
            // Mobile number provided, store it and send SMS
            UserModel user = context.getUser();
            if (user == null) {
                user = findUserByMobileNumber(context.getSession(), context.getRealm(), mobileNumber);
                if (user == null) {
                    Response challenge = context.form()
                        .setError("userNotFound", "No user found with this mobile number")
                        .createForm(TPL_MOBILE);
                    context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge);
                    return;
                }
                context.setUser(user);
            }
            
            // Update user's mobile number if it's different
            String existingNumber = user.getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE);
            if (!mobileNumber.equals(existingNumber)) {
                user.setSingleAttribute(MOBILE_NUMBER_ATTRIBUTE, mobileNumber);
            }
            
            sendSmsCode(context, mobileNumber);
        } else {
            // No mobile number provided, show the form
            Response challenge = context.form()
                .createForm(TPL_MOBILE);
            context.challenge(challenge);
        }
    }

    private UserModel findUserByMobileNumber(KeycloakSession session, RealmModel realm, String mobileNumber) {
        return session.users().searchForUserByUserAttributeStream(realm, MOBILE_NUMBER_ATTRIBUTE, mobileNumber)
            .findFirst()
            .orElse(null);
    }

    private void sendSmsCode(AuthenticationFlowContext context, String mobileNumber) {
        try {
            AuthenticatorConfigModel config = context.getAuthenticatorConfig();
            int length = Integer.parseInt(config.getConfig().getOrDefault("length", "6"));
            int ttl = Integer.parseInt(config.getConfig().getOrDefault("ttl", "300"));

            String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            authSession.setAuthNote("code", code);
            authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

            Theme theme = context.getSession().theme().getTheme(Theme.Type.LOGIN);
            Locale locale = context.getSession().getContext().resolveLocale(context.getUser());
            String smsAuthText = theme.getEnhancedMessages(context.getRealm(), locale).getProperty("smsAuthText", "Your SMS code is %1$s and is valid for %2$d minutes.");
            String smsText = String.format(smsAuthText, code, ttl/60);

            SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);

            Response challenge = context.form()
                .setAttribute("realm", context.getRealm())
                .setAttribute("mobile_number", mobileNumber)
                .createForm(TPL_CODE);
            context.challenge(challenge);
        } catch (Exception e) {
            logger.error("Failed to send SMS", e);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError("smsAuthSmsNotSent", e.getMessage())
                    .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

        if (enteredCode == null || enteredCode.trim().isEmpty()) {
            // If no code provided, treat it as a mobile number submission
            authenticate(context);
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String code = authSession.getAuthNote("code");
        String ttl = authSession.getAuthNote("ttl");

        if (code == null || ttl == null) {
            Response challenge = context.form()
                .setError("codeExpired")
                .createForm(TPL_CODE);
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
            return;
        }

        boolean valid = enteredCode.equals(code);
        long expirationTime = Long.parseLong(ttl);
        boolean expired = System.currentTimeMillis() > expirationTime;

        if (expired) {
            Response challenge = context.form()
                .setError("codeExpired")
                .createForm(TPL_CODE);
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
            return;
        }

        if (!valid) {
            Response challenge = context.form()
                .setError("invalidCode")
                .createForm(TPL_CODE);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }

        // Clear the code from the session
        authSession.removeAuthNote("code");
        authSession.removeAuthNote("ttl");

        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE) != null;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        user.addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
    }

    @Override
    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return Collections.singletonList((PhoneNumberRequiredActionFactory)session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class, PhoneNumberRequiredAction.PROVIDER_ID));
    }

    @Override
    public void close() {
    }
}
