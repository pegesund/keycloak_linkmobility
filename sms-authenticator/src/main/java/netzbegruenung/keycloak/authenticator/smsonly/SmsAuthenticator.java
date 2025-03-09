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

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;


public class SmsAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(SmsAuthenticator.class);
    private static final String TPL_CODE = "login-sms.ftl";
    private static final String TPL_MOBILE = "mobile_number_form.ftl";
    private static final String MOBILE_NUMBER_ATTRIBUTE = "mobile_number";
    private static final String MOBILE_NUMBER_FIELD = "mobile_number";
    private Map<String, String> config;

    public SmsAuthenticator(Map<String, String> config) {
        this.config = config;
    }

    public SmsAuthenticator() {
        // Default constructor for service loading
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        UserModel authenticatedUser = context.getAuthenticationSession().getAuthenticatedUser();
        UserModel contextUser = context.getUser();
        List<String> promptParam = context.getUriInfo().getQueryParameters().get("prompt");

        logger.infof("SMS Authenticate called for client %s. Context user: %s, Session user: %s, Prompt: %s", 
            clientId,
            contextUser != null ? contextUser.getUsername() : "null",
            authenticatedUser != null ? authenticatedUser.getUsername() : "null",
            promptParam);

        // Check if this is a prompt=none request
        if (promptParam != null && promptParam.contains("none")) {
            logger.info("Prompt=none request detected in SMS authenticator, attempting to use existing session");
            context.getSession().sessions().getUserSessionsStream(context.getRealm(), context.getAuthenticationSession().getClient())
                .findFirst()
                .ifPresent(userSession -> {
                    UserModel user = userSession.getUser();
                    if (user != null) {
                        logger.infof("Found existing session for user %s in SMS authenticator, setting user and completing", user.getUsername());
                        context.setUser(user);
                        context.success();
                        return;
                    }
                });
        }

        // If user is already authenticated, just success
        if (contextUser != null && authenticatedUser != null) {
            logger.infof("User %s is already authenticated for client %s, skipping SMS auth", 
                authenticatedUser.getUsername(), clientId);
            context.success();
            return;
        }

        Response challenge = createMobileNumberForm(context);
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        UserModel authenticatedUser = context.getAuthenticationSession().getAuthenticatedUser();
        UserModel contextUser = context.getUser();
        List<String> promptParam = context.getUriInfo().getQueryParameters().get("prompt");

        logger.infof("SMS Action called for client %s. Context user: %s, Session user: %s, Prompt: %s", 
            clientId,
            contextUser != null ? contextUser.getUsername() : "null",
            authenticatedUser != null ? authenticatedUser.getUsername() : "null",
            promptParam);

        // Check if this is a prompt=none request
        if (promptParam != null && promptParam.contains("none")) {
            logger.info("Prompt=none request detected in SMS action, attempting to use existing session");
            context.getSession().sessions().getUserSessionsStream(context.getRealm(), context.getAuthenticationSession().getClient())
                .findFirst()
                .ifPresent(userSession -> {
                    UserModel user = userSession.getUser();
                    if (user != null) {
                        logger.infof("Found existing session for user %s in SMS action, setting user and completing", user.getUsername());
                        context.setUser(user);
                        context.success();
                        return;
                    }
                });
        }

        // If user is already authenticated, just success
        if (contextUser != null && authenticatedUser != null) {
            logger.infof("User %s is already authenticated for client %s, skipping SMS auth action", 
                authenticatedUser.getUsername(), clientId);
            context.success();
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        
        String mobileNumber = formData.getFirst(MOBILE_NUMBER_FIELD);
        if (mobileNumber != null) {
            handleMobileNumberSubmission(context, mobileNumber);
            return;
        }

        String code = formData.getFirst("code");
        if (code != null) {
            handleSmsCodeSubmission(context, code);
            return;
        }

        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, 
            context.form().setError("invalidFormData").createForm(TPL_MOBILE));
    }

    private String normalizePhoneNumber(String mobileNumber, Map<String, String> config) {
        String defaultCountryCode = "47"; // Default to Norway
        if (config != null) {
            defaultCountryCode = config.getOrDefault("defaultCountryCode", "47");
        }

        if (!mobileNumber.startsWith("+")) {
            if (mobileNumber.startsWith("00")) {
                mobileNumber = "+" + mobileNumber.substring(2);
            } else if (mobileNumber.startsWith("0")) {
                mobileNumber = "+" + defaultCountryCode + mobileNumber.substring(1);
            } else {
                mobileNumber = "+" + defaultCountryCode + mobileNumber;
            }
            logger.infof("Normalized mobile number to: %s", mobileNumber);
        }
        return mobileNumber;
    }

    private void handleMobileNumberSubmission(AuthenticationFlowContext context, String mobileNumber) {
        if (mobileNumber.trim().isEmpty()) {
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, 
                context.form().setError("missingMobileNumber").createForm(TPL_MOBILE));
            return;
        }

        // Get config from context if not already set
        Map<String, String> smsConfig = this.config;
        if (smsConfig == null && context.getAuthenticatorConfig() != null) {
            smsConfig = context.getAuthenticatorConfig().getConfig();
        }

        // Normalize the phone number
        mobileNumber = normalizePhoneNumber(mobileNumber, smsConfig);
        logger.infof("Looking up user with normalized number: %s", mobileNumber);

        // Find user by mobile number
        UserModel user = findUserByMobileNumber(context.getSession(), context.getRealm(), mobileNumber);
        if (user == null) {
            logger.warn("No user found with mobile number: " + mobileNumber);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, 
                context.form().setError("userNotFound").createForm(TPL_MOBILE));
            return;
        }

        logger.infof("Found user %s, setting in context", user.getUsername());
        context.setUser(user);
        context.getAuthenticationSession().setAuthenticatedUser(user);
        
        sendSmsCode(context, mobileNumber);
    }

    private void handleSmsCodeSubmission(AuthenticationFlowContext context, String enteredCode) {
        UserModel user = context.getUser();
        if (user == null) {
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, 
                context.form().setError("userSessionExpired").createForm(TPL_MOBILE));
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String code = authSession.getAuthNote("code");
        String ttl = authSession.getAuthNote("ttl");

        if (code == null || ttl == null) {
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, 
                context.form().setError("codeExpired").createForm(TPL_CODE));
            return;
        }

        long expirationTime = Long.parseLong(ttl);
        if (System.currentTimeMillis() > expirationTime) {
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, 
                context.form().setError("codeExpired").createForm(TPL_CODE));
            return;
        }

        if (!enteredCode.equals(code)) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, 
                context.form().setError("invalidCode").createForm(TPL_CODE));
            return;
        }

        // Clear the code from the session
        authSession.removeAuthNote("code");
        authSession.removeAuthNote("ttl");

        // Complete authentication
        logger.info("SMS authentication successful for user: " + user.getUsername());
        context.success();
    }

    private void sendSmsCode(AuthenticationFlowContext context, String mobileNumber) {
        try {
            // Get config from context if not already set
            Map<String, String> smsConfig = this.config;
            if (smsConfig == null && context.getAuthenticatorConfig() != null) {
                smsConfig = context.getAuthenticatorConfig().getConfig();
            }

            int length = Integer.parseInt(smsConfig.getOrDefault("length", "6"));
            int ttl = Integer.parseInt(smsConfig.getOrDefault("ttl", "300"));

            String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            authSession.setAuthNote("code", code);
            authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

            Theme theme = context.getSession().theme().getTheme(Theme.Type.LOGIN);
            Locale locale = context.getSession().getContext().resolveLocale(context.getUser());
            String smsAuthText = theme.getEnhancedMessages(context.getRealm(), locale)
                .getProperty("smsAuthText", "Your SMS code is %1$s and is valid for %2$d minutes.");
            String smsText = String.format(smsAuthText, code, ttl/60);

            SmsServiceFactory.get(smsConfig).send(mobileNumber, smsText);
            context.challenge(context.form().createForm(TPL_CODE));
        } catch (Exception e) {
            logger.error("Failed to send SMS", e);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError("smsAuthSmsError").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
        }
    }

    private UserModel findUserByMobileNumber(KeycloakSession session, RealmModel realm, String mobileNumber) {
        logger.infof("Searching for user with mobile number: %s", mobileNumber);
        
        // Try exact match first
        UserModel user = session.users().searchForUserByUserAttributeStream(realm, MOBILE_NUMBER_ATTRIBUTE, mobileNumber)
            .findFirst()
            .orElse(null);

        if (user == null) {
            // Try without country code
            String numberWithoutCountry = mobileNumber.startsWith("+") ? mobileNumber.substring(1) : mobileNumber;
            if (numberWithoutCountry.startsWith("47")) {
                numberWithoutCountry = numberWithoutCountry.substring(2);
            }
            logger.infof("Trying search without country code: %s", numberWithoutCountry);
            
            user = session.users().searchForUserByUserAttributeStream(realm, MOBILE_NUMBER_ATTRIBUTE, numberWithoutCountry)
                .findFirst()
                .orElse(null);
        }

        if (user != null) {
            logger.infof("Found user: %s with mobile number: %s", user.getUsername(), mobileNumber);
        } else {
            logger.warnf("No user found with mobile number: %s", mobileNumber);
        }
        return user;
    }

    private Response createMobileNumberForm(AuthenticationFlowContext context) {
        return context.form().createForm(TPL_MOBILE);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        String mobileNumber = user.getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE);
        return mobileNumber != null && !mobileNumber.trim().isEmpty();
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return Collections.emptyList();
    }

    @Override
    public void close() {
    }
}
