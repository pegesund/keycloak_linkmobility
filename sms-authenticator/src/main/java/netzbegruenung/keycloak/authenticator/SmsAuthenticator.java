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

package netzbegruenung.keycloak.authenticator;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialData;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.keycloak.util.JsonSerialization;

import jakarta.ws.rs.core.Response;
import java.util.Locale;
import java.util.Optional;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class SmsAuthenticator implements Authenticator, CredentialValidator<SmsAuthCredentialProvider> {

	private static final Logger logger = Logger.getLogger(SmsAuthenticator.class);
	private static final String TPL_CODE = "login-sms.ftl";
	private static final String TPL_PHONE = "login-phone.ftl";

	private String generateTimeBasedCode(int length) {
		long timeSlice = System.currentTimeMillis() / 30000; // 30-second time slices
		return SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
	}

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		RealmModel realm = context.getRealm();
		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		String phoneNumber = authSession.getAuthNote("phoneNumber");
		if (phoneNumber == null) {
			// First step - show phone number form
			context.challenge(context.form()
				.setAttribute("realm", realm)
				.createForm(TPL_PHONE));
			return;
		}

		// Second step - send OTP
		int length = Integer.parseInt(config.getConfig().get("length"));
		String code = generateTimeBasedCode(length);
		authSession.setAuthNote("code", code);
		authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + 30000));

		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(null);
			String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
			String smsText = String.format(smsAuthText, code, 1);

			SmsServiceFactory.get(config.getConfig()).send(phoneNumber, smsText);

			context.challenge(context.form()
				.setAttribute("realm", realm)
				.createForm(TPL_CODE));
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String phoneNumber = authSession.getAuthNote("phoneNumber");
		logger.info("Action called. Phone number from session: " + phoneNumber);

		if (phoneNumber == null) {
			// Handle phone number submission
			String submittedPhone = context.getHttpRequest().getDecodedFormParameters().getFirst("phoneNumber");
			logger.info("Submitted phone number: " + submittedPhone);
			
			if (submittedPhone == null || submittedPhone.trim().isEmpty()) {
				logger.warn("No phone number submitted");
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
					context.form().setError("phoneNumberRequired")
						.createForm(TPL_PHONE));
				return;
			}
			
			try {
				// Store phone number and restart authentication
				authSession.setAuthNote("phoneNumber", submittedPhone);
				// Find or create user immediately after phone submission
				UserModel user = findOrCreateUser(context.getSession(), context.getRealm(), submittedPhone);
				context.setUser(user);
				logger.info("Created/found user for phone: " + submittedPhone);
				
				// Instead of attempted(), let's authenticate again to trigger OTP send
				authenticate(context);
			} catch (Exception e) {
				logger.error("Error processing phone number", e);
				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
					context.form().setError("internalError")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			}
			return;
		}

		// Handle OTP verification
		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");
		logger.info("Verifying OTP for phone: " + phoneNumber);
		
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null) {
			logger.error("No code or TTL found in session");
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		if (Long.parseLong(ttl) < System.currentTimeMillis()) {
			logger.warn("Code expired");
			context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
				context.form().setError("smsAuthCodeExpired")
					.createErrorPage(Response.Status.BAD_REQUEST));
			return;
		}

		String currentTimeCode = generateTimeBasedCode(code.length());
		boolean isValid = enteredCode.equals(code) || enteredCode.equals(currentTimeCode);
		logger.info("Code validation result: " + isValid);

		if (isValid) {
			// User is already set from phone number submission
			if (context.getUser() == null) {
				UserModel user = findOrCreateUser(context.getSession(), context.getRealm(), phoneNumber);
				context.setUser(user);
				logger.info("Re-set user for successful OTP");
			}
			context.success();
		} else {
			context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
				context.form().setAttribute("realm", context.getRealm())
					.setError("smsAuthCodeInvalid")
					.createForm(TPL_CODE));
		}
	}

	private UserModel findOrCreateUser(KeycloakSession session, RealmModel realm, String phoneNumber) {
		logger.info("Looking for user with phone: " + phoneNumber);
		
		// First try to find user by phone number attribute
		UserModel user = session.users().searchForUserByUserAttributeStream(realm, "phoneNumber", phoneNumber)
			.findFirst()
			.orElse(null);
		
		if (user == null) {
			logger.info("Creating new user for phone: " + phoneNumber);
			// Create new user with phone number as username
			String username = "phone_" + phoneNumber.replaceAll("[^0-9]", "");
			user = session.users().addUser(realm, username);
			user.setSingleAttribute("phoneNumber", phoneNumber);
			// Set some required attributes
			user.setEnabled(true);
			user.setEmailVerified(true);
			// Remove any required actions
			user.removeRequiredAction("CONFIGURE_TOTP");
		} else {
			logger.info("Found existing user for phone: " + phoneNumber);
			// Also remove required action for existing users
			user.removeRequiredAction("CONFIGURE_TOTP");
		}
		
		return user;
	}

	@Override
	public boolean requiresUser() {
		return false;  // Changed to false since we create the user after verification
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return getCredentialProvider(session).isConfiguredFor(realm, user, getType(session));
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		// Do nothing - we don't want to set any required actions
	}

	public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
		return Collections.singletonList((PhoneNumberRequiredActionFactory)session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class, PhoneNumberRequiredAction.PROVIDER_ID));
	}

	@Override
	public void close() {
	}

	@Override
	public SmsAuthCredentialProvider getCredentialProvider(KeycloakSession session) {
		return (SmsAuthCredentialProvider)session.getProvider(CredentialProvider.class, SmsAuthCredentialProviderFactory.PROVIDER_ID);
	}
}
