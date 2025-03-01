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

import jakarta.ws.rs.core.Response;
import java.util.Locale;
import java.util.Collections;
import java.util.List;

public class SmsAuthenticator implements Authenticator {

	private static final Logger logger = Logger.getLogger(SmsAuthenticator.class);
	private static final String TPL_CODE = "login-sms.ftl";
	private static final String MOBILE_NUMBER_ATTRIBUTE = "mobile_number";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		if (config == null || config.getConfig() == null) {
			logger.error("SMS authenticator config not found");
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthConfigError", "SMS authentication not properly configured").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		RealmModel realm = context.getRealm();

		String mobileNumber = user.getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE);
		if (mobileNumber == null) {
			logger.warn("No mobile number found for user: " + user.getUsername());
			context.failureChallenge(AuthenticationFlowError.INVALID_USER,
				context.form().setError("smsAuthNoPhone", "No mobile number configured").createErrorPage(Response.Status.BAD_REQUEST));
			return;
		}

		int length = Integer.parseInt(config.getConfig().getOrDefault("length", "6"));
		int ttl = Integer.parseInt(config.getConfig().getOrDefault("ttl", "300"));

		String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		authSession.setAuthNote("code", code);
		authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
			String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);

			context.challenge(context.form().setAttribute("realm", realm).createForm(TPL_CODE));
		} catch (Exception e) {
			logger.error("Failed to send SMS", e);
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null) {
			logger.error("No code or TTL found in auth session");
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthInternalError", "Authentication session expired").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");
		if (enteredCode == null || enteredCode.trim().isEmpty()) {
			logger.warn("No code entered by user");
			context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
				context.form().setAttribute("realm", context.getRealm())
					.setError("smsAuthCodeMissing", "Please enter the code").createForm(TPL_CODE));
			return;
		}

		boolean isValid = enteredCode.equals(code);
		if (isValid) {
			long expirationTime = Long.parseLong(ttl);
			if (System.currentTimeMillis() > expirationTime) {
				logger.warn("Code expired. Expiration: " + expirationTime + ", Current: " + System.currentTimeMillis());
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("smsAuthCodeExpired", "Code has expired").createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				context.success();
			}
		} else {
			AuthenticationExecutionModel execution = context.getExecution();
			if (execution.isRequired()) {
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
					context.form().setAttribute("realm", context.getRealm())
						.setError("smsAuthCodeInvalid", "Invalid code entered").createForm(TPL_CODE));
			} else if (execution.isConditional() || execution.isAlternative()) {
				context.attempted();
			}
		}
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		// Check if SMS authentication is configured
		AuthenticatorConfigModel config = realm.getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null || !Boolean.parseBoolean(config.getConfig().getOrDefault("forceSecondFactor", "false"))) {
			// If 2FA is not configured or not forced, consider it as configured
			return true;
		}
		
		// Check if user has mobile number
		return user.getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE) != null;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		// Only add the required action if 2FA is enabled and user doesn't have mobile number
		if (!configuredFor(session, realm, user)) {
			user.addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		}
	}

	public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
		return Collections.singletonList((PhoneNumberRequiredActionFactory)session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class, PhoneNumberRequiredAction.PROVIDER_ID));
	}

	@Override
	public void close() {
	}
}
