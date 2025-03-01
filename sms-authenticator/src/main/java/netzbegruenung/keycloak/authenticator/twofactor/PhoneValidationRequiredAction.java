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

package netzbegruenung.keycloak.authenticator.twofactor;

import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import jakarta.ws.rs.core.Response;

public class PhoneValidationRequiredAction implements RequiredActionProvider {
	private static final Logger logger = Logger.getLogger(PhoneValidationRequiredAction.class);
	public static final String PROVIDER_ID = "phone_validation_config";
	private static final String MOBILE_NUMBER_ATTRIBUTE = "mobile_number";

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		try {
			UserModel user = context.getUser();
			RealmModel realm = context.getRealm();

			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			String mobileNumber = authSession.getAuthNote("mobile_number");
			if (mobileNumber == null) {
				logger.error("No mobile number found in auth session");
				context.failure();
				return;
			}
			logger.infof("Validating phone number: %s of user: %s", mobileNumber, user.getUsername());

			// Use default values for SMS code
			int length = 6;
			int ttl = 300;

			String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
			authSession.setAuthNote("code", code);
			authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

			Theme theme = context.getSession().theme().getTheme(Theme.Type.LOGIN);
			Locale locale = context.getSession().getContext().resolveLocale(user);
			String smsAuthText = theme.getEnhancedMessages(realm,locale).getProperty("smsAuthText");
			String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

			// Use simulation mode for SMS
			Map<String, String> config = new HashMap<>();
			config.put("simulation", "true");
			SmsServiceFactory.get(config).send(mobileNumber, smsText);

			Response challenge = context.form()
				.setAttribute("realm", realm)
				.createForm("login-sms.ftl");
			context.challenge(challenge);
		} catch (Exception e) {
			logger.error("Failed to send SMS", e);
			context.failure();
		}
	}

	@Override
	public void processAction(RequiredActionContext context) {
		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String mobileNumber = authSession.getAuthNote("mobile_number");
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null || enteredCode == null) {
			logger.warn("Code or TTL is not set");
			handleInvalidSmsCode(context);
			return;
		}

		boolean isValid = enteredCode.equals(code);
		long expirationTime = Long.parseLong(ttl);
		if (isValid) {
			if (System.currentTimeMillis() > expirationTime) {
				// Code has expired
				logger.warn("Code expired. Expiration: " + expirationTime + ", Current: " + System.currentTimeMillis());
				Response challenge = context
					.form()
					.setAttribute("realm", context.getRealm())
					.setError("smsAuthCodeExpired")
					.createForm("login-sms.ftl");
				context.challenge(challenge);
			} else {
				// valid - store the mobile number as an attribute
				context.getUser().setSingleAttribute(MOBILE_NUMBER_ATTRIBUTE, mobileNumber);
				logger.infof("Successfully validated and stored mobile number [%s] for user: %s", 
					mobileNumber, context.getUser().getUsername());
				
				// Remove the required actions since validation is complete
				context.getUser().removeRequiredAction(PROVIDER_ID);
				context.success();
			}
		} else {
			// invalid code
			handleInvalidSmsCode(context);
		}
	}

	private void handleInvalidSmsCode(RequiredActionContext context) {
		Response challenge = context
			.form()
			.setAttribute("realm", context.getRealm())
			.setError("smsAuthCodeInvalid")
			.createForm("login-sms.ftl");
		context.challenge(challenge);
	}

	@Override
	public void close() {
	}
}
