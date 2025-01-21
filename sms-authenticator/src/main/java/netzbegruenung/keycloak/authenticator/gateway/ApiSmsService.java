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
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator.gateway;

import java.util.Map;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.jboss.logging.Logger;

public class ApiSmsService implements SmsService{

	private static final Logger logger = Logger.getLogger(SmsServiceFactory.class);

	private final String apiurl;
	private final String apiuser;
	private final String source;
	private final String countrycode;
	private final String platformPartnerId;
	
	ApiSmsService(Map<String, String> config) {
		apiurl = config.get("apiurl");
		apiuser = config.getOrDefault("apiuser", "");
		source = config.getOrDefault("source", "LINK TEST");
		countrycode = config.getOrDefault("countrycode", "");
		platformPartnerId = config.getOrDefault("platformPartnerId", "");
	}

	public void send(String phoneNumber, String message) {
		phoneNumber = clean_phone_number(phoneNumber, countrycode);
		HttpRequest request = null;
		var client = HttpClient.newHttpClient();
		try {
			var request_builder = HttpRequest.newBuilder()
				.uri(URI.create(apiurl))
				.header("Content-Type", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString(createJsonBody(phoneNumber, message)));

			if (apiuser != null && !apiuser.isEmpty()) {
				request = request_builder.setHeader("Authorization", "Basic " + apiuser).build();
			} else {
				request = request_builder.build();
			}

			// Log the curl equivalent
			/* 
			String jsonBody = createJsonBody(phoneNumber, message);
			logger.infof("Equivalent curl command: curl -X POST '%s' -H 'Content-Type: application/json' %s -d '%s'",
				apiurl,
				apiuser != null && !apiuser.isEmpty() ? "-H 'Authorization: Basic " + apiuser + "'" : "",
				jsonBody);
				*/

			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

			int statusCode = response.statusCode();
			String payload = "Response: " + response.body();

			if (statusCode >= 200 && statusCode < 300) {
				logger.infof("Sent SMS to %s [%s]", phoneNumber, payload);
			} else {
				logger.errorf("Failed to send message to %s [%s]. Validate your config.", phoneNumber, payload);
			}
		} catch (Exception e) {
			logger.errorf(e, "Failed to send message to %s with request: %s. Validate your config.", phoneNumber, request != null ? request.toString() : "null");
		}
	}

	private String createJsonBody(String phoneNumber, String message) {
		return String.format(
			"{\"source\":\"%s\",\"destination\":\"%s\",\"userData\":\"%s\",\"platformId\":\"SMS\",\"platformPartnerId\":\"%s\"}",
			source,
			phoneNumber,
			message,
			platformPartnerId
		);
	}

	private static String clean_phone_number(String phone_number, String countrycode) {
		if (phone_number == null || phone_number.isEmpty()) {
			return "";
		}

		// Remove any whitespace
		phone_number = phone_number.replaceAll("\\s+", "");

		// If number already starts with +, keep it as is
		if (phone_number.startsWith("+")) {
			return phone_number;
		}

		// If number starts with 00, replace with +
		if (phone_number.startsWith("00")) {
			return "+" + phone_number.substring(2);
		}

		// If number starts with 47, add +
		if (phone_number.startsWith("47")) {
			return "+" + phone_number;
		}

		// Add +47 if no country code is present
		return "+47" + phone_number;
	}
}
