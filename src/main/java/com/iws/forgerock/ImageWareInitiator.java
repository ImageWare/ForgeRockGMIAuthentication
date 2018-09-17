/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */

package com.iws.forgerock;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.assistedinject.Assisted;
import com.iws.forgerock.ImageWareCommon.UnauthorizedException;
import com.iws.forgerock.gmi.entity.DeviceApplication;
import com.iws.forgerock.gmi.entity.Message;
import com.iws.forgerock.gmi.entity.Person;
import com.iwsinc.usermanager.client.OauthBearerToken;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.RequiredValueValidator;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;
import javax.inject.Inject;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.sm.annotations.adapters.Password;

/**
 * A node that verifies a user account exists in the ImageWare GoVerifyID user
 * repository and sends a biometric verification message for ForgeRock authentication
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = ImageWareInitiator.Config.class)
public class ImageWareInitiator extends AbstractDecisionNode {
	

	private static final String BUNDLE = "com/iws/forgerock/ImageWareInitiator";
	
	private final Config config;
	private final CoreWrapper coreWrapper;
	private final static String DEBUG_FILE = "ImageWareInitiator";
	private Debug debug = Debug.getInstance(DEBUG_FILE);
	private ResourceBundle resourceBundle;

	private void setResourceBundle(ResourceBundle resourceBundle) { this.resourceBundle = resourceBundle; }
	
	private ResourceBundle getResourceBundle() { return resourceBundle; }

	/**
	 * Configuration for the node.
	 */
	public interface Config {
		@Attribute(order = 100,  validators = {RequiredValueValidator.class})
		default String tenantName() { return ""; }

		@Attribute(order = 200,  validators = {RequiredValueValidator.class})
		default String clientName() { return ""; }

		@Attribute(order = 300, validators = {RequiredValueValidator.class})
		@Password
		char[] clientSecret();

		@Attribute(order = 400,  validators = {RequiredValueValidator.class})
		default String userManagerURL() { return "https://gmi-ha.iwsinc.com/usermanager"; }

		@Attribute(order = 500,  validators = {RequiredValueValidator.class})
		default String gmiServerURL() { return "https://gmi-ha.iwsinc.com/gmiserver"; }

		@Attribute(order = 600,  validators = {RequiredValueValidator.class})
		default String gmiApplicationName() { return "GoVerifyID"; }

		@Attribute(order = 700,  validators = {RequiredValueValidator.class})
		default String gmiTemplateName() { return "GVID_VERIFY_CHOICE"; }

		@Attribute(order = 800,  validators = {RequiredValueValidator.class})
		default String messageReason() { return "ForgeRock custom authentication test message"; }
		
		@Attribute(order = 900,  validators = {RequiredValueValidator.class})
		default int messageExpiresInSeconds() { return 180; }
	}

	/**
	 * Create the node.
	 * 
	 * @param config
	 *            The service config.
	 */
	@Inject
	public ImageWareInitiator(@Assisted Config config, CoreWrapper coreWrapper) {
		this.config = config;
		this.coreWrapper = coreWrapper;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {

		debug.message("ImageWareInitiator started");
		setResourceBundle(context.request.locales.getBundleInPreferredLocale(ImageWareInitiator.BUNDLE,
				ImageWareInitiator.class.getClassLoader()));

		JsonValue sharedState = context.sharedState;
		String username = sharedState.get(USERNAME).asString();
		debug.message("Username {}.", username);


		ImageWareCommon.EmailObject emailObject = new ImageWareCommon.EmailObject(coreWrapper, getResourceBundle(),
				sharedState, username).getEmailObject();
		if (emailObject.isException()) return Action.send(emailObject.getCallbacks()).build();
		String emailAddress = emailObject.getEmailAddress();
		sharedState = emailObject.getSharedState();
		debug.message("Email Address {}.", emailAddress);


		TokenService.setConfig(config);
		TokenService tokenService = TokenService.getInstance();
		
		String tenant = config.tenantName();
		String gmiServerURL = config.gmiServerURL();
		Person person;

		try {
			person = validateUser(emailAddress, tokenService.getBearerToken(), gmiServerURL);
		} catch (UnauthorizedException ue) {
			tokenService.setBearerToken(null);
			
			try {
				person = validateUser(emailAddress, tokenService.getBearerToken(), gmiServerURL);
			} catch (UnauthorizedException e) {
				debug.error("Cannot successfully use new UserManager OAuth token.");
				throw new NodeProcessException(e);
			}
		}
		if (person == null) {
			return goTo(false).replaceSharedState(sharedState.
					put(ImageWareCommon.IMAGEWARE_OAUTH_BEARER_TOKEN, tokenService.getBearerToken().getAccessToken()).
					put(ImageWareCommon.IMAGEWARE_GMI_SERVER, gmiServerURL).
					put(ImageWareCommon.IMAGEWARE_TENANT_NAME, tenant).
					put(ImageWareCommon.IMAGEWARE_PARAM_APPLICATION_NAME, config.gmiApplicationName())).build();
		}
		
		debug.message("validateUser returning and moving to next step");

		String templatePath = gmiServerURL + "/tenant/" + tenant + "/app/" + config.gmiApplicationName() + "/template/"
				+ config.gmiTemplateName();
		String messageJson = "{" + "\"maxResponseAttempts\" : 3," + "\"template\" : \"" + templatePath + "\"," +
				"\"metadata\" :" + "{" + "\"reason\" :\"" + config.messageReason() + "\"" + "}," + "\"expiresIn\" :"
				+ config.messageExpiresInSeconds() + "}";
		debug.message("IWS Message JSON: {} ", messageJson);

		try {
			biometricVerifyUser(sharedState, tokenService.getBearerToken(),templatePath + "/person/" + person.getId
					() + "/message", gmiServerURL + "/tenant/" + tenant + "/person/" + person.getId() +
					"/message/%s/response", messageJson);
		} catch (UnauthorizedException ue) {
			tokenService.setBearerToken(null);
			try {
				biometricVerifyUser(sharedState, tokenService.getBearerToken(), templatePath + "/person/" + person.getId
								() + "/message",
						gmiServerURL + "/tenant/" + tenant + "/person/" + person.getId() + "/message/%s/response",
						messageJson);
			} catch (UnauthorizedException e) {
				debug.error("Cannot successfully use new UserManager OAuth token.");
				throw new NodeProcessException(e);
			}
			
		}
		debug.message("biometricVerifyUser returning and completing authentication");
		
		return goTo(true).replaceSharedState(sharedState.
				put(ImageWareCommon.IMAGEWARE_OAUTH_BEARER_TOKEN, tokenService.getBearerToken().getAccessToken()))
				.build();
	}

	private void biometricVerifyUser(JsonValue sharedState, OauthBearerToken token, String
			gmiMessageUrl, String gmiVerifyUrlTemp, String messageJson) throws NodeProcessException, UnauthorizedException {

		CloseableHttpResponse response;
		HttpPost httpPost = new HttpPost(gmiMessageUrl);
		httpPost.setHeader("Content-Type", "application/json");
		httpPost.setHeader("Authorization", "Bearer " + token.getAccessToken());
		
		try {
			httpPost.setEntity(new StringEntity(messageJson));
			response = HttpClients.createSystem().execute(httpPost);
		}
		catch (IOException e) {
			throw new NodeProcessException(e);
		}

		// investigate response for success/failure
		StatusLine statusLine = response.getStatusLine();

		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) throw ImageWareCommon
				.getUnauthorizedException(getResourceBundle().getString("unauthorizedAccess"));
		else if (statusLine.getStatusCode() != HttpStatus.SC_CREATED) {
			String msg = String.format(getResourceBundle().getString("gmiVerificationError"), ImageWareCommon
					.IMAGEWARE_APPLICATION_NAME, statusLine.getStatusCode(), statusLine.getReasonPhrase());
			debug.error(msg);
			throw new NodeProcessException(msg);
		}

		Message message;
		try {
			message = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).readValue
					(EntityUtils.toString(response.getEntity()), Message.class);
		} catch (IOException e) {
			throw new NodeProcessException(e);
		}

		if (message == null || message.getMessageId() == null) throw new NodeProcessException(getResourceBundle()
				.getString("cannotReadGmiMessage"));

		// share verification response url in state for retrieval later
		sharedState.put(ImageWareCommon.IMAGEWARE_VERIFY_URL, String.format(gmiVerifyUrlTemp, message.getMessageId()));
		debug.message("biometricVerifyUser returning true for sending message and moving to next step");
	}

	
	private Person validateUser(String emailAddress, OauthBearerToken token, String gmiServerURL) throws
			UnauthorizedException, NodeProcessException {
		Person person;
		CloseableHttpResponse response;

		String emailAddressEncoded = ImageWareCommon.encodeEmailAddress(emailAddress);
		
		HttpGet httpGet = new HttpGet(gmiServerURL + "/person?userId=" + emailAddressEncoded);
		httpGet.setHeader("Content-Type", "application/json");
		httpGet.setHeader("Authorization", "Bearer " + token.getAccessToken());

		try {
			response =  HttpClients.createSystem().execute(httpGet);
		} catch (IOException e) {
			debug.error("Exception in validateUser: '{}'", e);
			throw new NodeProcessException(e);
		}

		if (response == null) throw new NodeProcessException(String.format(getResourceBundle().getString("noResponse"),
					ImageWareCommon.IMAGEWARE_APPLICATION_NAME));

		// investigate response for success/failure
		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_NOT_FOUND) return null;
		else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) throw ImageWareCommon
				.getUnauthorizedException(getResourceBundle().getString("unauthorizedAccess"));
		else if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) throw ImageWareCommon
				.getUserManagerCallFailedException(String.format(getResourceBundle().getString("errorUserManager"),
						response.getStatusLine()));


		try {
			// get entity from response
			HttpEntity entity = response.getEntity();
			
			person = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).readValue
					(EntityUtils.toString(entity), Person.class);
			// and ensure it is fully consumed
			EntityUtils.consume(entity);
		} catch (IOException e) {
			throw new NodeProcessException(e);
		}

		if (person == null) throw new NodeProcessException("Person is null");
		
		// validate person is registered
		httpGet = new HttpGet(gmiServerURL + "/person/" + person.getId() + "/app/" + config.gmiApplicationName() +
				"/device");
		httpGet.setHeader("Content-Type", "application/json");
		httpGet.setHeader("Authorization", "Bearer " + token.getAccessToken());
		
		try {
			response =  HttpClients.createSystem().execute(httpGet);
		} catch (IOException e) {
			debug.error("Exception in validateUser: '{}'", e);
			throw new NodeProcessException(e);
		}

		if (response == null) {
			throw new NodeProcessException(String.format(getResourceBundle().getString("noResponse"),
					ImageWareCommon.IMAGEWARE_APPLICATION_NAME));
		}

		// investigate response for success/failure
		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
			throw ImageWareCommon.getUnauthorizedException(getResourceBundle().getString("unauthorizedAccess"));
		}			
		else if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
			throw ImageWareCommon.getUserManagerCallFailedException(String.format(getResourceBundle().getString
					("errorUserManager"), response.getStatusLine()));
		}

		List<DeviceApplication> devices;
		try {

			// get entity from response
			HttpEntity entity = response.getEntity();
			
			devices = Arrays.asList(new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
					.readValue(EntityUtils.toString(entity), DeviceApplication[].class));
			// and ensure it is fully consumed
			EntityUtils.consume(entity);
		} catch (IOException e) {
			throw new NodeProcessException(e);
		}

		// check for not yet registered or not yet enrolled scenario
		if ( devices.isEmpty() || person.getData() == null || person.getData().getBiometricMetadata() == null ) {
			// not registered or not enrolled
			return null;
		} else return person;
	}
}