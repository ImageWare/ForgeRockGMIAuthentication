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

import static com.iws.forgerock.ImageWareCommon.MAIL_ATTRIBUTE;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextOutputCallback;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.iws.forgerock.ImageWareCommon.UnauthorizedException;
import com.iws.forgerock.gmi.entity.Message;
import com.iws.forgerock.gmi.entity.Person;
import com.iwsinc.usermanager.client.OauthBearerToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that verifies a user account exists in the ImageWare GoVerifyID user
 * repository and sends a biometric verification message for ForgeRock authentication
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = ImageWareInitiator.Config.class)
public class ImageWareInitiator extends SingleOutcomeNode {
	private final Config config;
	private final CoreWrapper coreWrapper;
	private final static String DEBUG_FILE = "ImageWareInitiator";
	private Debug debug = Debug.getInstance(DEBUG_FILE);
//	private String userManagerURL;
	private String currentErrorMessage;
	private TokenService tokenService = null;

//	private String getUserManagerURL()
//	{
//		return userManagerURL;
//	}

//	private void setUserManagerURL(String userManagerUrl)
//	{
//		this.userManagerURL = userManagerUrl;
//	}
	
	private void setCurrentErrorMessage(String currentErrorMessage)
	{
		this.currentErrorMessage = currentErrorMessage;
	}
	
	private String getCurrentErrorMessage()
	{
		return currentErrorMessage;
	}
	
	


	/**
	 * Configuration for the node.
	 */
	public interface Config {
		@Attribute(order = 100,  validators = {RequiredValueValidator.class})
		default String tenantName() { return ""; }

		@Attribute(order = 200,  validators = {RequiredValueValidator.class})
		default String clientName() { return ""; }

		@Attribute(order = 300, validators = {RequiredValueValidator.class})
		default String clientSecret() { return ""; }

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
	 * @throws NodeProcessException
	 *             If the configuration was not valid.
	 */
	@Inject
	public ImageWareInitiator(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
		this.config = config;
		this.coreWrapper = coreWrapper;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {

		debug.message("ImageWareInitiator started");
		
		String emailAddress = null;
		
		try
		{
			validateConfiguration();

			String username = context.sharedState.get(USERNAME).asString();
			debug.message("Username {}.", username);

			AMIdentity userIdentity = getAmIdentity(context, username);

			emailAddress = getUserEmail(userIdentity);
			debug.message("Email Address {}.", emailAddress);
			
		}
		catch (NodeProcessException ex)
		{
			if (getCurrentErrorMessage() != null)
			{
				Action.ActionBuilder authenticateResult = goToNext();
				final List<Callback> callbacks = (List<Callback>) ImmutableList.of((Callback) new TextOutputCallback(0, getCurrentErrorMessage()));
				authenticateResult = Action.send(callbacks);
				// TODO send javascript to remove log in button
				
				return authenticateResult.build();
			}
			else
			{
				throw ex;
			}
		}

//		setUserManagerURL(config.userManagerURL() + "/oauth/token?scope=ignored&grant_type=client_credentials");
		
		TokenService.setConfig(config);
//		TokenService.setClientName(config.clientName());
//		TokenService.setClientSecret(config.clientSecret());
//		TokenService.setUserManagerURL(getUserManagerURL());
		
		tokenService = TokenService.getInstance();
		
		String tenant = config.tenantName();
		String gmiServerURL = config.gmiServerURL();
		Person person = null;

		try
		{
			person = validateUser(emailAddress, tokenService.getBearerToken(), gmiServerURL);
		
		}
		catch (UnauthorizedException ue)
		{
			tokenService.setBearerToken(null);
			
			try
			{
				person = validateUser(emailAddress, tokenService.getBearerToken(), gmiServerURL);
			}
			catch (UnauthorizedException e)
			{
				debug.error("Cannot successfully use new UserManager OAuth token.");
				throw new NodeProcessException(e);
			}
			
		}
		
		debug.message("validateUser returning and moving to next step");

		String templatePath = gmiServerURL + "/tenant/" + tenant + "/app/" + config.gmiApplicationName() + "/template/"
				+ config.gmiTemplateName();
		String messageJson = "{" + "\"maxResponseAttempts\" : 3," + "\"template\" : \"" + templatePath + "\"," +
				"\"metadata\" :" + "{" + "\"reason\" :\"" + config.messageReason() + "\"" + "}," + "\"expiresIn\" :"
				+ config.messageExpiresInSeconds() + "}";
		debug.message("IWS Message JSON: {} ", messageJson);

		try
		{
			biometricVerifyUser(context, tokenService.getBearerToken(), templatePath + "/person/" + person.getId() + "/message",
				gmiServerURL + "/tenant/" + tenant + "/person/" + person.getId() + "/message/%s/response",
				messageJson);
		}
		catch (UnauthorizedException ue)
		{
			tokenService.setBearerToken(null);
			
			try
			{
				biometricVerifyUser(context, tokenService.getBearerToken(), templatePath + "/person/" + person.getId() + "/message",
						gmiServerURL + "/tenant/" + tenant + "/person/" + person.getId() + "/message/%s/response",
						messageJson);
			}
			catch (UnauthorizedException e)
			{
				debug.error("Cannot successfully use new UserManager OAuth token.");
				throw new NodeProcessException(e);
			}
			
		}
		debug.message("biometricVerifyUser returning and completing authentication");
		
		return goToNext().replaceSharedState(context.sharedState.copy().
				put(ImageWareCommon.IMAGEWARE_OAUTH_BEARER_TOKEN, tokenService.getBearerToken().getAccessToken())).
				build();
	}


	private void validateConfiguration() throws NodeProcessException
	{
		
		if (StringUtils.isEmpty(config.tenantName())) 
		{ 
			setCurrentErrorMessage("Tenant Name is empty in node configuration");
			throw new NodeProcessException(getCurrentErrorMessage());
		}
		
		if (StringUtils.isEmpty(config.gmiApplicationName())) 
		{ 
			setCurrentErrorMessage("Application Name is empty in node configuration");
			throw new NodeProcessException(getCurrentErrorMessage());
		}

		if (StringUtils.isEmpty(config.clientName())) 
		{ 
			setCurrentErrorMessage("OAuth Client Name is empty in node configuration");
			throw new NodeProcessException(getCurrentErrorMessage());
		}

		if (StringUtils.isEmpty(config.clientSecret())) 
		{ 
			setCurrentErrorMessage("OAuth Client Secret is empty in node configuration");
			throw new NodeProcessException(getCurrentErrorMessage());
		}

		if (StringUtils.isEmpty(config.gmiTemplateName())) 
		{ 
			setCurrentErrorMessage("Template Name is empty in node configuration");
			throw new NodeProcessException(getCurrentErrorMessage());
		}
	}

	
	private String getUserEmail(AMIdentity userIdentity) throws NodeProcessException {
		Iterator<String> emailAddressIterator;
		try {
			emailAddressIterator = userIdentity.getAttribute(MAIL_ATTRIBUTE).iterator();
		}
		catch (IdRepoException | SSOException e) {
			debug.error("Error locating user attribute '{}' ", MAIL_ATTRIBUTE);
			throw new NodeProcessException(e);
		}

		if (!emailAddressIterator.hasNext()) {
			String errorMessage = String.format("User: '%s' has no email address in profile.", userIdentity.getName());
			debug.error(errorMessage);
			setCurrentErrorMessage(errorMessage);
			throw new NodeProcessException(errorMessage);
		}
		// getting primary (first) email address for user
		return emailAddressIterator.next();
	}

	private AMIdentity getAmIdentity(TreeContext context, String username) throws NodeProcessException {
		String errorMessage;

		if (StringUtils.isEmpty(username))
		{
			errorMessage = "Username not available.";
			debug.error(errorMessage);
			setCurrentErrorMessage(errorMessage);
			throw new NodeProcessException(errorMessage);
		}

		AMIdentity userIdentity = coreWrapper.getIdentity(username, coreWrapper.convertRealmPathToRealmDn(context
				.sharedState.get(REALM).asString()));
		if (userIdentity == null) {
			errorMessage = String.format("User: '%s' does not exist.", username);
			debug.error(errorMessage);
			setCurrentErrorMessage(errorMessage);
			throw new NodeProcessException(errorMessage);
		}
		return userIdentity;
	}


	private void biometricVerifyUser(TreeContext context, OauthBearerToken token, String
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

		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
			throw ImageWareCommon.getUnauthorizedException(String.format("Unauthorized acccess. May need a new OAuth token",
					response.getStatusLine()));
		}			
		else if (statusLine.getStatusCode() != HttpStatus.SC_CREATED) {
			String msg = String.format("GMI verification failed in %s error response: '%s: %s'", ImageWareCommon
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

		if (message == null || message.getMessageId() == null) {
			throw new NodeProcessException("biometricVerifyUser cannot read GMI Message");
		}

		// share verification response url in state for retrieval later
		context.sharedState.put(ImageWareCommon.IMAGEWARE_VERIFY_URL, String.format(gmiVerifyUrlTemp, message.getMessageId()));
		debug.message("biometricVerifyUser returning true for sending message and moving to next step");
	}

	private Person validateUser(String username, OauthBearerToken token, String gmiServerURL) throws
			UnauthorizedException, NodeProcessException {

		Person person;
		CloseableHttpResponse response;

		HttpGet httpGet = new HttpGet(gmiServerURL + "/person?userId=" + username);
		httpGet.setHeader("Content-Type", "application/json");
		httpGet.setHeader("Authorization", "Bearer " + token.getAccessToken());

		try {
			response =  HttpClients.createSystem().execute(httpGet);
		}
		catch (IOException e) {
			debug.error("Exception in validateUser: '{}'", e);
			throw new NodeProcessException(e);
		}

		if (response == null) {
			throw new NodeProcessException(String.format("Error. No response from %s", ImageWareCommon
					.IMAGEWARE_APPLICATION_NAME));
		}

		// investigate response for success/failure
		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
			throw ImageWareCommon.getUnauthorizedException(String.format("Unauthorized acccess. May need a new OAuth token",
					response.getStatusLine()));
		}			
		else if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
			throw ImageWareCommon.getUserManagerCallFailedException(String.format("Error in contacting UserManager. Status: %s",
					response.getStatusLine()));
		}

		try {

			// get entity from response
			HttpEntity entity = response.getEntity();
			
			person = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).readValue
					(EntityUtils.toString(entity), Person.class);
			// and ensure it is fully consumed
			EntityUtils.consume(entity);
		}
		catch (IOException e) {
			throw new NodeProcessException(e);
		}

		if (person == null) throw new NodeProcessException("Person is null");
		return person;
	}
}