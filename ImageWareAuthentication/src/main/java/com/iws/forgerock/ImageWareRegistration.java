/*
Ï * The contents of this file are subject to the terms of the Common Development and
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
import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextOutputCallback;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.iws.forgerock.ImageWareDecision.ImageWareDecisionOutcomeProvider;
import com.iws.forgerock.gmi.entity.Application;
import com.iws.forgerock.gmi.entity.Person;
import com.iwsinc.usermanager.client.OauthBearerToken;
import com.iwsinc.usermanager.exception.UserManagerCallFailedException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that creates a User in ImageWare's GoVerifyID backend for mobile biometric enrollment and verification
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = ImageWareRegistration.Config.class)
public class ImageWareRegistration extends AbstractDecisionNode
{

	private static final String BUNDLE = "com/iws/forgerock/ImageWareRegistration";
	
	private final Config config;
	private final CoreWrapper coreWrapper;
	private final static String DEBUG_FILE = "ImageWareRegistration";
	protected Debug debug = Debug.getInstance(DEBUG_FILE);
	
	private String gmiServerURL;
	private String userManagerURL;
	private OauthBearerToken bearerToken;
	private String currentErrorMessage;
	
	String getGmiServerURL()
	{
		return gmiServerURL;
	}

	private void setGmiServerURL(String gmiServerUrl)
	{
		this.gmiServerURL = gmiServerUrl;
	}
	
	private String getUserManagerURL()
	{
		return userManagerURL;
	}

	private void setUserManagerURL(String userManagerUrl)
	{
		this.userManagerURL = userManagerUrl;
	}

	private OauthBearerToken getBearerToken()
	{
		return bearerToken;
	}

	private void setBearerToken(OauthBearerToken bearerToken)
	{
		this.bearerToken = bearerToken;
	}
	
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
	public interface Config
	{
		@Attribute(order = 100,  validators = {RequiredValueValidator.class})
		default String tenantName() { return ""; }

		@Attribute(order = 200,  validators = {RequiredValueValidator.class})
		default String clientName() { return ""; }

		@Attribute(order = 300,  validators = {RequiredValueValidator.class})
		default String clientSecret() { return ""; }

		@Attribute(order = 400,  validators = {RequiredValueValidator.class})
		default String userManagerURL() { return "https://gmi-ha.iwsinc.com/usermanager"; }

		@Attribute(order = 500,  validators = {RequiredValueValidator.class})
		default String gmiServerURL() { return "https://gmi-ha.iwsinc.com/gmiserver"; }

		@Attribute(order = 600,  validators = {RequiredValueValidator.class})
		default String gmiApplicationName() { return "GoVerifyID"; }
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
	public ImageWareRegistration(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException
	{
		this.config = config;
		this.coreWrapper = coreWrapper;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException
	{

		// NOTE: The user being registered is a Person entity in GMI
	

		// Need both username and email from user interface or LDAP record
		

		String emailAddress = null;

		try
		{
			validateConfiguration();
			
			String username = context.sharedState.get(USERNAME).asString();
			debug.message("[" + DEBUG_FILE + "]: " + "Username {}.", username);
	
			AMIdentity userIdentity = getAmIdentity(context, username);
			emailAddress = getUserEmail(userIdentity);
			debug.message("Email Address {}.", emailAddress);
	
		}
		catch (NodeProcessException ex)
		{
			if (getCurrentErrorMessage() != null)
			{
				Action.ActionBuilder registerResult = this.goTo(false);
				final List<Callback> callbacks = (List<Callback>) ImmutableList.of((Callback) new TextOutputCallback(0, getCurrentErrorMessage()));
				registerResult = Action.send(callbacks);
				// TODO send javascript to remove log in button
				
				return registerResult.build();
			}
			else
			{
				throw ex;
			}
		}
		
		String tenant = config.tenantName();
		String applicationName = config.gmiApplicationName();
		String clientName = config.clientName();
		String clientSecret = config.clientSecret();
		
		setGmiServerURL(config.gmiServerURL());
		setUserManagerURL(config.userManagerURL() + "/oauth/token?scope=ignored&grant_type=client_credentials");
		

		// Step 1: authorize oauth client
		OauthBearerToken token = getOauthToken(clientName, clientSecret);
		setBearerToken(token);
		
		// Step 2: add GMI person 
		try
		{
			addUserAsPersonToGmi(emailAddress, tenant);
		}
		catch (NodeProcessException ex)
		{
			if (getCurrentErrorMessage() != null)
			{
				Action.ActionBuilder registerResult = this.goTo(false);
				final List<Callback> callbacks = (List<Callback>) ImmutableList.of((Callback) new TextOutputCallback(0, getCurrentErrorMessage()));
				registerResult = Action.send(callbacks);
				// TODO send javascript to remove log in button
				
				return registerResult.build();
			}
			else
			{
				throw ex;
			}
		}
				
		// Step 3: user needs to download GoVerifyID app and register with email address
		//	upon success, user will get a registration email
		//	after completing the registration step, the user will receive an Enroll Message on their mobile device
			
		
		// If the GMI TenantApplication.validationType property is set to "email" then this user will be able to self-register
		// Otherwise the user must wait for Tenant Admin to finalize the registration process
		ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(ImageWareRegistration.BUNDLE, ImageWareRegistration.class.getClassLoader());
        
		String userRegisterInfo = String.format(bundle.getString("selfRegistrationMessage"), applicationName);
				
		Application application = getTenantApplication(tenant, applicationName);
			
		if (! application.getValidationType().equals(ImageWareCommon.IMAGEWARE_EMAIL_VALIDATION_TYPE))
		{
			userRegisterInfo = bundle.getString("tenantRegistrationMessage");
		}
	
		Action.ActionBuilder registerResult = this.goTo(true);
		final List<Callback> callbacks = (List<Callback>) ImmutableList.of((Callback) new TextOutputCallback(0, userRegisterInfo));
		registerResult = Action.send(callbacks);
		
		return registerResult.build();
		
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
		String emailAddress = emailAddressIterator.next();
		if (StringUtils.isEmpty(emailAddress))
		{
			String errorMessage = String.format("User: '%s' has no email address in profile.", userIdentity.getName());
			debug.error(errorMessage);
			setCurrentErrorMessage(errorMessage);
			throw new NodeProcessException(errorMessage);
		}
		
		return emailAddress;
	}
	
	private AMIdentity getAmIdentity(TreeContext context, String username) throws NodeProcessException {
		String errorMessage;

		if (StringUtils.isEmpty(username))
		{
			errorMessage = "Username not available.";
			debug.error(errorMessage);
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


	private Application getTenantApplication(String tenant, String applicationName) throws NodeProcessException
	{
		Application application = null;
		CloseableHttpResponse response = null;
		OauthBearerToken token = getBearerToken();

		try
		{
			HttpGet httpGet = new HttpGet(gmiServerURL + "/tenant/" + tenant + "/app/" + applicationName);
			httpGet.setHeader("Content-Type", "application/json");
			httpGet.setHeader("Authorization", "Bearer " + token.getAccessToken());

			CloseableHttpClient httpclient = HttpClients.createSystem();

			try
			{
				response = httpclient.execute(httpGet);
				if (response != null)
				{
					// get entity from response
					org.apache.http.HttpEntity entity = response.getEntity();

					String jsonResponse = EntityUtils.toString(entity);

					// investigate response for success/failure
					if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_OK)
					{
						ObjectMapper objectMapper = new ObjectMapper();
						objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
						application = objectMapper.readValue(jsonResponse, Application.class);

						debug.message("[" + DEBUG_FILE + "]: " + "json from GMI server: '{}'", jsonResponse);
					}
					else
					{
						UserManagerCallFailedException e = new UserManagerCallFailedException();
						String msg = String.format("Error in contacting GMI Server. Status: %s", response.getStatusLine());
						e.setMessageCode(msg);
						throw e;
					}

					// and ensure it is fully consumed
					EntityUtils.consume(entity);
				}
				else
				{
					debug.error("[" + DEBUG_FILE + "]: " + "Error. No response from {}", ImageWareCommon.IMAGEWARE_APPLICATION_NAME);
				}

			}
			catch (Exception exp)
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} getTenantApplication: '{}'", ImageWareCommon.IMAGEWARE_APPLICATION_NAME, exp.getMessage());
				throw exp;
			}
		}
		catch (Exception exp)
		{
			debug.error(exp.getMessage());

		}
		finally
		{
			if (response != null)
			{
				try
				{
					response.close();
				}
				catch (Throwable t)
				{
				}
			}
		}

		if (application == null) throw new NodeProcessException("GMI Application is null");

		return application;
	}

	
	private Person addUserAsPersonToGmi(String emailAddress, String tenant) throws NodeProcessException 
	{
		Person person = null;
		CloseableHttpResponse response = null;
		OauthBearerToken token = getBearerToken();
	
		String gmiUrl = getGmiServerURL() + "/tenant/" + tenant + "/person";

		try
		{

			HttpPost httpPost = new HttpPost(gmiUrl);
			httpPost.setHeader("Content-Type", "application/json");
			httpPost.setHeader("Authorization", "Bearer " + token.getAccessToken());

			String messageJson = "{" + "\"userId\" : \"" + emailAddress + "\" }";
			
			httpPost.setEntity(new StringEntity(messageJson));
			CloseableHttpClient httpclient = HttpClients.createSystem();
			
			
			try
			{
				response = httpclient.execute(httpPost);	
				
				if (response != null)
				{

					// get entity from response
					org.apache.http.HttpEntity entity = response.getEntity();

					String jsonResponse = EntityUtils.toString(entity);

					// investigate response for success/failure
					if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_CONFLICT)
					{
						debug.error("Error in {}. User with email address {} already exists in tenant {}", ImageWareCommon.IMAGEWARE_APPLICATION_NAME, emailAddress, tenant);
						setCurrentErrorMessage(String.format("User with email address '%s' already exists for tenant '%s'", emailAddress, tenant));
					}
					else if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_CREATED)
					{
						ObjectMapper objectMapper = new ObjectMapper();
						objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
						person = objectMapper.readValue(jsonResponse, Person.class);
					}
					else
					{
						String msg = String.format("Cannot add user. Status: %s", response.getStatusLine());
						debug.error(msg);
					}
					
				}
			}
			catch (Exception exp)
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} addUserAsPersonToGmi: '{}'", ImageWareCommon.IMAGEWARE_APPLICATION_NAME, exp);
				throw exp;
			}
		}
		catch (Exception exp)
		{
			debug.error(exp.getMessage());
		}
		
		if (person == null) throw new NodeProcessException("GMI Person is null");
		
		return person;
	}
	

	private OauthBearerToken getOauthToken(String clientName, String clientSecret) throws
			NodeProcessException {

		CloseableHttpResponse response;

		HttpGet httpGet = new HttpGet(getUserManagerURL());
		httpGet.setHeader("Content-Type", "application/x-www-form-urlencoded");
		httpGet.setHeader("Authorization", "Basic " + new String(Base64.encodeBase64((clientName + ":" +
				clientSecret).getBytes())));

		try {
			response =  HttpClients.createSystem().execute(httpGet);
		}
		catch (Exception e) {
			debug.error("Exception in getBearerToken: '{}'", e);
			throw new NodeProcessException(e);
		}

		if (response == null) throw new  NodeProcessException(getUserManagerCallFailedException("Error in retrieving " +
				"response from UserManager. Response is null"));
		// get entity from response
		HttpEntity entity = response.getEntity();
		StatusLine statusLine = response.getStatusLine();

		// investigate response for success/failure
		if (statusLine.getStatusCode() != HttpStatus.SC_OK) {
			throw new NodeProcessException(getUserManagerCallFailedException( String.format("Error in contacting " +
					"UserManager. Status: %s", statusLine)));
		}

		OauthBearerToken token;
		try {
			token = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).readValue
					(EntityUtils.toString(entity), OauthBearerToken.class);

			// and ensure it is fully consumed
			EntityUtils.consume(entity);
		}
		catch (IOException e) {
			throw new NodeProcessException(e);
		}
		if (token == null) throw new NodeProcessException("OAuth Token is null");

		return token;
	}

	private UserManagerCallFailedException getUserManagerCallFailedException(String msg) {
		UserManagerCallFailedException e = new UserManagerCallFailedException();
		e.setMessageCode(msg);
		return e;
	}
}
