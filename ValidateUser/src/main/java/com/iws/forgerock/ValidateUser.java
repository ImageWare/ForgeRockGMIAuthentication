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

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;

import  org.apache.commons.codec.binary.Base64;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
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
import com.iwsinc.usermanager.client.OauthBearerToken;
import com.iwsinc.usermanager.exception.UserManagerCallFailedException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;

/** 
 * A node that verifies a user account exists in the ImageWare GoVerifyID user repository
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = ValidateUser.Config.class)
public class ValidateUser extends AbstractDecisionNode {

	public static final String IMAGEWARE_OAUTH_BEARER_TOKEN = "IMAGEWARE_OAUTH_BEARER_TOKEN";
	public static final String IMAGEWARE_USER = "IMAGEWARE_USER";
	public static final String IMAGEWARE_APPLICATION_NAME = "ImageWare GoVerifyID/GMI";
	
    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "ValidateUser";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100)
        default String tenantNameHeader() {
            return "GoVerifyID-Tenant-Name";
        }

        @Attribute(order = 200)
        default String clientNameHeader() {
            return "GoVerifyID-Client-Name";
        }

        @Attribute(order = 300)
        default String clientSecretHeader() {
            return "GoVerifyID-Client-Secret";
        }
        
        @Attribute(order = 400)
        default String userManagerURL() {
            return "GoVerifyID-UserManager-URL";
        }
        
        @Attribute(order = 500)
        default String gmiServerURL() {
            return "GoVerifyID-GMIServer-URL";
        }
    }


    /**
     * Create the node.
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public ValidateUser(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
    	
    	String username = context.sharedState.get(USERNAME).asString();
    	debug.error("[" + DEBUG_FILE + "]: " + "Username {}.", username);
		
        String tenant = config.tenantNameHeader();
        String clientName = config.clientNameHeader();
        String clientSecret = config.clientSecretHeader();
        String userManagerURL = config.userManagerURL();
        String gmiServerURL = config.gmiServerURL();
        String app = "GoVerifyID";
        String template = "GVID_VERIFY_CHOICE";
        
    	if (username == null || username.isEmpty())
    	{
    		 debug.error("[" + DEBUG_FILE + "]: " + "Username not available.");
    		 return goTo(false).build();
    	}
    	
    	userManagerURL += "/oauth/token?scope=ignored&grant_type=client_credentials";

    	OauthBearerToken token = getOauthToken(username, clientName, clientSecret, userManagerURL); 
    	if (token != null)
    	{
    		Person person = validateUser(username, token, tenant, gmiServerURL);
    		if (person != null)
    		{
   	   		 	debug.error("[" + DEBUG_FILE + "]: " + "validateUser returning true and moving to next step");

    			if (biometricVerifyUser(person, token, gmiServerURL, tenant, app, template ))
    			{

       	   		 	debug.error("[" + DEBUG_FILE + "]: " + "biometricVerifyUser returning true and completing authentication");

	       	         AMIdentity userIdentity = coreWrapper.getIdentity(username, context.sharedState.get(REALM).asString());
	       	         try {
	       	             if (userIdentity != null && userIdentity.isExists() && userIdentity.isActive()) {
	       	                 return goTo(true).replaceSharedState(context.sharedState.copy().put(USERNAME, username)).build();
	       	             }
	       	         } catch (IdRepoException e) {
	       	             debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
	       	         } catch (SSOException e) {
	       	             debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
	       	         }
	        			
       	         	return goTo(true).replaceSharedState(context.sharedState.copy().put(IMAGEWARE_USER, person)).build();
    			}
            	else
            	{
       	   		 	debug.error("[" + DEBUG_FILE + "]: " + "Returning false");
            		debug.error("[" + DEBUG_FILE + "]: " + "User failed verification in {} for User '{}' of Tenant '{}'", IMAGEWARE_APPLICATION_NAME, username, tenant);
        	   		 return goTo(false).build();
            	}
    		}
        	else
        	{

   	   		 	debug.error("[" + DEBUG_FILE + "]: " + "Returning false");
        		debug.error("[" + DEBUG_FILE + "]: " + "User not valid in {} for User '{}' of Tenant '{}'", IMAGEWARE_APPLICATION_NAME, username, tenant);
    	   		 return goTo(false).build();
        	}
    	}
    	else
    	{
	   		 debug.error("[" + DEBUG_FILE + "]: " + "{} Oauth bearer token not set in {} for User '{}' of Tenant '{}'", IMAGEWARE_APPLICATION_NAME, username, tenant);
	   		 return goTo(false).build();
    	}
    	
    	/*
        boolean hasUsername = context.request.headers.containsKey(config.usernameHeader());
        boolean hasPassword = context.request.headers.containsKey(config.passwordHeader());

        if (!hasUsername || !hasPassword) {
            return goTo(false).build();
        }

        String secret = config.secretKey();
        String password = context.request.headers.get(config.passwordHeader()).get(0);
        String username = context.request.headers.get(config.usernameHeader()).get(0);
        AMIdentity userIdentity = coreWrapper.getIdentity(username, context.sharedState.get(REALM).asString());
        try {
            if (secret.equals(password) && userIdentity != null && userIdentity.isExists() && userIdentity.isActive()) {
                return goTo(true).replaceSharedState(context.sharedState.copy().put(USERNAME, username)).build();
            }
        } catch (IdRepoException e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
        } catch (SSOException e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
        }
        return goTo(false).build();
        
        */
    }

	private boolean biometricVerifyUser(Person person, OauthBearerToken token, String gmiServerUrl, String tenant, String app, String template)
	{
		Boolean returnValue = null;
		String reason = "ForgeRock custom authentication";
		int expiresIn = 120;
		String templatePath = gmiServerUrl + "/tenant/" + tenant + "/app/" + app + "/template/" + template;
		String gmiMessageUrl = templatePath + "/person/" + person.getId() + "/message";

		
		String messageJson = 
				"{" +
			      "\"maxResponseAttempts\" : 3," +
			      "\"template\" : \"" + templatePath + "\"," +
			      "\"metadata\" :" +
			      "{" +
					"\"reason\" :\"" + reason + "\"" +
			      "}," +
			      "\"expiresIn\" :" + expiresIn +
			   "}";
		
		debug.error("[" + DEBUG_FILE + "]: " + "IWS Message JSON: {} ", messageJson);
		
		CloseableHttpResponse response = null;
		
		try
		{
			HttpPost httpPost = new HttpPost(gmiMessageUrl);
			httpPost.setHeader("Content-Type", "application/json");
			httpPost.setHeader("Authorization", "Bearer " + token.getAccessToken());

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
					if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_CREATED)
					{
						ObjectMapper objectMapper = new ObjectMapper();						
						// ignore existing Person Metadata and BiometricMetadata properties which are not included in com.iwsinc.forgerock.Person class
						objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
						Message message =  objectMapper.readValue(jsonResponse, Message.class);

						String verifyResponseUrl = gmiServerUrl + "/tenant/" + tenant + "/person/" + person.getId() + "/message/" + message.getMessageId() + "/response";
						
		   	   		 	debug.error("[" + DEBUG_FILE + "]: " + "biometricVerifyUser returning true for sending message and moving to next step");
		   	   		 	
		   	   		 	// poll and wait for response
		   	   		 	returnValue = handleVerifyResponse(verifyResponseUrl, token, expiresIn);
					}
					else
					{
						debug.error("[" + DEBUG_FILE + "]: " + "GMI verification failed in {} error response: '{}: {}'", IMAGEWARE_APPLICATION_NAME, response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
						
					}
				}	
			}
			catch (Exception exp)
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} getBearerToken: '{}'", IMAGEWARE_APPLICATION_NAME, exp);
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

		
		return (returnValue == null) ? false : returnValue;
	}

	private Boolean handleVerifyResponse(String verifyResponseUrl, OauthBearerToken token, int expiresInSeconds)
	{
		Boolean verifyComplete = null;
		boolean messageComplete = false;
		
		int iterateCount = expiresInSeconds / 3;
	 	for (int i=0; i<iterateCount; i++)
	 	{
   		 	try
			{
				Thread.sleep((long) (1000 * 2.5));
			} catch (InterruptedException e)
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} Thread.sleep: '{}'", IMAGEWARE_APPLICATION_NAME, e);
			}
   		 	
	   		 	
	   		 CloseableHttpResponse response = null;
	 		
	 		try
	 		{
	 			HttpGet httpGet = new HttpGet(verifyResponseUrl);
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
	 						// ignore existing Person Metadata and BiometricMetadata properties which are not included in com.iwsinc.forgerock.Person class
	 						objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
	 						List<MessageResponse> messageResponses =  Arrays.asList(objectMapper.readValue(jsonResponse, MessageResponse[].class));
	
	 						debug.error("[" + DEBUG_FILE + "]: " + "json from  GMI: '{}'", jsonResponse);
	 						
	 						for (MessageResponse messageResponse : messageResponses)
	 						{
	 							if (messageResponse.getTransactionType().equals("VERIFY") && messageResponse.getSucceeded())
	 							{
	 				 				debug.error("[" + DEBUG_FILE + "]: " + "Verification successful");
	 				 				verifyComplete = true;
	 							}
	 							else if (messageResponse.getTransactionType().equals("REJECT") && !messageResponse.getSucceeded() && messageResponse.getRejectionInfo().equals("User rejected alert."))
	 							{
	 				 				debug.error("[" + DEBUG_FILE + "]: " + "Verification was rejected");
	 				 				verifyComplete = false;
	 								
	 							}
	 							else if (messageResponse.getTransactionType().equals("REJECT") && !messageResponse.getSucceeded())
	 							{
	 				 				debug.error("[" + DEBUG_FILE + "]: " + "Verification has failed or timed out");
	 				 				verifyComplete = false;
	 								
	 							}
	 						}
	 					}
	 					else
	 					{
	 						UserManagerCallFailedException e = new UserManagerCallFailedException();
	 						String msg = String.format("Error in contacting UserManager. Status: %s", response.getStatusLine());
	 						e.setMessageCode(msg);
	 						throw e;
	 					}
	
	 					// and ensure it is fully consumed
	 					EntityUtils.consume(entity);
	 				}
	 				else
	 				{
	 					
	 				}
	 				
	 			}
	 			catch (Exception exp)
	 			{
	 				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} validateUser: '{}'", IMAGEWARE_APPLICATION_NAME, exp);
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

   		 	
   		 	
   		 	if (verifyComplete != null)
   		 	{
   		 		messageComplete = true;
   		 		break;
   		 	}
	 	}
	 	
	 	if (!messageComplete)
	 	{	
	 		debug.error("[" + DEBUG_FILE + "]: " + "Verification has timed out");
	 	}
	 	
		return verifyComplete;
	}

	private Person validateUser(String username, OauthBearerToken token, String tenant, String gmiServerURL)
	{
		Person person = null;
		CloseableHttpResponse response = null;
		
		try
		{
			HttpGet httpGet = new HttpGet(gmiServerURL + "/person?userId=" + username);
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
						// ignore existing Person Metadata and BiometricMetadata properties which are not included in com.iwsinc.forgerock.Person class
						objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
						person =  objectMapper.readValue(jsonResponse, Person.class);

						debug.error("[" + DEBUG_FILE + "]: " + "json from  GMI: '{}'", jsonResponse);
					}
					else
					{
						UserManagerCallFailedException e = new UserManagerCallFailedException();
						String msg = String.format("Error in contacting UserManager. Status: %s", response.getStatusLine());
						e.setMessageCode(msg);
						throw e;
					}

					// and ensure it is fully consumed
					EntityUtils.consume(entity);
				}
				else
				{
					
				}
				
			}
			catch (Exception exp)
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} validateUser: '{}'", IMAGEWARE_APPLICATION_NAME, exp);
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

		return person;
	}

	private OauthBearerToken getOauthToken(String username, String clientName, String clientSecret, String userManagerURL)
	{
		CloseableHttpResponse response = null;
		OauthBearerToken token = null;

		try
		{
			if (clientName != null && clientSecret != null)
			{
				String tokenString = clientName + ":" + clientSecret; 
				String accessToken = new String(Base64.encodeBase64(tokenString.getBytes()));
				HttpGet httpGet = new HttpGet(userManagerURL);
				httpGet.setHeader("Content-Type", "application/x-www-form-urlencoded");
				httpGet.setHeader("Authorization", "Basic " + accessToken);

				CloseableHttpClient httpclient = HttpClients.createSystem();

				try
				{
					response = httpclient.execute(httpGet);
				}
				catch (Exception exp)
				{
					debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} getBearerToken: '{}'", IMAGEWARE_APPLICATION_NAME, exp);
					throw exp;
				}

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
						token = objectMapper.readValue(jsonResponse, OauthBearerToken.class);	
					}
					else
					{
						UserManagerCallFailedException e = new UserManagerCallFailedException();
						String msg = String.format("Error in contacting UserManager. Status: %s", response.getStatusLine());
						e.setMessageCode(msg);
						throw e;
					}

					// and ensure it is fully consumed
					EntityUtils.consume(entity);
				}
				else
				{
					debug.error("[" + DEBUG_FILE + "]: " + "Unable to get {} security info", IMAGEWARE_APPLICATION_NAME);
					UserManagerCallFailedException e = new UserManagerCallFailedException();
					String msg = String.format("Error in retrieving response from UserManager. Response is null");
					e.setMessageCode(msg);
					throw e;
				}
			}
			else
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Unable to get {} security info", IMAGEWARE_APPLICATION_NAME);
				UserManagerCallFailedException e = new UserManagerCallFailedException();
				String msg = String.format("Error in contacting UserManager. Missing ClientName or ClientSecret");
				e.setMessageCode(msg);
				throw e;
				
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

		return token;
		
	}
}