package com.iws.forgerock;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.openam.auth.node.api.NodeProcessException;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iws.forgerock.ImageWareCommon.UnauthorizedException;
import com.iws.forgerock.gmi.entity.Application;
import com.iws.forgerock.gmi.entity.DeviceApplication;
import com.iws.forgerock.gmi.entity.Message;
import com.iws.forgerock.gmi.entity.MessageResponse;
import com.iws.forgerock.gmi.entity.Person;
import com.iwsinc.usermanager.client.OauthBearerToken;
import com.iwsinc.usermanager.exception.UserManagerCallFailedException;

public class ImageWareService
{

	private OauthBearerToken token;
	private String gmiServerUrl;
	private ResourceBundle resourceBundle;
	
	public ImageWareService(OauthBearerToken token, String gmiServerUrl, ResourceBundle resourceBundle)
	{
		this.token = token;
		this.gmiServerUrl = gmiServerUrl;
		this.resourceBundle = resourceBundle;

	}
	
	public OauthBearerToken getToken()
	{
		return token;
	}

	public void setToken(OauthBearerToken token)
	{
		this.token = token;
	}

	public String getGmiServerUrl()
	{
		return gmiServerUrl;
	}

	public void setGmiServerUrl(String gmiServerUrl)
	{
		this.gmiServerUrl = gmiServerUrl;
	}

	public ResourceBundle getResourceBundle()
	{
		return resourceBundle;
	}

	public void setResourceBundle(ResourceBundle resourceBundle)
	{
		this.resourceBundle = resourceBundle;
	}

	public CloseableHttpResponse postResponseFromImageWare(String gmiUrl, String jsonEntity) throws NodeProcessException
	{
		
		CloseableHttpResponse response;
		HttpPost httpPost = new HttpPost(gmiUrl);
		httpPost.setHeader("Content-Type", "application/json");
		httpPost.setHeader("Authorization", "Bearer " + token.getAccessToken());
		
		try {
			httpPost.setEntity(new StringEntity(jsonEntity));
			response = HttpClients.createSystem().execute(httpPost);
		}
		catch (IOException e) {
			throw new NodeProcessException(e);
		}
		
		return response;

	}
	
	public CloseableHttpResponse getResponseFromImageWare(String gmiMessageUrl) throws NodeProcessException
	{
		CloseableHttpResponse response;
		HttpGet httpGet = new HttpGet(gmiMessageUrl);
		httpGet.setHeader("Content-Type", "application/json");
		httpGet.setHeader("Authorization", "Bearer " + token.getAccessToken());
		
		try {
			response = HttpClients.createSystem().execute(httpGet);
		}
		catch (IOException e) {
			throw new NodeProcessException(e);
		}
		
		return response;

	}
	
	public Message postGMIMessage(String tenant, String applicationName, String templateName, Person person, String messageJson) throws NodeProcessException, UnauthorizedException
	{
		String gmiMessageUrl = getGmiServerUrl() + "/tenant/" + tenant + "/app/" + applicationName + "/template/" + templateName + "/person/" + person.getId() + "/message";
		
		CloseableHttpResponse response = postResponseFromImageWare(gmiMessageUrl, messageJson);
		
		// investigate response for success/failure
		StatusLine statusLine = response.getStatusLine();

		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) throw ImageWareCommon
				.getUnauthorizedException(getResourceBundle().getString("unauthorizedAccess"));
		else if (statusLine.getStatusCode() != HttpStatus.SC_CREATED) {
			String msg = String.format(getResourceBundle().getString("gmiVerificationError"), ImageWareCommon
					.IMAGEWARE_APPLICATION_NAME, statusLine.getStatusCode(), statusLine.getReasonPhrase());
			//debug.error(msg);
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

		return message;
	}

	public Person getGMIPerson(String emailAddress) throws NodeProcessException, UnauthorizedException
	{

		CloseableHttpResponse response = getResponseFromImageWare(getGmiServerUrl() + "/person?userId=" + ImageWareCommon.encodeEmailAddress(emailAddress));
		
		if (response == null) throw new NodeProcessException(String.format(getResourceBundle().getString("noResponse"),
					ImageWareCommon.IMAGEWARE_APPLICATION_NAME));

		// investigate response for success/failure
		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_NOT_FOUND) return null;
		else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) throw ImageWareCommon
				.getUnauthorizedException(getResourceBundle().getString("unauthorizedAccess"));
		else if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) throw ImageWareCommon
				.getUserManagerCallFailedException(String.format(getResourceBundle().getString("errorUserManager"),
						response.getStatusLine()));

		Person person;
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
		
		return person;
	}

	public List<DeviceApplication> getPersonDevices(Person person, String applicationName) throws NodeProcessException, UnauthorizedException
	{

		CloseableHttpResponse response = getResponseFromImageWare(getGmiServerUrl() + "/person/" + person.getId() + "/app/" +applicationName + "/device");
		
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

		return devices;
	}

	public Person addPerson(String emailAddress, String tenant) throws NodeProcessException, UnauthorizedException
	{
		Person person = null;

		String gmiUrl = getGmiServerUrl() + "/tenant/" + tenant + "/person";
		String messageJson = "{" + "\"userId\" : \"" + emailAddress + "\" }";
		
		CloseableHttpResponse response = postResponseFromImageWare(gmiUrl, messageJson);

		if (response != null) {
			// investigate response for success/failure
			int statusCode = response.getStatusLine().getStatusCode();
			if (statusCode == HttpStatus.SC_UNAUTHORIZED)
				throw ImageWareCommon.getUnauthorizedException(String.format("Unauthorized access. May need a new " +
						"OAuth token: %s", response.getStatusLine()));
			else if (statusCode == HttpStatus.SC_CONFLICT) {
				// if person exists in GMI, get the Person record
				String emailAddressEncoded = ImageWareCommon.encodeEmailAddress(emailAddress);


				CloseableHttpResponse getResponse = getResponseFromImageWare(getGmiServerUrl() + "/person?userId=" + emailAddressEncoded);
				
				if (getResponse != null) {
					// get entity from response
					
					try {
						HttpEntity entity = getResponse.getEntity();
	
						person = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).readValue
							(EntityUtils.toString(entity), Person.class);
						
						// and ensure it is fully consumed
						EntityUtils.consume(entity);
					}
					catch (IOException e) {
						throw new NodeProcessException(e);
					}
				}
			} else if (statusCode == HttpStatus.SC_CREATED) {
				// get entity from response
				try {
					
					HttpEntity entity = response.getEntity();
	
					person = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).readValue
							(EntityUtils.toString(entity), Person.class);
	
					// and ensure it is fully consumed
					EntityUtils.consume(entity);
				}
				catch (IOException e) {
					throw new NodeProcessException(e);
				}
			} else {
				String msg = String.format("Cannot add user. Status: %s", response.getStatusLine());
				throw new NodeProcessException(msg);
			}
		}
		
		return person;
	}

	public Application getTenantApplication(String tenant, String applicationName) throws NodeProcessException, UnauthorizedException
	{
		
		Application application = null;
		String gmiUrl = getGmiServerUrl() + "/tenant/" + tenant + "/person";

		CloseableHttpResponse response = getResponseFromImageWare(gmiUrl);

		if (response != null) {
			
			try {
				// get entity from response
				org.apache.http.HttpEntity entity = response.getEntity();
	
				// investigate response for success/failure
				if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
					throw ImageWareCommon.getUnauthorizedException("Unauthorized access. May need a new OAuth token");
				}			
				else if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_OK) {
					ObjectMapper objectMapper = new ObjectMapper();
					objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
					application = objectMapper.readValue(EntityUtils.toString(entity), Application.class);
				}
				else {
					UserManagerCallFailedException e = new UserManagerCallFailedException();
					String msg = String.format("Error in contacting GMI Server. Status: %s", response.getStatusLine());
					e.setMessageCode(msg);
					throw e;
				}
	
				// and ensure it is fully consumed
				EntityUtils.consume(entity);
			}
			catch (IOException e) {
				throw new NodeProcessException(e);
			}
		}
		else {
			String msg = String.format("Error. No response from {}", ImageWareCommon.IMAGEWARE_APPLICATION_NAME);
			throw new NodeProcessException(msg);
		}

		return application;
	}

	public List<MessageResponse> getGMIMessageResponses(String verifyResponseUrl) throws NodeProcessException, UnauthorizedException
	{
		List<MessageResponse> messageResponses;

		CloseableHttpResponse response = getResponseFromImageWare(verifyResponseUrl);
		
		if (response == null) {
			String msg = String.format(getResourceBundle().getString("handleVerifyResponseEmpty"), ImageWareCommon
					.IMAGEWARE_APPLICATION_NAME);
			throw new NodeProcessException(msg);
		}
		// get entity from response
		HttpEntity entity = response.getEntity();


		// investigate response for success/failure
		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
			throw ImageWareCommon.getUnauthorizedException(getResourceBundle().getString("unauthorizedAccess"));
		}			
		else if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
			throw new NodeProcessException(String.format(getResourceBundle().getString(
					"handleVerifyResponseIncorrectStatus"), ImageWareCommon.IMAGEWARE_APPLICATION_NAME, response
					.getStatusLine()));
		}
		
		try {
			messageResponses = Arrays.asList(new ObjectMapper().disable(DeserializationFeature.
					FAIL_ON_UNKNOWN_PROPERTIES).readValue(EntityUtils.toString(entity), MessageResponse[].class));
		} catch (IOException e) {
			throw new NodeProcessException(e);
		}

		// and ensure it is fully consumed
		try {
			EntityUtils.consume(entity);
		} catch (IOException e) {
			throw new NodeProcessException(e);
		}

		return messageResponses;


	}
}
