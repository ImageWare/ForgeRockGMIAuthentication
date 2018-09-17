package com.iws.forgerock;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iwsinc.usermanager.client.OauthBearerToken;
import java.io.IOException;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.openam.auth.node.api.NodeProcessException;

class TokenService {
	
	private static class TokenServiceHelper {
		private static final TokenService INSTANCE = new TokenService();
	}
	    
    static TokenService getInstance() {
    	return TokenServiceHelper.INSTANCE;
    }
     
 	private OauthBearerToken bearerToken = null;
 	private long tokenExpiresAt;
 	private static String clientName;
 	private static char[] clientSecret;
 	private static String userManagerURL;

	OauthBearerToken getBearerToken() throws NodeProcessException {
 		if (bearerToken == null || isTokenExpired()) storeOauthToken(clientName, clientSecret, userManagerURL);
 		return bearerToken;
 	}

 	void setBearerToken(OauthBearerToken bearerToken) { this.bearerToken = bearerToken; }

 	private long getTokenExpiresAt() { return tokenExpiresAt; }

 	private void setTokenExpiresAt(long tokenExpiresAt) { this.tokenExpiresAt = tokenExpiresAt; }
 	

	static void setConfig(ImageWareInitiator.Config config) {
		clientName = config.clientName();
		clientSecret = config.clientSecret();
		userManagerURL = config.userManagerURL() + "/oauth/token?scope=ignored&grant_type=client_credentials";
		
	}
	
	private boolean isTokenExpired() {
		return getTokenExpiresAt() <= System.currentTimeMillis() / 1000;
	}
	
    private void storeOauthToken(String clientName, char[] clientSecret, String userManagerURL) throws
			NodeProcessException {
		CloseableHttpResponse response;
		
		HttpGet httpGet = new HttpGet(userManagerURL);
		httpGet.setHeader("Content-Type", "application/x-www-form-urlencoded");
		httpGet.setHeader("Authorization", "Basic " + new String(Base64.encodeBase64((clientName + ":" + new String
				(clientSecret)).getBytes())));
	
		try {
			response =  HttpClients.createSystem().execute(httpGet);
		}
		catch (Exception e) {
			throw new NodeProcessException(e);
		}
	
		if (response == null) throw new NodeProcessException(ImageWareCommon.getUserManagerCallFailedException
				("Error in retrieving response from UserManager. Response is null"));
		// get entity from response
		HttpEntity entity = response.getEntity();
		StatusLine statusLine = response.getStatusLine();
	
		// investigate response for success/failure
		if (statusLine.getStatusCode() != HttpStatus.SC_OK) {
			throw new NodeProcessException(ImageWareCommon.getUserManagerCallFailedException( String.format("Error in contacting " +
					"UserManager. Status: %s", statusLine)));
		}
	
		OauthBearerToken token;
		try {
			token = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).readValue
					(EntityUtils.toString(entity), OauthBearerToken.class);
	
			long expiresAt = token.getExpiresIn() + System.currentTimeMillis()/1000;

			setBearerToken(token);
			setTokenExpiresAt(expiresAt);

			// and ensure it is fully consumed
			EntityUtils.consume(entity);
		}
		catch (IOException e) {
			throw new NodeProcessException(e);
		}

	}
    
}
