package com.iws.forgerock;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.util.UUID;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicStatusLine;
import org.forgerock.guava.common.base.Charsets;
import org.forgerock.guava.common.io.CharStreams;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.junit.Test;

import com.iwsinc.usermanager.client.OauthBearerToken;

public class TokenServiceTest
{

	OauthBearerToken getTestToken()
	{
		UUID guid = UUID.randomUUID();
		OauthBearerToken token = new OauthBearerToken();
		token.setAccessToken(guid.toString());
		token.setExpiresIn(12 * 60 * 60);
		token.setScope("ignored");
		token.setTokenType("client_credentials");
		
		return token;
	}
	
	OauthBearerToken getExpiredToken()
	{
		UUID guid = UUID.randomUUID();
		OauthBearerToken token = new OauthBearerToken();
		token.setAccessToken(guid.toString());
		token.setExpiresIn(0);
		token.setScope("ignored");
		token.setTokenType("client_credentials");
		
		return token;
	}
	

	@Test
	public void testTokenServiceHttp() throws NodeProcessException, IllegalStateException, IOException
	{
		OauthBearerToken testToken = getTestToken();
		

		CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
		CloseableHttpResponse response = mock(CloseableHttpResponse.class);
		HttpEntity entity = mock(HttpEntity.class);
		TokenService tokenService =  mock(TokenService.class);
		
		String jsonResponse = "{\"access_token\":\"467de2da-9ee3-4cd2-9734-28543ab52734\",\"token_type\":\"bearer\",\"expires_in\":43199,\"scope\":\"IGNORED\"}";
		
		when(tokenService.getBearerToken()).thenReturn(testToken);
		
		when(response.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, HttpStatus.SC_OK, "OK"));
		when(entity.getContent()).thenReturn(new ByteArrayInputStream(CharStreams.toString(new StringReader(jsonResponse)).getBytes(Charsets.UTF_8)));
		when(response.getEntity()).thenReturn(entity);
		
		when(httpClient.execute((HttpGet) any())).thenReturn(response);
		
		OauthBearerToken token = tokenService.getBearerToken();
		
	
		assertEquals("HTTP responses not matching", token, testToken);
		
	}
	
	@Test
	public void testTokenService() throws NodeProcessException
	{
		OauthBearerToken testToken = getTestToken();
		
		TokenService tsMock = mock(TokenService.class);
		when(tsMock.getBearerToken()).thenReturn(testToken);
		
		assertEquals(tsMock.getBearerToken(), testToken);
		
	}

	// Expired Token will not be retrieved the second time, a new token will be retrieved
	@Test
	public void testTokenServiceExpired() throws NodeProcessException
	{
		OauthBearerToken testToken = getTestToken();
		OauthBearerToken expiredToken = getTestToken();
		
		TokenService tsMock = mock(TokenService.class);
		when(tsMock.getBearerToken()).thenReturn(expiredToken).thenReturn(testToken);
		
		assertEquals(tsMock.getBearerToken(), expiredToken);
		assertEquals(tsMock.getBearerToken(), testToken);
		
		
	}
	
	
}
