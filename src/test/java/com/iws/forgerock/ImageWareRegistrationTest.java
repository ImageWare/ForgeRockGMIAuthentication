package com.iws.forgerock;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.core.CoreWrapper;
import org.junit.Test;

import com.iws.forgerock.ImageWareCommon.UnauthorizedException;
import com.iws.forgerock.gmi.entity.Application;
import com.iws.forgerock.gmi.entity.Person;

public class ImageWareRegistrationTest
{

	
	@Test
	public void testAddPersonToGmi() throws NodeProcessException, UnauthorizedException
	{
		CoreWrapper core = mock(CoreWrapper.class);
		
		ImageWareRegistration registration = new ImageWareRegistration(core);
		ImageWareService imageWareService = mock(ImageWareService.class);
		
		String email = "xxx@abc.com";
		String tenant = "Tenant";
		
		Person person = new Person();
		String uuid = UUID.randomUUID().toString();
		person.setId(uuid);
		
		when(imageWareService.addPerson(email, tenant)).thenReturn(person);
		
		registration.setImageWareService(imageWareService);
		registration.addUserAsPersonToGmi(email, tenant);
		
	}

	@Test(expected = NodeProcessException.class)
	public void testAddPersonToGmiNullPersonThrowsException() throws NodeProcessException, UnauthorizedException
	{
		CoreWrapper core = mock(CoreWrapper.class);
		
		ImageWareRegistration registration = new ImageWareRegistration(core);
		ImageWareService imageWareService = mock(ImageWareService.class);
		
		String email = "xxx@abc.com";
		String tenant = "Tenant";
		
		Person person = null;
		
		when(imageWareService.addPerson(email, tenant)).thenReturn(person);
		
		registration.setImageWareService(imageWareService);
		registration.addUserAsPersonToGmi(email, tenant);
		
	}


	
	@Test
	public void testGetTenantApplication() throws NodeProcessException, UnauthorizedException
	{
		CoreWrapper core = mock(CoreWrapper.class);
		
		ImageWareRegistration registration = new ImageWareRegistration(core);
		ImageWareService imageWareService = mock(ImageWareService.class);
		
		String tenant = "Tenant";
		String applicationName = "GoVerifyID";
		
		Application application = new Application();
		application.setCode(applicationName);
		
		when(imageWareService.getTenantApplication(tenant, applicationName)).thenReturn(application);
		
		registration.setImageWareService(imageWareService);
		Application found = registration.getTenantApplication(tenant, applicationName);
		
		assertEquals("Applications not matching", application, found);
		assertEquals("Application codes not matching", applicationName, found.getCode());
	}
	
	@Test(expected = NodeProcessException.class)
	public void testGetTenantApplicationNullApplicationThrowsException() throws NodeProcessException, UnauthorizedException
	{
		CoreWrapper core = mock(CoreWrapper.class);
		
		ImageWareRegistration registration = new ImageWareRegistration(core);
		ImageWareService imageWareService = mock(ImageWareService.class);
		
		String tenant = "Tenant";
		String applicationName = "GoVerifyID";
		
		Application application = null;
		
		when(imageWareService.getTenantApplication(tenant, applicationName)).thenReturn(application);
		
		registration.setImageWareService(imageWareService);
		registration.getTenantApplication(tenant, applicationName);
		
	}
}
