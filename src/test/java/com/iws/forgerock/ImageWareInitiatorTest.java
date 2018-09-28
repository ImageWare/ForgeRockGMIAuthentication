package com.iws.forgerock;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.ResourceBundle;
import java.util.UUID;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.util.i18n.PreferredLocales;
import org.junit.Test;

import com.iws.forgerock.ImageWareCommon.UnauthorizedException;
import com.iws.forgerock.ImageWareInitiator.Config;
import com.iws.forgerock.gmi.entity.BiometricMetadata;
import com.iws.forgerock.gmi.entity.DeviceApplication;
import com.iws.forgerock.gmi.entity.Message;
import com.iws.forgerock.gmi.entity.Metadata;
import com.iws.forgerock.gmi.entity.Person;

public class ImageWareInitiatorTest
{

	class ConfigStub implements Config
	{
		
		@Override
		public String gmiApplicationName()
		{
			// TODO Auto-generated method stub
			return "GoVerifyID";
		}

		@Override
		public String gmiTemplateName()
		{
			// TODO Auto-generated method stub
			return "Template";
		}

		@Override
		public String gmiServerURL()
		{
			// TODO Auto-generated method stub
			return "http://thegmiserver.com";
		}

		@Override
		public String tenantName()
		{
			// TODO Auto-generated method stub
			return "Tenant";
		}

		@Override
		public char[] clientSecret()
		{
			// TODO Auto-generated method stub
			return null;
		}
		
	}
	
	@Test
	public void testValidateUser() throws NodeProcessException, UnauthorizedException
	{
		Config config = new ConfigStub();
		CoreWrapper core = mock(CoreWrapper.class);
		
		ImageWareInitiator initiator = new ImageWareInitiator(config, core);
		ImageWareService imageWareService = mock(ImageWareService.class);
		
		String email = "xxx@abc.com";
		String applicationName = "GoVerifyID";
		
		Person person = new Person();
		String uuid = UUID.randomUUID().toString();
		person.setId(uuid);
		Metadata data = new Metadata();
		data.setBiometricMetadata(new BiometricMetadata());
		person.setData(data);
		
		
		List<DeviceApplication> devices = new ArrayList<DeviceApplication>();
		devices.add(mock(DeviceApplication.class));
		
		when(imageWareService.getGMIPerson(email)).thenReturn(person);
		when(imageWareService.getPersonDevices(person, applicationName)).thenReturn(devices);
		
		initiator.setImageWareService(imageWareService);
		Person found = initiator.validateUser(email);
		
		assertEquals("person not matching", person.getId(), found.getId());
	}
	

	@Test
	public void testValidateUserPersonIsNullWhenNoDevicesFound() throws NodeProcessException, UnauthorizedException
	{
		Config config = new ConfigStub();
		CoreWrapper core = mock(CoreWrapper.class);
		
		ImageWareInitiator initiator = new ImageWareInitiator(config, core);
		ImageWareService imageWareService = mock(ImageWareService.class);
		
		String email = "xxx@abc.com";
		String applicationName = "GoVerifyID";
		
		Person person = new Person();
		String uuid = UUID.randomUUID().toString();
		person.setId(uuid);
		Metadata data = new Metadata();
		data.setBiometricMetadata(new BiometricMetadata());
		person.setData(data);
		
		
		List<DeviceApplication> devices = new ArrayList<DeviceApplication>();
		
		when(imageWareService.getGMIPerson(email)).thenReturn(person);
		when(imageWareService.getPersonDevices(person, applicationName)).thenReturn(devices);
		
		initiator.setImageWareService(imageWareService);
		Person found = initiator.validateUser(email);
		
		assertNull("person should be null", found);
	}
	
	@Test
	public void testBiometricVerifyUser() throws NodeProcessException, UnauthorizedException
	{
		Config config = new ConfigStub();
		CoreWrapper core = mock(CoreWrapper.class);
		
		ImageWareInitiator initiator = new ImageWareInitiator(config, core);
		ImageWareService imageWareService = mock(ImageWareService.class);
		
		Person person = new Person();
		String uuid = UUID.randomUUID().toString();
		person.setId(uuid);
		Metadata data = new Metadata();
		data.setBiometricMetadata(new BiometricMetadata());
		person.setData(data);

		Message message = new Message();
		message.setMessageId(UUID.randomUUID().toString());
		
		
		JsonValue sharedState = new JsonValue(new HashMap<Object, String>());
		String messageJson = "";
		
		List<DeviceApplication> devices = new ArrayList<DeviceApplication>();
		devices.add(mock(DeviceApplication.class));
		
		when(imageWareService.postGMIMessage("Tenant", config.gmiApplicationName(), config.gmiTemplateName(), person, messageJson)).thenReturn(message);
		
		initiator.setImageWareService(imageWareService);
		initiator.setPerson(person);
		initiator.biometricVerifyUser(sharedState, messageJson);
	}
	
	@Test(expected = NodeProcessException.class)
	public void testBiometricVerifyUserMessageIsNullThrowsException() throws NodeProcessException, UnauthorizedException
	{
		Config config = new ConfigStub();
		CoreWrapper core = mock(CoreWrapper.class);
		
		ImageWareInitiator initiator = new ImageWareInitiator(config, core);
		ImageWareService imageWareService = mock(ImageWareService.class);
		
		Person person = new Person();
		String uuid = UUID.randomUUID().toString();
		person.setId(uuid);
		Metadata data = new Metadata();
		data.setBiometricMetadata(new BiometricMetadata());
		person.setData(data);

		Message message = null;
		ResourceBundle resourceBundle = (new PreferredLocales()).getBundleInPreferredLocale(ImageWareCommon.IMAGEWARE_INITIATOR_BUNDLE,	ImageWareInitiator.class.getClassLoader());
		
		JsonValue sharedState = new JsonValue(new HashMap<Object, String>());
		String messageJson = "";
		
		List<DeviceApplication> devices = new ArrayList<DeviceApplication>();
		devices.add(mock(DeviceApplication.class));

		when(imageWareService.postGMIMessage("Tenant", config.gmiApplicationName(), config.gmiTemplateName(), person, messageJson)).thenReturn(message);
		
		initiator.setImageWareService(imageWareService);
		initiator.setPerson(person);
		initiator.setResourceBundle(resourceBundle);
		initiator.biometricVerifyUser(sharedState, messageJson);
	}
	
}
