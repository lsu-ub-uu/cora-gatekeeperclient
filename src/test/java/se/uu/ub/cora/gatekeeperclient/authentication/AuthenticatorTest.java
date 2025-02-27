/*
 * Copyright 2016, 2025 Uppsala University Library
 *
 * This file is part of Cora.
 *
 *     Cora is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     Cora is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with Cora.  If not, see <http://www.gnu.org/licenses/>.
 */

package se.uu.ub.cora.gatekeeperclient.authentication;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import se.uu.ub.cora.beefeater.authentication.User;
import se.uu.ub.cora.httphandler.spies.HttpHandlerFactorySpy;
import se.uu.ub.cora.httphandler.spies.HttpHandlerSpy;
import se.uu.ub.cora.spider.authentication.AuthenticationException;

public class AuthenticatorTest {
	private AuthenticatorImp authenticator;
	private User user;
	private String baseUrl;
	private HttpHandlerFactorySpy httpHandlerFactory;
	private HttpHandlerSpy httpHandler;

	@BeforeMethod
	public void setUp() {
		httpHandler = new HttpHandlerSpy();
		httpHandlerFactory = new HttpHandlerFactorySpy();
		httpHandlerFactory.MRV.setDefaultReturnValuesSupplier("factor", () -> httpHandler);
		String jsonAnswer = """
				{
				  "children": [
				    {
				      "children": [
				        {
				          "children": [ {"name": "id", "value": "someRole1"} ],
				          "name": "permissionRole"
				        },
				        {
				          "children": [ {"name": "id", "value": "someRole2"} ],
				          "name": "permissionRole"
				        }
				      ],
				      "name": "userRole"
				    }
				  ],
				  "name": "someId"
				}""";
		httpHandler.MRV.setDefaultReturnValuesSupplier("getResponseText", () -> jsonAnswer);
		httpHandler.MRV.setDefaultReturnValuesSupplier("getResponseCode", () -> 200);

		baseUrl = "http://localhost:8080/gatekeeper/";
		authenticator = AuthenticatorImp.usingBaseUrlAndHttpHandlerFactory(baseUrl,
				httpHandlerFactory);
	}

	@Test
	public void testGetBaseURL() {
		assertEquals(authenticator.getBaseURL(), baseUrl);
	}

	@Test
	public void testHttpHandlerCalledCorrectly() {
		user = authenticator.getUserForToken("someToken");

		httpHandlerFactory.MCR.assertParameters("factor", 0,
				"http://localhost:8080/gatekeeper/rest/user/someToken");
		httpHandler.MCR.assertParameters("setRequestMethod", 0, "GET");
	}

	@Test
	public void testHttpHandlerCalledCorrectlyWithNullToken() {
		user = authenticator.getUserForToken(null);

		httpHandlerFactory.MCR.assertParameters("factor", 0,
				"http://localhost:8080/gatekeeper/rest/user/");
		httpHandler.MCR.assertParameters("setRequestMethod", 0, "GET");
	}

	@Test(expectedExceptions = AuthenticationException.class)
	public void testUnauthorizedToken() {
		httpHandler.MRV.setDefaultReturnValuesSupplier("getResponseCode", () -> 401);

		user = authenticator.getUserForToken("dummyNonAuthenticatedToken");
	}

	@Test
	public void testHttpAnswerParsedToActiveUser() {
		setResponseTextActiveUser();

		user = authenticator.getUserForToken("someToken");

		assertEquals(user.id, "someId");
		assertTrue(user.active);
		assertEquals(user.roles.size(), 0);
		assertEquals(user.permissionUnitIds.size(), 0);
	}

	private void setResponseTextActiveUser() {
		String jsonAnswer = """
				{
				  "children": [
				    {
				      "children": [],
				      "name": "userRole"
				    },
				    {"name": "activeStatus", "value": "active"}
				  ],
				  "name": "someId"
				}
				""";
		httpHandler.MRV.setDefaultReturnValuesSupplier("getResponseText", () -> jsonAnswer);
	}

	@Test
	public void testHttpAnswerParsedToInactiveUser() {
		setResponseTextInactiveUser();

		user = authenticator.getUserForToken("someToken");

		assertEquals(user.id, "someId");
		assertFalse(user.active);
	}

	private void setResponseTextInactiveUser() {
		String jsonAnswer = """
				{
				  "children": [
				    {
				      "children": [],
				      "name": "userRole"
				    },
				    {"name": "activeStatus", "value": "inactive"}
				  ],
				  "name": "someId"
				}
				""";
		httpHandler.MRV.setDefaultReturnValuesSupplier("getResponseText", () -> jsonAnswer);
	}

	@Test
	public void testHttpAnswerParsedToUserWithUserRoles() {
		setResponseTextUserWithPermissionRoles();

		user = authenticator.getUserForToken("someToken");

		assertEquals(user.roles.size(), 2);
		assertTrue(user.roles.contains("someRole1"));
		assertTrue(user.roles.contains("someRole2"));
	}

	private void setResponseTextUserWithPermissionRoles() {
		String jsonAnswer = """
				{
				  "children": [
				    {"name": "activeStatus", "value": "active"},
				    {
				      "children": [
				        {
				          "children": [ {"name": "id", "value": "someRole1"} ],
				          "name": "permissionRole"
				        },
				        {
				          "children": [ {"name": "id", "value": "someRole2"} ],
				          "name": "permissionRole"
				        }
				      ],
				      "name": "userRole"
				    }
				  ],
				  "name": "someId"
				}""";
		httpHandler.MRV.setDefaultReturnValuesSupplier("getResponseText", () -> jsonAnswer);
	}

	@Test
	public void testHttpAnswerParsedToUserWithPermissionUnits() {
		setResponseTextUserWithPermissionUnits();

		user = authenticator.getUserForToken("someToken");

		assertEquals(user.permissionUnitIds.size(), 2);
		assertTrue(user.permissionUnitIds.contains("somePermissionUnit001"));
		assertTrue(user.permissionUnitIds.contains("somePermissionUnit002"));
	}

	private void setResponseTextUserWithPermissionUnits() {
		String jsonAnswer = """
				{
				  "children": [
				    {
				      "children": [],
				      "name": "userRole"
				    },
				    {"name": "permissionUnit", "value": "somePermissionUnit001"},
				    {"name": "permissionUnit", "value": "somePermissionUnit002"},
				    {"name": "activeStatus", "value": "active"}
				  ],
				  "name": "someId"
				}
				""";
		httpHandler.MRV.setDefaultReturnValuesSupplier("getResponseText", () -> jsonAnswer);
	}

	@Test
	public void testHttpAnswerParsedToUserWithAllFields() {
		setResponseTextUserWithAllFields();

		user = authenticator.getUserForToken("someToken");

		assertEquals(user.id, "someId");
		assertTrue(user.active);
		assertEquals(user.permissionUnitIds.size(), 2);
		assertTrue(user.permissionUnitIds.contains("somePermissionUnit001"));
		assertTrue(user.permissionUnitIds.contains("somePermissionUnit002"));
		assertEquals(user.roles.size(), 2);
		assertTrue(user.roles.contains("someRole1"));
		assertTrue(user.roles.contains("someRole2"));
	}

	private void setResponseTextUserWithAllFields() {
		String jsonAnswer = """
				{
				  "children": [
				    {
				      "children": [
				        {
				          "children": [ {"name": "id", "value": "someRole1"} ],
				          "name": "permissionRole"
				        },
				        {
				          "children": [ {"name": "id", "value": "someRole2"} ],
				          "name": "permissionRole"
				        }
				      ],
				      "name": "userRole"
				    },
				    {"name": "permissionUnit", "value": "somePermissionUnit001"},
				    {"name": "permissionUnit", "value": "somePermissionUnit002"},
				    {"name": "activeStatus", "value": "active"}
				  ],
				  "name": "someId"
				}""";
		httpHandler.MRV.setDefaultReturnValuesSupplier("getResponseText", () -> jsonAnswer);
	}
}
