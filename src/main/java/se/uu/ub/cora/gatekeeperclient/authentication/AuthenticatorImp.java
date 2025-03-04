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

import se.uu.ub.cora.beefeater.authentication.User;
import se.uu.ub.cora.httphandler.HttpHandler;
import se.uu.ub.cora.httphandler.HttpHandlerFactory;
import se.uu.ub.cora.json.parser.JsonArray;
import se.uu.ub.cora.json.parser.JsonObject;
import se.uu.ub.cora.json.parser.JsonParser;
import se.uu.ub.cora.json.parser.JsonValue;
import se.uu.ub.cora.json.parser.org.OrgJsonParser;
import se.uu.ub.cora.spider.authentication.AuthenticationException;
import se.uu.ub.cora.spider.authentication.Authenticator;

public final class AuthenticatorImp implements Authenticator {
	private static final int STATUS_OK = 200;
	private static final String CHILDREN = "children";
	private static final String VALUE = "value";
	private HttpHandlerFactory httpHandlerFactory;
	private User user;
	private JsonObject jsonUser;
	private String responseText;
	private String baseUrl;

	private AuthenticatorImp(String baseUrl, HttpHandlerFactory httpHandlerFactory) {
		this.baseUrl = baseUrl;
		this.httpHandlerFactory = httpHandlerFactory;
	}

	public static AuthenticatorImp usingBaseUrlAndHttpHandlerFactory(String baseUrl,
			HttpHandlerFactory httpHandlerFactory) {
		return new AuthenticatorImp(baseUrl, httpHandlerFactory);
	}

	// TODO: Implement getGuestUser method instead of passsing null token to getUserForToken method
	@Override
	public User getUserForToken(String authToken) {
		getUserForTokenFromGatekeeper(authToken);
		return createUserFromResponseText();
	}

	private void getUserForTokenFromGatekeeper(String authToken) {
		String url = baseUrl + "rest/user/";
		if (authToken != null) {
			url += authToken;
		}
		HttpHandler httpHandler = httpHandlerFactory.factor(url);
		httpHandler.setRequestMethod("GET");
		if (httpHandler.getResponseCode() != STATUS_OK) {
			throw new AuthenticationException("authToken gives no authorization");
		}
		responseText = httpHandler.getResponseText();
	}

	private User createUserFromResponseText() {
		getJsonUserFromResponseText(responseText);
		setId();
		setUserFields();
		return user;
	}

	private void getJsonUserFromResponseText(String responseText) {
		JsonParser jsonParser = new OrgJsonParser();
		jsonUser = (JsonObject) jsonParser.parseString(responseText);
	}

	private void setId() {
		String id = getIdFromJsonUser();
		user = new User(id);
	}

	private String getIdFromJsonUser() {
		return jsonUser.getValueAsJsonString("name").getStringValue();
	}

	private void setUserFields() {
		JsonArray children = jsonUser.getValueAsJsonArray(CHILDREN);
		children.forEach(this::setUserField);
	}

	public String getBaseURL() {
		// Needed for test
		return baseUrl;
	}

	private void setUserField(JsonValue child) {
		JsonObject jsonObject = (JsonObject) child;
		String childName = jsonObject.getValueAsJsonString("name").getStringValue();
		if (isActiveStatus(childName)) {
			setActiveStatus(jsonObject);
		}
		if (isUserRole(childName)) {
			setUserRoles(jsonObject);
		}
		if (isPermissionUnit(childName)) {
			setPermissionUnit(jsonObject);
		}
	}

	private void setPermissionRole(JsonObject permissionRole) {
		String roleName = getRoleNameFromRoleChild(permissionRole);
		user.roles.add(roleName);
	}

	private String getRoleNameFromRoleChild(JsonObject permissionRole) {
		JsonArray permissionRoleChildren = permissionRole.getValueAsJsonArray(CHILDREN);
		JsonObject roleId = permissionRoleChildren.getValueAsJsonObject(0);
		return roleId.getValueAsJsonString(VALUE).getStringValue();
	}

	private boolean isActiveStatus(String childName) {
		return childName.equals("activeStatus");
	}

	private void setActiveStatus(JsonObject jsonObject) {
		String activeStatusValue = jsonObject.getValueAsJsonString(VALUE).getStringValue();
		user.active = activeStatusValue.equals("active");
	}

	private boolean isUserRole(String childName) {
		return childName.equals("userRole");
	}

	private void setUserRoles(JsonObject jsonObject) {
		JsonArray userRoles = jsonObject.getValueAsJsonArray(CHILDREN);
		for (JsonValue permissionRole : userRoles) {
			setPermissionRole((JsonObject) permissionRole);
		}
	}

	private boolean isPermissionUnit(String childName) {
		return childName.equals("permissionUnit");
	}

	private void setPermissionUnit(JsonObject jsonObject) {
		String value = jsonObject.getValueAsJsonString(VALUE).getStringValue();
		user.permissionUnitIds.add(value);
	}
}
