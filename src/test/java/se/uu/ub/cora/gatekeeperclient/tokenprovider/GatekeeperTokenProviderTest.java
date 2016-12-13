/*
 * Copyright 2016 Uppsala University Library
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

package se.uu.ub.cora.gatekeeperclient.tokenprovider;

import static org.testng.Assert.assertEquals;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import se.uu.ub.cora.gatekeeperclient.GatekeeperImp;
import se.uu.ub.cora.gatekeeperclient.UserInfo;
import se.uu.ub.cora.gatekeeperclient.UserPickerFactorySpy;
import se.uu.ub.cora.gatekeeperclient.authentication.User;
import se.uu.ub.cora.gatekeeperclient.tokenprovider.GatekeeperTokenProvider;
import se.uu.ub.cora.gatekeeperclient.tokenprovider.GatekeeperTokenProviderImp;

public class GatekeeperTokenProviderTest {
	private static final int FIRST_NON_HARDCODED = 3;
	private UserPickerFactorySpy userPickerFactory;
	private GatekeeperImp gatekeeper;
	private User logedInUser;
	private GatekeeperTokenProvider tokenProvider;

	@BeforeMethod
	public void setUp() {
		userPickerFactory = new UserPickerFactorySpy();
		GatekeeperImp.INSTANCE.setUserPickerFactory(userPickerFactory);
		gatekeeper = GatekeeperImp.INSTANCE;
		tokenProvider = new GatekeeperTokenProviderImp();
	}

	@Test
	public void testGetAuthTokenForUserInfo() {
		UserInfo userInfo = UserInfo.withLoginIdAndLoginDomain("someLoginId", "someLoginDomain");
		String authToken = tokenProvider.getAuthTokenForUserInfo(userInfo);

		assertEquals(userPickerFactory.factoredUserPickers.get(FIRST_NON_HARDCODED).usedUserInfo,
				userInfo);
		logedInUser = gatekeeper.getUserForToken(authToken);
		assertEquals(logedInUser.loginId, "someLoginId");
	}

}