/*
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.graphql.user;

import org.opencastproject.graphql.execution.context.OpencastContext;
import org.opencastproject.graphql.execution.context.OpencastContextManager;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.SecurityConstants;
import org.opencastproject.security.api.User;

/**
 * Decides whether the current user may see private details (email address, roles) of other users.
 */
public final class UserPrivileges {

  /** Users with this role may see the email addresses and roles of other users, like in the admin interface. */
  public static final String USERS_VIEW_ROLE = "ROLE_UI_USERS_VIEW";

  private UserPrivileges() {
  }

  /**
   * Check if the user of the current request context is a user administrator. Without a context nobody is.
   *
   * @return whether the current user may see email addresses and roles of other users
   */
  public static boolean canSeePrivateDetails() {
    OpencastContext context = OpencastContextManager.getCurrentContext();
    return context != null && isUserAdministrator(context.getUser(), context.getOrganization());
  }

  public static boolean isUserAdministrator(User user, Organization organization) {
    if (user == null) {
      return false;
    }
    return user.hasRole(SecurityConstants.GLOBAL_ADMIN_ROLE)
        || user.hasRole(USERS_VIEW_ROLE)
        || (organization != null && organization.getAdminRole() != null && user.hasRole(organization.getAdminRole()));
  }

}
