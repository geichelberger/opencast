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

package org.opencastproject.graphql.command;

import org.opencastproject.authorization.xacml.manager.api.AclService;
import org.opencastproject.authorization.xacml.manager.api.AclServiceFactory;
import org.opencastproject.authorization.xacml.manager.api.ManagedAcl;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.OpencastErrorType;
import org.opencastproject.graphql.execution.context.OpencastContext;
import org.opencastproject.graphql.type.input.AccessControlListInput;
import org.opencastproject.graphql.util.GraphQLObjectMapper;
import org.opencastproject.security.api.AccessControlEntry;
import org.opencastproject.security.api.AccessControlList;
import org.opencastproject.security.api.SecurityService;

import graphql.schema.DataFetchingEnvironment;

/**
 * Access control list handling shared by the commands that create or update events and series.
 */
final class AclSupport {

  private static final String ACL_ARGUMENT = "acl";

  private AclSupport() {
  }

  /**
   * @return the {@code acl} argument of the current field, or {@code null} if it was not given
   * @throws GraphQLRuntimeException of type {@link OpencastErrorType#BadRequest} if the argument cannot be read
   */
  static AccessControlListInput parseAclArgument(DataFetchingEnvironment environment) {
    try {
      return GraphQLObjectMapper.newInstance()
          .convertValue(environment.getArgument(ACL_ARGUMENT), AccessControlListInput.class);
    } catch (IllegalArgumentException e) {
      throw new GraphQLRuntimeException("Invalid value for argument '" + ACL_ARGUMENT + "'",
          OpencastErrorType.BadRequest, e);
    }
  }

  /**
   * Create the access control list from the given entries, merged with the managed ACL if one is referenced.
   *
   * @throws GraphQLRuntimeException of type {@link OpencastErrorType#BadRequest} if the managed ACL does not exist.
   *     Ignoring it would replace the ACL with the given entries only, which may be none at all.
   */
  static AccessControlList createAccessControlList(AccessControlListInput aclInput, OpencastContext context) {
    AccessControlList acl = new AccessControlList();
    for (var entry : aclInput.getEntries()) {
      for (var action : entry.getAction()) {
        acl.getEntries().add(new AccessControlEntry(entry.getRole(), action, true));
      }
    }

    if (aclInput.getManagedAclId() != null) {
      AclService aclService = context.getService(AclServiceFactory.class)
          .serviceFor(context.getService(SecurityService.class).getOrganization());
      ManagedAcl managedAcl = aclService.getAcl(aclInput.getManagedAclId())
          .orElseThrow(() -> new GraphQLRuntimeException(
              "Unknown managed ACL " + aclInput.getManagedAclId(), OpencastErrorType.BadRequest));
      acl.merge(managedAcl.getAcl());
    }
    return acl;
  }

}
