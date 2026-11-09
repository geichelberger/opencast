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

package org.opencastproject.graphql.acl;

import org.opencastproject.authorization.xacml.manager.api.ManagedAcl;
import org.opencastproject.graphql.type.output.OffsetPageInfo;

import java.util.List;
import java.util.stream.Collectors;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLNonNull;

@GraphQLName(GqlManagedAclCatalogue.TYPE_NAME)
@GraphQLNonNull
@GraphQLDescription("A list of ACLs")
public class GqlManagedAclCatalogue {

  public static final String TYPE_NAME = "ManagedAccessControlListCatalogue";

  private final List<ManagedAcl> acls;

  private final long totalCount;

  private final long offset;

  private final long limit;

  /**
   * @param acls the ACLs of the requested page
   * @param totalCount the number of ACLs over all pages
   */
  public GqlManagedAclCatalogue(List<ManagedAcl> acls, long totalCount, long offset, long limit) {
    this.acls = acls;
    this.totalCount = totalCount;
    this.offset = offset;
    this.limit = limit;
  }

  @GraphQLField
  @GraphQLNonNull
  public Long totalCount() {
    return totalCount;
  }

  @GraphQLField
  @GraphQLNonNull
  public OffsetPageInfo pageInfo() {
    return new OffsetPageInfo((totalCount + limit - 1) / limit, limit, offset);
  }

  @GraphQLField
  @GraphQLNonNull
  public List<GqlManagedAcl> nodes() {
    return acls.stream()
        .map(GqlManagedAcl::new)
        .collect(Collectors.toList());
  }


}
