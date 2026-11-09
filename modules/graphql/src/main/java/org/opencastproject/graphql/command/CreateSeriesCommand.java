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

import org.opencastproject.elasticsearch.api.SearchIndexException;
import org.opencastproject.elasticsearch.index.ElasticsearchIndex;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.OpencastErrorType;
import org.opencastproject.graphql.execution.context.OpencastContext;
import org.opencastproject.graphql.execution.context.OpencastContextManager;
import org.opencastproject.graphql.series.GqlSeries;
import org.opencastproject.graphql.type.input.AccessControlListInput;
import org.opencastproject.graphql.type.input.GqlCommonSeriesMetadataInput;
import org.opencastproject.index.service.api.IndexService;
import org.opencastproject.index.service.exception.IndexServiceException;
import org.opencastproject.metadata.dublincore.MetadataList;
import org.opencastproject.security.api.AccessControlList;
import org.opencastproject.series.api.SeriesService;

import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

public class CreateSeriesCommand extends AbstractCommand<GqlSeries> {

  private AccessControlListInput aclInput;

  public CreateSeriesCommand(final Builder builder) {
    super(builder);
    this.aclInput = builder.accessControlListInput;
  }

  @Override
  public GqlSeries execute() {
    OpencastContext context = OpencastContextManager.getCurrentContext();
    final ElasticsearchIndex index = context.getService(ElasticsearchIndex.class);
    final IndexService indexService = context.getService(IndexService.class);

    final Map<String, Object> seriesMetadata = environment.getArgument("metadata");

    MetadataList metadataList = MetadataSupport.createSeriesMetadataList(seriesMetadata, indexService);
    Map<String, String> options = new TreeMap<>();
    Optional<Long> optThemeId = Optional.empty();

    final SeriesService seriesService = context.getService(SeriesService.class);

    AccessControlList acl = AclSupport.createAccessControlList(aclInput, context);
    String seriesId;
    try {
      seriesId = indexService.createSeries(metadataList, options, Optional.of(acl), optThemeId);
    } catch (IndexServiceException e) {
      throw new GraphQLRuntimeException(e);
    }

    try {
      return new GqlSeries(
          index.getSeries(seriesId, context.getOrganization(), context.getUser())
              .orElseThrow(() -> new GraphQLRuntimeException(
                  "Series " + seriesId + " was created but is not available in the index yet",
                  OpencastErrorType.InternalError))
      );
    } catch (SearchIndexException e) {
      throw new GraphQLRuntimeException(e);
    }
  }

  public static Builder create(
      GqlCommonSeriesMetadataInput seriesMetadataInput,
      AccessControlListInput accessControlListInput
  ) {
    return new Builder(seriesMetadataInput, accessControlListInput);
  }

  public static class Builder extends AbstractCommand.Builder<GqlSeries> {

    private final GqlCommonSeriesMetadataInput seriesMetadataInput;

    private final AccessControlListInput accessControlListInput;

    public Builder(GqlCommonSeriesMetadataInput seriesMetadataInput, AccessControlListInput accessControlListInput) {
      this.seriesMetadataInput = seriesMetadataInput;
      this.accessControlListInput = accessControlListInput;
    }

    @Override
    public void validate() {
      super.validate();
      if (seriesMetadataInput == null) {
        throw new IllegalStateException("Series metadata cannot be null");
      }
      if (accessControlListInput == null) {
        throw new IllegalStateException("Access control list cannot be null");
      }
    }

    @Override
    public CreateSeriesCommand build() {
      validate();
      return new CreateSeriesCommand(this);
    }
  }

}
