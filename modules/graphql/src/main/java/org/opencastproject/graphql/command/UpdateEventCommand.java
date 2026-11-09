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
import org.opencastproject.graphql.event.GqlEvent;
import org.opencastproject.graphql.exception.GraphQLNotFoundException;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.GraphQLUnauthorizedException;
import org.opencastproject.graphql.exception.OpencastErrorType;
import org.opencastproject.graphql.execution.context.OpencastContext;
import org.opencastproject.graphql.execution.context.OpencastContextManager;
import org.opencastproject.graphql.type.input.AccessControlListInput;
import org.opencastproject.graphql.type.input.GqlCommonEventMetadataInput;
import org.opencastproject.graphql.util.MetadataFieldToGraphQLConverter;
import org.opencastproject.index.service.api.IndexService;
import org.opencastproject.index.service.catalog.adapter.events.CommonEventCatalogUIAdapter;
import org.opencastproject.index.service.exception.IndexServiceException;
import org.opencastproject.mediapackage.MediaPackageElementFlavor;
import org.opencastproject.metadata.dublincore.DublinCoreMetadataCollection;
import org.opencastproject.metadata.dublincore.MetadataField;
import org.opencastproject.metadata.dublincore.MetadataList;
import org.opencastproject.security.api.AccessControlList;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.util.NotFoundException;


import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

import graphql.schema.CoercingParseValueException;
import graphql.schema.GraphQLScalarType;
import graphql.schema.GraphQLTypeUtil;

public class UpdateEventCommand extends AbstractCommand<GqlEvent> {

  private final String eventId;

  public UpdateEventCommand(final Builder builder) {
    super(builder);
    this.eventId = builder.eventId;
  }

  @Override
  public GqlEvent execute() {
    OpencastContext context = OpencastContextManager.getCurrentContext();
    final ElasticsearchIndex index = context.getService(ElasticsearchIndex.class);
    final IndexService indexService = context.getService(IndexService.class);

    // Before anything else: the index service does not check write access for every kind of event
    EventSupport.requireWritableEvent(eventId, context);

    final Map<String, Object> eventMetadata = environment.getArgument("metadata");
    final AccessControlListInput aclInput = AclSupport.parseAclArgument(environment);

    // Prepare everything that can fail because of invalid input before the first write, so a bad request does not
    // leave the event half updated.
    final MetadataList metadata = createMetadataList(eventMetadata, indexService);
    final AccessControlList acl = aclInput != null ? AclSupport.createAccessControlList(aclInput, context) : null;

    try {
      indexService.updateEventMetadata(eventId, metadata, index);
      if (acl != null) {
        indexService.updateEventAcl(eventId, acl, index);
      }
    } catch (IndexServiceException | SearchIndexException e) {
      throw new GraphQLRuntimeException(e);
    } catch (UnauthorizedException e) {
      throw new GraphQLUnauthorizedException(e.getMessage());
    } catch (NotFoundException e) {
      throw new GraphQLNotFoundException(e.getMessage());
    }

    try {
      return new GqlEvent(indexService.getEvent(eventId, index)
          .orElseThrow(() -> new GraphQLRuntimeException(
              "Event " + eventId + " was updated but is not available in the index yet",
              OpencastErrorType.InternalError)));
    } catch (SearchIndexException e) {
      throw new GraphQLRuntimeException(e);
    }
  }

  private MetadataList createMetadataList(
      Map<String, Object> eventMetadata,
      IndexService indexService
  ) {
    CommonEventCatalogUIAdapter adapter = (CommonEventCatalogUIAdapter) indexService
        .getCommonEventCatalogUIAdapter();

    MetadataList list = new MetadataList();
    list.add(adapter, adapter.getRawFields());

    final MediaPackageElementFlavor flavor = MediaPackageElementFlavor
        .parseFlavor("dublincore/episode");

    final DublinCoreMetadataCollection collection = list.getMetadataByFlavor(flavor.toString());

    for (Map.Entry<String, Object> entry: eventMetadata.entrySet()) {
      String key = entry.getKey();
      final MetadataField target = MetadataSupport.requireField(collection, key, "event");
      var type = GraphQLTypeUtil.unwrapNonNull(MetadataFieldToGraphQLConverter.convertType(target));

      Object value;
      if (type instanceof GraphQLScalarType) {
        try {
          value = ((GraphQLScalarType)type).getCoercing()
              .parseValue(eventMetadata.get(key), environment.getGraphQlContext(), environment.getLocale());
        } catch (CoercingParseValueException e) {
          throw new GraphQLRuntimeException("Invalid value for metadata field '" + key + "': " + e.getMessage(),
              OpencastErrorType.BadRequest, e);
        }
      } else {
        value = eventMetadata.get(key);
      }

      if (value == null) {
        continue;
      }

      switch (target.getType()) {
        case DATE:
        case START_DATE:
          target.setValue(DateTimeFormatter.ofPattern(target.getPattern()).format((OffsetDateTime)value));
          break;
        case LONG:
          target.setValue(value);
          break;
        case TEXT:
          target.setValue(value);
          break;
        case BOOLEAN:
          target.setValue(value);
          break;
        case DURATION:
          target.setValue(((Duration) value).toMillis());
          break;
        case TEXT_LONG:
          target.setValue(value);
          break;
        case MIXED_TEXT:
          target.setValue(value);
          break;
        case START_TIME:
          target.setValue(value);
          break;
        case ORDERED_TEXT:
          target.setValue(value);
          break;
        case ITERABLE_TEXT:
          target.setValue(value);
          break;
        default:
          target.setValue(value);
          break;
      }
    }

    return list;
  }

  public static Builder create(String eventId, GqlCommonEventMetadataInput eventMetadataInput) {
    return new Builder(eventId, eventMetadataInput);
  }

  public static class Builder extends AbstractCommand.Builder<GqlEvent> {

    private final String eventId;

    private final GqlCommonEventMetadataInput eventMetadataInput;

    public Builder(String eventId, GqlCommonEventMetadataInput eventMetadataInput) {
      this.eventId = eventId;
      this.eventMetadataInput = eventMetadataInput;
    }

    @Override
    public void validate() {
      super.validate();
      if (eventId == null || eventId.isEmpty()) {
        throw new IllegalStateException("Event ID cannot be null or empty");
      }
      if (eventMetadataInput == null) {
        throw new IllegalStateException("Event metadata cannot be null");
      }
    }

    @Override
    public UpdateEventCommand build() {
      validate();
      return new UpdateEventCommand(this);
    }
  }

}
