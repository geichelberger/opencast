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
import org.opencastproject.elasticsearch.api.SearchResult;
import org.opencastproject.elasticsearch.index.ElasticsearchIndex;
import org.opencastproject.elasticsearch.index.objects.event.Event;
import org.opencastproject.elasticsearch.index.objects.event.EventSearchQuery;
import org.opencastproject.graphql.exception.GraphQLNotFoundException;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.GraphQLUnauthorizedException;
import org.opencastproject.graphql.execution.context.OpencastContext;
import org.opencastproject.index.service.api.IndexService;
import org.opencastproject.security.api.Permissions;

/**
 * Event handling shared by the commands that change or delete events.
 */
final class EventSupport {

  private EventSupport() {
  }

  /**
   * Look up an event the current user may modify. Call this before changing an event.
   *
   * <p>The services behind {@link IndexService} do not reliably check write access: removing an event, for example,
   * stops its workflows and deletes its schedule with read access only. Other APIs restrict these operations by role,
   * while GraphQL only requires a logged-in user, so the check has to happen here.
   *
   * @param eventId the id of the event
   * @param context the current context
   * @return the event
   * @throws GraphQLNotFoundException if the event does not exist or the user may not read it
   * @throws GraphQLUnauthorizedException if the user may read but not modify the event
   */
  static Event requireWritableEvent(String eventId, OpencastContext context) {
    final ElasticsearchIndex index = context.getService(ElasticsearchIndex.class);
    try {
      final SearchResult<Event> result = index.getByQuery(
          new EventSearchQuery(context.getOrganization().getId(), context.getUser())
              .withIdentifier(eventId)
              .withAction(Permissions.Action.WRITE));
      if (result.getPageSize() > 0) {
        return result.getItems()[0].getSource();
      }
      if (context.getService(IndexService.class).getEvent(eventId, index).isPresent()) {
        throw new GraphQLUnauthorizedException("Not allowed to modify event " + eventId);
      }
      throw new GraphQLNotFoundException("Event " + eventId + " not found");
    } catch (SearchIndexException e) {
      throw new GraphQLRuntimeException(e);
    }
  }

}
