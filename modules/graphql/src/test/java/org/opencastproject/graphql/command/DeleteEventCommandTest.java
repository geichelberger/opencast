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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.opencastproject.elasticsearch.api.SearchIndexException;
import org.opencastproject.elasticsearch.index.ElasticsearchIndex;
import org.opencastproject.elasticsearch.index.objects.event.Event;
import org.opencastproject.elasticsearch.index.objects.event.EventSearchQuery;
import org.opencastproject.graphql.config.GraphQLConfiguration;
import org.opencastproject.graphql.event.GqlDeleteEventPayload;
import org.opencastproject.graphql.event.GqlDeleteEventState;
import org.opencastproject.graphql.exception.GraphQLNotFoundException;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.GraphQLUnauthorizedException;
import org.opencastproject.index.service.api.IndexService;
import org.opencastproject.index.service.api.IndexService.EventRemovalResult;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.util.NotFoundException;
import org.opencastproject.workflow.api.WorkflowDatabaseException;

import org.easymock.EasyMock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

public class DeleteEventCommandTest extends AbstractCommandTest {

  private static final String EVENT_ID = "event-1";
  private static final String RETRACT_WORKFLOW_ID = "delete";

  private ElasticsearchIndex index;
  private IndexService indexService;
  private GraphQLConfiguration configuration;

  @BeforeEach
  void setUp() {
    index = EasyMock.createMock(ElasticsearchIndex.class);
    indexService = EasyMock.createMock(IndexService.class);
    configuration = EasyMock.createMock(GraphQLConfiguration.class);
    EasyMock.expect(configuration.eventRetractWorkflowId()).andReturn(RETRACT_WORKFLOW_ID).anyTimes();
    mockService(ElasticsearchIndex.class, index);
    mockService(IndexService.class, indexService);
    mockService(GraphQLConfiguration.class, configuration);
  }

  @Test
  void removesEventSuccessfully() throws Exception {
    assertRemovalResultIsMapped(EventRemovalResult.SUCCESS, GqlDeleteEventState.SUCCESS);
  }

  @Test
  void reportsAlreadyRemovedEventAsSuccess() throws Exception {
    assertRemovalResultIsMapped(EventRemovalResult.NOT_FOUND, GqlDeleteEventState.SUCCESS);
  }

  @Test
  void reportsRetractingEvent() throws Exception {
    assertRemovalResultIsMapped(EventRemovalResult.RETRACTING, GqlDeleteEventState.RETRACTING);
  }

  @Test
  void reportsGeneralFailureAsFailed() throws Exception {
    assertRemovalResultIsMapped(EventRemovalResult.GENERAL_FAILURE, GqlDeleteEventState.FAILED);
  }

  @Test
  void throwsNotFoundWhenEventDoesNotExist() throws Exception {
    expectNoWritableEvent(index);
    EasyMock.expect(indexService.getEvent(EVENT_ID, index)).andReturn(Optional.empty());

    EasyMock.replay(bundleContext, index, indexService, configuration);

    assertThrows(GraphQLNotFoundException.class, () -> buildCommand().execute());

    EasyMock.verify(indexService);
  }

  @Test
  void rejectsEventTheUserMayOnlyReadWithoutRemovingIt() throws Exception {
    expectNoWritableEvent(index);
    EasyMock.expect(indexService.getEvent(EVENT_ID, index))
        .andReturn(Optional.of(new Event(EVENT_ID, "mh_default_org")));

    // removeEvent is not expected, so calling it fails the test
    EasyMock.replay(bundleContext, index, indexService, configuration);

    assertThrows(GraphQLUnauthorizedException.class, () -> buildCommand().execute());

    EasyMock.verify(index, indexService);
  }

  @Test
  void wrapsSearchIndexExceptionAsGraphQLRuntimeException() throws Exception {
    EasyMock.expect(index.getByQuery(EasyMock.anyObject(EventSearchQuery.class)))
        .andThrow(new SearchIndexException("boom"));

    EasyMock.replay(bundleContext, index, indexService, configuration);

    assertThrows(GraphQLRuntimeException.class, () -> buildCommand().execute());
  }

  @Test
  void wrapsWorkflowDatabaseExceptionAsGraphQLRuntimeException() throws Exception {
    assertRemovalFailureIsMapped(new WorkflowDatabaseException("boom"), GraphQLRuntimeException.class);
  }

  @Test
  void wrapsUnauthorizedExceptionAsGraphQLUnauthorizedException() throws Exception {
    assertRemovalFailureIsMapped(new UnauthorizedException("nope"), GraphQLUnauthorizedException.class);
  }

  @Test
  void wrapsNotFoundExceptionAsGraphQLNotFoundException() throws Exception {
    assertRemovalFailureIsMapped(new NotFoundException("missing"), GraphQLNotFoundException.class);
  }

  @Test
  void buildFailsWhenIdIsNull() {
    assertThrows(IllegalArgumentException.class, () -> DeleteEventCommand.create(null)
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenEnvironmentIsMissing() {
    assertThrows(IllegalStateException.class, () -> DeleteEventCommand.create(EVENT_ID).build());
  }

  private void assertRemovalResultIsMapped(EventRemovalResult removalResult, GqlDeleteEventState expected)
          throws Exception {
    Event event = new Event(EVENT_ID, "mh_default_org");
    expectWritableEvent(index, event);
    EasyMock.expect(indexService.removeEvent(event, RETRACT_WORKFLOW_ID)).andReturn(removalResult);

    EasyMock.replay(bundleContext, index, indexService, configuration);

    GqlDeleteEventPayload payload = buildCommand().execute();

    assertEquals(EVENT_ID, payload.getId());
    assertEquals(expected, payload.getStatus());

    EasyMock.verify(indexService);
  }

  private void assertRemovalFailureIsMapped(Exception thrown, Class<? extends Throwable> expected)
          throws Exception {
    Event event = new Event(EVENT_ID, "mh_default_org");
    expectWritableEvent(index, event);
    EasyMock.expect(indexService.removeEvent(event, RETRACT_WORKFLOW_ID)).andThrow(thrown);

    EasyMock.replay(bundleContext, index, indexService, configuration);

    assertThrows(expected, () -> buildCommand().execute());

    EasyMock.verify(indexService);
  }

  private AbstractCommand<GqlDeleteEventPayload> buildCommand() {
    return DeleteEventCommand.create(EVENT_ID).environment(environment).build();
  }

}
