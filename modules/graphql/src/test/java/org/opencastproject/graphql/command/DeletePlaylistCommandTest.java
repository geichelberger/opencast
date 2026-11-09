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

import org.opencastproject.graphql.exception.GraphQLNotFoundException;
import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.GraphQLUnauthorizedException;
import org.opencastproject.graphql.playlist.type.output.GqlDeletePlaylistPayload;
import org.opencastproject.playlists.Playlist;
import org.opencastproject.playlists.PlaylistService;
import org.opencastproject.security.api.UnauthorizedException;
import org.opencastproject.util.NotFoundException;

import org.easymock.EasyMock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DeletePlaylistCommandTest extends AbstractCommandTest {

  private static final String PLAYLIST_ID = "playlist-1";

  private PlaylistService playlistService;

  @BeforeEach
  void setUp() {
    playlistService = EasyMock.createMock(PlaylistService.class);
    mockService(PlaylistService.class, playlistService);
  }

  @Test
  void removesPlaylistAndReturnsPayload() throws Exception {
    EasyMock.expect(playlistService.remove(PLAYLIST_ID)).andReturn(new Playlist());

    EasyMock.replay(bundleContext, playlistService);

    GqlDeletePlaylistPayload payload = buildCommand().execute();

    assertEquals(PLAYLIST_ID, payload.getId());
    EasyMock.verify(playlistService);
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
  void wrapsIllegalStateExceptionAsGraphQLRuntimeException() throws Exception {
    assertRemovalFailureIsMapped(new IllegalStateException("boom"), GraphQLRuntimeException.class);
  }

  @Test
  void buildFailsWhenIdIsNull() {
    assertThrows(IllegalArgumentException.class, () -> DeletePlaylistCommand.create(null)
        .environment(environment)
        .build());
  }

  @Test
  void buildFailsWhenEnvironmentIsMissing() {
    assertThrows(IllegalStateException.class, () -> DeletePlaylistCommand.create(PLAYLIST_ID).build());
  }

  private void assertRemovalFailureIsMapped(Exception thrown, Class<? extends Throwable> expected)
          throws Exception {
    EasyMock.expect(playlistService.remove(PLAYLIST_ID)).andThrow(thrown);

    EasyMock.replay(bundleContext, playlistService);

    assertThrows(expected, () -> buildCommand().execute());

    EasyMock.verify(playlistService);
  }

  private AbstractCommand<GqlDeletePlaylistPayload> buildCommand() {
    return DeletePlaylistCommand.create(PLAYLIST_ID).environment(environment).build();
  }

}
