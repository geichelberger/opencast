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

package org.opencastproject.graphql.playlist;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.opencastproject.graphql.playlist.type.output.GqlPlaylistList;
import org.opencastproject.playlists.Playlist;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class GqlPlaylistListTest {

  @Test
  public void countsOnlyWhenAskedAndOnce() {
    AtomicInteger counted = new AtomicInteger();
    GqlPlaylistList list = new GqlPlaylistList(List.of(new Playlist()), () -> {
      counted.incrementAndGet();
      return 45;
    }, 20, 40);

    assertEquals(1, list.nodes().size());
    assertEquals(0, counted.get());

    assertEquals(Long.valueOf(45), list.totalCount());
    assertEquals(Long.valueOf(3), list.pageInfo().pageCount());
    assertEquals(1, counted.get());
  }

}
