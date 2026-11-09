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

package org.opencastproject.graphql.datafetcher;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.OpencastErrorType;

import org.junit.jupiter.api.Test;

public class ParameterDataFetcherTest {

  @Test
  public void acceptsLimitsWithinRange() {
    assertEquals(1, ParameterDataFetcher.validateLimit(1));
    assertEquals(ParameterDataFetcher.MAX_PAGE_SIZE,
        ParameterDataFetcher.validateLimit(ParameterDataFetcher.MAX_PAGE_SIZE));
  }

  @Test
  public void rejectsLimitsOutOfRange() {
    for (int limit : new int[] { -1, 0, ParameterDataFetcher.MAX_PAGE_SIZE + 1 }) {
      GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class,
          () -> ParameterDataFetcher.validateLimit(limit));
      assertEquals(OpencastErrorType.BadRequest, e.getErrorType());
    }
  }

  @Test
  public void rejectsNegativeOffsets() {
    assertEquals(0, ParameterDataFetcher.validateOffset(0));
    GraphQLRuntimeException e = assertThrows(GraphQLRuntimeException.class,
        () -> ParameterDataFetcher.validateOffset(-1));
    assertEquals(OpencastErrorType.BadRequest, e.getErrorType());
  }

}
