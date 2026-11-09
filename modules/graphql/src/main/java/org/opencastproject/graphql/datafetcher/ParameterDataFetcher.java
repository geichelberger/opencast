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

import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.OpencastErrorType;
import org.opencastproject.graphql.util.GraphQLObjectMapper;

import java.util.Objects;

import graphql.schema.DataFetchingEnvironment;

public abstract class ParameterDataFetcher<T> implements ContextDataFetcher<T> {

  /** The largest page a client may request. Bounds the work a single request can cause. */
  public static final int MAX_PAGE_SIZE = 100;

  protected <E> E parseObjectParam(String name, Class<E> clazz, final DataFetchingEnvironment environment) {
    final Object param = environment.getArgument(name);
    if (param == null) {
      return null;
    }
    try {
      return GraphQLObjectMapper.newInstance().convertValue(param, clazz);
    } catch (IllegalArgumentException e) {
      throw new GraphQLRuntimeException("Invalid value for argument '" + name + "'", OpencastErrorType.BadRequest, e);
    }
  }

  protected <K> K parseParam(final String name, K defaultValue, final DataFetchingEnvironment environment) {
    return Objects.requireNonNullElse(environment.getArgument(name), defaultValue);
  }

  /**
   * Read the {@code limit} argument.
   *
   * @throws GraphQLRuntimeException if the limit is invalid, see {@link #validateLimit(int)}
   */
  protected int parseLimit(final int defaultValue, final DataFetchingEnvironment environment) {
    return validateLimit(parseParam("limit", defaultValue, environment));
  }

  /**
   * Read the {@code offset} argument.
   *
   * @throws GraphQLRuntimeException if the offset is invalid, see {@link #validateOffset(int)}
   */
  protected int parseOffset(final DataFetchingEnvironment environment) {
    return validateOffset(parseParam("offset", 0, environment));
  }

  /**
   * Check a page size given by a client.
   *
   * <p>A limit of 0 or less means "no limit" for the Elasticsearch index and {@code SmartIterator}, so the range is
   * validated instead of passed through.
   *
   * @return the limit
   * @throws GraphQLRuntimeException of type {@link OpencastErrorType#BadRequest} if the limit is not between 1 and
   *     {@link #MAX_PAGE_SIZE}
   */
  public static int validateLimit(final int limit) {
    if (limit < 1 || limit > MAX_PAGE_SIZE) {
      throw new GraphQLRuntimeException("limit must be between 1 and " + MAX_PAGE_SIZE, OpencastErrorType.BadRequest);
    }
    return limit;
  }

  /**
   * Check an offset given by a client.
   *
   * @return the offset
   * @throws GraphQLRuntimeException of type {@link OpencastErrorType#BadRequest} if the offset is negative
   */
  public static int validateOffset(final int offset) {
    if (offset < 0) {
      throw new GraphQLRuntimeException("offset must not be negative", OpencastErrorType.BadRequest);
    }
    return offset;
  }

}
